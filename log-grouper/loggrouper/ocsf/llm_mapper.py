"""OCSF mapping without retrieval: the model sees the schema itself.

Methods
  full   (M1) system prompt = whole compact OCSF schema (cached); one call picks the class and writes the
              mapping; validator-driven repair calls if needed.
  slice  (M2) call 1 picks the class from one-line class descriptions; call 2 gets the complete slice of
              that class (all attributes + every reachable object, enums) and writes the mapping; repairs.
  cover  (M3) slice + a coverage call: the vendor fields still left in `unmapped` are listed with values and
              the model adds mappings for those that fit (accepted only if validation still passes and the
              mapped share goes up).

Each step is a single prompt -> JSON answer, so it runs on the Claude API (`map_format`) or through the
benchmark's prompt/answer protocol (bench/map_bench.py).
"""
import json

from ..parse.validate import flatten
from .mapping import apply_mapping, prepare
from .rag import evaluate, parse_answer, profile, repair_prompt
from .schema_text import class_list_text, class_slice_text, full_schema_text

SPEC_RULES = """## Mapping spec (answer with this JSON only)
{"class_uid": <int>, "fields": [ ... ], "unmapped": true}
field: {"to": "<ocsf.path>", "from": "<vendor.path>" | ["<vendor.a>", "<vendor.b>"] (first non-empty) | "@timestamp"
        (event time the parser extracted), or "value": <constant>; optional "map": {"vendor value": ocsf value},
        "default": <value when the source is missing or not in map>, "type": integer|float|string|boolean|lower|
        upper|timestamp_ms, "skip_values": [...] (placeholders meaning no value; default "-", "None", "N/A", "null",
        "unknown")}
- Array elements by index: "evidences[0].src_endpoint.ip", "observables[0].value".
- Added automatically: class_uid/category_uid/type_uid, *_name captions of enums you set, metadata.version,
  raw_data, `unmapped` (vendor fields you did not use), `time` from @timestamp if you do not set it,
  activity_id/severity_id default 0.
- Always set metadata.product.vendor_name and metadata.product.name.
- Fill the required (!R) attributes of the class and of every object you use (e.g. connection_info.direction_id).
- MAP EVERY VENDOR FIELD THAT HAS A FITTING OCSF ATTRIBUTE (addresses, ports, MACs, hostnames, users,
  byte/packet counts, URLs, HTTP method/status, DNS query, rule/policy names, process/file details, ids,
  messages, severities, actions, interfaces/zones). Leave a field unmapped only if OCSF has no fitting place.
- Enums: map the vendor's actual values (listed in the profile) with a sensible default. Keep source vs
  destination and actor vs target right per the vendor's documented semantics. Ports and counts as integer,
  times as timestamp_ms. Do not invent data."""


def _profile_text(parser, events):
    prof, has_ts = profile(events)
    msgs = [e.get("message", "")[:400] for e in events[:3]]
    lines = [f"Vendor log: label={parser['label']} format={parser.get('format')} ({len(events)} parsed samples; "
             f"the parser extracted an event time (@timestamp) in {has_ts} of them)", "## Sample messages"]
    lines += [f"- {m}" for m in msgs]
    lines.append("## Parsed vendor fields (field | present | distinct | sample values)")
    for p in prof:
        lines.append(f"{p['field']} | {p['present']} | {p['distinct']} | "
                     + json.dumps(p["values"][:8 if p["enum_like"] else 3], ensure_ascii=False)[:240])
    return "\n".join(lines)


# ---------------------------------------------------------------- prompts
def full_system(schema):
    return ("You map parsed vendor security-log fields to OCSF. The complete OCSF schema follows.\n\n"
            + full_schema_text(schema) + "\n\n" + SPEC_RULES)


def full_user(parser, events):
    return _profile_text(parser, events) + "\n\nChoose the OCSF class that best fits most of these events and write the mapping spec."


def class_prompt(schema, parser, events):
    return (_profile_text(parser, events) + "\n\n## OCSF event classes (uid name (category): description)\n"
            + class_list_text(schema)
            + '\n\nPick the class that best describes most of these events. Answer JSON only: {"class_uid": <int>, "why": "<short>"}')


def slice_user(schema, parser, events, class_name):
    return (class_slice_text(class_name, schema) + "\n\n" + _profile_text(parser, events) + "\n\n" + SPEC_RULES
            + f"\nUse class_uid {schema.s['classes'][class_name]['uid']}.")


def coverage_prompt(spec, events, prepared, max_fields=60):
    """List vendor fields the accepted mapping leaves unused (with sample values)."""
    left = {}
    for ev in events:
        for k, v in flatten(apply_mapping(prepared, ev).get("unmapped")).items():
            left.setdefault(k, [])
            if len(left[k]) < 3 and v not in left[k]:
                left[k].append(v)
    if not left:
        return None
    rows = [f"vendor.{k} | {json.dumps(v, ensure_ascii=False)[:160]}" for k, v in list(left.items())[:max_fields]]
    return ("Your mapping below validated. These vendor fields are still unmapped:\n" + "\n".join(rows)
            + f"\n\nCurrent spec:\n{json.dumps(spec)}\n\nAdd mappings for every listed field that has a fitting "
            "attribute in the class/objects shown earlier (keep everything that is right). Return the full updated "
            "spec as JSON only.")


# ---------------------------------------------------------------- Claude API driver
def map_format(schema, parser, events, method="cover", model="claude-opus-5-5", effort="medium", client=None,
               max_repairs=2):
    """-> (spec or None, metrics, usage). Prompt caching on the schema text."""
    import anthropic
    client = client or anthropic.Anthropic()
    usage = {"calls": 0, "input_tokens": 0, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
             "output_tokens": 0}

    def call(system, messages, max_tokens=12000):
        kw = {"system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral", "ttl": "1h"}}]} if system else {}
        r = client.beta.messages.create(model=model, max_tokens=max_tokens, betas=["server-side-fallback-2026-07-01"],
                                        fallbacks="default", output_config={"effort": effort}, messages=messages, **kw)
        usage["calls"] += 1
        for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens"):
            usage[k] += getattr(r.usage, k, 0) or 0
        if r.stop_reason == "refusal":
            raise RuntimeError("refused")
        return r, "".join(b.text for b in r.content if b.type == "text")

    if method == "full":
        system, messages = full_system(schema), [{"role": "user", "content": full_user(parser, events)}]
    else:
        _, txt = call(None, [{"role": "user", "content": class_prompt(schema, parser, events)}], 1500)
        name = schema.cls(parse_answer(txt)["class_uid"])[0]
        system = None
        messages = [{"role": "user", "content": slice_user(schema, parser, events, name)}]
    spec = m = None
    for _ in range(1 + max_repairs):
        r, txt = call(system, messages)
        try:
            spec, m, verdict = evaluate(parse_answer(txt), parser, events, schema)
        except Exception as e:  # noqa: BLE001
            verdict, m = f"unparseable: {e}", {"valid_rate": 0, "errors": [[str(e), 1]], "error_examples": []}
        if not verdict:
            break
        messages += [{"role": "assistant", "content": r.content}, {"role": "user", "content": repair_prompt(spec or {}, m)}]
    else:
        return None, m, usage
    if method == "cover":
        cp = coverage_prompt(spec, events, prepare(spec, schema))
        if cp:
            messages += [{"role": "assistant", "content": r.content}, {"role": "user", "content": cp}]
            _, txt = call(system, messages)
            try:
                spec2, m2, v2 = evaluate(parse_answer(txt), parser, events, schema)
                if not v2 and m2["mapped_field_share"] > m["mapped_field_share"]:
                    spec, m = spec2, m2
            except Exception:  # noqa: BLE001
                pass
    return spec, m, usage


def map_store(store_path, groups_dir, labels=None, method="full", remap=False, logstash_home=None,
              model="claude-opus-5-5", effort="medium", fallback_agent=False, log=print):
    """Production entry point: map every active parser that has no mapping (or all, with remap) using the
    chosen method; validate; check accepted mappings in real Logstash; store them. Formats that still fail
    can go to the tool-using mapping agent (fallback_agent=True). Returns a usage/cost summary."""
    from ..parse.logstash import ocsf_conformance
    from .agent import MappingTools, run_mapping_agent
    tools = MappingTools(store_path, groups_dir, labels=labels, logstash_home=logstash_home)
    total = {"formats": 0, "accepted": 0, "failed": [], "calls": 0, "input_tokens": 0,
             "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 0}
    accepted = []
    for p in tools.parsers.all_ordered():
        evs = tools.parsed.get(p["id"])
        if not evs or (tools.mappings.for_parser(p["id"]) and not remap):
            continue
        total["formats"] += 1
        try:
            spec, m, usage = map_format(tools.schema, p, evs, method=method, model=model, effort=effort)
        except Exception as e:  # noqa: BLE001
            spec, m, usage = None, None, {}
            log(f"[{p['id']}] error: {e}")
        for k in ("calls", "input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "output_tokens"):
            total[k] += usage.get(k, 0)
        if spec is None:
            total["failed"].append(p["id"])
            continue
        accepted.append((p, spec, m))
    if accepted and logstash_home:                  # same conformance gate as every other change
        parsers = tools.parsers.all_ordered()
        maps = {p["id"]: dict(prepare(sp, tools.schema), id="draft-" + p["id"]) for p, sp, _ in accepted}
        samples = [(p["label"], e["message"]) for p, _, _ in accepted for e in tools.parsed[p["id"]][:20]]
        conf = ocsf_conformance(parsers, maps, samples, logstash_home)
        bad = {d["parser_id"] for d in conf["diffs"]}
        for p, sp, m in [x for x in accepted if x[0]["id"] in bad]:
            total["failed"].append(p["id"])
        accepted = [x for x in accepted if x[0]["id"] not in bad]
    for p, spec, m in accepted:
        old = tools.mappings.for_parser(p["id"])
        rec = dict(spec, status="active", origin=f"llm-{method}", metrics={k: m[k] for k in ("events", "valid_rate", "mapped_field_share")})
        if old:
            rec["id"] = old["id"]; rec["history"] = old.get("history", []) + [{"previous": {k: old[k] for k in ("class_uid", "fields")}}]
            tools.mappings.items[tools.mappings.items.index(old)] = rec
        else:
            rec["id"] = tools.mappings.next_id("m"); tools.mappings.items.append(rec)
        total["accepted"] += 1
    tools.mappings.save()
    if fallback_agent and total["failed"]:
        labels_f = sorted({tools.parsers.by_id(i)["label"] for i in total["failed"]})
        log(f"fallback: mapping agent for {labels_f}")
        run_mapping_agent(store_path, groups_dir, labels=labels_f, logstash_home=logstash_home, model=model, effort=effort)
    return total
