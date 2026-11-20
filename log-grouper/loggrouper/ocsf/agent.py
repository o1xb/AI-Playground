"""OCSF mapping agent and reviewer agent.

Mapper: for every active parser (one message format), choose the OCSF class and write a mapping from the
parsed vendor fields; validated against the OCSF schema on the parser's samples and run in real Logstash.
Reviewer: an independent agent (fresh context) that checks mappings for *semantic* errors a schema cannot
see (wrong class or activity, swapped source/destination, misread enums) and records issues the mapper
must address in its next session.
"""
import collections
import json
import os
import time

from ..agent_runtime import CodeTools, load_prompts, run_tool_agent
from ..parse.agent import load_samples
from ..parse.executor import run_parser, select_parser
from ..parse.logstash import ocsf_conformance
from ..parse.store import MappingStore, ParserStore
from ..parse.validate import FAILURE_TAGS, flatten
from .mapping import apply_mapping, prepare
from .schema import Schema
from .validate import mapping_metrics, mapping_verdict


class _Common:
    def _load_common(self, store_path, groups_dir, labels):
        self.parsers = ParserStore(store_path)
        self.mappings = MappingStore(store_path)
        self.schema = Schema()
        self.samples = load_samples(groups_dir, labels)
        self.parsed = {}                       # parser_id -> [parsed events]
        for label, msgs in self.samples.items():
            ps = self.parsers.ordered(label)
            for m in msgs:
                p = select_parser(ps, m)
                if p is None:
                    continue
                ev = run_parser(p, m)
                if FAILURE_TAGS & set(ev.get("tags", [])):
                    continue
                self.parsed.setdefault(p["id"], []).append(ev)

    def ocsf_search(self, query: str) -> str:
        """Search OCSF 1.4 classes and objects by keywords (e.g. "firewall traffic", "authentication")."""
        return "\n".join(self.schema.search(query)) or "no match"

    def ocsf_class(self, name_or_uid: str, include_optional: bool = False) -> str:
        """Attributes of an OCSF class: name | type | requirement | enum captions | description."""
        name, c = self.schema.cls(name_or_uid)
        if not c:
            return f"ERROR: unknown class {name_or_uid}"
        rows = [f"class {c['uid']} {name} ({c['category']}, category_uid {c['category_uid']}): {c['description']}",
                f"profiles: {c['profiles']}", "attribute | type | requirement | enum | description"]
        for k, a in sorted(c["attributes"].items(), key=lambda kv: ({"required": 0, "recommended": 1}.get(kv[1]["requirement"], 2), kv[0])):
            if a["requirement"] == "optional" and not include_optional:
                continue
            enum = ", ".join(f"{i}={v}" for i, v in list((a.get("enum") or {}).items())[:14])
            rows.append(f"{k} | {a['type']}{'[]' if a.get('is_array') else ''} | {a['requirement']}"
                        f"{' (profile ' + a['profile'] + ')' if a.get('profile') else ''} | {enum} | {a['description'][:110]}")
        if not include_optional:
            rows.append(f"(+{sum(1 for a in c['attributes'].values() if a['requirement'] == 'optional')} optional attributes; "
                        "include_optional=true to list)")
        return "\n".join(rows)

    def ocsf_object(self, name: str) -> str:
        """Attributes of an OCSF object (e.g. network_endpoint, user, network_connection_info)."""
        o = self.schema.s["objects"].get(name)
        if not o:
            return f"ERROR: unknown object {name}"
        rows = [f"object {name}: {o['description']}", "attribute | type | requirement | enum | description"]
        for k, a in sorted(o["attributes"].items()):
            enum = ", ".join(f"{i}={v}" for i, v in list((a.get("enum") or {}).items())[:12])
            rows.append(f"{k} | {a['type']}{'[]' if a.get('is_array') else ''} | {a['requirement']} | {enum} | {a['description'][:100]}")
        return "\n".join(rows)

    def _trace(self, parser_id, mapping, k=3):
        evs = self.parsed.get(parser_id, [])
        step = max(1, len(evs) // k)
        out = []
        for ev in evs[::step][:k]:
            out.append({"message": ev.get("message", "")[:400], "parsed_vendor": ev.get("vendor"),
                        "ocsf": apply_mapping(mapping, ev) if mapping else None})
        return out


class MappingTools(_Common, CodeTools):
    def __init__(self, store_path, groups_dir, labels=None, logstash_home=None, enable_code=False,
                 workspace=None, sandbox_backend="unshare", max_submits=6, drafts_path=None):
        self._load_common(store_path, groups_dir, labels)
        self.logstash_home = logstash_home
        self.max_submits, self.submits = max_submits, 0
        self.drafts, self.reports = [], []
        self.drafts_path = drafts_path
        if drafts_path and os.path.exists(drafts_path):
            with open(drafts_path) as f:
                d = json.load(f)
            self.drafts, self.submits = d["drafts"], d["submits"]
        self._init_code(enable_code, workspace, sandbox_backend, [store_path, groups_dir])
        if enable_code:
            self._write_workspace()

    def _persist(self):
        if self.drafts_path:
            with open(self.drafts_path, "w") as f:
                json.dump({"drafts": self.drafts, "submits": self.submits}, f)

    def _write_workspace(self):
        ws = self.workspace
        os.makedirs(os.path.join(ws, "parsed"), exist_ok=True)
        for pid, evs in self.parsed.items():
            with open(os.path.join(ws, "parsed", f"{pid}.jsonl"), "w") as f:
                f.writelines(json.dumps(e) + "\n" for e in evs)
        with open(os.path.join(ws, "mappings.json"), "w") as f:
            json.dump(self.mappings.active(), f, indent=1)
        with open(os.path.join(ws, "parsers.json"), "w") as f:
            json.dump(self.parsers.active(), f, indent=1)
        with open(os.path.join(ws, "README.txt"), "w") as f:
            f.write("parsed/<parser_id>.jsonl  parsed events {message, vendor: {...}, @timestamp?}\n"
                    "parsers.json, mappings.json  active specs\n"
                    "lib/loggrouper: from loggrouper.ocsf.schema import Schema; from loggrouper.ocsf.mapping import "
                    "prepare, apply_mapping; Schema().validate(event) -> (errors, warnings)\n")

    def overview(self) -> str:
        """Start here. Active parsers (one per format), their parsed sample counts, mapping status and
        open review issues."""
        rows = ["parser | label | format | parsed samples | mapping | valid_rate | review"]
        for p in self.parsers.all_ordered():
            if p["label"] not in self.samples:
                continue
            m = self.mappings.for_parser(p["id"])
            rev = (m or {}).get("review", {})
            rows.append(f"{p['id']} | {p['label']} | {p.get('format')} | {len(self.parsed.get(p['id'], []))} | "
                        f"{m['id'] + ' class ' + str(m['class_uid']) if m else '-'} | "
                        f"{(m or {}).get('metrics', {}).get('valid_rate', '-')} | "
                        f"{rev.get('verdict', '-')}{' (' + str(len(rev.get('issues', []))) + ' issues)' if rev.get('issues') else ''}")
        return "\n".join(rows)

    def parser_fields(self, parser_id: str, max_values: int = 5) -> str:
        """What a parser extracts: each vendor field with presence %, example values and a type guess,
        plus one full parsed event."""
        evs = self.parsed.get(parser_id)
        if not evs:
            return f"ERROR: no parsed samples for {parser_id}"
        stats = collections.OrderedDict()
        for ev in evs:
            for k, v in flatten(ev.get("vendor")).items():
                s = stats.setdefault(k, [0, collections.Counter()])
                s[0] += 1
                s[1][json.dumps(v)[:60]] += 1
        rows = [f"{parser_id}: {len(evs)} parsed samples; @timestamp set in "
                f"{sum(1 for e in evs if '@timestamp' in e)}", "field | present% | distinct | examples"]
        for k, (c, vals) in stats.items():
            rows.append(f"vendor.{k} | {round(100 * c / len(evs))} | {len(vals)} | " + ", ".join(v for v, _ in vals.most_common(max_values)))
        rows.append("example parsed event: " + json.dumps(evs[0])[:1500])
        return "\n".join(rows)

    def _spec(self, spec_json):
        spec = json.loads(spec_json) if isinstance(spec_json, str) else spec_json
        p = self.parsers.by_id(spec.get("parser_id", ""))
        if not p:
            raise ValueError("spec.parser_id must name an active parser")
        if not isinstance(spec.get("fields"), list) or "class_uid" not in spec:
            raise ValueError("spec needs parser_id, class_uid and fields: [...]")
        spec["label"], spec["format"] = p["label"], p.get("format")
        return spec, prepare(spec, self.schema)

    def try_mapping(self, spec_json: str, show: int = 1) -> str:
        """Dry-run a mapping spec (JSON string) on the parser's samples: schema validity, errors with
        examples, unused vendor fields, recommended attributes still missing, and sample outputs."""
        try:
            spec, prep = self._spec(spec_json)
        except (ValueError, KeyError) as e:
            return f"ERROR: {e}"
        try:
            m = mapping_metrics(prep, self.schema, self.parsed.get(spec["parser_id"], []))
        except Exception as e:  # noqa: BLE001
            return f"ERROR running mapping: {type(e).__name__}: {e}"
        m["verdict"] = mapping_verdict(m) or "ok"
        evs = self.parsed.get(spec["parser_id"], [])
        m["outputs"] = [apply_mapping(prep, e) for e in evs[:show]]
        for o in m["outputs"]:
            o.pop("raw_data", None)
        return json.dumps(m, indent=1, default=str)[:12000]

    def propose_mapping(self, spec_json: str, rationale: str) -> str:
        """Draft a mapping for a parser (replaces its current mapping on submit). Must pass validation."""
        try:
            spec, prep = self._spec(spec_json)
            m = mapping_metrics(prep, self.schema, self.parsed.get(spec["parser_id"], []))
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {type(e).__name__}: {e}"
        v = mapping_verdict(m)
        if v:
            return f"ERROR: not drafted - {v}"
        self.drafts = [d for d in self.drafts if d["spec"]["parser_id"] != spec["parser_id"]]
        self.drafts.append({"spec": spec, "rationale": rationale})
        self._persist()
        return f"drafted mapping for {spec['parser_id']}: valid_rate {m['valid_rate']}, mapped share {m['mapped_field_share']}"

    def get_review(self, parser_id: str) -> str:
        """The reviewer's verdict and issues for a parser's current mapping."""
        m = self.mappings.for_parser(parser_id)
        return json.dumps((m or {}).get("review") or "no review", indent=1)

    def submit(self) -> str:
        """Validate drafts, run them through real Logstash (parser + OCSF ruby step) against the Python
        executor, then activate. Returns verdicts."""
        if self.submits >= self.max_submits:
            return "ERROR: submit limit reached; finish with your summary"
        self.submits += 1
        origin = f"mapping-agent:{time.strftime('%Y%m%dT%H%M%S')}"
        ok, rejected = [], []
        for d in self.drafts:
            spec = d["spec"]
            prep = prepare(spec, self.schema)
            m = mapping_metrics(prep, self.schema, self.parsed.get(spec["parser_id"], []))
            v = mapping_verdict(m)
            if v:
                self.mappings.reject(spec, v, origin); rejected.append({"parser_id": spec["parser_id"], "reason": v})
            else:
                ok.append((d, spec, prep, m))
        conf = None
        if ok and self.logstash_home:
            ids = {s["parser_id"] for _, s, _, _ in ok}
            labels = {self.parsers.by_id(i)["label"] for i in ids}
            parsers = [p for p in self.parsers.all_ordered() if p["label"] in labels]
            maps = {s["parser_id"]: prep for _, s, prep, _ in ok}
            samples = []
            for i in ids:
                lbl = self.parsers.by_id(i)["label"]
                samples += [(lbl, e["message"]) for e in self.parsed.get(i, [])[:30]]
            try:
                conf = ocsf_conformance(parsers, maps, samples, self.logstash_home)
            except Exception as e:  # noqa: BLE001
                conf = {"error": str(e)[:400], "diffs": []}
        bad = set()
        if conf:
            if conf.get("error"):
                bad = {s["parser_id"] for _, s, _, _ in ok}
            for dd in conf.get("diffs", []):
                bad.add(dd.get("parser_id"))
        done = []
        for d, spec, prep, m in ok:
            if spec["parser_id"] in bad:
                why = (conf or {}).get("error") or "Logstash OCSF output differs from Python"
                self.mappings.reject(spec, why, origin); rejected.append({"parser_id": spec["parser_id"], "reason": why})
                continue
            old = self.mappings.for_parser(spec["parser_id"])
            spec = dict(spec, status="active", origin=origin, rationale=d["rationale"],
                        metrics={k: m[k] for k in ("events", "valid_rate", "mapped_field_share")})
            if old:
                spec["id"] = old["id"]
                spec["history"] = old.get("history", []) + [{"origin": origin, "previous": {k: old[k] for k in ("class_uid", "fields")},
                                                             "previous_review": old.get("review")}]
                self.mappings.items[self.mappings.items.index(old)] = spec
            else:
                spec["id"] = self.mappings.next_id("m")
                self.mappings.items.append(spec)
            done.append({"id": spec["id"], "parser_id": spec["parser_id"], "class_uid": spec["class_uid"],
                         "valid_rate": m["valid_rate"], "mapped_field_share": m["mapped_field_share"]})
        self.mappings.save()
        self.drafts = []
        self._persist()
        if self.enable_code:
            self._write_workspace()
        rep = {"accepted": done, "rejected": rejected,
               "logstash_check": None if conf is None else {k: conf.get(k) for k in ("checked", "identical", "error")}}
        self.reports.append(rep)
        return json.dumps(rep, indent=1)

    def tool_functions(self):
        return self.code_tool_functions() + [self.overview, self.parser_fields, self.ocsf_search, self.ocsf_class,
                                             self.ocsf_object, self.try_mapping, self.propose_mapping,
                                             self.get_review, self.submit]


class ReviewTools(_Common):
    """Read-only view of mappings plus one write: record_review. Runs in a fresh context, so it judges the
    mapping from the data, not from the mapper's reasoning."""

    def __init__(self, store_path, groups_dir, labels=None):
        self._load_common(store_path, groups_dir, labels)

    def list_mappings(self) -> str:
        """Active mappings to review: mapping | parser | label | format | class | current review."""
        rows = ["mapping | parser | label | format | class | review"]
        for m in self.mappings.active():
            if m["label"] not in self.samples:
                continue
            rows.append(f"{m['id']} | {m['parser_id']} | {m['label']} | {m.get('format')} | {m['class_uid']} "
                        f"{self.schema.cls(m['class_uid'])[0]} | {(m.get('review') or {}).get('verdict', '-')}")
        return "\n".join(rows)

    def show_mapping(self, mapping_id: str, samples: int = 3) -> str:
        """A mapping spec plus traces: original message -> parsed vendor fields -> OCSF output."""
        m = self.mappings.by_id(mapping_id)
        if not m:
            return f"ERROR: unknown mapping {mapping_id}"
        prep = prepare(m, self.schema)
        tr = self._trace(m["parser_id"], prep, samples)
        for t in tr:
            if t["ocsf"]:
                t["ocsf"].pop("raw_data", None)
        return json.dumps({"mapping": {k: m[k] for k in ("id", "parser_id", "label", "format", "class_uid", "fields")},
                           "traces": tr}, indent=1, default=str)[:15000]

    def record_review(self, mapping_id: str, verdict: str, issues: list[str], notes: str = "") -> str:
        """Record your review. verdict: "approve" or "changes_requested". issues: concrete, actionable
        problems (e.g. "src/dst swapped: vendor.dst_ip -> src_endpoint.ip"). The mapper must address them."""
        m = self.mappings.by_id(mapping_id)
        if not m:
            return f"ERROR: unknown mapping {mapping_id}"
        if verdict not in ("approve", "changes_requested"):
            return "ERROR: verdict must be approve or changes_requested"
        m["review"] = {"verdict": verdict, "issues": issues, "notes": notes, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
        self.mappings.save()
        return f"recorded {verdict} for {mapping_id} ({len(issues)} issues)"

    def tool_functions(self):
        return [self.list_mappings, self.show_mapping, self.ocsf_search, self.ocsf_class, self.ocsf_object,
                self.record_review]


def run_mapping_agent(store_path, groups_dir, labels=None, logstash_home=None, enable_code=True, **kw):
    tools = MappingTools(store_path, groups_dir, labels=labels, logstash_home=logstash_home, enable_code=enable_code)
    out = run_tool_agent(tools, load_prompts("mapping_agent.md", *(["mapping_code_tools.md"] if enable_code else [])),
                         "Map every parser in `overview` to OCSF (and address open review issues). "
                         "Finish with a short summary.", **kw)
    out["reports"] = tools.reports
    return out


def run_review_agent(store_path, groups_dir, labels=None, **kw):
    tools = ReviewTools(store_path, groups_dir, labels=labels)
    return run_tool_agent(tools, load_prompts("review_agent.md"),
                          "Review every mapping in `list_mappings` and record a verdict for each.", **kw)
