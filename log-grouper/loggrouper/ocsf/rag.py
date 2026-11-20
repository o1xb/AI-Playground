"""RAG-based OCSF mapper: retrieval over the OCSF schema + ONE structured LLM call per message format,
then deterministic validation and at most a couple of repair calls. Replaces the tool-using mapping agent
for the common case (far fewer calls and tokens).

  1. profile   parsed samples of a parser -> field profile (names, presence, types, examples, value sets)
  2. retrieve  embed the profile; rank OCSF classes; rank candidate OCSF attribute paths per vendor field
               (within the candidate classes), plus the enum attributes those classes offer
  3. prompt    one compact prompt with only that slice of the schema
  4. LLM       returns a mapping spec (JSON)
  5. validate  same validator as everywhere (schema validity on all samples); on failure, one repair
               prompt with the exact errors

Embedder: any sentence-transformers model; default google/embeddinggemma-300m (gated: needs a Hugging Face
token with license access). Embeddings of the schema are cached per model.
"""
import collections
import hashlib
import json
import os
import re

import numpy as np

from ..parse.validate import flatten
from .mapping import prepare
from .schema import Schema
from .validate import mapping_metrics, mapping_verdict

DEFAULT_MODEL = os.environ.get("LG_EMBED_MODEL", "google/embeddinggemma-300m")
CACHE_DIR = os.environ.get("LG_EMBED_CACHE", os.path.join(os.path.expanduser("~"), ".cache", "loggrouper"))
# always offered as one-liners: the classes security telemetry most often lands in
COMMON_CLASSES = ["network_activity", "http_activity", "dns_activity", "authentication", "detection_finding",
                  "tunnel_activity", "email_activity", "config_state", "device_config_state_change",
                  "account_change", "api_activity", "process_activity", "file_activity", "event_log",
                  "dhcp_activity", "web_resources_activity", "data_security_finding"]
COMMON_ENUMS = ["activity_id", "severity_id", "action_id", "disposition_id", "status_id",
                "connection_info.direction_id", "connection_info.protocol_num", "auth_protocol_id",
                "logon_type_id", "http_request.http_method", "confidence_id", "risk_level_id"]


# ------------------------------------------------------------------ embedder
class Embedder:
    def __init__(self, model=DEFAULT_MODEL, device="cpu"):
        from sentence_transformers import SentenceTransformer
        self.name = model
        self.m = SentenceTransformer(model, device=device)
        self.has_prompts = hasattr(self.m, "encode_query") and "gemma" in model.lower()

    def docs(self, texts, batch_size=64):
        f = self.m.encode_document if self.has_prompts else self.m.encode
        return np.asarray(f(list(texts), batch_size=batch_size, normalize_embeddings=True), dtype=np.float32)

    def queries(self, texts, batch_size=64):
        f = self.m.encode_query if self.has_prompts else self.m.encode
        return np.asarray(f(list(texts), batch_size=batch_size, normalize_embeddings=True), dtype=np.float32)


# ------------------------------------------------------------------ schema index
def _class_paths(schema, cls, max_depth=3):
    """All attribute paths reachable in a class (objects expanded, cycles cut)."""
    out = {}

    def walk(attrs, prefix, depth, seen):
        for k, a in attrs.items():
            p = prefix + k
            out.setdefault(p, a)
            t = a["type"]
            if t in schema.s["objects"] and depth < max_depth and t not in seen:
                walk(schema.s["objects"][t]["attributes"], p + ".", depth + 1, seen | {t})
    walk(cls["attributes"], "", 0, frozenset())
    return out


def _attr_doc(path, a):
    enum = ""
    if a.get("enum"):
        enum = " values: " + ", ".join(f"{v}" for k, v in list(a["enum"].items())[:10])
    return f"{path} ({a['type']}): {a.get('caption') or ''}. {a.get('description') or ''}{enum}"


class OcsfIndex:
    def __init__(self, embedder, schema=None):
        self.e, self.schema = embedder, schema or Schema()
        s = self.schema.s
        self.class_names = sorted(s["classes"])
        self.class_docs = [f"{s['classes'][n]['caption']} ({s['classes'][n]['category_caption']}): "
                           f"{s['classes'][n]['description']}" for n in self.class_names]
        self.class_paths = {n: _class_paths(self.schema, s["classes"][n]) for n in self.class_names}
        allp = {}
        for n in self.class_names:
            for p, a in self.class_paths[n].items():
                allp.setdefault(p, a)
        self.paths = sorted(allp)
        self.path_attr = allp
        key = hashlib.sha1((embedder.name + self.schema.version + str(len(self.paths))).encode()).hexdigest()[:12]
        cache = os.path.join(CACHE_DIR, f"ocsf-index-{key}.npz")
        if os.path.exists(cache):
            z = np.load(cache)
            self.C, self.P = z["C"], z["P"]
        else:
            self.C = embedder.docs(self.class_docs)
            self.P = embedder.docs([_attr_doc(p, allp[p]) for p in self.paths])
            os.makedirs(CACHE_DIR, exist_ok=True)
            np.savez_compressed(cache, C=self.C, P=self.P)
        self.pidx = {p: i for i, p in enumerate(self.paths)}
        self.class_idx = {n: np.array([self.pidx[p] for p in self.class_paths[n]], dtype=np.int64)
                          for n in self.class_names}

    def top_classes(self, qvec, k=3, field_vecs=None, w_cover=0.6):
        """Rank classes by description similarity blended with field coverage: how well each class's
        attributes match the vendor fields (mean of each field's best attribute similarity in the class)."""
        sc = self.C @ qvec
        if field_vecs is not None and len(field_vecs):
            S = field_vecs @ self.P.T                               # fields x all attribute paths
            cover = np.array([S[:, self.class_idx[n]].max(axis=1).mean() for n in self.class_names])
            z = lambda x: (x - x.mean()) / (x.std() + 1e-9)          # put both signals on one scale
            sc = (1 - w_cover) * z(sc) + w_cover * z(cover)
        order = np.argsort(-sc)[:k]
        return [(self.class_names[i], float(sc[i])) for i in order]

    def top_paths(self, qvec, allowed, k=6, type_hint=None):
        idx = np.array([self.pidx[p] for p in allowed], dtype=np.int64)
        sc = self.P[idx] @ qvec
        if type_hint:                                   # light boost for type-compatible attributes
            bonus = np.array([0.08 if _type_ok(self.path_attr[p]["type"], type_hint) else 0.0 for p in allowed])
            sc = sc + bonus
        order = np.argsort(-sc)[:k]
        return [(allowed[i], float(sc[i])) for i in order]


def _type_ok(t, hint):
    return {"ip": t == "ip_t", "port": t == "port_t", "int": t in ("integer_t", "long_t", "port_t"),
            "time": t in ("timestamp_t", "datetime_t"), "mac": t == "mac_t", "email": t == "email_t",
            "url": t in ("url_t", "string_t")}.get(hint, False)


# ------------------------------------------------------------------ profile
_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$")
_MAC = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def _hint(name, vals):
    sv = [str(v) for v in vals if v not in (None, "")]
    if sv and all(_IP.match(v) for v in sv):
        return "ip"
    if sv and all(_MAC.match(v) for v in sv):
        return "mac"
    if re.search(r"port", name, re.I) and all(v.isdigit() for v in sv):
        return "port"
    if re.search(r"time|date|ts$", name, re.I):
        return "time"
    if sv and all(re.match(r"^-?\d+$", v) for v in sv):
        return "int"
    if sv and any("@" in v for v in sv) and re.search(r"mail|user|from|to", name, re.I):
        return "email"
    if sv and any(v.startswith(("http://", "https://")) for v in sv):
        return "url"
    return None


def profile(events, max_values=6):
    stats = collections.OrderedDict()
    for ev in events:
        for k, v in flatten(ev.get("vendor")).items():
            s = stats.setdefault(k, {"n": 0, "vals": collections.Counter()})
            s["n"] += 1
            s["vals"][json.dumps(v)[:80] if not isinstance(v, str) else v[:80]] += 1
    out = []
    for k, s in stats.items():
        vals = [v for v, _ in s["vals"].most_common()]
        out.append({"field": "vendor." + k, "present": round(s["n"] / max(1, len(events)), 2),
                    "distinct": len(vals), "values": vals[:max_values],
                    "enum_like": len(vals) <= 12 and len(events) >= 5 and len(vals) < len(events),
                    "hint": _hint(k, vals[:20])})
    has_ts = sum(1 for e in events if "@timestamp" in e)
    return out, has_ts


# ------------------------------------------------------------------ prompt
RULES = """Mapping spec rules:
- {"class_uid": <int>, "fields": [ ... ], "unmapped": true}
- field: {"to": "<ocsf.path>", "from": "<vendor.path>" | ["<vendor.a>", "<vendor.b>"] (first non-empty) |
  "@timestamp" (event time the parser extracted), or "value": <constant>; optional "map": {"vendor value": ocsf value},
  "default": <value if source missing or not in map>, "type": integer|float|string|boolean|lower|upper|timestamp_ms,
  "skip_values": [...] (placeholders meaning no value; default "-", "None", "N/A", "null", "unknown")}
- Array elements by index: "evidences[0].src_endpoint.ip".
- Automatic: class_uid/category_uid/type_uid, *_name captions, metadata.version, raw_data, unmapped leftovers;
  `time` from @timestamp if you do not set it; activity_id/severity_id default 0.
- Always set metadata.product.vendor_name and metadata.product.name. Fill required attributes of every object
  you use (e.g. connection_info.direction_id). Map enums with the vendor's actual values (shown below) and a
  default. Keep source vs destination and actor vs target right per the vendor's documented semantics.
  Ports/counts as integer, times as timestamp_ms. Do not invent data.
Answer with the JSON spec only."""


def build_prompt(index, parser, events, k_classes=3, k_paths=5, class_names=None):
    prof, has_ts = profile(events)
    msgs = [e.get("message", "")[:400] for e in events[:2]]
    label, fmt = parser["label"], parser.get("format")
    q_class = f"{label} {fmt} log event: " + (msgs[0][:300] if msgs else "")
    qv = index.e.queries([q_class])[0]
    fq = index.e.queries([f"{p['field'][7:].replace('_', ' ').replace('.', ' ')}: {', '.join(map(str, p['values'][:3]))}"
                          for p in prof]) if prof else np.zeros((0, 1))
    if class_names:                                  # class chosen in step 1: retrieve attributes within it
        classes = [(n, 1.0) for n in class_names]
        allowed = sorted({p for n in class_names for p in index.class_paths[n]})
    else:
        classes = index.top_classes(qv, k_classes, fq)
        allowed = sorted({p for n, _ in classes for p in index.class_paths[n]} |
                         {p for n in COMMON_CLASSES if n in index.class_paths for p in index.class_paths[n]})
    lines = [f"# Map parsed {label} ({fmt}) log fields to OCSF {index.schema.version}",
             f"{len(events)} parsed samples; parser extracted an event time (@timestamp) in {has_ts} of them.",
             "## Sample messages"] + [f"- {m}" for m in msgs]
    lines.append("## Parsed vendor fields (field | present | distinct | hint | sample values)")
    for p in prof:
        lines.append(f"{p['field']} | {p['present']} | {p['distinct']} | {p['hint'] or '-'} | "
                     + json.dumps(p["values"][:6 if p["enum_like"] else 3], ensure_ascii=False)[:220])
    lines.append("## OCSF class (use this class_uid)" if class_names else
                 "## Candidate OCSF classes (choose one; another class only if clearly better)")
    s = index.schema.s
    for n, sc in classes:
        c = s["classes"][n]
        req = [k for k, a in c["attributes"].items() if a["requirement"] == "required" and not a.get("profile")]
        rec = [k for k, a in c["attributes"].items() if a["requirement"] == "recommended" and not a.get("profile")]
        lines.append(f"### {c['uid']} {n} ({c['caption']}): {c['description'][:220]}")
        lines.append(f"required: {', '.join(req)}")
        lines.append(f"recommended: {', '.join(rec)}")
        lines.append("activity_id: " + ", ".join(f"{k}={v}" for k, v in c["attributes"]["activity_id"].get("enum", {}).items()))
        if c.get("constraints"):
            lines.append(f"constraints: {json.dumps(c['constraints'])}")
    if not class_names:
        others = [n for n in COMMON_CLASSES if n in s["classes"] and n not in dict(classes)]
        lines.append("other common classes: " + "; ".join(f"{s['classes'][n]['uid']} {n}" for n in others))
    lines.append("## Candidate OCSF attributes per vendor field (ranked by similarity)")
    for i, p in enumerate(prof):
        top = index.top_paths(fq[i], allowed, k_paths, p["hint"])
        lines.append(f"{p['field']} -> " + ", ".join(f"{path} ({index.path_attr[path]['type']})" for path, _ in top))
    lines.append("## Enum attributes (path: id=meaning)")
    shown = 0
    for path in COMMON_ENUMS:
        a = next((index.class_paths[n].get(path) for n, _ in classes if index.class_paths[n].get(path)), None)
        if a and a.get("enum") and path != "activity_id":
            lines.append(f"{path}: " + ", ".join(f"{k}={v}" for k, v in list(a["enum"].items())[:14]))
            shown += 1
    lines.append("## Required attributes of commonly used objects")
    for obj in ("network_endpoint", "network_connection_info", "device", "user", "finding_info", "evidences",
                "http_request", "url", "file", "product"):
        o = s["objects"].get(obj)
        if o:
            req = [k for k, a in o["attributes"].items() if a["requirement"] == "required"]
            if req:
                lines.append(f"{obj}: {', '.join(req)}")
    lines.append(RULES)
    return "\n".join(lines), [n for n, _ in classes]


def build_class_prompt(schema, parser, events):
    """Step 1 (small): choose the OCSF class. The model knows OCSF; we give the full class list as one-liners."""
    prof, _ = profile(events)
    msgs = [e.get("message", "")[:300] for e in events[:3]]
    lines = [f"# Choose the OCSF {schema.version} event class for {parser['label']} ({parser.get('format')}) logs",
             "## Sample messages"] + [f"- {m}" for m in msgs]
    lines.append("## Parsed fields (name: sample values)")
    for p in prof[:80]:
        lines.append(f"{p['field'][7:]}: {json.dumps(p['values'][:3], ensure_ascii=False)[:90]}")
    lines.append("## OCSF classes (uid name: caption - description)")
    for n, c in sorted(schema.s["classes"].items(), key=lambda kv: kv[1]["uid"]):
        lines.append(f"{c['uid']} {n}: {c['description'][:110]}")
    lines.append('Pick the class that best describes most of these events. Answer JSON only: {"class_uid": <int>, "why": "<short>"}')
    return "\n".join(lines)


def parse_answer(text):
    """LLM answer -> spec dict (tolerates code fences / surrounding prose)."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in answer")
    return json.loads(m.group(0))


def repair_prompt(spec, metrics):
    return ("Your OCSF mapping spec failed validation on the parsed samples.\n"
            f"Spec:\n{json.dumps(spec)}\n"
            f"Validation: valid_rate={metrics['valid_rate']} errors={json.dumps(metrics['errors'][:10])}\n"
            f"Examples: {json.dumps(metrics['error_examples'][:2])[:1500]}\n"
            "Return the corrected full spec as JSON only (same rules as before).")


def evaluate(spec, parser, events, schema):
    spec = dict(spec, parser_id=parser["id"], label=parser["label"], format=parser.get("format"))
    prep = prepare(spec, schema)
    m = mapping_metrics(prep, schema, events)
    return spec, m, mapping_verdict(m)


# ------------------------------------------------------------------ Claude API driver
def map_with_claude(index, parser, events, model="claude-opus-5-5", effort="medium", max_repairs=2, client=None):
    """Production path: one call (+ repairs) per format. Returns (spec or None, metrics, usage)."""
    import anthropic
    client = client or anthropic.Anthropic()
    usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0}
    r = client.beta.messages.create(model=model, max_tokens=2000, betas=["server-side-fallback-2026-07-01"],
                                    fallbacks="default", output_config={"effort": "low"},
                                    messages=[{"role": "user", "content": build_class_prompt(index.schema, parser, events)}])
    usage["calls"] += 1
    usage["input_tokens"] += r.usage.input_tokens
    usage["output_tokens"] += r.usage.output_tokens
    if r.stop_reason == "refusal":
        return None, None, usage
    chosen = index.schema.cls(parse_answer("".join(b.text for b in r.content if b.type == "text"))["class_uid"])[0]
    prompt, _ = build_prompt(index, parser, events, class_names=[chosen] if chosen else None)
    messages = [{"role": "user", "content": prompt}]
    spec = m = None
    for attempt in range(1 + max_repairs):
        resp = client.beta.messages.create(model=model, max_tokens=8000, betas=["server-side-fallback-2026-07-01"],
                                           fallbacks="default", thinking={"type": "adaptive"},
                                           output_config={"effort": effort}, messages=messages)
        usage["calls"] += 1
        usage["input_tokens"] += resp.usage.input_tokens
        usage["output_tokens"] += resp.usage.output_tokens
        if resp.stop_reason == "refusal":
            return None, None, usage
        text = "".join(b.text for b in resp.content if b.type == "text")
        try:
            spec, m, verdict = evaluate(parse_answer(text), parser, events, index.schema)
        except Exception as e:  # noqa: BLE001
            verdict, m = f"unparseable: {e}", {"valid_rate": 0, "errors": [[str(e), 1]], "error_examples": []}
        if not verdict:
            return spec, m, usage
        messages += [{"role": "assistant", "content": resp.content},
                     {"role": "user", "content": repair_prompt(spec or {}, m)}]
    return None, m, usage
