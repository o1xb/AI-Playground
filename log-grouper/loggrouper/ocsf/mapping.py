"""OCSF mapping specs: executor (Python) and compilation for Logstash (ocsf_mapper.rb, same semantics).

Spec:
  {"id", "parser_id", "label", "format", "class_uid": 4001,
   "fields": [
     {"to": "activity_id", "from": "vendor.subtype", "map": {"start": 1, "end": 2}, "default": 6},
     {"to": "src_endpoint.ip", "from": "vendor.src_ip"},
     {"to": "src_endpoint.port", "from": "vendor.src_port", "type": "integer"},
     {"to": "actor.user.name", "from": ["vendor.src_user", "vendor.user"]},      # first non-empty
     {"to": "time", "from": "@timestamp", "type": "timestamp_ms"},
     {"to": "metadata.product.vendor_name", "value": "Palo Alto Networks"}],
   "unmapped": true, "raw_data": true}

Rules, in order: take `value`, else the first non-empty `from`; if nothing, use `default` if given,
else skip. With `map`, look the value up (exact, then lowercase); not found -> `default` or skip.
Then cast with `type` (integer, float, string, boolean, lower, upper, timestamp_ms); a failed cast
skips the field. Afterwards: class/category/type uids, activity_id (default 0), severity_id
(default 0), time from @timestamp if unset, metadata.version, *_name siblings from the schema,
raw_data, and `unmapped` = vendor fields not used.
"""
import base64
import copy
import datetime as _dt
import json
import os
import re

from .schema import Schema

RUBY_SCRIPT = os.path.join(os.path.dirname(__file__), "ocsf_mapper.rb")
NUM = re.compile(r"^[-+]?\d+(\.\d+)?([eE][-+]?\d+)?$")
INT = re.compile(r"^[-+]?\d+$")


_IDX = re.compile(r"^(.+)\[(\d+)\]$")


def _get(ev, path):
    """Dotted path; a segment may carry an array index: evidences[0].src_endpoint.ip"""
    cur = ev
    for k in path.split("."):
        m = _IDX.match(k)
        if m:
            k, i = m.group(1), int(m.group(2))
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
        if m:
            if not isinstance(cur, list) or i >= len(cur):
                return None
            cur = cur[i]
    return cur


def _set(ev, path, v):
    ks = path.split(".")
    cur = ev
    for n, k in enumerate(ks):
        last = n == len(ks) - 1
        m = _IDX.match(k)
        if m:
            k, i = m.group(1), int(m.group(2))
            if not isinstance(cur.get(k), list):
                cur[k] = []
            while len(cur[k]) <= i:
                cur[k].append({})
            if last:
                cur[k][i] = v
            else:
                if not isinstance(cur[k][i], dict):
                    cur[k][i] = {}
                cur = cur[k][i]
        elif last:
            cur[k] = v
        else:
            if not isinstance(cur.get(k), dict):
                cur[k] = {}
            cur = cur[k]


def _key(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    return str(v)


def _ts_ms(v):
    if isinstance(v, bool) or v is None:
        return None
    s = str(v).strip()
    if INT.match(s):
        x = int(s)
        if x < 10 ** 11:
            return x * 1000
        if x < 10 ** 14:
            return x
        if x < 10 ** 17:
            return x // 1000
        return x // 1000000
    if NUM.match(s):
        x = float(s)
        return int(x * 1000) if x < 1e11 else int(x)
    try:
        t = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=_dt.timezone.utc)
    return int(t.timestamp()) * 1000 + t.microsecond // 1000


def cast(v, typ):
    """-> (ok, value)"""
    if typ is None:
        return True, v
    if typ == "integer":
        s = _key(v)
        if isinstance(v, bool) or not NUM.match(s):
            return False, None
        return True, int(s) if INT.match(s) else int(float(s))
    if typ == "float":
        s = _key(v)
        if isinstance(v, bool) or not NUM.match(s):
            return False, None
        return True, float(s)
    if typ == "string":
        return True, _key(v)
    if typ == "boolean":
        s = _key(v).lower()
        if s in ("true", "t", "yes", "y", "1"):
            return True, True
        if s in ("false", "f", "no", "n", "0"):
            return True, False
        return False, None
    if typ == "lower":
        return True, _key(v).lower()
    if typ == "upper":
        return True, _key(v).upper()
    if typ == "timestamp_ms":
        x = _ts_ms(v)
        return (x is not None), x
    raise ValueError(f"unknown type {typ!r}")


def _remove_path(d, parts):
    if len(parts) == 1:
        d.pop(parts[0], None)
        return
    sub = d.get(parts[0])
    if isinstance(sub, dict):
        _remove_path(sub, parts[1:])
        if not sub:
            d.pop(parts[0], None)


def apply_mapping(spec, ev):
    """ev: parsed event {"message", "vendor": {...}, "@timestamp"?}. -> OCSF event (dict)."""
    out, used = {}, []
    for f in spec["fields"]:
        if "value" in f:
            v = f["value"]
        else:
            v = None
            srcs = f["from"] if isinstance(f["from"], list) else [f["from"]]
            for s in srcs:
                x = _get(ev, s)
                if x is not None and x != "" and x != [] and x != {}:
                    v = x; used.append(s)
                    break
        if v is None:
            if "default" not in f:
                continue
            v = f["default"]
        elif "map" in f:
            m = f["map"]
            k = _key(v)
            if k in m:
                v = m[k]
            elif k.lower() in {a.lower(): a for a in m}:
                v = m[{a.lower(): a for a in m}[k.lower()]]
            elif "default" in f:
                v = f["default"]
            else:
                continue
        ok, v = cast(v, f.get("type"))
        if not ok:
            continue
        _set(out, f["to"], v)
    c = spec["_class"]
    out["class_uid"] = c["uid"]
    out["category_uid"] = c["category_uid"]
    out.setdefault("activity_id", 0)
    out.setdefault("severity_id", 0)
    out["type_uid"] = c["uid"] * 100 + out["activity_id"] if isinstance(out["activity_id"], int) else None
    if "time" not in out and ev.get("@timestamp") is not None:
        t = _ts_ms(ev["@timestamp"])
        if t is not None:
            out["time"] = t
    _set(out, "metadata.version", spec["_version"])
    out["class_name"] = c["caption"]
    out["category_name"] = c["category_caption"]
    for id_path, name_path, captions in spec["_siblings"]:
        idv = _get(out, id_path)
        if idv is not None and _get(out, name_path) is None and str(idv) in captions:
            _set(out, name_path, captions[str(idv)])
    act = captions_for(spec, "activity_id").get(str(out["activity_id"]))
    if act:
        out["type_name"] = f"{c['caption']}: {act}"
    if spec.get("raw_data", True) and isinstance(ev.get("message"), str) and "raw_data" not in out:
        out["raw_data"] = ev["message"]
    if spec.get("unmapped", True) and isinstance(ev.get("vendor"), dict):
        rest = copy.deepcopy(ev["vendor"])
        for s in used:
            if s.startswith("vendor."):
                _remove_path(rest, s.split(".")[1:])
        if rest:
            out["unmapped"] = rest
    return out


def captions_for(spec, id_path):
    for p, _, c in spec["_siblings"]:
        if p == id_path:
            return c
    return {}


def prepare(spec, schema=None):
    """Attach the schema-derived parts both executors need (class info, sibling name tables)."""
    schema = schema or Schema()
    name, cls = schema.cls(spec["class_uid"])
    if cls is None:
        raise ValueError(f"unknown class_uid {spec['class_uid']}")
    sib = []
    targets = {f["to"] for f in spec["fields"]} | {"activity_id", "severity_id"}
    for t in sorted(targets):
        parts = [_IDX.sub(r"\1", x) for x in t.split(".")]
        attrs = cls["attributes"]
        a = None
        for i, p in enumerate(parts):
            a = attrs.get(p)
            if a is None:
                break
            if i < len(parts) - 1:
                obj = schema.s["objects"].get(a["type"])
                if not obj:
                    a = None
                    break
                attrs = obj["attributes"]
        if a and a.get("enum") and a.get("sibling"):
            sib.append([t, ".".join(t.split(".")[:-1] + [a["sibling"]]), a["enum"]])
    out = dict(spec)
    out["_class"] = {"uid": cls["uid"], "name": name, "caption": cls["caption"], "category_uid": cls["category_uid"],
                     "category_caption": cls["category_caption"]}
    out["_version"] = schema.version
    out["_siblings"] = sib
    return out


def ruby_params(prepared):
    data = {k: prepared[k] for k in ("fields", "_class", "_version", "_siblings") if k in prepared}
    data["unmapped"] = prepared.get("unmapped", True)
    data["raw_data"] = prepared.get("raw_data", True)
    return base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
