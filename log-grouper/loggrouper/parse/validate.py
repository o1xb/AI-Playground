"""Parser validation: does a candidate parser extract the right things, reliably, from the samples it
claims, without breaking the parsers already in service?"""
import ipaddress
import json
import re
import time

from .executor import get, run_parser, select_parser

FAILURE_TAGS = {"_grokparsefailure", "_dissectfailure", "_csvparsefailure", "_jsonparsefailure",
                "_dateparsefailure", "_noparser"}
MIN_PARSE_RATE = 0.95
MIN_TYPE_VALIDITY = 0.95
MAX_KEYS = 400


def _is_ip(v):
    try:
        ipaddress.ip_address(str(v).split("%")[0]); return True
    except ValueError:
        return False


def _is_port(v):
    try:
        return 0 <= int(v) <= 65535
    except (TypeError, ValueError):
        return False


def _is_int(v):
    if isinstance(v, bool):
        return False
    try:
        int(str(v)); return True
    except ValueError:
        return False


def _is_float(v):
    try:
        float(v); return True
    except (TypeError, ValueError):
        return False


TYPE_CHECKS = {
    "ip": _is_ip,
    "port": _is_port,
    "integer": _is_int,
    "float": _is_float,
    "timestamp": lambda v: bool(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", str(v))) or _is_float(v),
    "mac": lambda v: bool(re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", str(v))),
    "boolean": lambda v: isinstance(v, bool) or str(v).lower() in ("true", "false", "0", "1", "yes", "no"),
    "string": lambda v: isinstance(v, str) and v != "",
    "email": lambda v: bool(re.match(r"^[^@\s]+@[^@\s]+$", str(v))),
    "hostname": lambda v: bool(re.match(r"^[A-Za-z0-9_.:-]+$", str(v))),
}


def flatten(d, prefix=""):
    out = {}
    for k, v in (d or {}).items():
        if isinstance(v, dict) and v:
            out.update(flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def coverage(message, vendor):
    """Share of the message's characters that ended up in extracted string values (roughly)."""
    if not message:
        return 0.0
    covered = [False] * len(message)
    for k, v in flatten(vendor).items():
        leaf = k.rsplit(".", 1)[-1]
        if len(leaf) >= 2:                 # key names present in the text (kv/json) count as covered
            i = message.find(leaf)
            if i >= 0:
                for j in range(i, i + len(leaf)):
                    covered[j] = True
        vals = v if isinstance(v, list) else [v]
        for x in vals:
            s = str(x) if not isinstance(x, (dict, list)) else ""
            if len(s) < 2:
                continue
            i = message.find(s)
            if i >= 0:
                for j in range(i, i + len(s)):
                    covered[j] = True
    if message.lstrip().startswith("{"):
        return 1.0 if vendor else 0.0      # a json step takes everything
    return sum(covered) / len(message)


def output_of(spec, message):
    ev = run_parser(spec, message)
    return {"vendor": ev.get("vendor", {}), "tags": sorted(ev.get("tags", [])),
            **({"@timestamp": ev["@timestamp"]} if "@timestamp" in ev else {})}


def claimed(parsers_in_order, candidate, messages):
    """Messages this candidate would get, given its position among the label's parsers."""
    out = []
    for m in messages:
        p = select_parser(parsers_in_order, m)
        if p is candidate:
            out.append(m)
    return out


def metrics(spec, messages, max_examples=3):
    t0 = time.time()
    ok, fails, cov, keys, dates, date_ok = 0, [], [], set(), 0, 0
    types = {f: [0, 0, []] for f in (spec.get("field_types") or {})}
    has_date = any("date" in s for s in spec["steps"])
    for m in messages:
        o = output_of(spec, m)
        bad = FAILURE_TAGS & set(o["tags"])
        if not bad and o["vendor"]:
            ok += 1
        elif len(fails) < max_examples:
            fails.append({"message": m[:500], "tags": o["tags"], "vendor_keys": sorted(flatten(o["vendor"]))[:20]})
        cov.append(coverage(m, o["vendor"]))
        fl = flatten(o["vendor"])
        keys.update(fl)
        if has_date:
            dates += 1
            date_ok += "@timestamp" in o and "_dateparsefailure" not in o["tags"]
        for f, typ in (spec.get("field_types") or {}).items():
            key = f[len("vendor."):] if f.startswith("vendor.") else f
            v = fl.get(key)
            if v is None or v == "":
                continue
            chk = TYPE_CHECKS.get(typ)
            if chk is None:
                continue
            t = types[f]
            t[0] += 1
            good = all(chk(x) for x in (v if isinstance(v, list) else [v]))
            t[1] += good
            if not good and len(t[2]) < 3:
                t[2].append(str(v)[:80])
    n = max(1, len(messages))
    return {
        "samples": len(messages),
        "parse_rate": round(ok / n, 4),
        "coverage_mean": round(sum(cov) / n, 3) if cov else 0,
        "distinct_fields": len(keys),
        "date_rate": round(date_ok / dates, 4) if dates else None,
        "type_validity": {f: {"checked": c, "valid_rate": round(g / c, 4) if c else None, "bad_examples": b}
                          for f, (c, g, b) in types.items()},
        "failures": fails,
        "ms_per_1k": round((time.time() - t0) / n * 1e6, 1),
    }


def spec_problems(spec):
    """Static checks for constructs whose Logstash behaviour the executor cannot mirror."""
    for st in spec["steps"]:
        (op, a), = st.items()
        if op == "date" and any("E" in f.replace("'", "") and f not in ("ISO8601",) for f in a.get("formats", [])):
            return ("date formats with weekday tokens (EEE) are not allowed: Logstash/Joda moves the date to the named "
                    "weekday when they disagree. Strip the weekday with grok/gsub first.")
    return None


def verdict(m, spec=None):
    """-> None if acceptable, else the reason."""
    if spec is not None and spec_problems(spec):
        return spec_problems(spec)
    if m["samples"] == 0:
        return "claims no samples (check `when` and parser order)"
    if m["parse_rate"] < MIN_PARSE_RATE:
        return f"parse_rate {m['parse_rate']} < {MIN_PARSE_RATE}"
    if m["date_rate"] is not None and m["date_rate"] < MIN_PARSE_RATE:
        return f"date_rate {m['date_rate']} < {MIN_PARSE_RATE}"
    for f, t in m["type_validity"].items():
        if t["checked"] and t["valid_rate"] < MIN_TYPE_VALIDITY:
            return f"field {f}: only {t['valid_rate']} of values are valid {f} type (e.g. {t['bad_examples']})"
    if m["distinct_fields"] > MAX_KEYS:
        return f"{m['distinct_fields']} distinct fields: key explosion (use a target or stricter kv)"
    return None


def golden_regressions(parsers_in_order):
    """Every active parser's golden examples must still select that parser and give the pinned output."""
    broken = []
    for p in parsers_in_order:
        for g in p.get("golden", []):
            sel = select_parser(parsers_in_order, g["message"])
            if sel is None or sel["id"] != p["id"]:
                broken.append({"parser": p["id"], "reason": f"golden sample now goes to {sel['id'] if sel else None}",
                               "message": g["message"][:200]})
            elif output_of(p, g["message"]) != g["output"]:
                broken.append({"parser": p["id"], "reason": "golden output changed", "message": g["message"][:200]})
    return broken


def pick_golden(spec, messages, k=5):
    """Diverse golden examples: one per distinct output key set, successful parses first."""
    seen, out = set(), []
    for m in messages:
        o = output_of(spec, m)
        if FAILURE_TAGS & set(o["tags"]):
            continue
        sig = tuple(sorted(flatten(o["vendor"])))
        if sig in seen:
            continue
        seen.add(sig)
        out.append({"message": m, "output": json.loads(json.dumps(o))})
        if len(out) >= k:
            break
    return out
