"""Reduce a payload to a 'shape' so similar messages cluster together (for residue + parser profiling)."""
import json
import re

_MASKS = [
    (re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?"), "<TS>"),
    (re.compile(r"\b[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d(?:\.\d+)?"), "<TS>"),
    (re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}[: ]\d\d:\d\d:\d\d"), "<TS>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<UUID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+|/\d+)?\b"), "<IP>"),
    (re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I), "<MAC>"),
    (re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I), "<IP6>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<HEX>"),
    (re.compile(r"\b[0-9a-f]{16,}\b", re.I), "<HEX>"),
    (re.compile(r'"[^"]{0,200}"'), '"<S>"'),
    (re.compile(r"\d+"), "<N>"),
]
_JSON_KEY = re.compile(r'"([A-Za-z_@][\w.@-]{0,40})"\s*:')


def mask(s):
    for rx, tok in _MASKS:
        s = rx.sub(tok, s)
    return s


def shape(payload, tokens=7):
    t = payload.strip()
    if t.startswith("{"):
        try:
            d = json.loads(t)
            if isinstance(d, dict):
                return "JSON{" + ",".join(sorted(d)[:14]) + "}"
        except ValueError:
            keys = _JSON_KEY.findall(t)[:10]
            return "JSON~{" + ",".join(sorted(set(keys))) + "}"
    m = mask(t)
    # key=value payloads: shape by their keys, not values
    kv = re.findall(r'(?:^|[\s,;])([A-Za-z_][\w.-]{0,30})=', t)
    if len(kv) >= 5:
        return "KV{" + ",".join(kv[:10]) + "}"
    if t.count(",") >= 10:   # CSV-ish
        return "CSV:" + " ".join(m.split(",")[0:1]) + f"|cols~{t.count(',') // 5 * 5}"
    return " ".join(m.split()[:tokens])
