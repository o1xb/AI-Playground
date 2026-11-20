"""Python executor for parser specs. Mirrors the Logstash filters the spec compiles to, so the agent and
the validator can test a parser on thousands of samples in milliseconds. `logstash.py` checks that real
Logstash produces the same output before a parser is activated.

A parser spec:
  {"id", "label", "format", "when": <optional regex selecting this parser within the label>,
   "steps": [ {"<op>": {...}}, ... ],
   "field_types": {"vendor.src_ip": "ip", "vendor.dst_port": "port", ...}}   # checked by the validator

Field paths are dotted ("vendor.src_ip" -> Logstash [vendor][src_ip]). Parsed fields belong under
`vendor.`; `message` is the input. Ops:
  grok     {"field", "patterns": [...], "pattern_definitions": {...}}        tag _grokparsefailure
  dissect  {"field", "mapping"}                                              tag _dissectfailure
  kv       {"field", "target", "field_split": " ", "value_split": "=",
            "field_split_pattern", "value_split_pattern", "trim_value", "include_brackets": true}
  csv      {"field", "target", "columns": [...], "separator": ",", "quote_char": "\""}  tag _csvparsefailure
  json     {"field", "target"}                                               tag _jsonparsefailure
  date     {"field", "formats": [...], "target": "@timestamp", "timezone": "UTC"}  tag _dateparsefailure
  rename   {"from": "to", ...}
  convert  {"field": "integer|float|boolean|string", ...}
  remove   ["field", ...]
  lowercase ["field", ...]
  gsub     [["field", "regex", "replacement"], ...]
  add      {"field": "constant", ...}
"""
import calendar
import csv as _csv
import datetime as _dt
import io
import json
import os
import re

PATTERN_DIR = os.path.join(os.path.dirname(__file__), "grok_patterns")


# ---------------------------------------------------------------- field access
def path(p):
    return p.split(".") if p else []


def get(ev, p):
    cur = ev
    for k in path(p):
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def put(ev, p, v):
    ks = path(p)
    cur = ev
    for k in ks[:-1]:
        if not isinstance(cur.get(k), dict):
            cur[k] = {}
        cur = cur[k]
    cur[ks[-1]] = v


def delete(ev, p):
    ks = path(p)
    cur = ev
    for k in ks[:-1]:
        cur = cur.get(k) if isinstance(cur, dict) else None
        if cur is None:
            return
    if isinstance(cur, dict):
        cur.pop(ks[-1], None)


def logstash_ref(p):
    return "".join(f"[{k}]" for k in path(p))


def _tag(ev, t):
    tags = ev.setdefault("tags", [])
    if t not in tags:
        tags.append(t)


# ---------------------------------------------------------------- grok
_GROK_LIB = None


def grok_library():
    global _GROK_LIB
    if _GROK_LIB is None:
        lib = {}
        for fn in sorted(os.listdir(PATTERN_DIR)):
            if fn in ("LICENSE", "README"):
                continue
            with open(os.path.join(PATTERN_DIR, fn)) as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line or line.startswith("#") or " " not in line:
                        continue
                    name, pat = line.split(" ", 1)
                    lib[name] = pat
        _GROK_LIB = lib
    return _GROK_LIB


_REF = re.compile(r"%\{(\w+)(?::([^:}]+))?(?::(int|float))?\}")
_ONIG_NAMED = re.compile(r"\(\?<(?![=!])([^>]+)>")


def _bracket_to_dotted(name):
    if name.startswith("["):
        return ".".join(re.findall(r"\[([^\]]+)\]", name))
    return name


class Grok:
    """Compile a grok expression to a Python regex; captures map to dotted field paths."""

    def __init__(self, pattern, extra=None):
        lib = dict(grok_library())
        lib.update(extra or {})
        self.fields = {}          # group name -> (dotted field, type)
        self._n = 0
        rx = self._expand(pattern, lib, 0)
        self.regex = re.compile(rx)

    def _group(self, field, typ):
        self._n += 1
        g = f"g{self._n}"
        self.fields[g] = (_bracket_to_dotted(field), typ)
        return g

    def _expand(self, pat, lib, depth):
        if depth > 40:
            raise ValueError("grok pattern recursion too deep")

        def named(m):                     # Oniguruma (?<name>...) -> (?P<gN>...)
            return f"(?P<{self._group(m.group(1), None)}>"
        pat = _ONIG_NAMED.sub(named, pat)

        def ref(m):
            name, field, typ = m.group(1), m.group(2), m.group(3)
            if name not in lib:
                raise ValueError(f"unknown grok pattern %{{{name}}}")
            inner = self._expand(lib[name], lib, depth + 1)
            if field:
                return f"(?P<{self._group(field, typ)}>{inner})"
            return f"(?:{inner})"
        return _REF.sub(ref, pat)

    def match(self, s):
        m = self.regex.search(s)
        if not m:
            return None
        out = {}
        for g, (field, typ) in self.fields.items():
            v = m.group(g)
            if v is None or v == "":          # Logstash grok drops empty captures (keep_empty_captures false)
                continue
            if typ == "int":
                try:
                    v = int(v)
                except ValueError:
                    continue
            elif typ == "float":
                try:
                    v = float(v)
                except ValueError:
                    continue
            out[field] = v
        return out


# ---------------------------------------------------------------- dissect
_DISSECT_KEY = re.compile(r"%\{([^}]*)\}")


def _parse_dissect(mapping):
    """-> (leading delimiter, [(key, modifiers, delimiter_after), ...])"""
    parts = _DISSECT_KEY.split(mapping)
    lead, keys = parts[0], []
    for i in range(1, len(parts), 2):
        raw, delim = parts[i], parts[i + 1]
        pad = raw.endswith("->")
        if pad:
            raw = raw[:-2]
        mod = ""
        if raw[:1] in "+?&*":
            mod, raw = raw[0], raw[1:]
        order = None
        if mod == "+" and "/" in raw:
            raw, order = raw.rsplit("/", 1)
        keys.append({"key": raw, "mod": mod, "pad": pad, "delim": delim, "order": order})
    return lead, keys


def dissect(s, mapping):
    lead, keys = _parse_dissect(mapping)
    if lead:
        if not s.startswith(lead):
            return None
        pos = len(lead)
    else:
        pos = 0
    vals = []
    for i, k in enumerate(keys):
        d = k["delim"]
        if i == len(keys) - 1 and d == "":
            vals.append(s[pos:]); pos = len(s)
            break
        j = s.find(d, pos) if d else -1
        if j < 0:
            return None
        vals.append(s[pos:j])
        pos = j + len(d)
        if k["pad"]:
            while d and s.startswith(d, pos):
                pos += len(d)
    out, appends, refs = {}, {}, {}
    for k, v in zip(keys, vals):
        if k["key"] == "" or k["mod"] == "?":
            if k["mod"] == "?" and k["key"]:
                refs.setdefault("?" + k["key"], v)
            continue
        if k["mod"] == "+":
            appends.setdefault(k["key"], []).append((k["order"], v))
        elif k["mod"] == "*":
            refs[k["key"]] = v
        elif k["mod"] == "&":
            name = refs.get(k["key"])
            if name is not None:
                out[name] = v
        else:
            if k["key"] in appends:
                appends[k["key"]].insert(0, (None, v))
            else:
                out[k["key"]] = v
    for key, items in appends.items():
        if key in out:
            items.insert(0, (None, out.pop(key)))
        items.sort(key=lambda t: (t[0] is not None, int(t[0]) if t[0] else 0))
        out[key] = " ".join(v for _, v in items)
    return out


# ---------------------------------------------------------------- kv
_BRACKETS = [('"', '"'), ("'", "'"), ("<", ">"), ("(", ")"), ("[", "]")]


def kv(s, field_split=" ", value_split="=", field_split_pattern=None, value_split_pattern=None,
       trim_value=None, include_brackets=True, whitespace="lenient", allow_empty_values=False):
    fs = field_split_pattern or "[" + re.escape(field_split) + "]"
    vs = value_split_pattern or "[" + re.escape(value_split) + "]"
    if whitespace == "lenient":            # Logstash default: spaces allowed around the value separator
        vs = r"\s*" + vs + r"\s*"
    rep = "*" if allow_empty_values else "+"
    if include_brackets:
        # quoted values may contain backslash-escaped closing quotes (kept verbatim, as Logstash does)
        quoted = "|".join(re.escape(o) + "(?P<q%d>(?:\\\\.|[^%s\\\\])*)" % (i, re.escape(c)) + re.escape(c)
                          for i, (o, c) in enumerate(_BRACKETS))
        val = f"(?:{quoted}|(?P<plain>(?:(?!{fs}).){rep}))"
    else:
        val = f"(?P<plain>(?:(?!{fs}).){rep})"
    rx = re.compile(f"(?:^|{fs})(?P<key>(?:(?!{fs}|{vs}).)+?){vs}{val}")
    out = {}
    for m in rx.finditer(s):
        k = m.group("key").strip()
        v = next((m.group(g) for g in m.groupdict() if g.startswith("q") and m.group(g) is not None), None)
        if v is None:
            v = m.group("plain")
        if trim_value:
            v = v.strip(trim_value)
        if not k or (v == "" and not allow_empty_values):   # Logstash kv drops empty (quoted) values
            continue
        if k in out:                       # Logstash collects repeated keys into an array
            out[k] = (out[k] if isinstance(out[k], list) else [out[k]]) + [v]
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------- date (Joda subset)
_JODA = [("yyyy", r"(?P<Y>\d{4})"), ("yy", r"(?P<y>\d{2})"), ("MMMM", r"(?P<B>[A-Za-z]+)"),
         ("MMM", r"(?P<b>[A-Za-z]{3})"), ("MM", r"(?P<m>\d{2})"), ("M", r"(?P<m>\d{1,2})"),
         ("dd", r"(?P<d>\d{2})"), ("d", r"(?P<d>\d{1,2})"), ("HH", r"(?P<H>\d{2})"), ("H", r"(?P<H>\d{1,2})"),
         ("mm", r"(?P<M>\d{2})"), ("ss", r"(?P<S>\d{2})"), ("SSSSSSSSS", r"(?P<f>\d{9})"),
         ("SSSSSS", r"(?P<f>\d{6})"), ("SSS", r"(?P<f>\d{3})"), ("ZZZ", r"(?P<zn>[A-Za-z_/+-]+)"),
         ("ZZ", r"(?P<z>Z|[+-]\d\d:\d\d)"), ("Z", r"(?P<z>Z|[+-]\d\d:?\d\d)"), ("EEE", r"[A-Za-z]{3}"),
         ("EEEE", r"[A-Za-z]+")]
_MONTHS = {m.lower(): i for i, m in enumerate(calendar.month_abbr) if m}
_MONTHS.update({m.lower(): i for i, m in enumerate(calendar.month_name) if m})


def _joda_regex(fmt):
    out, i = "", 0
    while i < len(fmt):
        if fmt[i] == "'":
            j = fmt.index("'", i + 1)
            out += re.escape(fmt[i + 1:j]) if j > i + 1 else "'"
            i = j + 1
            continue
        for tok, rx in _JODA:
            if fmt.startswith(tok, i):
                out += rx; i += len(tok)
                break
        else:
            out += re.escape(fmt[i]); i += 1
    return re.compile("^" + out + "$")


def _tz(name):
    if name in (None, "", "UTC", "Etc/UTC", "Z"):
        return _dt.timezone.utc
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return _dt.timezone.utc


def parse_date(value, formats, timezone="UTC", now=None):
    """-> ISO8601 UTC string with millisecond precision (Logstash's @timestamp format) or None."""
    s = str(value).strip()
    now = now or _dt.datetime.now(_dt.timezone.utc)
    for fmt in formats:
        try:
            if fmt in ("UNIX", "UNIX_MS"):
                x = float(s)
                t = _dt.datetime.fromtimestamp(x / (1000 if fmt == "UNIX_MS" else 1), _dt.timezone.utc)
                return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if fmt == "ISO8601":
                t = _dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1) if "T" not in s else s.replace("Z", "+00:00"))
                if t.tzinfo is None:
                    t = t.replace(tzinfo=_tz(timezone))
                return t.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            m = _joda_regex(fmt).match(s)
            if not m:
                continue
            g = m.groupdict()
            year = int(g["Y"]) if g.get("Y") else (2000 + int(g["y"]) if g.get("y") else None)
            month = int(g["m"]) if g.get("m") else _MONTHS.get((g.get("b") or g.get("B") or "").lower())
            if month is None:
                continue
            frac = g.get("f") or "0"
            tz = _tz(timezone)
            if g.get("z"):
                z = g["z"]
                if z == "Z":
                    tz = _dt.timezone.utc
                else:
                    z = z.replace(":", "")
                    tz = _dt.timezone((1 if z[0] == "+" else -1) * _dt.timedelta(hours=int(z[1:3]), minutes=int(z[3:5])))
            elif g.get("zn"):
                tz = _tz(g["zn"])
            guess = year is None
            t = _dt.datetime(year or now.year, month, int(g.get("d") or 1), int(g.get("H") or 0), int(g.get("M") or 0),
                             int(g.get("S") or 0), int(frac[:6].ljust(6, "0")), tzinfo=tz)
            if guess:                          # Logstash's year guess for year-less dates: only the New Year boundary
                if now.month == 1 and month == 12:
                    t = t.replace(year=t.year - 1)
                elif now.month == 12 and month == 1:
                    t = t.replace(year=t.year + 1)
            return t.astimezone(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            continue
    return None


# ---------------------------------------------------------------- run
def _convert(v, typ):
    if isinstance(v, list):
        return [_convert(x, typ) for x in v]
    if typ == "integer":
        try:
            return int(float(v)) if not isinstance(v, bool) else int(v)
        except (TypeError, ValueError):
            return v
    if typ == "float":
        try:
            return float(v)
        except (TypeError, ValueError):
            return v
    if typ == "boolean":
        s = str(v).lower()
        return True if s in ("true", "t", "yes", "y", "1") else False if s in ("false", "f", "no", "n", "0") else v
    if typ == "string":
        return v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return v


def run_step(ev, op, a):
    if op == "grok":
        s = get(ev, a.get("field", "message"))
        if not isinstance(s, str):
            _tag(ev, "_grokparsefailure"); return
        for p in a["patterns"]:
            r = Grok(p, a.get("pattern_definitions")).match(s)
            if r is not None:
                for k, v in r.items():
                    put(ev, k, v)
                return
        _tag(ev, "_grokparsefailure")
    elif op == "dissect":
        s = get(ev, a.get("field", "message"))
        r = dissect(s, a["mapping"]) if isinstance(s, str) else None
        if r is None:
            _tag(ev, "_dissectfailure"); return
        for k, v in r.items():
            put(ev, _bracket_to_dotted(k), v)
    elif op == "kv":
        s = get(ev, a.get("field", "message"))
        if not isinstance(s, str):
            return
        r = kv(s, a.get("field_split", " "), a.get("value_split", "="), a.get("field_split_pattern"),
               a.get("value_split_pattern"), a.get("trim_value"), a.get("include_brackets", True),
               a.get("whitespace", "lenient"), a.get("allow_empty_values", False))
        tgt = a.get("target")
        if tgt:
            if r:
                put(ev, tgt, r)            # Logstash kv replaces the target object
        else:
            ev.update(r)
    elif op == "csv":
        s = get(ev, a.get("field", "message"))
        try:
            row = next(_csv.reader(io.StringIO(s), delimiter=a.get("separator", ","),
                                   quotechar=a.get("quote_char", '"')))
        except (StopIteration, _csv.Error, TypeError):
            _tag(ev, "_csvparsefailure"); return
        cols = a.get("columns", [])
        tgt = a.get("target")
        for i, v in enumerate(row):
            name = cols[i] if i < len(cols) else f"column{i + 1}"
            if v == "":                    # Ruby CSV yields nil for empty fields; Logstash keeps them as null
                if a.get("skip_empty_columns"):
                    continue
                v = None
            put(ev, f"{tgt}.{name}" if tgt else name, v)
    elif op == "json":
        s = get(ev, a.get("field", "message"))
        try:
            d = json.loads(s)
        except (TypeError, ValueError):
            _tag(ev, "_jsonparsefailure"); return
        tgt = a.get("target")
        if tgt:
            put(ev, tgt, d)
        elif isinstance(d, dict):
            ev.update(d)
    elif op == "date":
        v = get(ev, a["field"])
        if v is None:
            return
        r = parse_date(v, a["formats"], a.get("timezone", "UTC"))
        if r is None:
            _tag(ev, "_dateparsefailure"); return
        put(ev, a.get("target", "@timestamp"), r)
    elif op == "rename":
        for src, dst in a.items():
            v = get(ev, src)
            if v is not None:
                delete(ev, src); put(ev, dst, v)
    elif op == "convert":
        for f, typ in a.items():
            v = get(ev, f)
            if v is not None:
                put(ev, f, _convert(v, typ))
    elif op == "remove":
        for f in a:
            delete(ev, f)
    elif op == "lowercase":
        for f in a:
            v = get(ev, f)
            if isinstance(v, str):
                put(ev, f, v.lower())
    elif op == "gsub":
        for f, rx, rep in a:
            v = get(ev, f)
            if isinstance(v, str):
                put(ev, f, re.sub(rx, rep, v))
    elif op == "add":
        for f, v in a.items():
            put(ev, f, v)
    else:
        raise ValueError(f"unknown parser op {op!r}")


def run_parser(spec, message):
    ev = {"message": message}
    for step in spec["steps"]:
        (op, a), = step.items()
        run_step(ev, op, a)
    return ev


def select_parser(parsers, message):
    """First parser of the label whose `when` matches (or that has none)."""
    for p in parsers:
        w = p.get("when")
        if not w or re.search(w, message):
            return p
    return None
