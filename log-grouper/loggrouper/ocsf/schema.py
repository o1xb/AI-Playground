"""OCSF schema: resolve the ocsf-schema source tree into one compact JSON, search it, validate events.

  python3 -m loggrouper.ocsf.schema build <ocsf-schema checkout> loggrouper/ocsf/schema-1.4.0.json
"""
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(__file__)
DEFAULT_SCHEMA = os.path.join(HERE, "schema-1.4.0.json")


# ---------------------------------------------------------------- build
def _load(p):
    with open(p) as f:
        return json.load(f)


def _short(s, n=220):
    s = re.sub(r"<[^>]+>", "", s or "").replace("\n", " ")
    return s if len(s) <= n else s[:n].rsplit(" ", 1)[0] + "..."


def build(src):
    dictionary = _load(os.path.join(src, "dictionary.json"))
    dattrs = dictionary["attributes"]
    types = {k: {"base": v.get("type"), "caption": v.get("caption")} for k, v in dictionary["types"]["attributes"].items()}
    cats = _load(os.path.join(src, "categories.json"))["attributes"]

    def includes(attrs, base_dir):
        out = {}
        inc = attrs.get("$include")
        for p in ([inc] if isinstance(inc, str) else inc or []):
            fp = os.path.join(src, p)
            if os.path.exists(fp):
                prof = os.path.basename(p)[:-5] if p.startswith("profiles/") else None
                for k, v in _load(fp).get("attributes", {}).items():
                    out[k] = {**v, **({"profile": prof} if prof else {})}
        out.update({k: v for k, v in attrs.items() if k != "$include"})
        return out

    def merge_attr(name, override):
        base = dict(dattrs.get(name, {}))
        o = override or {}
        enum = dict(base.get("enum") or {})
        enum.update(o.get("enum") or {})
        a = {**base, **{k: v for k, v in o.items() if k != "enum"}}
        if enum:
            a["enum"] = enum
        return a

    # objects
    raw_objects = {}
    for fn in os.listdir(os.path.join(src, "objects")):
        if fn.endswith(".json"):
            o = _load(os.path.join(src, "objects", fn))
            raw_objects[o["name"]] = o

    def resolve_obj(name, seen=()):
        o = raw_objects[name]
        attrs = {}
        if o.get("extends") and o["extends"] in raw_objects and o["extends"] not in seen:
            attrs.update(resolve_obj(o["extends"], seen + (name,))["attributes"])
        for k, v in includes(o.get("attributes", {}), src).items():
            attrs[k] = {**attrs.get(k, {}), **v}
        return {"caption": o.get("caption"), "description": o.get("description"), "attributes": attrs,
                "constraints": o.get("constraints")}

    objects = {}
    for name in raw_objects:
        if name.startswith("_"):
            continue
        r = resolve_obj(name)
        objects[name] = {"caption": r["caption"], "description": _short(r["description"]),
                         "constraints": r["constraints"],
                         "attributes": {k: _compact(k, merge_attr(k, v)) for k, v in r["attributes"].items()}}

    # event classes
    raw_events = {}
    for root, _, files in os.walk(os.path.join(src, "events")):
        for fn in files:
            if fn.endswith(".json"):
                e = _load(os.path.join(root, fn))
                raw_events[e["name"]] = e

    def resolve_event(name, seen=()):
        e = raw_events[name]
        attrs, cat, profiles = {}, e.get("category"), list(e.get("profiles") or [])
        if e.get("extends") and e["extends"] in raw_events and e["extends"] not in seen:
            parent = resolve_event(e["extends"], seen + (name,))
            attrs.update(parent["attributes"]); cat = cat or parent["category"]
            profiles = parent["profiles"] + profiles
        for k, v in includes(e.get("attributes", {}), src).items():
            prev = attrs.get(k, {})
            enum = dict(prev.get("enum") or {}); enum.update(v.get("enum") or {})
            attrs[k] = {**prev, **v, **({"enum": enum} if enum else {})}
        return {"attributes": attrs, "category": cat, "profiles": profiles}

    classes = {}
    for name, e in raw_events.items():
        if "uid" not in e or name in ("base_event",):
            continue
        r = resolve_event(name)
        cat = r["category"]
        if cat not in cats:
            continue
        uid = cats[cat]["uid"] * 1000 + e["uid"]
        classes[name] = {"uid": uid, "caption": e.get("caption"), "description": _short(e.get("description"), 400),
                         "category": cat, "category_uid": cats[cat]["uid"], "category_caption": cats[cat]["caption"],
                         "profiles": sorted(set(r["profiles"])), "constraints": e.get("constraints"),
                         "attributes": {k: _compact(k, merge_attr(k, v)) for k, v in r["attributes"].items()}}
    profiles = {}
    pdir = os.path.join(src, "profiles")
    for fn in os.listdir(pdir):
        if fn.endswith(".json"):
            p = _load(os.path.join(pdir, fn))
            profiles[p["name"]] = {k: _compact(k, merge_attr(k, v)) for k, v in p.get("attributes", {}).items()}
    version = _load(os.path.join(src, "version.json"))["version"]
    return {"version": version, "types": types, "classes": classes, "objects": objects, "profiles": profiles}


def _compact(name, a):
    out = {"type": a.get("type"), "requirement": a.get("requirement", "optional")}
    if a.get("is_array"):
        out["is_array"] = True
    if a.get("enum"):
        out["enum"] = {k: v.get("caption") if isinstance(v, dict) else v for k, v in a["enum"].items()}
    if a.get("sibling"):
        out["sibling"] = a["sibling"]
    if a.get("profile"):
        out["profile"] = a["profile"]
    if name in ("class_uid", "category_uid", "type_uid"):
        out.pop("enum", None)            # generated per class; checked separately
    out["caption"] = a.get("caption")
    out["description"] = _short(a.get("description"), 160)
    return out


# ---------------------------------------------------------------- use
class Schema:
    def __init__(self, path=DEFAULT_SCHEMA):
        with open(path) as f:
            self.s = json.load(f)
        self.version = self.s["version"]
        self.by_uid = {c["uid"]: (n, c) for n, c in self.s["classes"].items()}

    def cls(self, name_or_uid):
        if isinstance(name_or_uid, int) or str(name_or_uid).isdigit():
            return self.by_uid.get(int(name_or_uid), (None, None))
        return (name_or_uid, self.s["classes"].get(name_or_uid))

    def attrs(self, cls, profiles=()):
        a = dict(cls["attributes"])
        for p in profiles:
            for k, v in self.s["profiles"].get(p, {}).items():
                a.setdefault(k, v)
        return a

    def base_type(self, t):
        seen = 0
        while t in self.s["types"] and self.s["types"][t].get("base") and seen < 5:
            t = self.s["types"][t]["base"]; seen += 1
        return t

    def search(self, query, limit=15):
        q = [w for w in re.split(r"\W+", query.lower()) if w]
        def score(*texts):
            t = " ".join(x or "" for x in texts).lower()
            return sum(t.count(w) for w in q)
        rows = []
        for n, c in self.s["classes"].items():
            sc = score(n, c["caption"], c["description"]) * 3
            if sc:
                rows.append((sc, f"class {c['uid']} {n} ({c['category']}): {c['description'][:140]}"))
        for n, o in self.s["objects"].items():
            sc = score(n, o["caption"], o["description"]) * 2
            if sc:
                rows.append((sc, f"object {n}: {o['description'][:140]}"))
        return [r for _, r in sorted(rows, key=lambda x: -x[0])[:limit]]

    # ------------------------------------------------------------ validation
    def validate(self, ev):
        """-> (errors, warnings). Structural validation against the class and object definitions."""
        errs, warns = [], []
        name, cls = self.cls(ev.get("class_uid", -1))
        if cls is None:
            return [f"unknown class_uid {ev.get('class_uid')}"], []
        profiles = (ev.get("metadata") or {}).get("profiles") or []
        attrs = self.attrs(cls, ["host", "network_proxy", "security_control", "cloud", "container", "datetime",
                                 "load_balancer", "osint", "data_classification", "incident", "trace"])
        if ev.get("category_uid") != cls["category_uid"]:
            errs.append(f"category_uid must be {cls['category_uid']}")
        act = ev.get("activity_id")
        if isinstance(act, int) and ev.get("type_uid") != cls["uid"] * 100 + act:
            errs.append(f"type_uid must be class_uid*100+activity_id = {cls['uid'] * 100 + act}")
        self._check_obj(ev, attrs, "", errs, warns, top=True, profiles=set(profiles))
        alo = (cls.get("constraints") or {}).get("at_least_one") or []
        groups = [alo] if alo and all(isinstance(x, str) for x in alo) else alo   # flat list = one constraint
        for c in groups:
            if not any(ev.get(k) not in (None, "", [], {}) for k in c):
                errs.append(f"at least one of {c} is required")
        return errs, warns

    def _check_obj(self, obj, attrs, path, errs, warns, top=False, depth=0, profiles=frozenset()):
        if depth > 8:
            return
        for k, a in attrs.items():
            if a.get("profile") and a["profile"] not in profiles:
                continue                      # profile attributes only bind when the profile is declared
            if a["requirement"] == "required" and obj.get(k) in (None, "", [], {}):
                errs.append(f"missing required {path}{k}")
            elif top and a["requirement"] == "recommended" and k not in obj:
                warns.append(f"missing recommended {path}{k}")
        for k, v in obj.items():
            if k not in attrs:
                if not (top and k == "unmapped"):
                    errs.append(f"unknown attribute {path}{k}")
                continue
            if k == "unmapped":
                continue
            a = attrs[k]
            vals = v if isinstance(v, list) else [v]
            if a.get("is_array") and not isinstance(v, list):
                errs.append(f"{path}{k} must be an array")
            if not a.get("is_array") and isinstance(v, list):
                errs.append(f"{path}{k} must not be an array")
            t = a["type"]
            for x in vals:
                if t in self.s["objects"]:
                    if not isinstance(x, dict):
                        errs.append(f"{path}{k} must be an object ({t})")
                    else:
                        self._check_obj(x, self.s["objects"][t]["attributes"], f"{path}{k}.", errs, warns, depth=depth + 1)
                    continue
                e = _type_error(self.base_type(t), t, x)
                if e:
                    errs.append(f"{path}{k}: {e}")
                elif a.get("enum") and str(x) not in a["enum"]:
                    errs.append(f"{path}{k}: {x!r} not in enum {sorted(a['enum'], key=lambda s: int(s) if s.lstrip('-').isdigit() else 0)[:12]}")


def _type_error(base, t, x):
    if base in ("integer_t", "long_t"):
        if isinstance(x, bool) or not isinstance(x, int):
            return f"expected integer, got {type(x).__name__} {str(x)[:40]!r}"
        if t == "port_t" and not 0 <= x <= 65535:
            return "port out of range"
        if t == "timestamp_t" and x < 10 ** 11:
            return "timestamp_t is epoch milliseconds"
    elif base == "float_t":
        if isinstance(x, bool) or not isinstance(x, (int, float)):
            return f"expected number, got {type(x).__name__}"
    elif base == "boolean_t":
        if not isinstance(x, bool):
            return f"expected boolean, got {type(x).__name__}"
    elif base == "string_t" or t in ("ip_t", "mac_t", "email_t", "url_t", "hostname_t"):
        if not isinstance(x, str):
            return f"expected string, got {type(x).__name__} {str(x)[:40]!r}"
        if t == "ip_t":
            try:
                ipaddress.ip_address(x.split("%")[0])
            except ValueError:
                return f"invalid IP {x[:40]!r}"
        if t == "mac_t" and not re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", x):
            return f"invalid MAC {x[:40]!r}"
    return None


if __name__ == "__main__" and sys.argv[1:2] == ["build"]:
    s = build(sys.argv[2])
    with open(sys.argv[3], "w") as f:
        json.dump(s, f, separators=(",", ":"))
    print(f"OCSF {s['version']}: {len(s['classes'])} classes, {len(s['objects'])} objects -> {sys.argv[3]}")
