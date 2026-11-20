"""OCSF schema rendered as compact prompt text (no retrieval).

full_schema_text()   every class (attributes with type + requirement) and every object, enums with captions:
                     for a cached system prompt.
class_list_text()    one line per class: for the class-choice call.
class_slice_text(c)  one class with its attributes and every object reachable from it (depth-limited), with
                     short descriptions and enums: for the mapping call once the class is known.
"""
from .schema import Schema

REQ = {"required": "R", "recommended": "r", "optional": ""}


def _attr_line(name, a, desc=0, enum_max=12):
    t = a["type"] + ("[]" if a.get("is_array") else "")
    flag = REQ.get(a["requirement"], "")
    if a.get("profile"):
        flag = (flag + " p:" + a["profile"]).strip()
    out = f"{name}:{t}" + (f"!{flag}" if flag else "")
    if a.get("enum"):
        out += " {" + ", ".join(f"{k}={v}" for k, v in list(a["enum"].items())[:enum_max]) + "}"
    if desc and a.get("description"):
        out += " - " + a["description"][:desc]
    return out


def class_list_text(schema=None):
    s = (schema or Schema()).s
    return "\n".join(f"{c['uid']} {n} ({c['category']}): {c['description'][:110]}"
                     for n, c in sorted(s["classes"].items(), key=lambda kv: kv[1]["uid"]))


def full_schema_text(schema=None, desc=0):
    schema = schema or Schema()
    s = schema.s
    lines = [f"# OCSF {schema.version} schema (compact).",
             "Notation: name:type!R = required, !r = recommended, p:<profile> = profile attribute; "
             "{id=caption} = enum; types ending _t are scalars, other types are objects listed below.",
             "", "## Event classes"]
    for n, c in sorted(s["classes"].items(), key=lambda kv: kv[1]["uid"]):
        lines.append(f"### {c['uid']} {n} [{c['category']}] {c['description'][:160]}")
        lines.append("; ".join(_attr_line(k, a, desc) for k, a in sorted(c["attributes"].items())))
        if c.get("constraints"):
            lines.append(f"constraints: {c['constraints']}")
    lines += ["", "## Objects"]
    for n, o in sorted(s["objects"].items()):
        lines.append(f"### {n}: {o['description'][:120]}")
        lines.append("; ".join(_attr_line(k, a, desc) for k, a in sorted(o["attributes"].items())))
    return "\n".join(lines)


def class_slice_text(class_name, schema=None, max_depth=3, desc=90):
    schema = schema or Schema()
    s = schema.s
    c = s["classes"][class_name]
    lines = [f"# OCSF {schema.version} class {c['uid']} {class_name} ({c['caption']}, category {c['category']})",
             c["description"],
             "Notation: name:type!R = required, !r = recommended; {id=caption} = enum; object types are listed below.",
             "## Class attributes"]
    lines += [_attr_line(k, a, desc) for k, a in sorted(c["attributes"].items(),
              key=lambda kv: ({"required": 0, "recommended": 1}.get(kv[1]["requirement"], 2), kv[0]))
              if not a.get("profile")]
    if c.get("constraints"):
        lines.append(f"constraints: {c['constraints']}")
    seen, frontier = set(), [a["type"] for a in c["attributes"].values() if a["type"] in s["objects"]
                             and not a.get("profile")]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for t in frontier:
            if t in seen:
                continue
            seen.add(t)
            nxt += [a["type"] for a in s["objects"][t]["attributes"].values() if a["type"] in s["objects"]]
        frontier = nxt
        depth += 1
    lines.append("## Objects used by this class")
    for t in sorted(seen):
        o = s["objects"][t]
        lines.append(f"### {t}: {o['description'][:120]}")
        lines.append("; ".join(_attr_line(k, a, 0) for k, a in sorted(o["attributes"].items())))
    return "\n".join(lines)
