"""Compile parser specs to a Logstash filter section.

Events reaching Logstash carry `[loggrouper][label]` (set by the grouper) and `message` (the unwrapped
payload). Within a label, parsers are tried in order by their `when` regex; the chosen parser id is
recorded in `[loggrouper][parser]`, and events with no parser get the tag `_noparser`.
"""
import json
import re

from .executor import logstash_ref


class NeedsEscapes(ValueError):
    pass


def _q(s):
    """Logstash config string literal. Logstash does NOT process backslash escapes unless
    config.support_escapes is on, so values (regexes especially) are written raw, in whichever quote
    character they do not contain."""
    s = str(s)
    if '"' not in s:
        return '"' + s + '"'
    if "'" not in s:
        return "'" + s + "'"
    raise NeedsEscapes(f"value contains both quote characters: {s[:60]!r}")


def _hash(d):
    return "{ " + " ".join(f"{_q(k)} => {_q(v)}" for k, v in d.items()) + " }"


def _arr(xs):
    return "[" + ", ".join(_q(x) for x in xs) + "]"


def _regex_literal(rx):
    return "/" + rx.replace("/", "\\/") + "/"


_GROK_FIELD = re.compile(r"%\{(\w+):([^:}\[]+)((?::(?:int|float))?)\}")
_ONIG_FIELD = re.compile(r"\(\?<([A-Za-z_][\w.]*\.[\w.]+)>")
_DISSECT_FIELD = re.compile(r"%\{([+?&*]?)([A-Za-z_@][\w@]*(?:\.[\w@]+)+)((?:/\d+)?(?:->)?)\}")


def _brackets(dotted):
    return "".join(f"[{k}]" for k in dotted.split("."))


def grok_for_logstash(pattern):
    """Dotted capture names (spec style) -> Logstash nested field references."""
    pattern = _GROK_FIELD.sub(lambda m: f"%{{{m.group(1)}:{_brackets(m.group(2)) if '.' in m.group(2) else m.group(2)}{m.group(3)}}}", pattern)
    return _ONIG_FIELD.sub(lambda m: f"(?<{_brackets(m.group(1))}>", pattern)


def dissect_for_logstash(mapping):
    return _DISSECT_FIELD.sub(lambda m: f"%{{{m.group(1)}{_brackets(m.group(2))}{m.group(3)}}}", mapping)


def _target(t):
    return logstash_ref(t) if t else None


def compile_step(op, a, ind):
    pad = " " * ind
    if op == "grok":
        pats = [grok_for_logstash(x) for x in a["patterns"]]
        lines = [f'{pad}grok {{', f'{pad}  match => {{ {_q(logstash_ref(a.get("field", "message")))} => {_arr(pats)} }}']
        if a.get("pattern_definitions"):
            defs = {k: grok_for_logstash(v) for k, v in a["pattern_definitions"].items()}
            lines.append(f'{pad}  pattern_definitions => {_hash(defs)}')
        return lines + [f"{pad}}}"]
    if op == "dissect":
        m = dissect_for_logstash(a["mapping"])
        return [f'{pad}dissect {{ mapping => {{ {_q(logstash_ref(a.get("field", "message")))} => {_q(m)} }} }}']
    if op == "kv":
        opts = [f'source => {_q(logstash_ref(a.get("field", "message")))}']
        if a.get("target"):
            opts.append(f'target => {_q(_target(a["target"]))}')
        if a.get("field_split_pattern"):
            opts.append(f'field_split_pattern => {_q(a["field_split_pattern"])}')
        else:
            opts.append(f'field_split => {_q(a.get("field_split", " "))}')
        if a.get("value_split_pattern"):
            opts.append(f'value_split_pattern => {_q(a["value_split_pattern"])}')
        else:
            opts.append(f'value_split => {_q(a.get("value_split", "="))}')
        if a.get("trim_value"):
            opts.append(f'trim_value => {_q(a["trim_value"])}')
        opts.append(f'include_brackets => {"true" if a.get("include_brackets", True) else "false"}')
        opts.append(f'whitespace => {_q(a.get("whitespace", "lenient"))}')
        opts.append(f'allow_empty_values => {"true" if a.get("allow_empty_values") else "false"}')
        return [f"{pad}kv {{"] + [f"{pad}  {o}" for o in opts] + [f"{pad}}}"]
    if op == "csv":
        opts = [f'source => {_q(logstash_ref(a.get("field", "message")))}',
                f'separator => {_q(a.get("separator", ","))}', f'quote_char => {_q(a.get("quote_char", chr(34)))}']
        if a.get("columns"):
            opts.append(f'columns => {_arr(a["columns"])}')
        if a.get("target"):
            opts.append(f'target => {_q(_target(a["target"]))}')
        if a.get("skip_empty_columns"):
            opts.append("skip_empty_columns => true")
        return [f"{pad}csv {{"] + [f"{pad}  {o}" for o in opts] + [f"{pad}}}"]
    if op == "json":
        opts = [f'source => {_q(logstash_ref(a.get("field", "message")))}']
        if a.get("target"):
            opts.append(f'target => {_q(_target(a["target"]))}')
        return [f"{pad}json {{ {' '.join(opts)} }}"]
    if op == "date":
        return [f'{pad}date {{ match => [{_q(logstash_ref(a["field"]))}, {", ".join(_q(f) for f in a["formats"])}] '
                f'target => {_q(logstash_ref(a.get("target", "@timestamp")))} timezone => {_q(a.get("timezone", "UTC"))} }}']
    if op == "rename":
        return [f"{pad}mutate {{ rename => {_hash({logstash_ref(k): logstash_ref(v) for k, v in a.items()})} }}"]
    if op == "convert":
        return [f"{pad}mutate {{ convert => {_hash({logstash_ref(k): v for k, v in a.items()})} }}"]
    if op == "remove":
        return [f"{pad}mutate {{ remove_field => {_arr([logstash_ref(f) for f in a])} }}"]
    if op == "lowercase":
        return [f"{pad}mutate {{ lowercase => {_arr([logstash_ref(f) for f in a])} }}"]
    if op == "gsub":
        flat = []
        for f, rx, rep in a:
            flat += [logstash_ref(f), rx, rep]
        return [f"{pad}mutate {{ gsub => {_arr(flat)} }}"]
    if op == "add":
        return [f"{pad}mutate {{ add_field => {_hash({logstash_ref(k): v for k, v in a.items()})} }}"]
    raise ValueError(f"unknown parser op {op!r}")


def compile_parser(spec, ind=6):
    out = []
    for step in spec["steps"]:
        (op, a), = step.items()
        out += compile_step(op, a, ind)
    out.append(f'{" " * ind}mutate {{ add_field => {{ "[loggrouper][parser]" => {_q(spec["id"])} }} }}')
    return out


def compile_filter(parsers):
    """parsers: list of specs (any labels). -> Logstash `filter { ... }` text."""
    by_label = {}
    for p in parsers:
        by_label.setdefault(p["label"], []).append(p)
    lines = ["filter {"]
    first_label = True
    for label, ps in by_label.items():
        kw = "if" if first_label else "} else if"
        lines.append(f'  {kw} [loggrouper][label] == {_q(label)} {{')
        first_label = False
        catch_all = False
        for i, p in enumerate(ps):
            cond = f'[message] =~ {_regex_literal(p["when"])}' if p.get("when") else None
            if i == 0:
                lines.append(f"    if {cond} {{" if cond else "    if [message] {")
            else:
                lines.append(f"    }} else if {cond} {{" if cond else "    } else {")
            lines += compile_parser(p)
            if cond is None:              # a parser without `when` catches the rest; later ones are unreachable
                catch_all = True
                break
        # catch-all first parser: `if [message]` still needs an else for events without a message
        lines.append("    }" if catch_all and len(ps) > 1 else '    } else { mutate { add_tag => ["_noparser"] } }')
    if by_label:
        lines.append('  } else { mutate { add_tag => ["_noparser"] } }')
    lines.append("}")
    return "\n".join(lines)
