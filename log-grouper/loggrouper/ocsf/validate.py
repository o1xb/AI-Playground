"""OCSF mapping validation: run a mapping over a parser's parsed samples and check every output
against the OCSF schema; measure how much of the parsed data the mapping uses."""
import collections
import re

from ..parse.validate import flatten
from .mapping import apply_mapping

MIN_VALID = 0.95


def _norm_err(e):
    return re.sub(r"'[^']*'|\d{3,}", "…", e)[:120]


def mapping_metrics(prepared, schema, parsed_events, max_examples=3):
    valid, errs, warns, share, examples = 0, collections.Counter(), collections.Counter(), [], {}
    unknown = 0
    for ev in parsed_events:
        out = apply_mapping(prepared, ev)
        e, w = schema.validate(out)
        if not e:
            valid += 1
        for x in e:
            k = _norm_err(x)
            errs[k] += 1
            unknown += x.startswith("unknown attribute")
            if k not in examples and len(examples) < 12:
                examples[k] = {"error": x, "vendor": {kk: v for kk, v in list(flatten(ev.get("vendor")).items())[:15]}}
        for x in w:
            warns[_norm_err(x)] += 1
        total = len(flatten(ev.get("vendor")))
        left = len(flatten(out.get("unmapped")))
        if total:
            share.append(1 - left / total)
    n = max(1, len(parsed_events))
    return {"events": len(parsed_events), "valid_rate": round(valid / n, 4),
            "mapped_field_share": round(sum(share) / len(share), 3) if share else 0.0,
            "errors": errs.most_common(12), "error_examples": list(examples.values())[:max_examples],
            "recommended_missing": warns.most_common(10), "unknown_attribute_errors": unknown}


def mapping_verdict(m):
    if m["events"] == 0:
        return "no parsed samples for this parser"
    if m["unknown_attribute_errors"]:
        return "maps to attributes that do not exist in the class/object (see errors)"
    if m["valid_rate"] < MIN_VALID:
        return f"only {m['valid_rate']} of outputs are schema-valid (need {MIN_VALID}); see errors"
    return None
