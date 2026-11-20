"""Score several mapping stores on the held-out lines of a fixed set of formats (parser ids), side by side.

  python3 bench/score_subset.py <test.jsonl> <parser store> <ids> name=<mapping store dir> [name=...]
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score_ocsf import score
from loggrouper.ocsf.mapping import apply_mapping, prepare
from loggrouper.ocsf.schema import Schema
from loggrouper.parse.executor import run_parser, select_parser
from loggrouper.parse.store import MappingStore, ParserStore
from loggrouper.parse.validate import FAILURE_TAGS

test, pstore, ids = sys.argv[1], sys.argv[2], set(sys.argv[3].split(","))
sch, ps = Schema(), ParserStore(pstore)
rows = [json.loads(l) for l in open(test)]
sel = []
for r in rows:
    p = select_parser(ps.ordered(r["label"]), r["message"])
    if p and p["id"] in ids:
        e = run_parser(p, r["message"])
        sel.append((r, p, e, not (FAILURE_TAGS & set(e.get("tags", [])))))
print(f"{len(sel)} held-out lines of {len(ids)} formats")
print(f"{'method':16s} {'mapped':>7s} {'valid':>6s} {'precision':>9s} {'recall':>7s} {'ts~':>5s}  per-field recall (src.ip dst.ip src.port dst.port transport user bytes mac url)")
for arg in sys.argv[4:]:
    name, d = arg.split("=", 1)
    ms = MappingStore(d)
    prep = {m["parser_id"]: prepare(m, sch) for m in ms.active() if m["parser_id"] in ids}
    ev = [apply_mapping(prep[p["id"]], e) if ok and p["id"] in prep else None for r, p, e, ok in sel]
    rep = score([x[0] for x in sel], ev, [x[3] for x in sel], sch)
    s = rep["summary"]
    agg = {}
    for l in rep["labels"]:
        for f, v in l["per_field"].items():
            a, b = v.split(" ")[0].split("/")
            x = agg.setdefault(f, [0, 0]); x[0] += int(a); x[1] += int(b)
    pf = lambda f: f"{agg[f][0] / agg[f][1]:.0%}" if f in agg and agg[f][1] else "-"
    print(f"{name:16s} {s['mapped_rate']:7.3f} {s['ocsf_valid_rate']:6.3f} {s['field_precision']:9.3f} {s['field_recall']:7.3f} "
          f"{s['timestamp_match_allowing_tz_year_artefacts']:5.2f}  " + " ".join(pf(f) for f in (
              "source.ip", "destination.ip", "source.port", "destination.port", "network.transport", "user.name",
              "source.bytes", "source.mac", "url.original")))
