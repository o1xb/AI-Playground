"""Merge parser stores written by parallel parser agents (disjoint labels) into one store, with fresh
unique ids, then re-validate every parser on the samples and against real Logstash.

  python3 bench/merge_stores.py <out store dir> <groups dir> <logstash home|-> <store dir> [<store dir> ...]
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from loggrouper.parse.agent import load_samples
from loggrouper.parse.logstash import conformance
from loggrouper.parse.store import ParserStore
from loggrouper.parse.validate import claimed, metrics, verdict

out_dir, groups, ls_home, srcs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
merged = ParserStore(out_dir)
merged.data["parsers"] = []
seen_labels = {}
n = 1
for src in srcs:
    st = ParserStore(src)
    for p in st.all_ordered():
        if p["label"] in seen_labels and seen_labels[p["label"]] != src:
            raise SystemExit(f"label {p['label']} written by two stores")
        seen_labels[p["label"]] = src
        q = dict(p, id=f"p{n:05d}", source_store=os.path.basename(src.rstrip("/")), source_id=p["id"])
        n += 1
        merged.data["parsers"].append(q)
    merged.data["rejected"] += st.data.get("rejected", [])
samples = load_samples(groups)
problems, cf_samples = [], []
for label in sorted({p["label"] for p in merged.active()}):
    ps = merged.ordered(label)
    for p in ps:
        msgs = claimed(ps, p, samples.get(label, []))
        m = metrics(p, msgs)
        v = verdict(m, p)
        p["metrics"] = {k: m[k] for k in ("samples", "parse_rate", "coverage_mean", "distinct_fields", "date_rate")}
        if v:
            problems.append((p["id"], label, p.get("format"), v))
        cf_samples += [(label, x) for x in msgs[:25]]
merged.save()
print(f"merged {len(merged.active())} parsers for {len(seen_labels)} labels")
for x in problems:
    print("  VALIDATION:", x)
if ls_home != "-":
    r = conformance(merged.all_ordered(), cf_samples, ls_home)
    print(f"Logstash conformance on merged store: {r['identical']}/{r['checked']} identical")
    for d in r["diffs"][:5]:
        print("  DIFF", d["label"], d["python"].get("loggrouper"), d["message"][:120])
