"""Make a (merged) parser store self-consistent: unique `order` per label (current selection order kept),
and golden examples re-pinned to current executor output. Run after merging stores or after executor
semantics change; the store must already pass validation and Logstash conformance.

  python3 bench/repin_store.py <store dir> <groups dir>
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from loggrouper.parse.agent import load_samples
from loggrouper.parse.store import ParserStore
from loggrouper.parse.validate import claimed, golden_regressions, pick_golden

st = ParserStore(sys.argv[1])
samples = load_samples(sys.argv[2])
before = sum(len(golden_regressions(st.ordered(l))) for l in {p["label"] for p in st.active()})
for label in sorted({p["label"] for p in st.active()}):
    ps = st.ordered(label)
    for i, p in enumerate(ps):
        p["order"] = 99999 if p.get("fallback") else (i + 1) * 10
    ps = st.ordered(label)
    for p in ps:
        p["golden"] = pick_golden(p, claimed(ps, p, samples.get(label, [])))
after = sum(len(golden_regressions(st.ordered(l))) for l in {p["label"] for p in st.active()})
st.save()
print(f"golden regressions before: {before}, after: {after}")
