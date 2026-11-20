"""Parsing/OCSF benchmark from Elastic integration test data: each sample line comes with the fields
Elastic's own pipeline extracts (`*-expected.json`, ECS). Lines are routed by the grouper (as in
production), then split by hash into train (given to the agents) and test (held out, for scoring).

  python3 bench/build_parse_bench.py <ei/packages> <rules dir> <out dir> pkg1,pkg2,...
"""
import glob, hashlib, json, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from loggrouper.rules import RuleStore
from loggrouper.unwrap import Unwrapper

pkgdir, rules, out, pkgs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split(",")
cap = int(os.environ.get("CAP", "300"))
st = RuleStore(rules)
u = Unwrapper(st.wrappers)
rows = []
for pkg in pkgs:
    items = []
    for f in sorted(glob.glob(f"{pkgdir}/{pkg}/data_stream/*/_dev/test/pipeline/test-*.log")):
        if not os.path.exists(f + "-expected.json"):
            continue
        cfg = f + "-config.yml"
        if os.path.exists(cfg) and "multiline" in open(cfg).read():
            continue
        lines = [l.rstrip("\r\n") for l in open(f, errors="replace")]
        exp = json.load(open(f + "-expected.json"))["expected"]
        nonempty = [l for l in lines if l.strip()]
        if len(exp) == len(nonempty):
            pairs = zip(nonempty, exp)
        elif len(exp) == len(lines):
            pairs = zip(lines, exp)
        else:
            continue
        for l, e in pairs:
            if l.strip() and e is not None:
                items.append((l, e, f.split("/data_stream/")[1].split("/")[0]))
    random.Random(pkg).shuffle(items)
    for l, e, ds in items[:cap]:
        payload, _, views = u.views(l)
        r, _ = st.match_views(views)
        label = r["label"] if r else "__unrouted__"
        split = "train" if int(hashlib.sha1(l.encode()).hexdigest(), 16) % 2 == 0 else "test"
        rows.append({"pkg": pkg, "data_stream": ds, "label": label, "split": split, "message": payload, "expected": e})
os.makedirs(os.path.join(out, "train", "groups"), exist_ok=True)
for fn in glob.glob(os.path.join(out, "train", "groups", "*.jsonl")):
    os.remove(fn)
with open(os.path.join(out, "test.jsonl"), "w") as t:
    for r in rows:
        if r["split"] == "train":
            with open(os.path.join(out, "train", "groups", f"{r['label']}.jsonl"), "a") as g:
                g.write(json.dumps({"raw": r["message"], "label": r["label"]}) + "\n")
        else:
            t.write(json.dumps(r) + "\n")
from collections import Counter
print("rows", len(rows), Counter(r["split"] for r in rows))
print(sorted(Counter((r["pkg"], r["label"]) for r in rows).items()))
