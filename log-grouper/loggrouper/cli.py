"""loggrouper CLI.

  run       classify a file / Kafka topic in batches (fast path), buffer the residue
  packet    write the residue packet a learner (sub-agent or Claude API) works from
  apply     validate + merge a learner's candidate rules, then drain the residue
  learn     packet -> Claude API -> apply, in one step
  profile   per-group format inventory: the hand-off for writing grok/dissect parsers + OCSF maps
  seed      import rules from an ad-hoc classifier script (ordered r()/rp() regex calls)
"""
import argparse
import ast
import collections
import json
import os
import sys

from .engine import Engine
from .learn import apply_candidates
from .rules import RuleStore
from .sources import file_batches, kafka_batches
from .templates import shape


def _engine(a):
    store = RuleStore(a.store)
    return store, Engine(store, a.out, a.state)


def cmd_run(a):
    store, eng = _engine(a)
    start = eng.checkpoint()["next_offset"] if a.resume else 0
    src = (kafka_batches(a.kafka, a.topic, a.group, a.batch_size) if a.kafka
           else file_batches(a.input, a.batch_size, start))
    total = collections.Counter()
    for base, lines in src:
        st = eng.process_batch(base, lines)
        total.update({k: v for k, v in st.items() if k != "seconds"})
        print(json.dumps({"batch_offset": base, "lines": len(lines), **st}))
        res = len(eng.load_residual())
        if a.learner == "api" and res >= a.learn_threshold:
            _learn_api(store, eng, a)
    eng.close()
    m, r = total["matched"], total["residual"]
    print(json.dumps({"total_lines": m + r, "fast_path": m, "residual_new": r,
                      "fast_path_pct": round(100 * m / max(1, m + r), 2),
                      "residual_buffer": len(eng.load_residual()), "rules": len(store.compiled)}))


def cmd_packet(a):
    store, eng = _engine(a)
    pk = eng.build_packet(max_clusters=a.max_clusters)
    with open(a.output, "w") as f:
        json.dump(pk, f, indent=1)
    print(f"packet: {pk['residual_lines']} residual lines -> {len(pk['clusters'])}/{pk['clusters_total']} clusters -> {a.output}")


def _apply(store, eng, packet, cand, origin):
    rep = apply_candidates(store, packet, eng.load_residual(), cand, origin)
    moved, left = eng.reclassify_residual()
    eng.close()
    print(json.dumps({"accepted": len(rep["accepted"]), "rejected": len(rep["rejected"]),
                      "residual_drained": moved, "residual_left": left}))
    for r in rep["rejected"]:
        print("  REJECTED", r["label"], "-", r["reason"])
    return rep


def cmd_apply(a):
    store, eng = _engine(a)
    with open(a.packet) as f:
        packet = json.load(f)
    with open(a.candidates) as f:
        cand = json.load(f)
    _apply(store, eng, packet, cand, a.origin)


def _learn_api(store, eng, a):
    from .llm_learner import learn_with_claude
    packet = eng.build_packet(max_clusters=a.max_clusters)
    cand, usage = learn_with_claude(packet)
    print(json.dumps({"learner": "claude-api", "input_tokens": usage.input_tokens,
                      "output_tokens": usage.output_tokens}))
    _apply(store, eng, packet, cand, "claude-api")


def cmd_learn(a):
    store, eng = _engine(a)
    _learn_api(store, eng, a)


def cmd_profile(a):
    """Inventory each group by (rule, shape) so parser authors see every distinct format with samples."""
    store = RuleStore(a.store)
    gdir = os.path.join(a.out, "groups")
    from .unwrap import Unwrapper
    unwrap = Unwrapper(store.wrappers)
    prof = {}
    for fn in sorted(os.listdir(gdir)):
        label = fn[:-6]
        fmts = collections.defaultdict(lambda: {"count": 0, "examples": []})
        layers = collections.Counter()
        n = 0
        with open(os.path.join(gdir, fn)) as f:
            for line in f:
                rec = json.loads(line); n += 1
                payload, _ = unwrap(rec["raw"])
                layers["+".join(rec["layers"]) or "raw"] += 1
                key = (rec.get("format") or rec["rule"], shape(payload, tokens=4))
                fm = fmts[key]; fm["count"] += 1
                if len(fm["examples"]) < 2:
                    fm["examples"].append(payload[:500])
        prof[label] = {"lines": n, "transports": dict(layers),
                       "formats": [{"rule_or_format": k[0], "shape": k[1], **v}
                                   for k, v in sorted(fmts.items(), key=lambda kv: -kv[1]["count"])[:a.top]]}
    with open(os.path.join(a.out, "profile.json"), "w") as f:
        json.dump(prof, f, indent=1)
    print(f"{len(prof)} groups profiled -> {os.path.join(a.out, 'profile.json')}")


def cmd_seed(a):
    """Read r(label, pattern, conf, flags) / rp(...) calls from a classifier script WITHOUT executing it."""
    store = RuleStore(a.store)
    tree = ast.parse(open(a.script).read())
    pre, main = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("r", "rp"):
            args = node.args
            if len(args) < 2 or not all(isinstance(x, ast.Constant) for x in args[:2]):
                continue
            conf = args[2].value if len(args) > 2 and isinstance(args[2], ast.Constant) else "high"
            flags = ""
            if len(args) > 3 and isinstance(args[3], ast.Attribute):
                flags = {"I": "i", "IGNORECASE": "i", "M": "m", "S": "s"}.get(args[3].attr, "")
            (pre if node.func.id == "rp" else main).append(
                (node.lineno, {"label": args[0].value, "pattern": args[1].value, "confidence": conf, "flags": flags}))
    n = 0
    for prio_base, lst in ((10, sorted(pre, key=lambda x: x[0])), (1000, sorted(main, key=lambda x: x[0]))):
        for i, (_, r) in enumerate(lst):
            store.add({**r, "priority": prio_base + i * 10}, a.origin); n += 1
    store.save()
    print(f"seeded {n} rules from {a.script}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="loggrouper")
    p.add_argument("--store", default="rules"); p.add_argument("--out", default="out")
    p.add_argument("--state", default="state")
    sp = p.add_subparsers(dest="cmd", required=True)
    r = sp.add_parser("run"); r.add_argument("--input"); r.add_argument("--kafka")
    r.add_argument("--topic", default="security-logs"); r.add_argument("--group", default="loggrouper")
    r.add_argument("--batch-size", type=int, default=20000); r.add_argument("--resume", action="store_true")
    r.add_argument("--learner", choices=["none", "api"], default="none")
    r.add_argument("--learn-threshold", type=int, default=200); r.add_argument("--max-clusters", type=int, default=80)
    k = sp.add_parser("packet"); k.add_argument("--output", required=True); k.add_argument("--max-clusters", type=int, default=80)
    ap = sp.add_parser("apply"); ap.add_argument("--packet", required=True); ap.add_argument("--candidates", required=True)
    ap.add_argument("--origin", default="subagent")
    ln = sp.add_parser("learn"); ln.add_argument("--max-clusters", type=int, default=80)
    pf = sp.add_parser("profile"); pf.add_argument("--top", type=int, default=15)
    sd = sp.add_parser("seed"); sd.add_argument("script"); sd.add_argument("--origin", default="seed")
    a = p.parse_args(argv)
    if a.cmd == "run" and not (a.input or a.kafka):
        p.error("run needs --input FILE or --kafka HOST:PORT")
    {"run": cmd_run, "packet": cmd_packet, "apply": cmd_apply, "learn": cmd_learn,
     "profile": cmd_profile, "seed": cmd_seed}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
