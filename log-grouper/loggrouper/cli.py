"""loggrouper CLI.

  run       classify a file / Kafka topic in batches (fast path), buffer the residue
  packet    write the residue packet a learner (sub-agent or Claude API) works from
  apply     validate + merge a learner's candidate rules, then drain the residue
  learn     packet -> Claude API -> apply, in one step (--agent: tool-using learner agent)
  tool      call one learner-agent tool from the shell (testing / driving the agent by hand)
  review    list rules held for human review; --approve / --discard ids
  audit     list message shapes that landed in more than one group (over-reaching rules)
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
           else file_batches(a.input, a.batch_size, start, a.first_line_pattern))
    total = collections.Counter()
    for base, lines in src:
        st = eng.process_batch(base, lines)
        total.update({k: v for k, v in st.items() if k != "seconds"})
        print(json.dumps({"batch_offset": base, "lines": len(lines), **st}))
        res = len(eng.load_residual())
        if a.learner == "api" and res >= a.learn_threshold:
            _learn_api(store, eng, a)
        elif a.learner == "agent" and res >= a.learn_threshold:
            _learn_agent(store, eng, a)
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
                      "rule_updates": len(rep["updated"]), "updates_refused": len(rep["rejected_updates"]),
                      "residual_drained": moved, "residual_left": left}))
    for r in rep["rejected"]:
        print("  REJECTED", r["label"], "-", r["reason"])
    for d in rep.get("disputed", []):
        print("  DISPUTED", d["id"], d["label"], "also matches observed examples of", d["also_matches_observed_of"])
    for u in rep["updated"]:
        print("  UPDATED", u["id"], {k: v for k, v in u.items() if k not in ("id", "rationale")})
    for u in rep["rejected_updates"]:
        print("  UPDATE REFUSED", u.get("id"), "-", u["reason"])
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


def _learn_agent(store, eng, a):
    from .agent import run_learner_agent
    out = run_learner_agent(store, eng, model=a.model, effort=a.effort,
                            review_new_labels=a.review_new_labels, enable_code=a.code_tools != "off",
                            sandbox_backend=a.code_tools if a.code_tools != "off" else "unshare",
                            stream_sample=list(eng.recent) or None)
    eng.close()
    print(json.dumps({k: v for k, v in out.items() if k != "summary"}))
    print(out.get("summary", ""))


def cmd_learn(a):
    store, eng = _engine(a)
    if a.agent:
        _learn_agent(store, eng, a)
    else:
        _learn_api(store, eng, a)


def cmd_tool(a):
    """Shell bridge to the agent's tools (same code the API agent calls). Drafts persist in --state."""
    from .agent import LearnerTools
    store, eng = _engine(a)
    t = LearnerTools(store, eng, drafts_path=os.path.join(a.state, "agent_drafts.json"),
                     review_new_labels=a.review_new_labels, enable_code=a.code_tools != "off",
                     sandbox_backend=a.code_tools if a.code_tools != "off" else "unshare",
                     workspace=os.path.join(a.state, "agent_workspace"))
    fn = {f.__name__: f for f in t.tool_functions()}.get(a.name)
    if fn is None:
        sys.exit(f"unknown tool {a.name}; tools: {[f.__name__ for f in t.tool_functions()]}")
    raw = sys.stdin.read() if a.args == "-" else (a.args or "{}")     # "-": JSON args on stdin (no shell quoting)
    print(fn(**json.loads(raw)))
    eng.close()


def cmd_ptool(a):
    """Shell bridge to the parser agent's tools."""
    from .parse.agent import ParserTools
    t = ParserTools(a.parsers, os.path.join(a.out, "groups"), labels=a.labels.split(",") if a.labels else None,
                    logstash_home=a.logstash_home, enable_code=a.code_tools != "off",
                    sandbox_backend=a.code_tools if a.code_tools != "off" else "unshare",
                    workspace=os.path.join(a.state, "parser_workspace"),
                    drafts_path=os.path.join(a.state, "parser_drafts.json"),
                    failures=a.failures, review_new_parsers=a.review_new_parsers)
    fn = {f.__name__: f for f in t.tool_functions()}.get(a.name)
    if fn is None:
        sys.exit(f"unknown tool {a.name}; tools: {[f.__name__ for f in t.tool_functions()]}")
    raw = sys.stdin.read() if a.args == "-" else (a.args or "{}")
    print(_call(fn, raw))


def _call(fn, raw):
    """Call a tool with JSON args; argument errors come back as tool errors, as the API would report them."""
    import inspect
    try:
        args = json.loads(raw)
    except ValueError as e:
        return f"ERROR: arguments are not valid JSON: {e}"
    try:
        inspect.signature(fn).bind(**args)
    except TypeError as e:
        return f"ERROR: {e}. Signature: {fn.__name__}{inspect.signature(fn)}"
    return fn(**args)


def cmd_parse_learn(a):
    from .parse.agent import run_parser_agent
    out = run_parser_agent(a.parsers, os.path.join(a.out, "groups"), labels=a.labels.split(",") if a.labels else None,
                           logstash_home=a.logstash_home, enable_code=a.code_tools != "off",
                           failures=a.failures, review_new_parsers=a.review_new_parsers,
                           model=a.model, effort=a.effort)
    print(json.dumps({k: v for k, v in out.items() if k != "summary"}, default=str)[:4000])
    print(out["summary"])


def cmd_mtool(a):
    """Shell bridge to the OCSF mapping agent's tools (or the reviewer's, with --reviewer)."""
    from .ocsf.agent import MappingTools, ReviewTools
    labels = a.labels.split(",") if a.labels else None
    if a.reviewer:
        t = ReviewTools(a.parsers, os.path.join(a.out, "groups"), labels=labels)
    else:
        t = MappingTools(a.parsers, os.path.join(a.out, "groups"), labels=labels, logstash_home=a.logstash_home,
                         enable_code=a.code_tools != "off", sandbox_backend=a.code_tools if a.code_tools != "off" else "unshare",
                         workspace=os.path.join(a.state, "mapping_workspace"),
                         drafts_path=os.path.join(a.state, "mapping_drafts.json"))
    fn = {f.__name__: f for f in t.tool_functions()}.get(a.name)
    if fn is None:
        sys.exit(f"unknown tool {a.name}; tools: {[f.__name__ for f in t.tool_functions()]}")
    raw = sys.stdin.read() if a.args == "-" else (a.args or "{}")
    print(_call(fn, raw))


def cmd_map_learn(a):
    from .ocsf.agent import run_mapping_agent, run_review_agent
    labels = a.labels.split(",") if a.labels else None
    g = os.path.join(a.out, "groups")
    for rnd in range(a.rounds):
        out = run_mapping_agent(a.parsers, g, labels=labels, logstash_home=a.logstash_home,
                                enable_code=a.code_tools != "off", model=a.model, effort=a.effort)
        print(f"[mapping round {rnd + 1}]", out["summary"])
        rev = run_review_agent(a.parsers, g, labels=labels, model=a.model, effort=a.effort)
        print(f"[review round {rnd + 1}]", rev["summary"])


def cmd_preview(a):
    from .parse.store import ParserStore
    st = ParserStore(a.parsers)
    if a.approve or a.discard:
        for pid in (a.approve or []) + (a.discard or []):
            p = st.by_id(pid)
            if not p or p.get("status") != "candidate":
                print(f"{pid}: not a candidate"); continue
            p["status"] = "active" if pid in (a.approve or []) else "discarded"
            print(f"{pid}: {p['status']}")
        st.save()
        return
    for p in st.items:
        if p.get("status") == "candidate":
            print(f"{p['id']} {p['label']}/{p.get('format')} when={p.get('when')!r} metrics={p.get('metrics')}\n"
                  f"    why: {p.get('rationale', '')[:200]}")


def cmd_export(a):
    """Write the deployable Logstash bundle: filter config (all active parsers + OCSF mappings) and the
    Ruby OCSF mapper it references."""
    import shutil
    from .ocsf.mapping import RUBY_SCRIPT, prepare
    from .ocsf.schema import Schema
    from .parse.compiler import compile_filter
    from .parse.store import MappingStore, ParserStore
    os.makedirs(a.dest, exist_ok=True)
    ps, ms, sch = ParserStore(a.parsers), MappingStore(a.parsers), Schema()
    maps = {m["parser_id"]: prepare(m, sch) for m in ms.active()}
    rb = os.path.join(a.ruby_dir or a.dest, "ocsf_mapper.rb")
    with open(os.path.join(a.dest, "loggrouper-filter.conf"), "w") as f:
        f.write("# generated by loggrouper export: %d parsers, %d OCSF mappings\n" % (len(ps.active()), len(maps)))
        f.write(compile_filter(ps.all_ordered(), maps, rb) + "\n")
    shutil.copy(RUBY_SCRIPT, os.path.join(a.dest, "ocsf_mapper.rb"))
    with open(os.path.join(a.dest, "loggrouper-output.conf.example"), "w") as f:
        f.write("""# Route parse failures to a dead letter the parser agent learns from
# (python3 -m loggrouper.cli parse-learn --failures <file>), everything else onward as OCSF.
output {
  if "_noparser" in [tags] or "_grokparsefailure" in [tags] or "_dissectfailure" in [tags]
     or "_csvparsefailure" in [tags] or "_jsonparsefailure" in [tags] {
    file { path => "/var/log/loggrouper/parse_failures.jsonl" codec => json_lines }
    # or: kafka { topic_id => "loggrouper-parse-failures" codec => json }
  } else {
    # OCSF events: your sink here, e.g. kafka { topic_id => "ocsf-events" codec => json }
    stdout { codec => json_lines }
  }
}
""")
    print(f"wrote {a.dest}/loggrouper-filter.conf and ocsf_mapper.rb ({len(ps.active())} parsers, {len(maps)} mappings)")


def cmd_review(a):
    store = RuleStore(a.store)
    if a.approve or a.discard:
        for rid in (a.approve or []) + (a.discard or []):
            r = store.by_id(rid)
            if r is None or r.get("status") != "candidate":
                print(f"{rid}: not a candidate rule"); continue
            r["status"] = "active" if rid in (a.approve or []) else "discarded"
            print(f"{rid}: {r['status']}")
        store.save()
        return
    for r in store.rules["rules"]:
        if r.get("status") == "candidate":
            print(f"{r['id']} {r['label']} pattern={r['pattern']!r}\n    why: {r.get('rationale', '')}\n"
                  f"    e.g. {(r.get('examples') or [''])[0][:200]!r}")


def cmd_audit(a):
    """Shapes routed to more than one group (likely an over-reaching rule)."""
    store, eng = _engine(a)
    for c in eng.find_conflicts():
        print(c["conflict_id"], c["shape"][:80])
        for l, g in c["labels"].items():
            print(f"    {l:32s} {g['count']:5d}  rules={g['rules']}")


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
    r.add_argument("--batch-size", type=int, default=20000)
    r.add_argument("--first-line-pattern", help="multiline framing for file input: regex that starts a record"); r.add_argument("--resume", action="store_true")
    r.add_argument("--learner", choices=["none", "api", "agent"], default="none")
    r.add_argument("--learn-threshold", type=int, default=200); r.add_argument("--max-clusters", type=int, default=80)
    k = sp.add_parser("packet"); k.add_argument("--output", required=True); k.add_argument("--max-clusters", type=int, default=80)
    ap = sp.add_parser("apply"); ap.add_argument("--packet", required=True); ap.add_argument("--candidates", required=True)
    ap.add_argument("--origin", default="subagent")
    ln = sp.add_parser("learn"); ln.add_argument("--max-clusters", type=int, default=80)
    ln.add_argument("--agent", action="store_true", help="tool-using agent (default: single structured call)")
    tl = sp.add_parser("tool"); tl.add_argument("name"); tl.add_argument("args", nargs="?")
    rv = sp.add_parser("review"); rv.add_argument("--approve", nargs="*"); rv.add_argument("--discard", nargs="*")
    pt = sp.add_parser("ptool"); pt.add_argument("name"); pt.add_argument("args", nargs="?")
    pl = sp.add_parser("parse-learn")
    for x in (pt, pl):
        x.add_argument("--labels", default="")
        x.add_argument("--failures", help="parse-failure dead letter (JSON lines) from the exported pipeline")
        x.add_argument("--review-new-parsers", action="store_true", help="new parsers wait as candidates")
    pv = sp.add_parser("preview", help="list/approve/discard parsers held for review")
    pv.add_argument("--approve", nargs="*"); pv.add_argument("--discard", nargs="*")
    mt = sp.add_parser("mtool"); mt.add_argument("name"); mt.add_argument("args", nargs="?")
    mt.add_argument("--reviewer", action="store_true")
    ml = sp.add_parser("map-learn"); ml.add_argument("--rounds", type=int, default=2)
    for x in (mt, ml):
        x.add_argument("--labels", default="")
    ex = sp.add_parser("export"); ex.add_argument("dest")
    ex.add_argument("--ruby-dir", help="directory where ocsf_mapper.rb will live on the Logstash host (default: dest)")
    sp.add_parser("audit")
    pf = sp.add_parser("profile"); pf.add_argument("--top", type=int, default=15)
    sd = sp.add_parser("seed"); sd.add_argument("script"); sd.add_argument("--origin", default="seed")
    p.add_argument("--parsers", default="parsers", help="parser/mapping store directory")
    p.add_argument("--logstash-home", default=os.environ.get("LOGSTASH_HOME"))
    p.add_argument("--model", default="claude-opus-5-5")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--code-tools", choices=["off", "unshare", "docker"], default="off",
                   help="give the learner agent sandboxed run_python/run_bash (unshare: Linux namespaces; docker)")
    p.add_argument("--review-new-labels", action="store_true",
                   help="hold rules for labels never seen before as candidates until approved")
    a = p.parse_args(argv)
    if a.cmd == "run" and not (a.input or a.kafka):
        p.error("run needs --input FILE or --kafka HOST:PORT")
    {"run": cmd_run, "packet": cmd_packet, "apply": cmd_apply, "learn": cmd_learn,
     "profile": cmd_profile, "seed": cmd_seed, "audit": cmd_audit,
     "tool": cmd_tool, "review": cmd_review, "ptool": cmd_ptool, "parse-learn": cmd_parse_learn,
     "mtool": cmd_mtool, "map-learn": cmd_map_learn, "export": cmd_export, "preview": cmd_preview}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
