"""Live Claude API check: run each AI step for real on a COPY of the stores and record usage + results.

Everything in this repo so far was exercised with Claude Code sub-agents standing in for the API. This script
runs the production code paths against the real API (needs ANTHROPIC_API_KEY or an `ant auth login` profile):

  mapper   M1 (full OCSF schema as cached system prompt) on N formats; validates; records tokens/cost
  review   one reviewer session over those mappings (tool-using, read-only + record_review)
  parser   parser agent on one label with its parsers removed (rewrites them from scratch)
  grouper  grouping learner agent on the current residue of a grouping run (if a state dir is given)

  python3 bench/live_api_check.py <work dir> <groups dir> [--steps mapper,review,parser,grouper]
          [--formats 5] [--label sonicwall_firewall] [--logstash-home $LOGSTASH_HOME] [--grouping-state DIR]

Writes <work dir>/live_report.json and prints a summary. Never touches the repo's stores.
"""
import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
PRICES = {   # $/1M tokens; cache write priced at the 1h rate (2x input)
    "claude-opus-5-5": {"input_tokens": 4.0, "output_tokens": 20.0, "cache_read_input_tokens": 0.20, "cache_creation_input_tokens": 8.0},
    "claude-sonnet-5-5": {"input_tokens": 2.0, "output_tokens": 10.0, "cache_read_input_tokens": 0.10, "cache_creation_input_tokens": 4.0},
}
PRICE = dict(PRICES["claude-opus-5-5"])


def cost(u):
    return round(sum(u.get(k, 0) * p for k, p in PRICE.items()) / 1e6, 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("work"); ap.add_argument("groups")
    ap.add_argument("--steps", default="mapper,review")
    ap.add_argument("--formats", type=int, default=5)
    ap.add_argument("--label", default="sonicwall_firewall")
    ap.add_argument("--logstash-home", default=os.environ.get("LOGSTASH_HOME"))
    ap.add_argument("--grouping-state")
    ap.add_argument("--model", default="claude-opus-5-5")
    a = ap.parse_args()
    PRICE.clear(); PRICE.update(PRICES.get(a.model, PRICES["claude-opus-5-5"]))
    steps = a.steps.split(",")
    store = os.path.join(a.work, "store")
    shutil.rmtree(store, ignore_errors=True)
    os.makedirs(store)
    for f in ("parsers.json", "mappings.json"):
        shutil.copy(os.path.join(HERE, "..", "parsers", f), store)
    report = {"model": a.model, "steps": {}}

    if "mapper" in steps:
        from loggrouper.ocsf.agent import MappingTools
        from loggrouper.ocsf.llm_mapper import map_format
        t = MappingTools(store, a.groups)
        ids = [p["id"] for p in t.parsers.all_ordered() if t.parsed.get(p["id"]) and not p.get("fallback")][:a.formats]
        rows, tot = [], {}
        for pid in ids:
            p = t.parsers.by_id(pid)
            t0 = time.time()
            spec, m, u = map_format(t.schema, p, t.parsed[pid], method="full", model=a.model)
            rows.append({"parser": pid, "label": p["label"], "ok": spec is not None, "seconds": round(time.time() - t0, 1),
                         "calls": u.get("calls"), "valid_rate": (m or {}).get("valid_rate"),
                         "mapped_share": (m or {}).get("mapped_field_share"), "usage": u, "cost_usd": cost(u)})
            for k, v in u.items():
                tot[k] = tot.get(k, 0) + v
            print(json.dumps(rows[-1]))
        report["steps"]["mapper"] = {"formats": rows, "total_usage": tot, "total_cost_usd": cost(tot),
                                     "cost_per_format_usd": round(cost(tot) / max(1, len(rows)), 4)}

    if "review" in steps:
        from loggrouper.ocsf.agent import run_review_agent
        t0 = time.time()
        out = run_review_agent(store, a.groups, labels=None, model=a.model, max_iterations=40)
        report["steps"]["review"] = {"seconds": round(time.time() - t0), "usage": out["usage"],
                                     "cost_usd": cost(out["usage"]), "summary": out["summary"][:2000]}

    if "parser" in steps:
        from loggrouper.parse.agent import run_parser_agent
        from loggrouper.parse.store import ParserStore
        ps = ParserStore(store)
        for p in ps.active(a.label):
            p["status"] = "retired"
        ps.save()
        t0 = time.time()
        out = run_parser_agent(store, a.groups, labels=[a.label], logstash_home=a.logstash_home, model=a.model)
        ps = ParserStore(store)
        report["steps"]["parser"] = {"label": a.label, "seconds": round(time.time() - t0),
                                     "new_parsers": len(ps.active(a.label)), "usage": out["usage"],
                                     "cost_usd": cost(out["usage"]), "summary": out["summary"][:2000]}

    if "grouper" in steps and a.grouping_state:
        from loggrouper.agent import run_learner_agent
        from loggrouper.engine import Engine
        from loggrouper.rules import RuleStore
        rs = RuleStore(os.path.join(a.grouping_state, "rules"))
        eng = Engine(rs, os.path.join(a.grouping_state, "out"), os.path.join(a.grouping_state, "state"))
        t0 = time.time()
        out = run_learner_agent(rs, eng, model=a.model, enable_code=False)
        report["steps"]["grouper"] = {"seconds": round(time.time() - t0), **{k: out.get(k) for k in ("accepted", "rejected", "usage")},
                                      "cost_usd": cost(out.get("usage") or {})}

    with open(os.path.join(a.work, "live_report.json"), "w") as f:
        json.dump(report, f, indent=1, default=str)
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk in ("total_cost_usd", "cost_per_format_usd", "cost_usd", "seconds", "new_parsers")}
                      for k, v in report["steps"].items()}, indent=1))


if __name__ == "__main__":
    main()
