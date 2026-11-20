"""End to end in REAL Logstash: the full compiled pipeline (all parsers + OCSF mappings) runs over the
held-out test lines; Logstash's own OCSF output is scored against Elastic's expected ECS fields and
compared event-by-event with the Python pipeline.

  python3 bench/e2e_logstash.py <bench>/test.jsonl <store dir> <logstash home> [report.json]
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from loggrouper.ocsf.mapping import prepare
from loggrouper.ocsf.schema import Schema
from loggrouper.parse.logstash import LOGSTASH_INTERNAL, logstash_outputs
from loggrouper.parse.store import MappingStore, ParserStore
from score_ocsf import print_report, python_pipeline, score

test, store, ls_home = sys.argv[1:4]
schema = Schema()
rows = [json.loads(l) for l in open(test)]
parsers, maps = ParserStore(store), MappingStore(store)
prepared = {m["parser_id"]: prepare(m, schema) for m in maps.active()}
raw = logstash_outputs(parsers.all_ordered(), [(r["label"], r["message"]) for r in rows], ls_home,
                       mappings=prepared, raw=True)
ls_events, ls_flags = [], []
for ev in raw:
    tags = set(ev.get("tags") or [])
    ok = not (tags & {"_grokparsefailure", "_dissectfailure", "_csvparsefailure", "_jsonparsefailure",
                      "_dateparsefailure", "_noparser"})
    ls_flags.append(ok)
    mapped = ok and (ev.get("loggrouper") or {}).get("mapping")
    ls_events.append({k: v for k, v in ev.items() if k not in LOGSTASH_INTERNAL} if mapped else None)
rep = score(rows, ls_events, ls_flags, schema)
py_events, _ = python_pipeline(rows, store, schema)
same = sum(1 for a, b in zip(py_events, ls_events) if json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True))
rep["summary"]["identical_to_python"] = f"{same}/{len(rows)}"
print("Scored on Logstash's own output:")
print_report(rep)
if len(sys.argv) > 4:
    with open(sys.argv[4], "w") as f:
        json.dump(rep, f, indent=1, default=str)
