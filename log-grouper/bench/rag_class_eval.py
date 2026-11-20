"""Retrieval-only check (no LLM): does class retrieval put the class the agents chose (and the reviewer mostly
confirmed) in the candidate list? python3 bench/rag_class_eval.py <store with agent mappings> <work dir>"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from loggrouper.parse.store import MappingStore
from loggrouper.ocsf.schema import Schema
ms, sch = MappingStore(sys.argv[1]), Schema()
prep = json.load(open(os.path.join(sys.argv[2], "prep.json")))
top1 = top3 = n = 0
for pid, meta in prep["parsers"].items():
    m = ms.for_parser(pid)
    if not m:
        continue
    name = sch.cls(m["class_uid"])[0]
    n += 1; top1 += meta["candidate_classes"][0] == name; top3 += name in meta["candidate_classes"]
print(f"{prep['embed_model']}: agent class = retrieved top-1 {top1}/{n} ({top1/n:.0%}), in top-3 {top3}/{n} ({top3/n:.0%}); "
      f"retrieval {prep['retrieval_s_per_format']}s/format; prompt ~{prep['prompt_tokens_est_mean']} tokens")
