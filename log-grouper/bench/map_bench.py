"""Benchmark for the no-retrieval OCSF mappers (loggrouper/ocsf/llm_mapper.py) with a prompt/answer protocol, so
any LLM - or a Claude Code sub-agent restricted to answering only from the prompt - plays the model.

  system <method> <store> <groups> <work>            print the system prompt (method full: the cached schema)
  next   <method> <store> <groups> <work> <ids>      print the next prompt
  answer <method> <store> <groups> <work> <ids>      record the answer (stdin)
  apply  <method> <store> <groups> <work>            write <work>/store (parsers + accepted mappings), usage summary

Methods: full (M1), slice (M2), cover (M3).
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from loggrouper.ocsf.agent import MappingTools
from loggrouper.ocsf.llm_mapper import (class_prompt, coverage_prompt, full_system, full_user, slice_user)
from loggrouper.ocsf.mapping import prepare
from loggrouper.ocsf.rag import evaluate, parse_answer, repair_prompt
from loggrouper.parse.store import MappingStore


def tokens(s):
    return round(len(s) / 3.6)


cmd, method, store, groups, work = sys.argv[1:6]
ids = sys.argv[6].split(",") if len(sys.argv) > 6 and sys.argv[6] else []
os.makedirs(work, exist_ok=True)
tools = MappingTools(store, groups)
sch = tools.schema
parsers = [p for p in tools.parsers.all_ordered() if tools.parsed.get(p["id"]) and (not ids or p["id"] in ids)]
st_path = os.path.join(work, "state.json")
state = json.load(open(st_path)) if os.path.exists(st_path) else {"_system_tokens": 0, "_system_reads": 0}


def save():
    with open(st_path + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(st_path + ".tmp", st_path)


if cmd == "system":
    if method != "full":
        print("(no system prompt for this method)"); sys.exit()
    txt = full_system(sch)
    state["_system_tokens"] = tokens(txt); save()
    print(txt); sys.exit()

if cmd in ("next", "answer"):
    cur = None
    for p in parsers:
        s = state.setdefault(p["id"], {"stage": "map" if method == "full" else "class", "calls": 0,
                                       "prompt_tokens": 0, "answer_tokens": 0, "repairs": 0})
        if s["stage"] not in ("done", "failed"):
            cur = (p, s)
            break
    if cur is None:
        print("DONE"); sys.exit()
    p, s = cur
    ev = tools.parsed[p["id"]]
    if cmd == "next":
        if s["stage"] == "class":
            prompt = class_prompt(sch, p, ev)
        elif s["stage"] == "map":
            prompt = full_user(p, ev) if method == "full" else slice_user(sch, p, ev, s["class"])
        elif s["stage"] == "repair":
            prompt = s["repair_prompt"]
        else:                                   # cover
            prompt = s["cover_prompt"]
        s["pending"] = tokens(prompt); save()
        print(f"=== PROMPT {p['id']} ({s['stage']}) ===\n{prompt}")
        sys.exit()
    # answer
    txt = sys.stdin.read()
    s["calls"] += 1; s["prompt_tokens"] += s.pop("pending", 0); s["answer_tokens"] += tokens(txt)
    if method == "full":
        state["_system_reads"] += 1               # each call re-reads the cached system prompt
    try:
        ans = parse_answer(txt)
    except Exception as e:  # noqa: BLE001
        ans, err = None, str(e)
    if s["stage"] == "class":
        name = sch.cls(ans.get("class_uid", -1))[0] if ans else None
        if name:
            s["class"], s["stage"] = name, "map"
            print(f"recorded class {name}; call next")
        else:
            print('ERROR: answer must be JSON {"class_uid": <valid uid>}')
        save(); sys.exit()
    if s["stage"] == "cover":
        try:
            spec2, m2, v2 = evaluate(ans, p, ev, sch)
            if not v2 and m2["mapped_field_share"] > s["metrics"]["mapped_field_share"]:
                s["spec"], s["metrics"] = spec2, {k: m2[k] for k in ("valid_rate", "mapped_field_share")}
                print(f"COVERAGE ACCEPTED {p['id']}: mapped share {m2['mapped_field_share']}")
            else:
                print(f"coverage not taken ({v2 or 'no gain'}); keeping the validated spec")
        except Exception as e:  # noqa: BLE001
            print(f"coverage answer unusable ({e}); keeping the validated spec")
        s["stage"] = "done"; save(); sys.exit()
    if ans is None:
        spec, m, verdict = {}, {"valid_rate": 0, "errors": [[err, 1]], "error_examples": []}, "unparseable"
    else:
        spec, m, verdict = evaluate(ans, p, ev, sch)
    if not verdict:
        s["spec"], s["metrics"] = spec, {k: m[k] for k in ("valid_rate", "mapped_field_share")}
        cp = coverage_prompt(spec, ev, prepare(spec, sch)) if method == "cover" else None
        if cp:
            s["stage"], s["cover_prompt"] = "cover", cp
            print(f"VALID {p['id']} (share {m['mapped_field_share']}); call next for the coverage prompt")
        else:
            s["stage"] = "done"
            print(f"ACCEPTED {p['id']}: valid_rate {m['valid_rate']}, mapped share {m['mapped_field_share']}")
    elif s["repairs"] >= 2:
        s["stage"] = "failed"; print(f"FAILED {p['id']} after 2 repairs: {verdict}")
    else:
        s["repairs"] += 1; s["stage"] = "repair"; s["repair_prompt"] = repair_prompt(spec, m)
        print(f"REJECTED ({verdict}); call next for the repair prompt")
    save(); sys.exit()

if cmd == "apply":
    out = os.path.join(work, "store")
    shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
    shutil.copy(os.path.join(store, "parsers.json"), out)
    ms = MappingStore(out)
    done = [(k, v) for k, v in state.items() if not k.startswith("_") and v.get("spec")]
    for k, v in done:
        ms.items.append(dict(v["spec"], id=ms.next_id("m"), status="active", origin=f"llm-{method}"))
    ms.save()
    per = [v for k, v in state.items() if not k.startswith("_")]
    n = max(1, len(per))
    print(json.dumps({"method": method, "formats": len(per), "accepted": len(done),
                      "failed": sum(1 for v in per if v["stage"] == "failed"),
                      "calls_per_format": round(sum(v["calls"] for v in per) / n, 2),
                      "prompt_tokens_per_format": round(sum(v["prompt_tokens"] for v in per) / n),
                      "answer_tokens_per_format": round(sum(v["answer_tokens"] for v in per) / n),
                      "cached_system_tokens": state.get("_system_tokens", 0),
                      "cached_system_reads_per_format": round(state.get("_system_reads", 0) / n, 2)}))
