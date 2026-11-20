"""RAG mapper benchmark (model answers come from files, so any LLM - or a Claude Code sub-agent playing
the single call - can answer).

  prep   <store> <groups dir> <work dir> [embed model]  -> work/prompts/<parser>.txt (+ timing, sizes)
  apply  <store> <groups dir> <work dir>                -> validates work/answers/<parser>.json; writes
                                                           work/repairs/<parser>.txt for failures and
                                                           work/store/ (parsers + accepted RAG mappings)
"""
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from loggrouper.ocsf.agent import MappingTools
from loggrouper.ocsf.rag import Embedder, OcsfIndex, build_prompt, evaluate, parse_answer, repair_prompt
from loggrouper.ocsf.schema import Schema
from loggrouper.parse.store import MappingStore, ParserStore


def tokens(s):
    return round(len(s) / 3.6)          # rough chars->tokens for English+JSON (no API here to count)


cmd, store, groups, work = sys.argv[1:5]
os.makedirs(work, exist_ok=True)
tools = MappingTools(store, groups)                 # reuse: parsed samples per parser (fallbacks included)
parsers = [p for p in tools.parsers.all_ordered() if tools.parsed.get(p["id"])]

if cmd == "prep":
    model = sys.argv[5] if len(sys.argv) > 5 else None
    t0 = time.time()
    emb = Embedder(model) if model else Embedder()
    t_load = time.time() - t0
    t0 = time.time()
    index = OcsfIndex(emb, tools.schema)
    t_index = time.time() - t0
    os.makedirs(os.path.join(work, "prompts"), exist_ok=True)
    meta, t_ret = {}, []
    for p in parsers:
        t0 = time.time()
        prompt, classes = build_prompt(index, p, tools.parsed[p["id"]])
        t_ret.append(time.time() - t0)
        with open(os.path.join(work, "prompts", f"{p['id']}.txt"), "w") as f:
            f.write(prompt)
        meta[p["id"]] = {"label": p["label"], "format": p.get("format"), "candidate_classes": classes,
                         "prompt_tokens_est": tokens(prompt)}
    json.dump({"embed_model": emb.name, "load_s": round(t_load, 1), "index_build_or_load_s": round(t_index, 1),
               "retrieval_s_per_format": round(sum(t_ret) / len(t_ret), 3), "formats": len(parsers),
               "prompt_tokens_est_mean": round(sum(m["prompt_tokens_est"] for m in meta.values()) / len(meta)),
               "parsers": meta}, open(os.path.join(work, "prep.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in json.load(open(os.path.join(work, "prep.json"))).items() if k != "parsers"}))

elif cmd in ("next", "answer", "status"):
    # Interactive protocol for an LLM stand-in: `next` prints the next prompt, `answer` (stdin) records the reply.
    # Per parser: class prompt -> mapping prompt -> up to 2 repair prompts. Every answer = one LLM call.
    from loggrouper.ocsf.rag import build_class_prompt
    ids = [x for x in (sys.argv[5].split(",") if len(sys.argv) > 5 and sys.argv[5] else [])]
    todo = [p for p in parsers if not ids or p["id"] in ids]
    st_path = os.path.join(work, "state.json")
    state = json.load(open(st_path)) if os.path.exists(st_path) else {}
    model = os.environ.get("LG_EMBED_MODEL_BENCH")
    def save():
        json.dump(state, open(st_path + ".tmp", "w"), indent=1); os.replace(st_path + ".tmp", st_path)
    def current():
        for p in todo:
            s_ = state.setdefault(p["id"], {"stage": "class", "calls": 0, "prompt_tokens": 0, "answer_tokens": 0})
            if s_["stage"] not in ("done", "failed"):
                return p, s_
        return None, None
    p, s_ = current()
    if cmd == "status":
        from collections import Counter
        print(Counter(v["stage"] for k, v in state.items() if not ids or k in ids)); sys.exit()
    if p is None:
        print("DONE"); sys.exit()
    if cmd == "next":
        if s_["stage"] == "class":
            prompt = build_class_prompt(tools.schema, p, tools.parsed[p["id"]])
        elif s_["stage"] == "mapping":
            emb = Embedder(model) if model else Embedder()
            prompt, _ = build_prompt(OcsfIndex(emb, tools.schema), p, tools.parsed[p["id"]], class_names=[s_["class"]])
        else:
            prompt = s_["repair_prompt"]
        s_["pending_prompt_tokens"] = tokens(prompt); save()
        print(f"=== PROMPT {p['id']} ({s_['stage']}) ===\n{prompt}")
    else:
        txt = sys.stdin.read()
        s_["calls"] += 1; s_["prompt_tokens"] += s_.pop("pending_prompt_tokens", 0); s_["answer_tokens"] += tokens(txt)
        try:
            ans = parse_answer(txt)
        except Exception as e:  # noqa: BLE001
            ans = None; err = str(e)
        if s_["stage"] == "class":
            name = tools.schema.cls(ans.get("class_uid", -1))[0] if ans else None
            if name:
                s_["class"], s_["stage"] = name, "mapping"
                print(f"recorded class {name}; call `next` for the mapping prompt")
            else:
                print("ERROR: answer must be JSON {\"class_uid\": <valid uid>}")
        else:
            if ans is None:
                spec, m, verdict = {}, {"valid_rate": 0, "errors": [[err, 1]], "error_examples": []}, "unparseable"
            else:
                spec, m, verdict = evaluate(ans, p, tools.parsed[p["id"]], tools.schema)
            if not verdict:
                s_["stage"], s_["spec"], s_["metrics"] = "done", spec, {k: m[k] for k in ("valid_rate", "mapped_field_share")}
                print(f"ACCEPTED {p['id']}: valid_rate {m['valid_rate']}, mapped share {m['mapped_field_share']}")
            elif s_.get("repairs", 0) >= 2:
                s_["stage"] = "failed"; print(f"FAILED {p['id']} after 2 repairs: {verdict}")
            else:
                s_["repairs"] = s_.get("repairs", 0) + 1; s_["stage"] = "repair"
                s_["repair_prompt"] = repair_prompt(spec, m); print(f"REJECTED ({verdict}); call `next` for the repair prompt")
        save()

elif cmd == "apply":
    sch = Schema()
    out_store = os.path.join(work, "store")
    shutil.rmtree(out_store, ignore_errors=True)
    os.makedirs(out_store)
    shutil.copy(os.path.join(store, "parsers.json"), out_store)
    ms = MappingStore(out_store)
    os.makedirs(os.path.join(work, "repairs"), exist_ok=True)
    res = {"accepted": 0, "failed": 0, "missing": 0, "answer_tokens_est": 0, "failures": {}}
    state = json.load(open(os.path.join(work, "state.json"))) if os.path.exists(os.path.join(work, "state.json")) else {}
    for p in parsers:
        st_ = state.get(p["id"], {})
        if st_.get("stage") == "done":
            txt = json.dumps(st_["spec"])
        else:
            fn = os.path.join(work, "answers", f"{p['id']}.json")
            if not os.path.exists(fn):
                res["missing"] += 1
                continue
            txt = open(fn).read()
        res["answer_tokens_est"] += tokens(txt)
        try:
            spec, m, verdict = evaluate(parse_answer(txt), p, tools.parsed[p["id"]], sch)
        except Exception as e:  # noqa: BLE001
            spec, m, verdict = {}, {"valid_rate": 0, "errors": [[str(e)[:200], 1]], "error_examples": []}, f"bad answer: {e}"
        if verdict:
            res["failed"] += 1
            res["failures"][p["id"]] = verdict[:200]
            with open(os.path.join(work, "repairs", f"{p['id']}.txt"), "w") as f:
                f.write(repair_prompt(spec, m))
            continue
        spec.update(id=ms.next_id("m"), status="active", origin="rag-oneshot",
                    metrics={k: m[k] for k in ("events", "valid_rate", "mapped_field_share")})
        ms.items.append(spec)
        res["accepted"] += 1
        if os.path.exists(os.path.join(work, "repairs", f"{p['id']}.txt")):
            os.remove(os.path.join(work, "repairs", f"{p['id']}.txt"))
    ms.save()
    calls = sum(v.get("calls", 0) for v in state.values())
    res["llm_calls"] = calls
    res["prompt_tokens_est"] = sum(v.get("prompt_tokens", 0) for v in state.values())
    res["answer_tokens_est"] = sum(v.get("answer_tokens", 0) for v in state.values()) or res["answer_tokens_est"]
    print(json.dumps({k: v for k, v in res.items() if k != "failures"}))
    for k, v in list(res["failures"].items())[:10]:
        print("  FAIL", k, v)
