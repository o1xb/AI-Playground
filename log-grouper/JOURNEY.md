# log-grouper: what we built, why, and where it stands

> Continuing on a new machine? Read this file, then follow **`NEXT.md`** step by step.

A generic system that takes a **mixed security log stream** (file or Kafka), works out which
vendor/product/format each message came from, **parses** it into fields, and **maps** those fields to
**OCSF 1.4**, with AI writing the rules once and compiled rules (Logstash) doing the per-event work.

```
mixed stream ──► 1. GROUP ──► 2. PARSE ──► 3. MAP TO OCSF ──► OCSF events
 (Kafka/file)    vendor +     vendor       vendor fields ->
                 format       fields       OCSF attributes
```

Per event: **no LLM, no tokens.** Grouping = saved regex rules; parsing = compiled Logstash filters;
mapping = a compiled Ruby step in the same Logstash pipeline (`cli export` writes the bundle).
AI only runs for what is new: unclassified lines, parse failures, unmapped formats.

---

## 1. How we got here (chronological)

| Step | What happened | Outcome |
|---|---|---|
| Experiment 1 | Downloaded public vendor sample logs (Elastic integration test data, Loghub), mixed them, asked a sub-agent to group them blind | 591 lines / 11 sources: 99.3% correct |
| Experiment 2 | Harder stream: 67 vendors, syslog relays, Filebeat JSON envelopes, truncation | 3,525 lines: ~99% correct after answer-key quirks; agent used bash + Python + regex |
| Grouping system | Turned the agent's approach into a **rule store** + fast path + residue clustering + **learner agent** + **validator** | Rules reused across batches; LLM only for the residue |
| Fixes | Multiline framing, API envelopes, syslog-header views, literal prefilter (3.2x faster), regression checks, conflict + suspect detection, confirmed vs observed examples | Fresh streams: 99%+ fast path, 95–99% accurate |
| Production agent | Tool-using learner on the Claude API (SDK tool runner), regex sandbox, review gate, tool bridge for testing | 12 unseen vendors: 6% -> 100% correct |
| Code tools | Sandboxed `run_python` / `run_bash` (Linux namespaces / Docker) | Same accuracy in 1 session instead of 2, ~220k vs ~330k tokens |
| Parsing stage | Declarative parser specs, Python executor that mirrors Logstash, compiler to Logstash, **real Logstash 8.19.3 conformance** | 663/663 identical; 66 agent-written parsers for 15 vendors |
| Benchmark | Elastic test lines with Elastic's own expected output (ECS), split 50/50 train / held-out | Objective field-level scoring |
| Fallback parsers | One catch-all envelope parser per vendor for unseen message types | Held-out parse 93.1% -> 95.7% |
| OCSF stage | OCSF 1.4 resolver/validator, mapping engine in Python **and** Ruby (identical in Logstash), mapping agent, **independent AI reviewer** | 65 mappings; reviewer flagged 41 with real semantic issues |
| Fix round | Mapping/parser fixes from review (partially completed when stopped) | precision 88.5%, recall 72.2% |
| RAG mapper | User's idea: replace the mapping agent's ~50 tool calls with retrieval over the OCSF schema + one or two structured LLM calls per format + validator repair | Built; evaluation in progress (see section 5) |

Key lessons recorded along the way:
- Every "the AI is wrong" investigation also found **engine bugs** (Logstash escape handling, kv/csv/date
  semantics, an OCSF `at_least_one` bug that blocked 4 classes, duplicate ids). The conformance checks
  against real Logstash were essential.
- Benchmark artefacts must be separated from real errors (e.g. timestamps: Elastic test configs set a
  device timezone not present in the log line; year-less syslog dates).
- Pure embedding retrieval is **poor at choosing the OCSF class** (agent's class in top-3 only 26% with
  bge-small); the LLM chooses the class better. Retrieval is used for attribute candidates and enums.

---

## 2. Components (code map)

| Path | What |
|---|---|
| `loggrouper/unwrap.py` | Peel transport envelopes; header-stripped and outer-layer fallback views |
| `loggrouper/rules.py` | Rule store (rules, confirmed/observed examples, rejected, unidentifiable, dismissed suspects), literal prefilter |
| `loggrouper/engine.py` | Batch engine, residue, packets, conflicts, suspects (stable content-hashed ids) |
| `loggrouper/learn.py` | Validator for rule proposals (collision, over-match, regression, speed) |
| `loggrouper/agent.py` | Grouping learner agent tools |
| `loggrouper/agent_runtime.py` | Shared Claude API tool-runner loop + sandboxed code tools |
| `loggrouper/code_sandbox.py`, `regex_sandbox.py` | Sandboxes (unshare/docker; regex timeouts) |
| `loggrouper/parse/executor.py` | Parser spec executor (grok with Logstash's own pattern library, dissect, kv, csv, json, date, mutate) |
| `loggrouper/parse/compiler.py` | Parser specs (+ OCSF mappings) -> Logstash filter config |
| `loggrouper/parse/logstash.py` | Conformance runs in real Logstash |
| `loggrouper/parse/validate.py`, `store.py`, `agent.py` | Parser validator, stores, parser agent (logstash_check, retire, fallback, failure loop, review gate) |
| `loggrouper/ocsf/schema.py` (+ `schema-1.4.0.json`) | Resolved OCSF 1.4 schema, search, validator |
| `loggrouper/ocsf/mapping.py`, `ocsf_mapper.rb` | Mapping engine (Python + Ruby; array paths, skip_values) |
| `loggrouper/ocsf/validate.py`, `agent.py` | Mapping validator, mapping agent, reviewer agent |
| `loggrouper/ocsf/rag.py` | RAG mapper (field profiles, schema index, class-choice + mapping prompts, repair, Claude API driver) |
| `loggrouper/cli.py` | `run`, `learn`, `tool`, `ptool`, `parse-learn`, `preview`, `mtool`, `map-learn`, `export`, ... |
| `rules/` | Learned grouping rules |
| `parsers/parsers.json`, `parsers/mappings.json` | Learned parsers (81) and OCSF mappings |
| `prompts/` | System prompts for all agents |
| `bench/` | Benchmarks, scorers, merge/repin tools, RAG bench (`RESULTS.md` has all numbers) |
| `tests/` | 27 tests incl. real-Logstash conformance (`LOGSTASH_HOME=...`) |

---

## 3. Results (held-out lines the agents never saw; details in `bench/RESULTS.md`)

| | Result |
|---|---|
| Grouping, fresh streams | 99%+ routed by saved rules, 95–99% correct |
| Parsing (15 vendors, 1,294 held-out lines) | **95.7%** parsed (quick manual baseline 26%) |
| Mapped to OCSF | **95.5%** of lines, **98.5%** schema-valid |
| Field accuracy vs Elastic's own extraction | precision **88.5%**, recall **72.2%** |
| Timestamps | 88% allowing for benchmark tz/year artefacts (53% strict) |
| Python vs real Logstash | identical everywhere checked (parsers 663/663, full pipeline 1294/1294) |

## 4. Cost

- Steady state: **zero tokens** for known formats.
- Development so far: ~4.7M sub-agent tokens in total (grouping ~1.2M, parsing ~1.4M, mapping ~1.4M,
  review ~0.3M, fixes ~0.4M) — roughly $20–35 at Claude API rates; ran inside Claude Code here.
- Onboarding a new vendor with the current agents: ~280k tokens (~$1.5–2); mapping is the largest share,
  which the RAG mapper targets.

## 5a. OCSF mapping decision (final)

Compared on the same benchmark: tool-using mapping agent, RAG one-shot, M1 (whole compact OCSF schema in a
cached system prompt, one call + validator repairs), M2 (class first + class slice), M3 (M2 + coverage call),
and a Bash+Python agent with the schema as files. **M1 won**: on all 81 formats it matches or beats the agent
(precision 89.1%, recall 72.6%, timestamps 91.5%) with 1.3 calls per format, in seconds. It is now the
default (`cli map-learn --method full`); the tool-using agent is the fallback. Costs: `COSTS.md`.

## 5. RAG mapper: first measurement (partial, 47 formats)

~2.3x cheaper than the mapping agent (~9k tokens and 2.3 calls per format) with similar precision (85% vs
87%) and validity (99%), but much lower recall (42% vs 69%): one-shot mappings leave many fields unmapped.
Planned fix: a coverage call on the leftover fields, plus EmbeddingGemma 2 retrieval. Details in
`bench/RESULTS.md`.

## 5b. Stopped when moving to another machine

- **RAG mapper run**: three stand-in "LLMs" (sub-agents restricted to answer only from the prompt; one
  answer = one LLM call) were mapping all 81 formats via `bench/rag_bench.py next/answer`, state in the
  scratchpad (`rag_run0..2/state.json`) — not in git. Re-run on your machine (section 6).
- **EmbeddingGemma 2** (`google/embeddinggemma-2`, 744M, ungated): index build over 11.8k OCSF attribute
  paths was running on a 4-core CPU (>10 min). `google/embeddinggemma-300m` is gated (accept the license
  on Hugging Face). The small `BAAI/bge-small-en-v1.5` indexes in ~97 s and retrieves in ~0.8 s/format.

## 6. Continue on a Mac (M4 Pro)

```bash
git clone <repo> && cd AI-Playground && git checkout claude/adoring-planck-wczlod
cd log-grouper
python3 -m venv .venv && source .venv/bin/activate        # Python 3.11+ (developed on 3.13)
pip install anthropic "sentence-transformers[image]" torch
huggingface-cli login                                        # HF token (needed for gated models only)
# Logstash for conformance checks (Apple Silicon build):
curl -O https://artifacts.elastic.co/downloads/logstash/logstash-8.19.3-darwin-aarch64.tar.gz && tar xzf logstash-8.19.3-darwin-aarch64.tar.gz
export LOGSTASH_HOME=$PWD/logstash-8.19.3
python3 -m unittest discover -s tests                        # all tests incl. Logstash conformance
```
- Embeddings run on the Apple GPU automatically (`mps`); override with `LG_EMBED_DEVICE=cpu|mps|cuda`,
  model with `LG_EMBED_MODEL=google/embeddinggemma-2`.
- The code-tools sandbox `unshare` is Linux-only: on macOS use `--code-tools docker` (Docker Desktop) or
  leave code tools off.
- Rebuild the benchmark data with the commands in `STATUS.md` (Elastic integrations sparse checkout),
  then:
  ```bash
  python3 bench/rag_bench.py prep  parsers <train>/groups /tmp/rag google/embeddinggemma-2
  python3 bench/rag_class_eval.py  parsers /tmp/rag      # retrieval quality, no LLM
  # with an API key: loggrouper.ocsf.rag.map_with_claude(...) per parser, or drive next/answer by hand
  python3 bench/rag_bench.py apply parsers <train>/groups /tmp/rag
  python3 bench/score_ocsf.py      <bench>/test.jsonl /tmp/rag/store
  ```

### Or on Linux (recommended: everything native, incl. the unshare sandbox)

```bash
git clone <repo> && cd AI-Playground && git checkout claude/adoring-planck-wczlod && cd log-grouper
python3 -m venv .venv && source .venv/bin/activate
pip install anthropic "sentence-transformers[image]" torch     # CUDA build if you have an NVIDIA GPU
huggingface-cli login
curl -O https://artifacts.elastic.co/downloads/logstash/logstash-8.19.3-linux-x86_64.tar.gz   # or -linux-aarch64
tar xzf logstash-8.19.3-linux-x86_64.tar.gz && export LOGSTASH_HOME=$PWD/logstash-8.19.3
python3 -m unittest discover -s tests
unshare -rn true && echo "unshare sandbox OK"
```
- Embeddings use CUDA automatically when available; CPU works but EmbeddingGemma 2 (744M) is slow there
  (index build >10 min on 4 cores; cached afterwards).
- `--code-tools unshare` needs unprivileged user namespaces. Ubuntu 23.10+ restricts them via AppArmor:
  `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`, or use `--code-tools docker`.

## 7. Next steps

1. Finish the RAG mapper evaluation (EmbeddingGemma 2 vs bge-small; accuracy, calls, tokens vs the
   mapping agent) and make it the default mapper if it holds up; keep the agent for hard cases.
2. Production: run the agents on the live Claude API once; wire Kafka end to end; Logstash throughput
   test; XML/CEF support; timezone abbreviations; Docker sandbox in production.
