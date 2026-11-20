# NEXT: continue on a new machine (Linux)

Instructions for Claude Code. Read `JOURNEY.md` first (what exists and why), then do the steps below in
order. Work on branch `claude/adoring-planck-wczlod`; commit and push after each step that changes code or
results. Record every measurement in `bench/RESULTS.md`.

Paths below assume the repo root is `AI-Playground/` and you work in `AI-Playground/log-grouper`.
Use `W=$HOME/lgwork` for all generated data (it is not in git).

---

## Step 0 — environment (one time)

```bash
cd AI-Playground/log-grouper
python3 -m venv .venv && source .venv/bin/activate          # Python 3.11+ (developed on 3.13)
pip install anthropic "sentence-transformers[image]" torch   # CUDA torch if there is an NVIDIA GPU
huggingface-cli login                                        # only needed for gated models
W=$HOME/lgwork; mkdir -p $W
curl -L -o $W/ls.tgz https://artifacts.elastic.co/downloads/logstash/logstash-8.19.3-linux-x86_64.tar.gz
tar xzf $W/ls.tgz -C $W && export LOGSTASH_HOME=$W/logstash-8.19.3
python3 -m unittest discover -s tests          # expect: OK (27 tests incl. 2 real-Logstash conformance tests)
unshare -rn true && echo "unshare sandbox OK"  # else use --code-tools docker (see JOURNEY.md)
python3 -c "import torch;print('cuda', torch.cuda.is_available())"
```
Done when: all tests pass.

## Step 1 — rebuild the benchmark and reproduce the baseline

```bash
cd $W && git clone -q --depth 1 --filter=blob:none --no-checkout https://github.com/elastic/integrations.git ei
cd ei && git sparse-checkout init --no-cone
for p in panw fortinet_fortigate cisco_asa checkpoint juniper_srx sonicwall_firewall pfsense sophos \
         watchguard_firebox zscaler_zia suricata cisco_ios iptables cisco_meraki; do
  echo "/packages/$p/data_stream/*/_dev/test/pipeline/test-*"; done > .git/info/sparse-checkout
git checkout -q HEAD
cd - >/dev/null   # back to log-grouper
python3 -I bench/build_parse_bench.py $W/ei/packages rules $W/pbench \
  panw,fortinet_fortigate,cisco_asa,checkpoint,juniper_srx,sonicwall_firewall,pfsense,sophos,watchguard_firebox,zscaler_zia,suricata,cisco_ios,iptables,cisco_meraki
mkdir -p $W/store && cp parsers/parsers.json parsers/mappings.json $W/store/
python3 -I bench/score_ocsf.py $W/pbench/test.jsonl $W/store
python3 -I bench/e2e_logstash.py $W/pbench/test.jsonl $W/store $LOGSTASH_HOME
```
Done when: numbers match `bench/RESULTS.md` (about parse 0.957, mapped 0.955, valid 0.985,
precision 0.885, recall 0.722) and the Logstash run reports `identical_to_python` for all lines.
If the Elastic test data changed upstream, numbers may differ slightly: note it and continue.

## Step 2 — RAG mapper with EmbeddingGemma 2 (retrieval only, no LLM)

```bash
export LG_EMBED_CACHE=$W/embcache
python3 bench/rag_bench.py prep $W/store $W/pbench/train/groups $W/rag_gemma2 google/embeddinggemma-2
python3 -I bench/rag_class_eval.py $W/store $W/rag_gemma2
python3 bench/rag_bench.py prep $W/store $W/pbench/train/groups $W/rag_bge BAAI/bge-small-en-v1.5
python3 -I bench/rag_class_eval.py $W/store $W/rag_bge
```
Record: index build time (first run), retrieval seconds per format, prompt size, device (cuda/mps/cpu),
and class top-1/top-3 agreement for both embedders.

Also add an **attribute-retrieval check** (new script `bench/rag_attr_eval.py`, no LLM): for each existing
agent mapping in `parsers/mappings.json`, take each `from` vendor field and its `to` OCSF path, and measure
how often that path is in the field's top-5 retrieved candidates (restricted to the mapping's class). This
is the retrieval quality that matters most. Compare both embedders.

## Step 3 — fix RAG recall (main open problem)

Partial result so far (47 formats, bge-small): RAG ≈ 9k tokens and 2.3 calls per format with precision
85% and validity 99%, but **recall 42%** vs 69% for the mapping agent (the single call leaves many fields
unmapped). Improve `loggrouper/ocsf/rag.py`:

1. **Coverage pass**: after a mapping validates, list the vendor fields still in `unmapped` that have a
   good retrieved candidate (score above a threshold) and ask one more call to add mappings for them
   (return the full updated spec). Accept only if validation still passes and mapped share increases.
2. **Prompt**: tell the model explicitly to map every vendor field that has a fitting candidate; show
   per-field candidates for *all* fields (they are), and the typical OCSF homes for MACs, byte/packet
   counts, URLs, DNS query, HTTP method/status, rule/policy names, users.
3. **Retrieval**: use whichever embedder wins step 2; consider adding attribute docs that include the
   vendor-agnostic synonyms (e.g. "src", "source", "client", "sip") to the OCSF attribute text.
4. Wire the coverage pass into `map_with_claude` and into the `next/answer` protocol in `bench/rag_bench.py`.

## Step 4 — measure RAG vs agent on all 81 formats

Either with a Claude API key (`ANTHROPIC_API_KEY`): call `loggrouper.ocsf.rag.map_with_claude` per parser
(write a small `bench/rag_run_api.py` that loops over parsers, records calls/tokens from the API usage,
writes the accepted specs to `$W/rag_api/store/mappings.json`), or without a key: drive
`bench/rag_bench.py next/answer` with sub-agents that may only answer from the prompt (see JOURNEY.md).
Then:
```bash
python3 bench/rag_bench.py apply $W/store $W/pbench/train/groups $W/rag_run     # (protocol route)
python3 -I bench/score_ocsf.py $W/pbench/test.jsonl $W/rag_run/store
python3 -I bench/e2e_logstash.py $W/pbench/test.jsonl $W/rag_run/store $LOGSTASH_HOME
```
Report side by side with the agent mappings: calls, tokens, validity, precision, recall, timestamp match,
failures. Optionally run the reviewer (`cli mtool --reviewer`) on the RAG mappings.

**Decision rule**: if RAG recall is within ~5 points of the agent and precision/validity are equal or
better, make RAG the default mapper (`cli map-learn --rag`), keeping the mapping agent for formats where
RAG fails validation after repairs.

## Step 5 — finish the open review issues

31 of the 41 reviewer "changes_requested" items were not addressed when the fix round was stopped
(see `review` fields in `parsers/mappings.json`). Fix them with the chosen mapper (RAG repair prompt seeded
with the review issues, or the mapping agent), re-score, commit.

## Step 6 — production readiness

1. Live Claude API run of each agent once (grouping learner, parser agent, RAG mapper) on a copy of the
   stores; record real token usage from the API.
2. Kafka end to end: local broker (KRaft), `cli run --kafka ...`, exported Logstash bundle consuming
   per-label topics, dead-letter topic for parse failures -> `cli parse-learn --failures`.
3. Logstash throughput test with the exported bundle (events/s per core).
4. Gaps: timezone abbreviations (IST/CEST) in parsers, XML/CEF formats, Docker sandbox backend tested.
5. Update `README.md` with the final architecture and operating guide.

---

### Facts to keep in mind
- Never put Elastic's expected output into prompts or agent context: it is only for scoring.
- Known benchmark artefacts: Elastic test configs set device timezones not present in log lines, and
  year-less syslog dates — reported separately as `timestamp_match_allowing_tz_year_artefacts`.
- Every engine change that touches parsing/mapping semantics must keep the real-Logstash conformance tests
  green (`LOGSTASH_HOME=... python3 -m unittest discover -s tests`).
- Stores: `rules/` (grouping), `parsers/parsers.json` (81 parsers), `parsers/mappings.json` (OCSF).
