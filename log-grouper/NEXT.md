# NEXT: what is left, in order (for Claude Code on a new machine)

Read `JOURNEY.md` first. Work on branch `claude/adoring-planck-wczlod`; commit and push after each step;
record every measurement in `bench/RESULTS.md`. Generated data goes to `W=$HOME/lgwork` (not in git).

## Already decided / done (do not redo)
- Grouping (rules + learner agent), parsing (81 parsers, Logstash-identical), OCSF mapping are built and
  benchmarked. Final numbers: parse 95.7%, OCSF 95.5% (98% valid), precision 89.1%, recall 72.6%.
- OCSF mapper decision: **M1** (whole compact OCSF schema as a cached system prompt, one call per format +
  validator repairs) is the default — `cli map-learn --method full`. It beat RAG, class-first and the
  tool-using agent at equal accuracy. The tool-using mapping agent is the fallback (`--fallback-agent`).
  RAG experiments are finished; ignore the RAG steps from earlier versions of this file.
- All AI steps so far ran through Claude Code sub-agents standing in for the API. **Nothing has run on the
  live Claude API yet** — that is step 1.

---

## Step 0 — environment

```bash
cd AI-Playground/log-grouper
python3 -m venv .venv && source .venv/bin/activate
pip install anthropic torch "sentence-transformers[image]" kafka-python
W=$HOME/lgwork; mkdir -p $W
curl -L -o $W/ls.tgz https://artifacts.elastic.co/downloads/logstash/logstash-8.19.3-linux-x86_64.tar.gz
tar xzf $W/ls.tgz -C $W && export LOGSTASH_HOME=$W/logstash-8.19.3
python3 -m unittest discover -s tests            # expect OK, incl. the real-Logstash conformance tests
```

Rebuild the benchmark (needed by steps 1, 4):
```bash
cd $W && git clone -q --depth 1 --filter=blob:none --no-checkout https://github.com/elastic/integrations.git ei
cd ei && git sparse-checkout init --no-cone
for p in panw fortinet_fortigate cisco_asa checkpoint juniper_srx sonicwall_firewall pfsense sophos \
         watchguard_firebox zscaler_zia suricata cisco_ios iptables cisco_meraki; do
  echo "/packages/$p/data_stream/*/_dev/test/pipeline/test-*"; done > .git/info/sparse-checkout
git checkout -q HEAD; cd - >/dev/null
python3 -I bench/build_parse_bench.py $W/ei/packages rules $W/pbench \
  panw,fortinet_fortigate,cisco_asa,checkpoint,juniper_srx,sonicwall_firewall,pfsense,sophos,watchguard_firebox,zscaler_zia,suricata,cisco_ios,iptables,cisco_meraki
mkdir -p $W/store && cp parsers/*.json $W/store/
python3 -I bench/score_ocsf.py $W/pbench/test.jsonl $W/store     # expect ~ precision 0.891, recall 0.726
```

## Step 1 — LIVE CLAUDE API RUN (most important)

Needs `ANTHROPIC_API_KEY` (or `ant auth login`). Runs the real production code paths on a COPY of the stores
(`$W/live/store`); never modifies the repo's stores. Start small, then widen:

```bash
export ANTHROPIC_API_KEY=...            # or: ant auth login
# 1a. OCSF mapper (M1) on 5 formats: real calls, real prompt caching, real token usage + $ per format
python3 bench/live_api_check.py $W/live $W/pbench/train/groups --steps mapper --formats 5
# 1b. widen to all formats, then score those live mappings on the held-out benchmark
python3 bench/live_api_check.py $W/live $W/pbench/train/groups --steps mapper --formats 100
python3 -I bench/score_ocsf.py $W/pbench/test.jsonl $W/live/store
# 1c. independent reviewer session (tool-using) over the mappings
python3 bench/live_api_check.py $W/live $W/pbench/train/groups --steps review
# 1d. parser agent from scratch on one vendor (its parsers retired in the copy), real Logstash check
python3 bench/live_api_check.py $W/live $W/pbench/train/groups --steps parser --label sonicwall_firewall --logstash-home $LOGSTASH_HOME
# 1e. grouping learner on a residue (run `cli run` on a stream into $W/grp first, see JOURNEY.md)
python3 bench/live_api_check.py $W/live $W/pbench/train/groups --steps grouper --grouping-state $W/grp
```
Check and record in `bench/RESULTS.md`:
- `$W/live/live_report.json`: calls, tokens (input / cache read / cache write / output), seconds and $ per
  step and per format. Confirm `cache_read_input_tokens` is large on the 2nd+ mapper call (schema cached);
  if it stays 0, prompt caching is not working — fix before scaling.
- Compare live accuracy with the sub-agent results (precision/recall/validity) and live cost with `COSTS.md`;
  update `bench/cost_model.py` with the measured numbers and regenerate `COSTS.md`.
- Watch for refusals (`stop_reason == "refusal"`): security log content can trigger safety classifiers; the
  code sends `fallbacks: "default"`. Note any that happen.

## Step 2 — Kafka end to end
Local broker (Kafka 3.9 KRaft, single node). Produce a mixed stream into topic `security-logs`; run
`cli --review-new-labels run --kafka localhost:9092 --topic security-logs --batch-size 20000 --learner agent`;
export the bundle (`cli --parsers parsers export $W/bundle`) and run Logstash with a Kafka input per label (or
one input + the `[loggrouper][label]` field) and the dead-letter output from
`loggrouper-output.conf.example`; feed the dead letter to `cli parse-learn --failures ...`.

## Step 3 — supervisor service (the generic "any stream" system)
One long-running Python process (`loggrouper/supervisor.py`, new) that loops: consume batch → group (fast
path) → if residue ≥ threshold run the grouping learner → if parse failures ≥ threshold run the parser agent
→ for new parsers run M1 mapping (+ optional reviewer) → re-export the Logstash bundle and reload Logstash
(pipeline reload) → record spend and counts. Fixed code orchestrates; LLM output is applied only through the
validators. Add a small status report (new vendors, failure rates, spend per day).

## Step 4 — Logstash throughput
Exported bundle (81 parsers + 78 mappings) with `LS_JAVA_OPTS=-Xmx2g`: measure events/s per worker on the
benchmark lines replayed at volume; tune workers/batch size.

## Step 5 — remaining gaps
- 5 formats with no event time: decide ingest-time fallback (`time` from Logstash @timestamp, flagged) vs.
  leaving them unmapped.
- Timezone abbreviations (IST, CEST, EDT) in parsers -> offsets.
- XML and CEF formats (add `xml` / CEF handling to the parser executor + compiler + conformance).
- 4 Python/Logstash differences on unseen lines (kv/grok edge cases; see `bench/RESULTS.md`).

## Step 6 — operations
Review gates on by default for new vendors/parsers; Docker sandbox for code tools in production; packaging
(container with Logstash + the supervisor); README operating guide.

### Rules to keep
- Elastic's expected output is for scoring only — never put it in prompts or agent context.
- Engine changes must keep `LOGSTASH_HOME=... python3 -m unittest discover -s tests` green.
- Agents never get unrestricted shell/git/network: LLM-written code runs only in the sandbox; deployment
  is done by fixed code.
