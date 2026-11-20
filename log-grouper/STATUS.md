# Status (parked) — see JOURNEY.md for the full story

## Done
- Grouping: rule store + learner agent (tools, sandboxed code tools, review gate). See bench/RESULTS.md.
- Parsing: spec executor = real Logstash (663/663 identical), validator, parser agent with
  logstash_check / retire / fallback parsers. 66 parsers for 15 vendors in `parsers/parsers.json`
  (100% of train samples, 93.1% of held-out lines parse before fallback parsers).
- OCSF: 1.4.0 schema resolver/validator, mapping engine in Python + Ruby (identical in Logstash),
  mapping agent + independent reviewer agent, `export` to a Logstash bundle, end-to-end benchmark
  (`bench/e2e_logstash.py`, Logstash output == Python output on 1294/1294 held-out lines).

## In flight when parked
- Fallback-parser agent (one fallback per label) and three OCSF mapping agents were running.
  `parsers/mappings_partial_*.json` are snapshots of their mapping stores at park time.

## Resume
1. Rebuild the benchmark: `bench/build_parse_bench.py` (Elastic integrations test data, 14 packages).
2. Merge mappings: `bench/merge_mappings.py <store> <mapping stores...>`.
3. Run the reviewer (`cli mtool --reviewer ...` or `map-learn`), then a mapping fix round.
4. Score: `bench/score_ocsf.py` and `bench/e2e_logstash.py`.
5. Production gaps: parse-failure (dead-letter) loop -> parser agent; parser review gate;
   xml/cef filters; timezone abbreviations; live Claude API run; Logstash throughput test.

## Rebuilding the scratch environment (not in git)
```bash
W=/tmp/lgwork; mkdir -p $W && cd $W
# Elastic integrations test data (sparse)
git clone -q --depth 1 --filter=blob:none --no-checkout https://github.com/elastic/integrations.git ei
cd ei && git sparse-checkout init --no-cone
for p in panw fortinet_fortigate cisco_asa checkpoint juniper_srx sonicwall_firewall pfsense sophos \
         watchguard_firebox zscaler_zia suricata cisco_ios iptables cisco_meraki; do
  echo "/packages/$p/data_stream/*/_dev/test/pipeline/test-*"; done > .git/info/sparse-checkout
git checkout -q HEAD && cd ..
# Logstash 8.19.3 (needs artifacts.elastic.co allowed; the "AI-Playground" cloud environment allows it)
curl -sO https://artifacts.elastic.co/downloads/logstash/logstash-8.19.3-linux-x86_64.tar.gz && tar xzf logstash-8.19.3-linux-x86_64.tar.gz
# OCSF schema source (only needed to rebuild loggrouper/ocsf/schema-1.4.0.json, which is committed)
git clone -q --depth 1 --branch v1.4.0 https://github.com/ocsf/ocsf-schema.git ocsf-src
# Benchmark (train/test split is deterministic)
cd /home/user/AI-Playground/log-grouper
python3 -I bench/build_parse_bench.py $W/ei/packages rules $W/pbench \
  panw,fortinet_fortigate,cisco_asa,checkpoint,juniper_srx,sonicwall_firewall,pfsense,sophos,watchguard_firebox,zscaler_zia,suricata,cisco_ios,iptables,cisco_meraki
# Store for the next steps: parsers/parsers.json is the merged parser store
mkdir -p $W/store && cp parsers/parsers.json $W/store/
python3 -I bench/score_ocsf.py $W/pbench/test.jsonl $W/store        # held-out parse rate (expect 0.931)
```
Agents are driven either via the Claude API (`cli parse-learn`, `cli map-learn`, needs ANTHROPIC_API_KEY)
or by a Claude Code sub-agent through the bridges (`cli ptool ...`, `cli mtool ...`, `--code-tools unshare`).
