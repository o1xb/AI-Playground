# Status (parked)

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
