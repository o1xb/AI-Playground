Measured: Sonnet 5.5 matches Opus 5.5 on the OCSF mapper (precision 89.5% vs 89.6%, recall 72.6% vs 73.9%, same class on 19/20 formats) and on the parser agent (SonicWall from scratch: 121/121 held-out lines parsed, Logstash-identical). See bench/RESULTS.md.

# Cost model: claude-opus-5-5

Prices per 1M tokens: input $4.0, output $20.0, cache_read $0.2, cache_write_1h $8.0.
Token figures are measured in this repo's benchmark runs (bench/RESULTS.md); agent sessions are split
into cache reads / fresh input / output with an assumed mix (85/10/5 with prompt caching, 0/95/5 without).

## One-time cost to onboard one vendor (avg 5.4 log formats per vendor)

| Step | Tokens per vendor | Cost per vendor |
|---|---|---|
| Grouping rules (learner agent, code tools) | 18k | $0.03 – $0.09 |
| Parsers (parser agent, incl. fallback parser) | 63k | $0.10 – $0.30 |
| OCSF mapping, M1 (5.4 formats x 1.25 calls, schema cached) | 17k + cached schema | $0.23 – $0.73 |
| Optional AI review (one call per format) | 27k + cached schema | $0.26 |
| **Total** | | **$0.36 – $1.39** |

For comparison, mapping with the tool-using agent instead of M1: $0.18 – $0.54 per vendor.

## What a customer pays

- **Known vendors/formats: $0 in LLM cost.** Grouping, parsing and mapping run as compiled rules in Logstash.
- **New vendor:** $0.36 – $1.39 once (all its formats).
- **New message type of a known vendor (drift):** about $0.06 – $0.15 (one parser + one mapping).
- **Example:** a customer sending 10 vendors we have never seen: $4 – $14 once; a customer whose vendors are all known: $0.

Not included: compute for Logstash/Kafka (runs the compiled pipeline; scales with event volume, not with
LLM usage), the embedding model (not needed for M1), and engineering time for human review gates.

Levers: running the parser/learner agents on a cheaper model (e.g. Sonnet) for routine formats; batching
many formats inside one 1-hour cache window (the schema cache write is paid once per window); skipping the
optional review for vendors whose mappings validate cleanly.

# Cost model: claude-sonnet-5-5

Prices per 1M tokens: input $2.0, output $10.0, cache_read $0.1, cache_write_1h $4.0.
Token figures are measured in this repo's benchmark runs (bench/RESULTS.md); agent sessions are split
into cache reads / fresh input / output with an assumed mix (85/10/5 with prompt caching, 0/95/5 without).

## One-time cost to onboard one vendor (avg 5.4 log formats per vendor)

| Step | Tokens per vendor | Cost per vendor |
|---|---|---|
| Grouping rules (learner agent, code tools) | 18k | $0.01 – $0.04 |
| Parsers (parser agent, incl. fallback parser) | 63k | $0.05 – $0.15 |
| OCSF mapping, M1 (5.4 formats x 1.25 calls, schema cached) | 17k + cached schema | $0.11 – $0.37 |
| Optional AI review (one call per format) | 27k + cached schema | $0.13 |
| **Total** | | **$0.18 – $0.69** |

For comparison, mapping with the tool-using agent instead of M1: $0.09 – $0.27 per vendor.

## What a customer pays

- **Known vendors/formats: $0 in LLM cost.** Grouping, parsing and mapping run as compiled rules in Logstash.
- **New vendor:** $0.18 – $0.69 once (all its formats).
- **New message type of a known vendor (drift):** about $0.03 – $0.07 (one parser + one mapping).
- **Example:** a customer sending 10 vendors we have never seen: $2 – $7 once; a customer whose vendors are all known: $0.

Not included: compute for Logstash/Kafka (runs the compiled pipeline; scales with event volume, not with
LLM usage), the embedding model (not needed for M1), and engineering time for human review gates.

Levers: running the parser/learner agents on a cheaper model (e.g. Sonnet) for routine formats; batching
many formats inside one 1-hour cache window (the schema cache write is paid once per window); skipping the
optional review for vendors whose mappings validate cleanly.
