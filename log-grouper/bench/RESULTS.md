# Benchmark results (2026-11-20)

Data: Elastic `integrations` pipeline test logs (public samples), mixed and wrapped by `build_stream.py`.
Answer keys were never shown to any agent.

| Run | Data | LLM | Fast-path coverage | Accuracy of classified |
|---|---|---|---|---|
| 1 | 591 lines, 11 vendors, raw | sub-agent from scratch | 100% | 99.3% (4 Fortinet lines split as FortiManager) |
| 2 | 3,525 lines, 67 vendors, 58% wrapped, 4% truncated | sub-agent from scratch (~10 min, ~300k tokens) | 99.9% | 95.7% raw / ~99% after answer-key quirks |
| A | 7,303 unseen lines: 37 known vendors (held-out) + 13 new vendors | none (rules seeded from run 2) | 92.4% known / 4.6% new | 97.0% |
| A + learn | residue of A: 1,651 lines -> 120 clusters (200 KB) | sub-agent learner (~4 min, ~160k tokens) | 94.0% known / 85.2% new | 97.0% / 100% |
| B | 10,828 lines (runs 2 + A re-mixed), batches of 5,000 | none | 94.9% | 96% |

| C | 7,228 records, all 80 vendors, multiline records kept whole (new builder) | none, old code | 97.4% | 95.2% |
| C + learn | residue 186 lines + 5 conflicts | sub-agent learner (~6 min, ~170k tokens): 42 rules + 1 priority fix | 99.4% | — |
| D | 7,228 fresh records (different sample + wrappers) | none, rules after C | 99.2% (was 97.3% with the earlier rules) | 95.5% (≈98.5% excluding the answer-key quirks below) |
| E | 2,311 records: 30 known vendors + 12 vendors new to the store | none | 98.4% known / 5.9% new | 99.8% / 0% (21 new-vendor lines swallowed by broad rules) |
| E + agent round 1 | residue 369 lines | production tools via shell bridge (~9 min, ~190k tokens): 35 rules, 9 new labels | 99.4% new | 94.1% new |
| E + agent round 2 | 15 suspects | same (~4 min, ~140k tokens): 3 fixes placed above greedy rules, 12 dismissed | — | — |
| F | fresh re-run of E's stream, rules after round 2 | none | 98.7% known / 99.4% new | 99.8% / **100%** |
| F' | fresh re-run of run D's stream (regression check) | none | 99.2% | 95.7% (was 95.5%) |
| G | same start as E (369 residue lines, 15 suspects), agent WITH sandboxed run_python/run_bash | 1 session (~15 min, ~220k tokens, 41 bridge calls of which 20 run_python): 44 rules, 0 rejected, all suspects settled | 98.8% known / 99.2% new | 99.8% / **100%** |
| G' | fresh re-run of run D's stream with G's rules (regression check) | none | 99.2% | 95.7% |

E vs G: same end accuracy; with code tools the agent did in one session what took two without
(~220k vs ~330k tokens), found the Vectra/CrowdStrike and Jamf/eslogger cases by scripting over
whole lines, and batch-tested all candidate regexes against residue, stored examples, per-label
samples and the stream sample before proposing (0 rejections).

Rounds E were driven by a Claude Code sub-agent playing the production agent, restricted to the
same `LearnerTools` methods the Claude API agent calls (via `cli tool`), with no file access.

Known answer-key quirks: Elastic's `cisco_ftd` samples contain literal `%ASA-` lines; the `system` samples are
mostly macOS; FireEye samples are Suricata EVE inside `rawmsg`; pfSense samples include haproxy/squid/snort lines.

Fixed since the first runs:
- Multi-line records are framed with `first_line_pattern` (file source and bench builder); residue fell from 5.1% to 2.6% before learning.
- API page envelopes are unwrapped; outer layers stay available as fallback match views.
- Syslog PRI/timestamp/host is stripped as a fallback view for `^`-anchored rules.
- Literal prefilter per rule: ~6,500 lines/s single core (was ~2,000), identical routing.
- Conflict audit (one message shape in two groups) feeds the learner, which can move, disable or tighten rules.
- Every change is regression-checked against stored examples; examples are split into confirmed
  (learner-attributed) and observed (seen at match time), so a line mis-stored by an over-reaching rule
  no longer blocks a correct new rule.

Still open:
- Cisco IOS vs NX-OS vs WLC splits (~38 lines in run D).
- Broad vendor-name alternatives still exist (r00006 `crowdstrike`, r00110 `Symantec`, r00044
  `Check Point`); specific rules now sit above them for the cases found, but they should be narrowed.
- r00022 (modsecurity `"transaction":{`) appears to hold a Google Cloud Spanner audit line as an
  observed example: review.
- Ivanti rule r00043 (`PCS\d`, case-insensitive) matches random IDs; flagged as a dispute, not yet tightened.
- Fortinet FortiAnalyzer lines go to FortiGate via the broad `devname=` rule.

## Parsing + OCSF (held-out half of Elastic test lines, 14 packages, 1294 lines)

Scored by `bench/score_ocsf.py`: for each held-out line, our parser + OCSF mapping vs the fields
Elastic's own pipeline extracted (ECS), matched to the corresponding OCSF attributes.

| Stage | Parse | Mapped to OCSF | OCSF schema-valid | Field recall | Field precision |
|---|---|---|---|---|---|
| Hand-written quick parsers + mappings (baseline) | 26% | 9% | 30% | 64% (of 9%) | 95% |
| Agent parsers (66) | 93.1% | - | - | - | - |
| + agent fallback parsers (81) | 95.7% | - | - | - | - |
| + agent OCSF mappings, round 1 (55 mappings) | 95.7% | 82.6% | 99.3% | 73.4% | 86.9% |

## RAG mapper vs mapping agent (partial run, 47 of 81 formats, bge-small embedder)

Same parsers, same held-out lines (752 lines of those 47 formats). RAG = class-choice call + one
retrieval-backed mapping call + validator repairs; "LLM" played by sub-agents allowed to answer only from
the prompt (one answer = one call). State: `bench/rag_partial/state_bge_small.json`.

| | RAG one-shot | Mapping agent |
|---|---|---|
| LLM calls per format | 2.26 (class + mapping + ~0.3 repairs) | ~10-15 tool turns |
| Tokens per format (prompt + answer) | ~8.6k + ~0.6k ≈ **9k** | ~21k (agent session totals / formats) |
| OCSF schema-valid | 98.7% | 99.0% |
| Field precision | 85.4% | 86.5% |
| Field recall | **42.3%** | 68.7% |
| 6 formats failed after 2 repairs | yes | - |

Read: about 2.3x cheaper with similar precision and validity, but it maps far fewer fields (recall).
Next: a coverage pass (show the fields left unmapped with their retrieved candidates, ask for additions)
and EmbeddingGemma 2 for retrieval, then re-measure.

## OCSF mapping without retrieval (20 busiest formats, 13 vendors, 1,074 held-out lines)

LLM played by sub-agents allowed to answer only from the prompt (one answer = one call). States in
`bench/llm_mapper_runs/`. Same parsers for all; scored by `bench/score_subset.py`.

| Method | Calls/format | Prompt tokens/format | Valid | Precision | Recall | ts~ |
|---|---|---|---|---|---|---|
| Mapping agent (tools) | ~10–15 turns | ~21k | 99.7% | 89.0% | 73.6% | 0.87 |
| **M1 full schema, cached system prompt** | **1.25** | **~2.3k + 63k cached** | 99.5% | 89.6% | **73.9%** | 0.92 |
| M2 class call + class slice | 2.35 | ~14k | 99.3% | 89.7% | 63.3% | 0.92 |
| M3 = M2 + coverage call | 3.25 | ~15k | 99.4% | 90.2% | 66.6% | 0.92 |
| RAG one-shot (bge-small; 47 formats, earlier run) | 2.26 | ~9k | 98.7% | 85.4% | 42.3% | — |

Single format (SonicWall sonicos_kv, 121 held-out lines): mapping agent 89.2/81.5, M1 89.2/81.5 (1 call,
~2.3k tokens + cached schema), Bash+Python agent with the schema as files 89.2/81.1 (10 tool calls, ~91k
tokens, ~2 min; maps more fields than the benchmark measures).

Conclusion: M1 (whole compact schema as a cached system prompt, one call + validator repairs) matches the
tool-using agent's accuracy with ~1/10 of its calls, in seconds instead of minutes. In dollars the two are
similar once prompt caching is priced in (~$0.04 vs ~$0.03 per format, see COSTS.md); the earlier "1/4 of
the cost" compared raw token counts and overstated the saving. Choosing the class first (M2/M3) loses recall
on mixed formats. Retrieval (RAG) was the weakest. Keep a tool-using agent only as the fallback.

## Final: M1 on all 81 formats (production stores in `parsers/`)

M1 mapped 76 of 81 formats (1.3 calls/format, ~1.6k prompt + ~0.8k answer tokens + 63k cached schema);
the 5 failures are formats whose logs carry no event time (Cisco IOS uptime/no-timestamp, a malformed Check
Point timestamp, two fallbacks) — the mapper refuses to invent `time`. Production store = M1 mappings +
the agent's mapping for 2 of those (fallback).

| Full held-out benchmark (1,294 lines, 15 vendors) | Mapping agent | **M1 + fallback (production)** |
|---|---|---|
| Parsed | 95.7% | 95.7% |
| Mapped to OCSF | 95.5% | 95.5% |
| OCSF schema-valid | 98.5% | 98.0% |
| Field precision | 88.5% | **89.1%** |
| Field recall | 72.2% | **72.6%** |
| Timestamps (allowing for tz/year artefacts) | 87.8% | **91.5%** |
| Real Logstash vs Python, held-out lines | 1294/1294 | 1290/1294 (4 kv/grok edge cases on unseen lines) |

Engine changes in this round: target-type inference in `prepare()` (casts follow the OCSF attribute type),
Ruby CSV strictness mirrored in the executor, ISO-only timestamp casting in the Ruby mapper, Logstash heap
configurable (`LG_LS_HEAP`, default 2g; the full 81-parser + 78-mapping pipeline needs more than 768m).
