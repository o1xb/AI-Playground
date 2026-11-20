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
