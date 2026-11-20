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
- Symantec: the old rule r00110 (bare `Symantec`) still catches ~15 cloud SES events; the learner's
  conflict fix moved the SES rule above it, but that rule doesn't match every SES event type. Needs a
  pattern-tightening update in the next learning round.
- Ivanti rule r00043 (`PCS\d`, case-insensitive) matches random IDs; flagged as a dispute, not yet tightened.
- Fortinet FortiAnalyzer lines go to FortiGate via the broad `devname=` rule.
