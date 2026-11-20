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

Known answer-key quirks: Elastic's `cisco_ftd` samples contain literal `%ASA-` lines; the `system` samples are
mostly macOS; FireEye samples are Suricata EVE inside `rawmsg`; pfSense samples include haproxy/squid/snort lines.

Open issues found:
- Multi-line pretty-printed JSON samples arrive as one fragment per line (most of the remaining residue).
- API envelopes (`data[]`, page metadata) are not unwrapped.
- Syslog PRI/host prefix is not normalised before `^`-anchored rules.
- Validation only checks new rules; an older broad Symantec rule swallowed ~33 cloud SES events.
- ~2,000 lines/s single-threaded; needs a keyword prefilter or parallel workers for high-volume topics.
