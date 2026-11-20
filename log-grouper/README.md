# log-grouper

Groups a mixed security log stream (file or Kafka topic) by **originating source**
(vendor + product, plus message format) so each group can get its own Logstash
grok/dissect parser and OCSF mapping.

The design keeps the LLM off the hot path:

```
 Kafka / file ──► batch (e.g. 20k) ──► unwrap envelopes ──► rule fast path ──► groups/<label>.jsonl
                                       (filebeat JSON,       (rules/rules.json,     (or topic logs.<label>)
                                        syslog relays)        first match wins)
                                                                   │ no match
                                                                   ▼
                                                     residual buffer (state/residual.jsonl)
                                                                   │ cluster by message shape
                                                                   ▼
                                                residue packet: ≤N clusters × few examples
                                                                   │
                                            learner (Claude Code sub-agent, or Claude API)
                                                                   │ candidate rules (JSON)
                                                                   ▼
                                  validator: compiles? matches its own cluster? collides with
                                  another label's known examples? over-matches other clusters?
                                  too slow?  ── reject → rules/rejected.json (fed back to learner)
                                                                   │ accept
                                                                   ▼
                                  rules/rules.json  (versioned, hit counts, examples, origin)
                                  residue is drained through the new rules; next batch reuses them
```

## Files

| Path | What it is |
|---|---|
| `rules/rules.json` | The learned rule library: `label`, `pattern`, `flags`, `format`, `priority`, `confidence`, `origin`, `hits`, `examples`. Commit it; it *is* the learned knowledge. |
| `rules/rejected.json` | Proposals the validator refused, with reasons. |
| `prompts/learner.md` | Instructions for the learner (same text for a sub-agent or the API). |
| `loggrouper/unwrap.py` | Envelope peeling (configurable via `rules/wrappers.json`). |
| `loggrouper/engine.py` | Batch processing, residue buffer, packet builder, checkpoints. |
| `loggrouper/learn.py` | Candidate rule validation and merge. |
| `loggrouper/llm_learner.py` | Claude API learner (structured JSON output). |
| `loggrouper/sources.py` | File and Kafka batch sources (offsets committed after each batch). |

## Usage

```bash
# 1. fast path over a stream, in batches
python3 -m loggrouper.cli --store rules --out out --state state run --input stream.log --batch-size 20000
#    or from Kafka (pip install kafka-python):
python3 -m loggrouper.cli run --kafka localhost:9092 --topic security-logs --batch-size 20000

# 2a. learn with a Claude Code sub-agent: write the packet, have the agent follow prompts/learner.md,
#     then validate + merge its proposals
python3 -m loggrouper.cli packet --output packet.json
python3 -m loggrouper.cli apply --packet packet.json --candidates candidates.json --origin subagent

# 2b. or learn automatically via the Claude API (pip install anthropic; ANTHROPIC_API_KEY)
python3 -m loggrouper.cli run --input stream.log --learner api --learn-threshold 500

# 3. hand-off for parser authors: every group's distinct formats, transports and examples
python3 -m loggrouper.cli profile        # -> out/profile.json
```

## Status

- Tested: file source, fast path, residue packets, sub-agent learning loop, validation, profile.
- Not exercised yet: the Kafka source (no broker was available in the test environment) and the
  Claude API learner (no API key there).
