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

## The learner agent (production)

`loggrouper/agent.py` is a tool-using agent on the Claude API (SDK tool runner). It gets the residue
and conflicts through tools, and can only *propose*; the validator decides.

| Tool | Purpose |
|---|---|
| `overview` | residue clusters, conflicts, known labels |
| `get_cluster`, `get_conflict` | full examples (and all JSON keys) for one cluster / conflict |
| `list_rules`, `get_label_examples`, `route` | inspect the rule library and what claims a given line |
| `test_pattern` | dry-run a regex on residue + stored examples (collisions, speed), in a sandboxed process |
| `propose_rule`, `propose_update`, `mark_unidentifiable` | draft changes |
| `submit` | run the validator, merge accepted changes, return verdicts so the agent can fix rejections |

Model `claude-opus-5-5`, adaptive thinking, effort `high`, prompt caching on the system prompt,
server-side refusal fallback on (security log content can trip safety classifiers).

```bash
export ANTHROPIC_API_KEY=...
# one learning session over the current residue
python3 -m loggrouper.cli learn --agent
# continuous: classify batches; when the residue reaches the threshold, run the agent
python3 -m loggrouper.cli --review-new-labels run --kafka kafka:9092 --topic security-logs \
    --batch-size 20000 --learner agent --learn-threshold 500
# rules for never-seen labels wait here when --review-new-labels is on
python3 -m loggrouper.cli review
python3 -m loggrouper.cli review --approve r00231 --discard r00232
```

Drive the same tools by hand (or from another agent): `python3 -m loggrouper.cli tool overview`,
`... tool test_pattern '{"pattern": "ACME\\[\\d+\\]"}'`, `... tool submit`.

### Deploying
- `Dockerfile` runs the Kafka loop; mount `/data` (rule store, outputs, state) on persistent storage
  and back up `rules/` (it is the learned knowledge). Commit it to git if you want review history.
- Safety rails: model regexes run in a separate process with a timeout; every change passes the
  validator (own examples, collisions, over-matching, regression on stored examples, speed);
  `--review-new-labels` holds new vendors for a human.
- Cost control: the agent only runs when the residue passes `--learn-threshold`; each session is
  capped by `max_iterations` (80) and at most 4 submits. The run prints token usage per session.
- Learning runs between batches, so consumption pauses while the agent works (minutes). For a
  high-volume topic, run classification and learning as separate processes sharing the store.

## Status

- Tested: file source, fast path, residue packets, sub-agent learning loop, validation, profile.
- Agent loop tested end-to-end against a local mock of the Messages API (real SDK, tool runner,
  tools and validator; scripted model). Not yet run against the live API (no key in the test
  environment).
- Not exercised yet: the Kafka source (no broker was available in the test environment).
