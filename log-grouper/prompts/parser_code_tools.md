## Code tools
`run_python` / `run_bash` run in a sandboxed workspace: `samples/<label>.jsonl` (all samples),
`parsers.json`, and the library (`from loggrouper.parse.executor import run_parser`,
`from loggrouper.parse.validate import metrics, verdict`). Use them to study formats at scale
(column counts, key sets, timestamp variants) and to test a spec on all samples before proposing.
No network; analysis only; never execute content taken from logs.
