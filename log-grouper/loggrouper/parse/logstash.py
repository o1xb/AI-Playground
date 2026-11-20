"""Conformance check: run compiled parsers in real Logstash and compare with the Python executor.

Logstash runs as a one-shot batch (stdin -> filter -> stdout, ~10-20 s JVM start-up), so this is the
final gate before a parser is activated, not part of the agent's inner loop.
"""
import json
import os
import subprocess
import tempfile

from .compiler import compile_filter
from .executor import run_parser, select_parser

COMPARED_ROOTS = ("vendor", "tags", "loggrouper")


def _norm(ev, with_ts):
    out = {k: ev[k] for k in COMPARED_ROOTS if k in ev}
    if "loggrouper" in out:
        out["loggrouper"] = {k: v for k, v in out["loggrouper"].items() if k == "parser"}
    if with_ts and "@timestamp" in ev and "_dateparsefailure" not in (ev.get("tags") or []):
        out["@timestamp"] = ev["@timestamp"]
    if "tags" in out:
        out["tags"] = sorted(out["tags"])
    return {k: v for k, v in out.items() if v not in ({}, [], None)}


def python_outputs(parsers, samples):
    """samples: [(label, message)] -> normalised executor outputs (same shape as Logstash's)."""
    by_label = {}
    for p in parsers:
        by_label.setdefault(p["label"], []).append(p)
    out = []
    for label, msg in samples:
        p = select_parser(by_label.get(label, []), msg)
        if p is None:
            out.append({"tags": ["_noparser"]}); continue
        ev = run_parser(p, msg)
        ev.setdefault("loggrouper", {})["parser"] = p["id"]          # (fallback test copies carry id + "_alone")
        out.append(_norm(ev, any("date" in s for s in p["steps"])))
    return out


def logstash_outputs(parsers, samples, logstash_home, workdir=None, timeout=600, mappings=None, raw=False):
    workdir = workdir or tempfile.mkdtemp(prefix="lg-logstash-")
    conf = os.path.join(workdir, "pipeline.conf")
    with open(conf, "w") as f:
        f.write('input { stdin { codec => json_lines } }\n')
        from ..ocsf.mapping import RUBY_SCRIPT
        f.write(compile_filter(parsers, mappings, RUBY_SCRIPT) + "\n")
        f.write('output { stdout { codec => json_lines } }\n')
    data = "".join(json.dumps({"message": m, "loggrouper": {"label": l}, "seq": i}) + "\n"
                   for i, (l, m) in enumerate(samples))
    env = dict(os.environ, LS_JAVA_OPTS=f"-Xms256m -Xmx{os.environ.get('LG_LS_HEAP', '2g')} "
                                          f"-XX:HeapDumpPath={tempfile.gettempdir()}")  # never dump into the repo
    env.pop("JAVA_TOOL_OPTIONS", None)
    p = subprocess.run([os.path.join(logstash_home, "bin", "logstash"), "-f", conf, "--path.data",
                        os.path.join(workdir, "data"), "-l", os.path.join(workdir, "logs"), "--log.level", "error",
                        "--pipeline.workers", "1"],
                       input=data, capture_output=True, text=True, timeout=timeout, env=env)
    events = {}
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if "seq" in ev:
                events[ev["seq"]] = ev
    if len(events) != len(samples):
        err = (p.stderr or "")[-3000:]
        raise RuntimeError(f"logstash returned {len(events)}/{len(samples)} events (exit {p.returncode}). {err}")
    if raw:
        return [events[i] for i in range(len(samples))]
    by_label = {}
    for x in parsers:
        by_label.setdefault(x["label"], []).append(x)
    out = []
    for i, (label, msg) in enumerate(samples):
        ev = events[i]
        pid = (ev.get("loggrouper") or {}).get("parser")
        spec = next((x for x in by_label.get(label, []) if x["id"] == pid), None)
        out.append(_norm(ev, bool(spec and any("date" in s for s in spec["steps"]))))
    return out


def conformance(parsers, samples, logstash_home):
    """-> {"checked", "identical", "diffs": [{"index", "label", "message", "python", "logstash"}]}"""
    py = python_outputs(parsers, samples)
    ls = logstash_outputs(parsers, samples, logstash_home)
    for a, b in zip(py, ls):
        if "@timestamp" not in a:          # date step did not run/succeed: Logstash's value is ingest time
            b.pop("@timestamp", None)
    diffs = [{"index": i, "label": samples[i][0], "message": samples[i][1][:300], "python": a, "logstash": b}
             for i, (a, b) in enumerate(zip(py, ls)) if a != b]
    return {"checked": len(samples), "identical": len(samples) - len(diffs), "diffs": diffs}


LOGSTASH_INTERNAL = ("@timestamp", "@version", "event", "host", "seq", "loggrouper", "tags")


def ocsf_conformance(parsers, mappings, samples, logstash_home):
    """Full pipeline (parser + OCSF mapping) in real Logstash vs Python. mappings: {parser_id: prepared}."""
    from ..ocsf.mapping import apply_mapping
    by_label = {}
    for p in parsers:
        by_label.setdefault(p["label"], []).append(p)
    py, pids = [], []
    for label, msg in samples:
        p = select_parser(by_label.get(label, []), msg)
        m = mappings.get(p["id"]) if p else None
        py.append(apply_mapping(m, run_parser(p, msg)) if m else None)
        pids.append(p["id"] if p else None)
    ls = logstash_outputs(parsers, samples, logstash_home, mappings=mappings, raw=True)
    diffs = []
    for i, (a, ev) in enumerate(zip(py, ls)):
        if a is None:
            continue
        b = {k: v for k, v in ev.items() if k not in LOGSTASH_INTERNAL}
        if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
            diffs.append({"index": i, "label": samples[i][0], "parser_id": pids[i], "message": samples[i][1][:300],
                          "python": a, "logstash": b})
    checked = sum(1 for a in py if a is not None)
    return {"checked": checked, "identical": checked - len(diffs), "diffs": diffs}
