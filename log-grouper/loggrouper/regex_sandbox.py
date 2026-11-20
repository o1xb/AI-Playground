"""Run model-written regexes against data in a child process with a hard timeout.

Python's `re` cannot be interrupted, so a pattern with catastrophic backtracking would hang the
pipeline. Every pattern the learner writes is first exercised here; only patterns that finish
quickly on real residue and stored examples reach the validator and the fast path.
"""
import multiprocessing as mp
import re

from .rules import FLAGS

# forkserver: safe from multi-threaded parents (Kafka consumers, HTTP clients); spawn elsewhere
_CTX = mp.get_context("forkserver" if "forkserver" in mp.get_all_start_methods() else "spawn")


def _worker(pattern, flags, texts, q):
    try:
        f = 0
        for c in flags:
            f |= FLAGS[c]
        rx = re.compile(pattern, f)
        q.put(("ok", [bool(rx.search(t)) for t in texts]))
    except Exception as e:  # noqa: BLE001 - report any compile/runtime error to the caller
        q.put(("error", f"{type(e).__name__}: {e}"))


def safe_match(pattern, flags, texts, timeout=3.0):
    """-> (list[bool] | None, error | None). None + error on bad pattern or timeout."""
    if any(c not in FLAGS for c in flags):
        return None, f"unknown flag in {flags!r}; use only i, m, s"
    q = _CTX.Queue()
    p = _CTX.Process(target=_worker, args=(pattern, flags, list(texts), q), daemon=True)
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.kill(); p.join()
        return None, f"timed out after {timeout}s on {len(texts)} lines (catastrophic backtracking?)"
    try:
        kind, val = q.get(timeout=1)
    except Exception:  # noqa: BLE001
        return None, "worker exited without a result"
    return (val, None) if kind == "ok" else (None, val)
