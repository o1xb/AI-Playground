"""Validate learner-proposed rules before they enter the store. Nothing an LLM writes runs unchecked."""
import re
import time

from .rules import compile_rule

LABEL_RX = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
MAX_PATTERN = 600
MAX_SECONDS_PER_1K = 0.25


def apply_candidates(store, packet, residual, cand, origin):
    """cand = {"rules":[{label, pattern, flags?, confidence, format?, explains_clusters:[..], rationale}],
               "unidentifiable":[cluster_id,..]}"""
    clusters = {c["cluster_id"]: c for c in packet["clusters"]}
    owner = {}                                   # cluster -> label the learner assigned it
    for r in cand.get("rules", []):
        for cid in r.get("explains_clusters", []):
            owner.setdefault(cid, r["label"])
    for cid in cand.get("unidentifiable", []):
        owner.setdefault(cid, "__unidentifiable__")
    shape_to_cid = {c["shape"]: cid for cid, c in clusters.items()}
    bank = store.label_examples()
    known_patterns = {(r["pattern"], r.get("flags", "")) for r in store.rules["rules"]}
    sample = residual[:3000]
    report = {"accepted": [], "rejected": []}

    for r in cand.get("rules", []):
        reason = None
        try:
            if not LABEL_RX.match(r.get("label", "")):
                raise ValueError("label must be lowercase vendor_product")
            if len(r["pattern"]) > MAX_PATTERN:
                raise ValueError("pattern too long")
            if (r["pattern"], r.get("flags", "")) in known_patterns:
                raise ValueError("duplicate of existing rule")
            rx = compile_rule(r)
            # 1) must match the examples it claims to explain
            claimed = [e for cid in r.get("explains_clusters", []) for e in clusters.get(cid, {}).get("examples", [])]
            if not claimed or not any(rx.search(e) for e in claimed):
                raise ValueError("matches none of its claimed cluster examples")
            # 2) must not collide with lines already known to belong to a different label
            for lbl, exs in bank.items():
                if lbl != r["label"] and any(rx.search(e) for e in exs):
                    raise ValueError(f"collides with known label {lbl}")
            # 3) must not over-match residue the learner attributed elsewhere; also check speed
            t0 = time.time()
            stolen = set()
            for item in sample:
                if rx.search(item["payload"]):
                    cid = shape_to_cid.get(item["shape"])
                    o = owner.get(cid)
                    if o is not None and o != r["label"]:
                        stolen.add(cid)
            per1k = (time.time() - t0) / max(1, len(sample)) * 1000
            if per1k > MAX_SECONDS_PER_1K:
                raise ValueError(f"too slow ({per1k:.2f}s per 1k lines) - possible catastrophic backtracking")
            if stolen:
                raise ValueError(f"over-matches clusters owned by other labels: {sorted(stolen)[:5]}")
        except (ValueError, re.error, KeyError) as e:
            reason = str(e)
        if reason:
            store.reject(r, reason, origin)
            report["rejected"].append({"label": r.get("label"), "pattern": r.get("pattern"), "reason": reason})
        else:
            claimed_ex = [e for cid in r.get("explains_clusters", []) for e in clusters.get(cid, {}).get("examples", [])][:3]
            nr = store.add({**r, "examples": claimed_ex}, origin)
            known_patterns.add((r["pattern"], r.get("flags", "")))
            bank.setdefault(r["label"], []).extend(claimed_ex)
            report["accepted"].append({"id": nr["id"], "label": nr["label"], "pattern": nr["pattern"]})
    store.save()
    return report
