"""Validate learner proposals before they enter the store. Nothing an LLM writes runs unchecked.

Two kinds of proposal:
  rules         new rules for residue clusters (appended after all existing rules)
  rule_updates  changes to existing rules to settle a conflict: {"id", "priority_before": <rule id>}
                (move above another rule) or {"id", "status": "disabled"}

Every accepted change must pass a regression check: each stored example of every label must still be
routed to its own label by the full, ordered rule set.
"""
import re
import time

from .rules import compile_rule

LABEL_RX = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
MAX_PATTERN = 600
MAX_SECONDS_PER_1K = 0.25


def _routing_score(store, bank):
    """How many stored examples route to their own label, and which labels lose examples."""
    ok, lost = 0, {}
    for lbl, ex in bank:
        r = store.match(ex)
        if r is not None and r["label"] == lbl:
            ok += 1
        else:
            lost[lbl] = lost.get(lbl, 0) + 1
    return ok, lost


def _flat_bank(store):
    return [(lbl, e) for lbl, exs in store.label_examples().items() for e in exs]


def apply_candidates(store, packet, residual, cand, origin):
    clusters = {c["cluster_id"]: c for c in packet["clusters"]}
    owner = {}                                   # cluster -> label the learner assigned it
    for r in cand.get("rules", []):
        for cid in r.get("explains_clusters", []):
            owner.setdefault(cid, r["label"])
    for cid in cand.get("unidentifiable", []):
        owner.setdefault(cid, "__unidentifiable__")
    shape_to_cid = {}
    for cid, c in clusters.items():
        for shp in c.get("member_shapes", [c["shape"]]):
            shape_to_cid[shp] = cid
    known_patterns = {(r["pattern"], r.get("flags", "")) for r in store.rules["rules"]}
    sample = residual[:3000]
    report = {"accepted": [], "rejected": [], "updated": []}
    bank = _flat_bank(store)
    base_ok, _ = _routing_score(store, bank)

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
            # 2) must not match lines already known to belong to a different label (guards future data)
            for lbl, e in bank:
                if lbl != r["label"] and rx.search(e):
                    raise ValueError(f"collides with known label {lbl}")
            # 3) must not over-match residue the learner attributed elsewhere; also check speed
            t0 = time.time()
            stolen = set()
            for item in sample:
                if rx.search(item["payload"]):
                    o = owner.get(shape_to_cid.get(item["shape"]))
                    if o is not None and o != r["label"]:
                        stolen.add(shape_to_cid.get(item["shape"]))
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
            continue
        claimed_ex = [e for cid in r.get("explains_clusters", []) for e in clusters.get(cid, {}).get("examples", [])]
        nr = store.add({**r, "examples": [e for e in claimed_ex if rx.search(e)][:3]}, origin)
        store._compile()
        ok, lost = _routing_score(store, bank)       # 4) regression check
        if ok < base_ok:
            store.rules["rules"].remove(nr); store._compile()
            reason = f"regression: would re-route stored examples of {sorted(lost)}"
            store.reject(r, reason, origin)
            report["rejected"].append({"label": r["label"], "pattern": r["pattern"], "reason": reason})
            continue
        known_patterns.add((r["pattern"], r.get("flags", "")))
        bank += [(nr["label"], e) for e in nr["examples"]]
        base_ok, _ = _routing_score(store, bank)
        report["accepted"].append({"id": nr["id"], "label": nr["label"], "pattern": nr["pattern"]})

    report["updated"], report["rejected_updates"] = apply_updates(store, packet, cand.get("rule_updates", []), origin)
    store.save()
    return report


def apply_updates(store, packet, updates, origin):
    """Settle conflicts (one message shape routed to two labels). An update is kept only if it moves
    conflict examples to the owner label the learner named and breaks no stored example."""
    conflicts = {c["conflict_id"]: c for c in packet.get("conflicts", [])}
    done, refused = [], []
    for u in updates:
        rule = store.by_id(u.get("id", ""))
        reason = None
        if rule is None:
            reason = "unknown rule id"
        conf_ex = []
        for cid in u.get("fixes_conflicts", []):
            c = conflicts.get(cid)
            if c:
                conf_ex += [(u.get("owner_label"), e) for g in c["labels"].values() for e in g["examples"]]
        if not reason and not conf_ex:
            reason = "names no known conflict"
        if reason:
            refused.append({**u, "reason": reason}); continue
        bank = _flat_bank(store)
        before_ok, _ = _routing_score(store, bank)
        before_fix, _ = _routing_score(store, conf_ex)
        saved = (rule["priority"], rule.get("status", "active"))
        if "priority_before" in u:
            other = store.by_id(u["priority_before"])
            if other is None:
                refused.append({**u, "reason": "unknown priority_before id"}); continue
            rule["priority"] = other["priority"] - 1
        if u.get("status") in ("disabled", "active"):
            rule["status"] = u["status"]
        store._compile()
        after_ok, lost = _routing_score(store, bank)
        after_fix, _ = _routing_score(store, conf_ex)
        if after_ok < before_ok or after_fix <= before_fix:
            rule["priority"], rule["status"] = saved
            store._compile()
            why = (f"regression on {sorted(lost)}" if after_ok < before_ok
                   else "does not route the conflict examples to the owner label")
            refused.append({**u, "reason": why})
            store.reject({"label": rule["label"], "pattern": rule["pattern"]}, "update refused: " + why, origin)
            continue
        rule.setdefault("history", []).append({"origin": origin, "change": {k: u[k] for k in u if k != "rationale"}})
        done.append({**u, "fixed_examples": after_fix - before_fix})
    return done, refused
