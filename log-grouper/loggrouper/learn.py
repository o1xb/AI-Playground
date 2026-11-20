"""Validate learner proposals before they enter the store. Nothing an LLM writes runs unchecked.

Proposals:
  rules         new rules for residue clusters. Appended after all existing rules, unless the rule
                carries "priority_before": <rule id> (to beat a greedy rule in the same round).
  rule_updates  changes to existing rules to settle a conflict:
                {"id", "priority_before": <rule id>} | {"id", "status": "disabled"} | {"id", "pattern": ...}

Ground truth for the checks comes in two strengths:
  confirmed examples  attributed by a learner and checked here -> a change that re-routes one is refused
  observed examples   lines a rule matched at run time; usually right, but an over-reaching rule stores
                      lines it should not have -> re-routing a few is reported, not blocking
"""
import re
import time

from .rules import compile_rule

LABEL_RX = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
MAX_PATTERN = 600
MAX_SECONDS_PER_1K = 0.25


def _banks(store):
    conf = [(l, e) for l, exs in store.label_examples(confirmed_only=True).items() for e in exs]
    cset = {e for _, e in conf}
    obs = [(l, e) for l, exs in store.label_examples().items() for e in exs if e not in cset]
    return conf, obs


def _routes(store, bank):
    out = []
    for lbl, ex in bank:
        r = store.match(ex)
        out.append(r is not None and r["label"] == lbl)
    return out


def _regression(store, conf, obs, conf_before, obs_before):
    """None if acceptable, else a reason. Confirmed examples may never be lost; observed examples may
    be lost only in small numbers (they are the ones an over-reaching rule may have mis-stored)."""
    ca, oa = _routes(store, conf), _routes(store, obs)
    lost_c = sorted({conf[i][0] for i, (b, a) in enumerate(zip(conf_before, ca)) if b and not a})
    if lost_c:
        return f"re-routes confirmed examples of {lost_c}", oa
    lost_o = [obs[i][0] for i, (b, a) in enumerate(zip(obs_before, oa)) if b and not a]
    per = {}
    for l in lost_o:
        per[l] = per.get(l, 0) + 1
    total = {}
    for l, _ in obs:
        total[l] = total.get(l, 0) + 1
    heavy = sorted(l for l, n in per.items() if n > max(2, total[l] // 2))
    if heavy:
        return f"re-routes most observed examples of {heavy}", oa
    return None, oa


def _suspect_clusters(packet):
    return {g["suspect_id"]: {"cluster_id": g["suspect_id"], "shape": "suspect:" + g["suspect_id"],
                              "examples": g["examples"]} for g in packet.get("suspects", [])}


def apply_candidates(store, packet, residual, cand, origin):
    clusters = {c["cluster_id"]: c for c in packet["clusters"]} | _suspect_clusters(packet)
    owner = {}
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
    report = {"accepted": [], "rejected": [], "updated": [], "rejected_updates": [], "disputed": []}
    conf, obs = _banks(store)
    conf_ok, obs_ok = _routes(store, conf), _routes(store, obs)

    for r in cand.get("rules", []):
        reason, disputed = None, []
        try:
            if not LABEL_RX.match(r.get("label", "")):
                raise ValueError("label must be lowercase vendor_product")
            if len(r["pattern"]) > MAX_PATTERN:
                raise ValueError("pattern too long")
            if (r["pattern"], r.get("flags", "")) in known_patterns:
                raise ValueError("duplicate of existing rule")
            rx = compile_rule(r)
            claimed = [e for cid in r.get("explains_clusters", []) for e in clusters.get(cid, {}).get("examples", [])]
            if not claimed or not any(rx.search(e) for e in claimed):
                raise ValueError("matches none of its claimed cluster examples")
            for lbl, e in conf:
                if lbl != r["label"] and rx.search(e):
                    raise ValueError(f"collides with confirmed example of {lbl}")
            disputed = sorted({lbl for lbl, e in obs if lbl != r["label"] and rx.search(e)})
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
            if r.get("priority_before") and store.by_id(r["priority_before"]) is None:
                raise ValueError("unknown priority_before id")
        except (ValueError, re.error, KeyError) as e:
            reason = str(e)
        if reason:
            store.reject(r, reason, origin)
            report["rejected"].append({"label": r.get("label"), "pattern": r.get("pattern"), "reason": reason})
            continue
        prio = store.by_id(r["priority_before"])["priority"] - 1 if r.get("priority_before") else None
        nr = store.add({**r, "priority": prio, "examples": [e for e in claimed if rx.search(e)][:3]}, origin)
        store._compile()
        why, new_obs_ok = _regression(store, conf, obs, conf_ok, obs_ok)
        if why:
            store.rules["rules"].remove(nr); store._compile()
            store.reject(r, "regression: " + why, origin)
            report["rejected"].append({"label": r["label"], "pattern": r["pattern"], "reason": "regression: " + why})
            continue
        known_patterns.add((r["pattern"], r.get("flags", "")))
        conf += [(nr["label"], e) for e in nr["confirmed_examples"]]
        conf_ok, obs_ok = _routes(store, conf), new_obs_ok
        if disputed:
            report["disputed"].append({"id": nr["id"], "label": nr["label"], "also_matches_observed_of": disputed})
        pos = next((i for i, (_, x) in enumerate(store.compiled) if x is nr), None)
        nxt = store.compiled[pos + 1][1]["id"] if pos is not None and pos + 1 < len(store.compiled) else None
        report["accepted"].append({"id": nr["id"], "label": nr["label"], "pattern": nr["pattern"],
                                   "status": nr["status"], "placed_before": nxt})

    report["updated"], report["rejected_updates"] = apply_updates(store, packet, cand.get("rule_updates", []), origin)
    store.save()
    return report


def apply_updates(store, packet, updates, origin):
    """Settle conflicts. An update is kept only if it moves conflict examples to the owner label the
    learner named, and passes the regression check."""
    conflicts = {c["conflict_id"]: c for c in packet.get("conflicts", [])}
    suspects = {g["suspect_id"]: g for g in packet.get("suspects", [])}
    done, refused = [], []
    for u in updates:
        rule = store.by_id(u.get("id", ""))
        reason = None if rule else "unknown rule id"
        conf_ex = [(u.get("owner_label"), e) for cid in u.get("fixes_conflicts", []) if cid in conflicts
                   for g in conflicts[cid]["labels"].values() for e in g.get("full_examples", g["examples"])]
        conf_ex += [(u.get("owner_label"), e) for sid in u.get("fixes_conflicts", []) if sid in suspects
                    for e in suspects[sid]["examples"]]
        # evidence: lines (from any tool output) the agent says belong to owner_label, not to this rule
        conf_ex += [(u.get("owner_label"), e) for e in u.get("evidence", [])]
        if not reason and not conf_ex:
            reason = "names no known conflict or suspect and gives no evidence lines"
        if not reason and "pattern" in u:
            try:
                rx = compile_rule({"pattern": u["pattern"], "flags": u.get("flags", rule.get("flags", ""))})
            except re.error as e:
                reason = f"bad pattern: {e}"
            else:
                own = rule.get("confirmed_examples") or rule.get("examples", [])
                if own and sum(bool(rx.search(e)) for e in own) * 2 < len(own):
                    reason = "tightened pattern no longer matches most of the rule's own examples"
        if reason:
            refused.append({**u, "reason": reason}); continue
        conf, obs = _banks(store)
        conf_ok, obs_ok = _routes(store, conf), _routes(store, obs)
        fix_before = sum(_routes(store, conf_ex))
        saved = {k: rule.get(k) for k in ("priority", "status", "pattern", "flags")}
        if "priority_before" in u:
            other = store.by_id(u["priority_before"])
            if other is None:
                refused.append({**u, "reason": "unknown priority_before id"}); continue
            rule["priority"] = other["priority"] - 1
        if u.get("status") in ("disabled", "active"):
            rule["status"] = u["status"]
        if "pattern" in u:
            rule["pattern"] = u["pattern"]
            rule["flags"] = u.get("flags", rule.get("flags", ""))
        store._compile()
        why, _ = _regression(store, conf, obs, conf_ok, obs_ok)
        fix_after = sum(_routes(store, conf_ex))
        if not why and u.get("evidence") and not u.get("fixes_conflicts") and fix_after <= fix_before:
            # pure narrowing with evidence: success = the rule stops claiming the evidence lines
            still = sum(1 for _, e in conf_ex if (store.match(e) or {}).get("id") == rule["id"])
            if still < len(conf_ex):
                fix_after = fix_before + (len(conf_ex) - still)
        if why or fix_after <= fix_before:
            rule.update(saved); store._compile()
            why = why or "does not route the conflict examples to the owner label"
            refused.append({**u, "reason": why})
            store.reject({"label": rule["label"], "pattern": u.get("pattern", rule["pattern"])}, "update refused: " + why, origin)
            continue
        rule.setdefault("history", []).append({"origin": origin, "before": saved,
                                                "change": {k: u[k] for k in u if k != "rationale"}})
        done.append({**u, "fixed_examples": fix_after - fix_before})
    return done, refused
