"""Production learner agent: Claude + tools over the rule store and the residue buffer.

It does what the Claude Code sub-agent did during development (inspect residue, write regexes,
test them against real data, settle conflicts), but through explicit tools, so it runs anywhere
with an Anthropic API key:

    from loggrouper.agent import run_learner_agent
    report = run_learner_agent(store, engine)

The model never touches the store directly. It can only *propose*; `submit` runs the same
validator as the CLI and returns its verdicts so the model can fix rejected proposals.
"""
import json
import os
import time

from .learn import apply_candidates
from .regex_sandbox import safe_match

PROMPTS = os.path.join(os.path.dirname(__file__), "..", "prompts")
DEFAULT_MODEL = "claude-opus-5-5"


class LearnerTools:
    """Tool implementations. Plain methods returning strings, so they can be driven by the Claude
    API tool runner, a test, or a CLI bridge alike."""

    def __init__(self, store, engine, max_clusters=150, review_new_labels=False, max_submits=4, drafts_path=None):
        self.store, self.engine = store, engine
        self.review_new_labels = review_new_labels
        self.max_clusters = max_clusters
        self.max_submits, self.submits = max_submits, 0
        self.reports = []
        self.draft_rules, self.draft_updates = [], []
        self.drafts_path = drafts_path          # lets a shell bridge keep drafts between calls
        if drafts_path and os.path.exists(drafts_path):
            with open(drafts_path) as f:
                d = json.load(f)
            self.draft_rules, self.draft_updates, self.submits = d["rules"], d["updates"], d["submits"]
        self._refresh()

    def _refresh(self):
        self.packet = self.engine.build_packet(max_clusters=self.max_clusters, examples=8, json_chars=3000)
        self.clusters = {c["cluster_id"]: c for c in self.packet["clusters"]}
        self.conflicts = {c["conflict_id"]: c for c in self.packet["conflicts"]}
        self.suspects = {g["suspect_id"]: g for g in self.packet["suspects"]}
        self.residual = self.engine.load_residual()
        self.shape_to_cid = {s: cid for cid, c in self.clusters.items() for s in c.get("member_shapes", [c["shape"]])}

    def _persist(self):
        if self.drafts_path:
            with open(self.drafts_path, "w") as f:
                json.dump({"rules": self.draft_rules, "updates": self.draft_updates, "submits": self.submits}, f)

    def _examples_of(self, ids):
        out = []
        for i in ids:
            if i in self.clusters:
                out += self.clusters[i]["examples"]
            elif i in self.suspects:
                out += self.suspects[i]["examples"]
        return out

    # -- read-only views ----------------------------------------------------
    def overview(self, offset: int = 0, limit: int = 40, width: int = 140) -> str:
        """Start here. Residue clusters (unclassified lines, largest first; page with offset/limit),
        conflicts (one message shape in several labels), suspects (lines a rule claims that look unlike
        that rule's own examples - often a sibling product swallowed by a broad vendor rule), known labels."""
        p = self.packet
        cl = p["clusters"][offset:offset + limit]
        lines = [f"residual_lines={p['residual_lines']} clusters={len(p['clusters'])} "
                 f"(showing {offset}-{offset + len(cl) - 1}; ignored as previously unidentifiable: "
                 f"{p.get('ignored_unidentifiable_lines', 0)} lines)",
                 "", "CLUSTERS (id | lines | shape | first example):"]
        for c in cl:
            lines.append(f"{c['cluster_id']} | {c['count']} | {c['shape'][:60]} | {c['examples'][0][:width]!r}")
        if offset == 0:
            lines += ["", "CONFLICTS (id | shape | label:count:rules):"]
            for c in p["conflicts"]:
                lines.append(f"{c['conflict_id']} | {c['shape'][:60]} | " + "; ".join(
                    f"{l}:{g['count']}:{','.join(g['rules'])}" for l, g in c["labels"].items()))
            lines += ["", "SUSPECTS (id | rule | label | lines unlike the rule's examples | example):"]
            for g in p["suspects"]:
                lines.append(f"{g['suspect_id']} | {g['rule']} | {g['label']} | {g['count']} | {g['examples'][0][:width]!r}")
            lines += ["", "KNOWN LABELS: " + ", ".join(p["existing_labels"])]
        return "\n".join(lines)

    def get_cluster(self, cluster_id: str, max_examples: int = 4, max_chars: int = 1200, show_keys: bool = False) -> str:
        """Examples for one residue cluster (cXXX) or suspect (sXXX). show_keys adds every JSON key seen."""
        if cluster_id in self.suspects:
            g = self.suspects[cluster_id]
            return json.dumps({"suspect_id": cluster_id, "rule": g["rule"], "label": g["label"], "pattern": g["pattern"],
                               "count": g["count"], "claimed_lines": [e[:max_chars] for e in g["examples"][:max_examples]],
                               "rule_own_examples": g["rule_examples"]}, indent=1)
        c = self.clusters.get(cluster_id)
        if not c:
            return f"ERROR: unknown cluster {cluster_id}"
        out = {"cluster_id": cluster_id, "count": c["count"], "shape": c["shape"],
               "examples": [e[:max_chars] for e in c["examples"][:max_examples]]}
        if show_keys and "all_keys" in c:
            out["all_keys"] = c["all_keys"]
        return json.dumps(out, indent=1)

    def get_conflict(self, conflict_id: str, max_chars: int = 1200) -> str:
        """Labels, rule ids and examples for one conflict."""
        c = self.conflicts.get(conflict_id)
        if not c:
            return f"ERROR: unknown conflict {conflict_id}"
        return json.dumps({"conflict_id": conflict_id, "shape": c["shape"],
                           "labels": {l: {"count": g["count"], "rules": g["rules"],
                                          "examples": [e[:max_chars] for e in g["examples"]]}
                                      for l, g in c["labels"].items()}}, indent=1)

    def list_rules(self, label: str = "") -> str:
        """Active rules in match order (first match wins). Optionally only those for `label`."""
        out = []
        for _, r in self.store.compiled:
            if label and r["label"] != label:
                continue
            out.append(f"{r['id']} prio={r['priority']} {r['label']} hits={r['hits']} "
                       f"flags={r.get('flags', '')!r} pattern={r['pattern']!r}")
        return "\n".join(out) or f"no active rules for {label!r}"

    def get_label_examples(self, label: str, max_chars: int = 600) -> str:
        """Stored examples for a label: confirmed (learner-attributed, trusted) and observed (seen at match
        time; may include lines an over-reaching rule wrongly claimed)."""
        conf = self.store.label_examples(confirmed_only=True).get(label, [])
        obs = [e for e in self.store.label_examples().get(label, []) if e not in conf]
        if not conf and not obs:
            return f"no examples for {label!r}"
        return json.dumps({"confirmed": [e[:max_chars] for e in conf[:8]],
                           "observed": [e[:max_chars] for e in obs[:8]]}, indent=1)

    def route(self, text: str) -> str:
        """Which existing rule would claim this text (after unwrapping), and via which view."""
        payload, layers, views = self.engine.unwrap.views(text)
        r, vi = self.store.match_views(views)
        if r is None:
            return f"no rule matches (layers={layers})"
        return f"{r['id']} {r['label']} (view {vi}, layers={layers}) pattern={r['pattern']!r}"

    def test_pattern(self, pattern: str, flags: str = "", label: str = "", cluster_ids: list[str] = []) -> str:
        """Dry-run a regex (Python re.search) before proposing it. Reports: residue lines matched per
        cluster; for `cluster_ids` (clusters/suspects you intend to claim) the lines it MISSES; stored
        examples of `label` it matches (needed before narrowing a rule); collisions with stored examples
        of other labels, with snippets; and speed."""
        texts = [i["payload"] for i in self.residual]
        claimed = self._examples_of(cluster_ids)
        bank = [(l, e, "confirmed") for l, exs in self.store.label_examples(confirmed_only=True).items() for e in exs]
        cset = {e for _, e, _ in bank}
        bank += [(l, e, "observed") for l, exs in self.store.label_examples().items() for e in exs if e not in cset]
        t0 = time.time()
        allt = texts + claimed + [e for _, e, _ in bank]
        hits, err = safe_match(pattern, flags, allt)
        if err:
            return f"ERROR: {err}"
        dt = time.time() - t0
        rh = hits[:len(texts)]
        ch = hits[len(texts):len(texts) + len(claimed)]
        bh = hits[len(texts) + len(claimed):]
        per = {}
        for item, h in zip(self.residual, rh):
            cid = self.shape_to_cid.get(item["shape"], "other")
            tot, m = per.get(cid, (0, 0))
            per[cid] = (tot + 1, m + h)
        own = [h for (l, _, _), h in zip(bank, bh) if l == label]
        coll = [(l, k, e) for (l, e, k), h in zip(bank, bh) if h and l != label]
        out = {"residue_lines_matched": sum(rh),
               "clusters_matched": {cid: f"{m}/{tot}" for cid, (tot, m) in sorted(per.items()) if m},
               "ms_per_1k_lines": round(dt / max(1, len(allt)) * 1e6, 1)}
        if cluster_ids:
            out["claimed_examples_matched"] = f"{sum(ch)}/{len(claimed)}"
            out["claimed_examples_missed"] = [e[:300] for e, h in zip(claimed, ch) if not h][:3]
        if label:
            out["own_label_stored_examples_matched"] = f"{sum(own)}/{len(own)}"
        out["collisions"] = [{"label": l, "kind": k, "example": e[:300]} for l, k, e in coll[:5]]
        out["collision_count"] = len(coll)
        return json.dumps(out, indent=1)

    # -- proposals ----------------------------------------------------------
    def propose_rule(self, label: str, pattern: str, explains_clusters: list[str], rationale: str,
                     format: str = "", flags: str = "", confidence: str = "medium",
                     priority_before: str = "") -> str:
        """Add a new rule to the draft. label: lowercase vendor_product (reuse a known label when it is the
        same product). explains_clusters: cluster/suspect ids it covers, or ["auto"] to claim every residue
        cluster the pattern matches that no other draft claims. priority_before: rule id to place this rule
        directly above (when an existing rule would otherwise claim these lines, e.g. a suspect)."""
        if explains_clusters == ["auto"]:
            taken = {c for r in self.draft_rules for c in r["explains_clusters"]}
            texts = [i["payload"] for i in self.residual]
            hits, err = safe_match(pattern, flags, texts)
            if err:
                return f"ERROR: {err}"
            explains_clusters = sorted({self.shape_to_cid[i["shape"]] for i, h in zip(self.residual, hits)
                                        if h and i["shape"] in self.shape_to_cid} - taken)
            if not explains_clusters:
                return "ERROR: pattern matches no unclaimed residue cluster"
        ex = self._examples_of(explains_clusters)
        if not ex:
            return "ERROR: explains_clusters names no known cluster or suspect"
        hits, err = safe_match(pattern, flags, ex)
        if err:
            return f"ERROR: {err}"
        if not any(hits):
            return "ERROR: pattern matches none of the examples of the clusters it claims"
        rule = {"label": label, "pattern": pattern, "flags": flags, "format": format,
                "confidence": confidence, "explains_clusters": explains_clusters, "rationale": rationale}
        if priority_before:
            if self.store.by_id(priority_before) is None:
                return f"ERROR: unknown rule id {priority_before}"
            rule["priority_before"] = priority_before
        self.draft_rules.append(rule)
        self._persist()
        return (f"drafted rule #{len(self.draft_rules) - 1} for {label}, claiming {explains_clusters}: matches "
                f"{sum(hits)}/{len(ex)} of the sample lines shown for those clusters (use test_pattern for full counts)")

    def propose_update(self, rule_id: str, owner_label: str, rationale: str, fixes_conflicts: list[str] = [],
                       evidence: list[str] = [], priority_before: str = "", pattern: str = "", status: str = "") -> str:
        """Change an existing rule: move it (priority_before), narrow it (pattern) or retire it
        (status="disabled"). Justify with conflict/suspect ids (fixes_conflicts) and/or evidence: lines the
        rule wrongly claims, which really belong to owner_label (e.g. a collision from test_pattern)."""
        if not (priority_before or pattern or status):
            return "ERROR: give priority_before, pattern or status"
        if not (fixes_conflicts or evidence):
            return "ERROR: give fixes_conflicts (kXXX/sXXX) or evidence lines"
        if pattern:
            _, err = safe_match(pattern, "", ["x"])
            if err:
                return f"ERROR: {err}"
        u = {"id": rule_id, "owner_label": owner_label, "fixes_conflicts": fixes_conflicts,
             "evidence": evidence, "rationale": rationale}
        u.update({k: v for k, v in (("priority_before", priority_before), ("pattern", pattern), ("status", status)) if v})
        self.draft_updates.append(u)
        self._persist()
        return f"drafted update #{len(self.draft_updates) - 1} for {rule_id}"

    def mark_unidentifiable(self, cluster_ids: list[str], reason: str) -> str:
        """Record clusters that cannot be attributed to a vendor (better than a guessed rule). Stored by
        message shape, so later sessions skip them; takes effect immediately."""
        n = 0
        for cid in cluster_ids:
            c = self.clusters.get(cid)
            for shp in (c.get("member_shapes", [c["shape"]]) if c else []):
                self.store.unidentifiable[shp] = {"reason": reason, "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
                n += 1
        self.store.save()
        self._refresh()
        return f"recorded {n} shapes from {len(cluster_ids)} clusters as unidentifiable; cluster ids renumbered, call overview"

    def dismiss_suspects(self, suspect_ids: list[str], reason: str) -> str:
        """Record suspects you reviewed and judged correctly routed (e.g. another event type of the same
        product), so they are not raised again in later sessions."""
        n = 0
        for sid in suspect_ids:
            g = self.suspects.get(sid)
            if g:
                lst = self.store.dismissed.setdefault(g["rule"], [])
                lst += [x for x in g.get("shapes", ()) if x not in lst]
                n += 1
        self.store.save()
        self._refresh()
        return f"dismissed {n} suspects; ids renumbered, call overview"

    def submit(self) -> str:
        """Validate all drafted rules/updates and merge the accepted ones into the rule store. Returns
        accepted (with position) / rejected with reasons. Cluster ids are renumbered afterwards."""
        if self.submits >= self.max_submits:
            return "ERROR: submit limit reached; finish with your summary"
        self.submits += 1
        cand = {"rules": self.draft_rules, "rule_updates": self.draft_updates, "unidentifiable": []}
        new_labels = set()
        if self.review_new_labels:
            known = set(self.store.labels())
            for r in cand["rules"]:
                if r["label"] not in known:
                    r["status"] = "candidate"; new_labels.add(r["label"])
        rep = apply_candidates(self.store, self.packet, self.residual, cand, f"agent:{time.strftime('%Y%m%dT%H%M%S')}")
        self.reports.append(rep)
        self.draft_rules, self.draft_updates = [], []
        self._persist()
        moved, left = self.engine.reclassify_residual()
        self._refresh()
        return json.dumps({"accepted": rep["accepted"], "rejected": rep["rejected"],
                           "updates_applied": rep["updated"], "updates_refused": rep["rejected_updates"],
                           "disputed": rep["disputed"], "held_for_human_review": sorted(new_labels),
                           "residue_drained": moved, "residue_left": left,
                           "note": "cluster ids are renumbered; call overview"}, indent=1)

    def tool_functions(self):
        return [self.overview, self.get_cluster, self.get_conflict, self.list_rules, self.get_label_examples,
                self.route, self.test_pattern, self.propose_rule, self.propose_update,
                self.mark_unidentifiable, self.dismiss_suspects, self.submit]


def system_prompt():
    with open(os.path.join(PROMPTS, "learner.md")) as f:
        rules = f.read()
    with open(os.path.join(PROMPTS, "agent_workflow.md")) as f:
        workflow = f.read()
    return workflow + "\n\n" + rules


def run_learner_agent(store, engine, model=DEFAULT_MODEL, effort="high", max_iterations=80,
                      review_new_labels=False, client=None, log=print):
    """Run one learning session over the current residue. Returns a summary dict."""
    import anthropic
    from anthropic import beta_tool

    tools = LearnerTools(store, engine, review_new_labels=review_new_labels)
    if not (tools.packet["clusters"] or tools.packet["conflicts"] or tools.packet["suspects"]):
        return {"skipped": "no residue, conflicts or suspects"}
    client = client or anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model=model,
        max_tokens=16000,
        max_iterations=max_iterations,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",            # security logs can trip safety classifiers; fall back instead of stopping
        thinking={"type": "adaptive"},
        output_config={"effort": effort},
        cache_control={"type": "ephemeral"},
        system=system_prompt(),
        tools=[beta_tool(f) for f in tools.tool_functions()],
        messages=[{"role": "user", "content":
                   "A new residue batch is ready. Call `overview`, then classify what you can, settle "
                   "conflicts, and `submit`. Finish with a short summary of what you added and what you left."}],
    )
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "turns": 0}
    final = None
    for message in runner:
        usage["turns"] += 1
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens"):
            usage[k] += getattr(message.usage, k, 0) or 0
        for b in message.content:
            if b.type == "tool_use":
                log(f"[agent] {b.name}({json.dumps(b.input)[:160]})")
        if message.stop_reason == "refusal":
            log(f"[agent] refused: {getattr(message, 'stop_details', None)}")
        final = message
    if tools.draft_rules or tools.draft_updates:      # model stopped without submitting its last drafts
        log("[agent] submitting leftover drafts")
        tools.submit()
    summary = "".join(b.text for b in (final.content if final else []) if b.type == "text")
    accepted = sum(len(r["accepted"]) for r in tools.reports)
    rejected = sum(len(r["rejected"]) for r in tools.reports)
    return {"accepted": accepted, "rejected": rejected, "submits": tools.submits,
            "unidentifiable_shapes": len(store.unidentifiable), "usage": usage, "summary": summary,
            "stop_reason": final.stop_reason if final else None}
