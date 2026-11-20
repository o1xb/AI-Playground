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
        self.packet = engine.build_packet(max_clusters=max_clusters, examples=8, json_chars=3000)
        self.clusters = {c["cluster_id"]: c for c in self.packet["clusters"]}
        self.conflicts = {c["conflict_id"]: c for c in self.packet["conflicts"]}
        self.residual = engine.load_residual()
        self.draft_rules, self.draft_updates, self.unidentifiable = [], [], {}
        self.review_new_labels = review_new_labels
        self.max_submits, self.submits = max_submits, 0
        self.reports = []
        self.drafts_path = drafts_path          # lets a shell bridge keep drafts between calls
        if drafts_path and os.path.exists(drafts_path):
            with open(drafts_path) as f:
                d = json.load(f)
            self.draft_rules, self.draft_updates = d["rules"], d["updates"]
            self.unidentifiable, self.submits = d["unidentifiable"], d["submits"]

    def _persist(self):
        if self.drafts_path:
            with open(self.drafts_path, "w") as f:
                json.dump({"rules": self.draft_rules, "updates": self.draft_updates,
                           "unidentifiable": self.unidentifiable, "submits": self.submits}, f)

    # -- read-only views ----------------------------------------------------
    def overview(self) -> str:
        """Start here. Summary of the residue (unclassified lines) as clusters of similar messages,
        the current conflicts (one message shape routed to several labels), and the known labels."""
        p = self.packet
        lines = [f"residual_lines={p['residual_lines']} clusters={len(p['clusters'])} (of {p['clusters_total']})",
                 "", "CLUSTERS (id | lines | shape | first example, trimmed):"]
        for c in p["clusters"]:
            lines.append(f"{c['cluster_id']} | {c['count']} | {c['shape'][:80]} | {c['examples'][0][:160]!r}")
        lines += ["", "CONFLICTS (id | shape | label:count:rules):"]
        for c in p["conflicts"]:
            lines.append(f"{c['conflict_id']} | {c['shape'][:70]} | " + "; ".join(
                f"{l}:{g['count']}:{','.join(g['rules'])}" for l, g in c["labels"].items()))
        lines += ["", "KNOWN LABELS: " + ", ".join(p["existing_labels"])]
        return "\n".join(lines)

    def get_cluster(self, cluster_id: str) -> str:
        """Full examples (up to 8, up to 3000 chars each) and all JSON keys for one residue cluster."""
        c = self.clusters.get(cluster_id)
        if not c:
            return f"ERROR: unknown cluster {cluster_id}"
        return json.dumps({k: c[k] for k in ("cluster_id", "count", "shape", "member_shapes", "examples")}
                          | ({"all_keys": c["all_keys"]} if "all_keys" in c else {}), indent=1)

    def get_conflict(self, conflict_id: str) -> str:
        """Labels, rule ids and examples for one conflict."""
        c = self.conflicts.get(conflict_id)
        if not c:
            return f"ERROR: unknown conflict {conflict_id}"
        return json.dumps({"conflict_id": conflict_id, "shape": c["shape"],
                           "labels": {l: {"count": g["count"], "rules": g["rules"], "examples": g["examples"]}
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

    def get_label_examples(self, label: str) -> str:
        """Stored examples for a label: confirmed (learner-attributed, trusted) and observed (seen at match
        time; may include lines an over-reaching rule wrongly claimed)."""
        conf = self.store.label_examples(confirmed_only=True).get(label, [])
        obs = [e for e in self.store.label_examples().get(label, []) if e not in conf]
        if not conf and not obs:
            return f"no examples for {label!r}"
        return json.dumps({"confirmed": [e[:600] for e in conf[:8]], "observed": [e[:600] for e in obs[:8]]}, indent=1)

    def route(self, text: str) -> str:
        """Which existing rule would claim this text (after unwrapping), and via which view."""
        payload, layers, views = self.engine.unwrap.views(text)
        r, vi = self.store.match_views(views)
        if r is None:
            return f"no rule matches (layers={layers})"
        return f"{r['id']} {r['label']} (view {vi}, layers={layers}) pattern={r['pattern']!r}"

    def test_pattern(self, pattern: str, flags: str = "", label: str = "") -> str:
        """Dry-run a regex (Python re.search). Reports matches per residue cluster, matches on stored
        examples of other labels (collisions), and speed. Run this before proposing."""
        texts = [i["payload"] for i in self.residual]
        bank = [(l, e, "confirmed") for l, exs in self.store.label_examples(confirmed_only=True).items() for e in exs]
        bank += [(l, e, "observed") for l, exs in self.store.label_examples().items() for e in exs]
        t0 = time.time()
        hits, err = safe_match(pattern, flags, texts + [e for _, e, _ in bank])
        if err:
            return f"ERROR: {err}"
        dt = time.time() - t0
        rh, bh = hits[:len(texts)], hits[len(texts):]
        per_cluster = {}
        shape_to_cid = {s: cid for cid, c in self.clusters.items() for s in c.get("member_shapes", [c["shape"]])}
        for item, h in zip(self.residual, rh):
            cid = shape_to_cid.get(item["shape"], "unclustered")
            tot, m = per_cluster.get(cid, (0, 0))
            per_cluster[cid] = (tot + 1, m + h)
        matched = {cid: f"{m}/{tot}" for cid, (tot, m) in sorted(per_cluster.items()) if m}
        coll = sorted({f"{l}({kind})" for (l, _, kind), h in zip(bank, bh) if h and l != label})
        return json.dumps({"residue_lines_matched": sum(rh), "clusters_matched": matched,
                           "collides_with_stored_examples_of": coll,
                           "ms_per_1k_lines": round(dt / max(1, len(hits)) * 1e6, 1)}, indent=1)

    # -- proposals ----------------------------------------------------------
    def propose_rule(self, label: str, pattern: str, explains_clusters: list[str], rationale: str,
                     format: str = "", flags: str = "", confidence: str = "medium",
                     priority_before: str = "") -> str:
        """Add a new rule to the draft. label: lowercase vendor_product (reuse a known label when it is the
        same product). explains_clusters: cluster ids it covers. priority_before: optional rule id to place
        this rule directly above (only when an existing rule would otherwise claim these lines)."""
        ex = [e for cid in explains_clusters for e in self.clusters.get(cid, {}).get("examples", [])]
        if not ex:
            return "ERROR: explains_clusters names no known cluster"
        hits, err = safe_match(pattern, flags, ex)
        if err:
            return f"ERROR: {err}"
        if not any(hits):
            return "ERROR: pattern matches none of the examples of the clusters it claims"
        rule = {"label": label, "pattern": pattern, "flags": flags, "format": format,
                "confidence": confidence, "explains_clusters": explains_clusters, "rationale": rationale}
        if priority_before:
            rule["priority_before"] = priority_before
        self.draft_rules.append(rule)
        self._persist()
        return f"drafted rule #{len(self.draft_rules) - 1} for {label}: matches {sum(hits)}/{len(ex)} claimed examples"

    def propose_update(self, rule_id: str, owner_label: str, fixes_conflicts: list[str], rationale: str,
                       priority_before: str = "", pattern: str = "", status: str = "") -> str:
        """Change an existing rule to settle conflicts: move it (priority_before), narrow it (pattern), or
        retire it (status="disabled"). owner_label: the label that really produced the conflict lines."""
        if not (priority_before or pattern or status):
            return "ERROR: give priority_before, pattern or status"
        if pattern:
            _, err = safe_match(pattern, "", ["x"])
            if err:
                return f"ERROR: {err}"
        u = {"id": rule_id, "owner_label": owner_label, "fixes_conflicts": fixes_conflicts, "rationale": rationale}
        u.update({k: v for k, v in (("priority_before", priority_before), ("pattern", pattern), ("status", status)) if v})
        self.draft_updates.append(u)
        self._persist()
        return f"drafted update #{len(self.draft_updates) - 1} for {rule_id}"

    def mark_unidentifiable(self, cluster_ids: list[str], reason: str) -> str:
        """Record clusters that cannot be attributed to a vendor (better than a guessed rule)."""
        for cid in cluster_ids:
            self.unidentifiable[cid] = reason
        self._persist()
        return f"marked {len(cluster_ids)} clusters unidentifiable"

    def submit(self) -> str:
        """Validate all drafted rules/updates and merge the accepted ones into the rule store. Returns
        accepted/rejected with reasons; fix rejected ones and submit again if useful."""
        if self.submits >= self.max_submits:
            return "ERROR: submit limit reached; finish with your summary"
        self.submits += 1
        cand = {"rules": self.draft_rules, "rule_updates": self.draft_updates,
                "unidentifiable": list(self.unidentifiable)}
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
        self.residual = self.engine.load_residual()
        return json.dumps({"accepted": rep["accepted"], "rejected": rep["rejected"],
                           "updates_applied": rep["updated"], "updates_refused": rep["rejected_updates"],
                           "disputed": rep["disputed"],
                           "held_for_human_review": sorted(new_labels),
                           "residue_drained": moved, "residue_left": left}, indent=1)

    def tool_functions(self):
        return [self.overview, self.get_cluster, self.get_conflict, self.list_rules, self.get_label_examples,
                self.route, self.test_pattern, self.propose_rule, self.propose_update,
                self.mark_unidentifiable, self.submit]


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
    if not tools.packet["clusters"] and not tools.packet["conflicts"]:
        return {"skipped": "no residue or conflicts"}
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
            "unidentifiable": len(tools.unidentifiable), "usage": usage, "summary": summary,
            "stop_reason": final.stop_reason if final else None}
