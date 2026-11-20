"""Batch engine: unwrap -> rule fast-path -> grouped output; unmatched lines go to a residue buffer."""
import collections
import json
import os
import re
import time

from .templates import shape
from .unwrap import Unwrapper


class Engine:
    def __init__(self, store, out_dir, state_dir):
        self.store, self.out_dir, self.state_dir = store, out_dir, state_dir
        os.makedirs(os.path.join(out_dir, "groups"), exist_ok=True)
        os.makedirs(state_dir, exist_ok=True)
        self.unwrap = Unwrapper(store.wrappers)
        self.residual_path = os.path.join(state_dir, "residual.jsonl")
        self.ckpt_path = os.path.join(state_dir, "checkpoint.json")
        self._fh = {}

    # -- outputs (file sink; in production swap for a producer to topic logs.<label>) --------------
    def _emit(self, label, rec):
        fh = self._fh.get(label)
        if fh is None:
            fh = self._fh[label] = open(os.path.join(self.out_dir, "groups", f"{label}.jsonl"), "a")
        fh.write(json.dumps(rec) + "\n")

    def close(self):
        for fh in self._fh.values():
            fh.close()
        self._fh.clear()

    def checkpoint(self):
        if os.path.exists(self.ckpt_path):
            with open(self.ckpt_path) as f:
                return json.load(f)
        return {"next_offset": 0, "batches": 0}

    def _save_ckpt(self, ck):
        with open(self.ckpt_path, "w") as f:
            json.dump(ck, f)

    def classify(self, offset, raw):
        payload, layers, views = self.unwrap.views(raw)
        r, vi = self.store.match_views(views)
        rec = {"offset": offset, "layers": layers, "raw": raw}
        if r is None:
            return None, payload, rec
        self.store.record_hit(r, views[vi])
        rec.update(label=r["label"], rule=r["id"], format=r.get("format"), confidence=r["confidence"])
        if vi:
            rec["matched_view"] = vi      # 1 = header-stripped, 2+ = an outer envelope
        return r, payload, rec

    def process_batch(self, base_offset, lines):
        t0 = time.time()
        stats = collections.Counter()
        with open(self.residual_path, "a") as res:
            for i, raw in enumerate(lines):
                off = base_offset + i
                r, payload, rec = self.classify(off, raw)
                if r is None:
                    stats["residual"] += 1
                    res.write(json.dumps({"offset": off, "raw": raw, "payload": payload,
                                          "shape": shape(payload)}) + "\n")
                else:
                    stats["matched"] += 1
                    self._emit(r["label"], rec)
        self.store.save()           # persists hit counts / examples
        ck = self.checkpoint()
        ck["next_offset"] = base_offset + len(lines)
        ck["batches"] += 1
        self._save_ckpt(ck)         # == Kafka offset commit point
        stats["seconds"] = round(time.time() - t0, 3)
        return dict(stats)

    # -- residue ------------------------------------------------------------
    def load_residual(self):
        if not os.path.exists(self.residual_path):
            return []
        with open(self.residual_path) as f:
            return [json.loads(l) for l in f if l.strip()]

    def reclassify_residual(self):
        """After new rules land, drain the residue buffer through the fast path again."""
        left, moved = [], 0
        for item in self.load_residual():
            r, payload, rec = self.classify(item["offset"], item["raw"])
            if r is None:
                left.append(item)
            else:
                moved += 1
                self._emit(r["label"], rec)
        with open(self.residual_path, "w") as f:
            for item in left:
                f.write(json.dumps(item) + "\n")
        self.store.save()
        return moved, len(left)

    def find_conflicts(self, min_count=2, max_conflicts=20):
        """Structured message shapes (JSON key sets, key=value, CSV) that ended up in more than one
        group. One shape normally means one producer, so this usually exposes a rule that over-reaches."""
        by_shape = collections.defaultdict(lambda: collections.defaultdict(lambda: {"count": 0, "rules": collections.Counter(), "examples": []}))
        gdir = os.path.join(self.out_dir, "groups")
        for fn in sorted(os.listdir(gdir)) if os.path.isdir(gdir) else []:
            with open(os.path.join(gdir, fn)) as f:
                for line in f:
                    rec = json.loads(line)
                    payload, _ = self.unwrap(rec["raw"])
                    shp = shape(payload)
                    if not shp.startswith(("JSON{", "KV{", "CSV:")):
                        continue
                    g = by_shape[shp][rec["label"]]
                    g["count"] += 1; g["rules"][rec["rule"]] += 1
                    if len(g["examples"]) < 2:
                        g["examples"].append(payload)
        # merge structurally similar shapes (key-set Jaccard >= 0.5), then look for multi-label clusters
        merged = []                                  # [rep_shape, keyset, {label: agg}]
        for shp, labels in sorted(by_shape.items(), key=lambda kv: -sum(g["count"] for g in kv[1].values())):
            ks = _keyset(shp)
            target = None
            for m in merged:
                if (ks and m[1] and len(ks & m[1]) / len(ks | m[1]) >= 0.5) or (not ks and m[0] == shp):
                    target = m; break
            if target is None:
                target = [shp, set(ks) if ks else None, {}]; merged.append(target)
            elif ks:
                target[1] |= ks
            for l, g in labels.items():
                agg = target[2].setdefault(l, {"count": 0, "rules": collections.Counter(), "examples": []})
                agg["count"] += g["count"]; agg["rules"].update(g["rules"])
                agg["examples"] += g["examples"][:2 - len(agg["examples"])]
        out = []
        for shp, ks, labels in merged:
            big = {l: g for l, g in labels.items() if g["count"] >= min_count}
            if len(big) >= 2:
                out.append({"shape": shp, "labels": {l: {"count": g["count"], "rules": dict(g["rules"]),
                                                        "examples": [e[:1500] for e in g["examples"]],
                                                        "full_examples": g["examples"]}
                                                    for l, g in big.items()}})
        out.sort(key=lambda c: -sum(g["count"] for g in c["labels"].values()))
        for i, c in enumerate(out[:max_conflicts]):
            c["conflict_id"] = f"k{i:03d}"
        return out[:max_conflicts]

    def find_suspects(self, min_count=3, max_suspects=20):
        """Lines a rule claims that look nothing like that rule's own stored examples: JSON claimed by a
        rule whose examples are all text (or vice versa), or JSON whose keys barely overlap its examples.
        Catches broad vendor-name rules swallowing a sibling product (no conflict shows, because the
        sibling never reaches another group)."""
        prof = {}
        for _, r in self.store.compiled:
            exs = r.get("confirmed_examples") or r.get("examples", [])
            if len(exs) < 2:
                continue
            shapes = [shape(e) for e in exs]
            prof[r["id"]] = (r, [_keyset(x) for x in shapes], any(x.startswith("JSON") for x in shapes))
        found = {}
        gdir = os.path.join(self.out_dir, "groups")
        for fn in sorted(os.listdir(gdir)) if os.path.isdir(gdir) else []:
            with open(os.path.join(gdir, fn)) as f:
                for line in f:
                    rec = json.loads(line)
                    if rec["rule"] not in prof:
                        continue
                    r, keysets, has_json = prof[rec["rule"]]
                    payload, _ = self.unwrap(rec["raw"])
                    shp = shape(payload)
                    ks = _keyset(shp)
                    if shp.startswith("JSON"):
                        best = max((len(ks & k) / len(ks | k) for k in keysets if k and ks), default=0.0)
                        unlike = best < 0.15
                    else:
                        unlike = has_json and all(k for k in keysets)   # text line, rule only ever saw JSON
                    if unlike and shp in self.store.dismissed.get(rec["rule"], ()):
                        unlike = False
                    if unlike:
                        g = found.setdefault(rec["rule"], {"rule": r["id"], "label": r["label"], "pattern": r["pattern"],
                                                           "count": 0, "examples": [], "rule_examples": [e[:400] for e in
                                                           (r.get("confirmed_examples") or r.get("examples", []))[:2]]})
                        g["count"] += 1
                        g.setdefault("shapes", set()).add(shp)
                        if len(g["examples"]) < 4:
                            g["examples"].append(payload)
        out = sorted((g for g in found.values() if g["count"] >= min_count), key=lambda g: -g["count"])[:max_suspects]
        for i, g in enumerate(out):
            g["suspect_id"] = f"s{i:03d}"
        return out

    def build_packet(self, max_clusters=80, examples=4, max_chars=700, json_chars=1500):
        """Compress the residue to one entry per shape cluster: this is all the learner ever sees.
        JSON clusters whose key sets overlap strongly are merged, and carry their full key list."""
        groups = collections.defaultdict(list)
        ignored = set(self.store.unidentifiable)
        skipped = 0
        for item in self.load_residual():
            if item["shape"] in ignored:
                skipped += 1
                continue
            groups[item["shape"]].append(item["payload"])
        ordered = sorted(groups.items(), key=lambda kv: -len(kv[1]))
        merged = []                       # [shape, member_shapes, payloads, keyset]
        for shp, payloads in ordered:
            ks = _keyset(shp)
            for m in merged:
                if ks and m[3] and len(ks & m[3]) / len(ks | m[3]) >= 0.6:
                    m[1].append(shp); m[2].extend(payloads); m[3] |= ks
                    break
            else:
                merged.append([shp, [shp], list(payloads), set(ks) if ks else None])
        clusters = []
        for i, (shp, members, payloads, ks) in enumerate(merged[:max_clusters]):
            uniq = list(dict.fromkeys(payloads))
            step = max(1, len(uniq) // examples)
            lim = json_chars if shp.startswith("JSON") else max_chars
            c = {"cluster_id": f"c{i:03d}", "shape": shp, "member_shapes": members, "count": len(payloads),
                 "examples": [p[:lim] for p in uniq[::step][:examples]]}
            if shp.startswith("JSON"):
                c["all_keys"] = sorted(_json_keys(uniq[:20]))[:120]
            clusters.append(c)
        return {
            "residual_lines": sum(len(v) for v in groups.values()),
            "ignored_unidentifiable_lines": skipped,
            "clusters_total": len(merged),
            "clusters": clusters,
            "conflicts": self.find_conflicts(),
            "suspects": self.find_suspects(),
            "existing_labels": self.store.labels(),
            "existing_rules": [{"id": r["id"], "label": r["label"], "pattern": r["pattern"],
                                "priority": r["priority"], "format": r.get("format")}
                               for _, r in self.store.compiled],
            "previously_rejected": self.store.rejected["rejected"][-50:],
        }


def _keyset(shp):
    if shp.startswith(("JSON{", "JSON~{", "KV{")):
        inner = shp[shp.index("{") + 1:-1]
        return {k for k in inner.split(",") if k}
    return None


def _json_keys(payloads, depth=2):
    keys = set()

    def walk(d, prefix, lvl):
        if isinstance(d, dict) and lvl < depth:
            for k, v in d.items():
                keys.add(prefix + k)
                walk(v, prefix + k + ".", lvl + 1)
    for p in payloads:
        try:
            walk(json.loads(p), "", 0)
        except ValueError:
            keys.update(re.findall(r'"([A-Za-z_@][\w.@-]{0,40})"\s*:', p))
    return keys
