"""Batch engine: unwrap -> rule fast-path -> grouped output; unmatched lines go to a residue buffer."""
import collections
import json
import os
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
        payload, layers = self.unwrap(raw)
        r = self.store.match(payload)
        rec = {"offset": offset, "layers": layers, "raw": raw}
        if r is None:
            return None, payload, rec
        self.store.record_hit(r, payload)
        rec.update(label=r["label"], rule=r["id"], format=r.get("format"), confidence=r["confidence"])
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

    def build_packet(self, max_clusters=80, examples=4, max_chars=700):
        """Compress the residue to one entry per shape cluster: this is all the learner ever sees."""
        groups = collections.defaultdict(list)
        for item in self.load_residual():
            groups[item["shape"]].append(item["payload"])
        clusters = []
        for i, (shp, payloads) in enumerate(sorted(groups.items(), key=lambda kv: -len(kv[1]))[:max_clusters]):
            uniq = list(dict.fromkeys(payloads))
            step = max(1, len(uniq) // examples)
            clusters.append({"cluster_id": f"c{i:03d}", "shape": shp, "count": len(payloads),
                             "examples": [p[:max_chars] for p in uniq[::step][:examples]]})
        return {
            "residual_lines": sum(len(v) for v in groups.values()),
            "clusters_total": len(groups),
            "clusters": clusters,
            "existing_labels": self.store.labels(),
            "existing_rules": [{"label": r["label"], "pattern": r["pattern"], "format": r.get("format")}
                               for _, r in self.store.compiled],
            "previously_rejected": self.store.rejected["rejected"][-50:],
        }
