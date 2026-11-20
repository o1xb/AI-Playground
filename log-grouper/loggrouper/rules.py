"""Persistent, versioned rule store. Rules are data (JSON), so every run reuses what earlier runs learned."""
import datetime
import json
import os
import re

FLAGS = {"i": re.I, "m": re.M, "s": re.S}
MAX_EXAMPLES = 5


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def compile_rule(r):
    f = 0
    for c in r.get("flags", ""):
        f |= FLAGS[c]
    return re.compile(r["pattern"], f)


class RuleStore:
    """rules.json      – active + candidate rules, ordered by priority (first match wins)
       rejected.json   – proposals that failed validation (fed back to the learner so it doesn't repeat them)
       wrappers.json   – optional envelope config for the unwrapper"""

    def __init__(self, path):
        self.path = path
        os.makedirs(path, exist_ok=True)
        self.rules = self._load("rules.json", {"version": 0, "rules": []})
        self.rejected = self._load("rejected.json", {"rejected": []})
        self.wrappers = self._load("wrappers.json", None)
        self._compile()

    def _load(self, name, default):
        p = os.path.join(self.path, name)
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
        return default

    def _compile(self):
        act = [r for r in self.rules["rules"] if r.get("status", "active") == "active"]
        act.sort(key=lambda r: (r["priority"], r["id"]))
        self.compiled = [(compile_rule(r), r) for r in act]

    def save(self):
        self.rules["version"] += 1
        self.rules["updated"] = now()
        for name, obj in (("rules.json", self.rules), ("rejected.json", self.rejected)):
            tmp = os.path.join(self.path, name + ".tmp")
            with open(tmp, "w") as f:
                json.dump(obj, f, indent=1)
            os.replace(tmp, os.path.join(self.path, name))
        self._compile()

    # -- matching -----------------------------------------------------------
    def match(self, payload):
        for rx, r in self.compiled:
            if rx.search(payload):
                return r
        return None

    # -- mutation -----------------------------------------------------------
    def next_id(self):
        n = max([int(r["id"][1:]) for r in self.rules["rules"]] or [0])
        return f"r{n + 1:05d}"

    def next_priority(self):
        # learned rules go after everything known, so they can only claim lines nothing else matched
        return max([r["priority"] for r in self.rules["rules"]] or [0]) + 10

    def add(self, rule, origin):
        r = {"id": self.next_id(), "label": rule["label"], "pattern": rule["pattern"],
             "flags": rule.get("flags", ""), "confidence": rule.get("confidence", "medium"),
             "format": rule.get("format"), "priority": rule.get("priority") or self.next_priority(),
             "status": rule.get("status", "active"), "origin": origin, "created": now(),
             "hits": 0, "examples": rule.get("examples", [])[:MAX_EXAMPLES],
             "rationale": rule.get("rationale", "")}
        self.rules["rules"].append(r)
        return r

    def reject(self, rule, reason, origin):
        self.rejected["rejected"].append({**{k: rule.get(k) for k in ("label", "pattern", "flags")},
                                          "reason": reason, "origin": origin, "at": now()})

    def record_hit(self, rule, payload):
        rule["hits"] += 1
        ex = rule.setdefault("examples", [])
        if len(ex) < MAX_EXAMPLES and payload[:400] not in ex:
            ex.append(payload[:400])

    def labels(self):
        return sorted({r["label"] for r in self.rules["rules"] if r.get("status", "active") == "active"})

    def label_examples(self):
        out = {}
        for r in self.rules["rules"]:
            if r.get("status", "active") == "active":
                out.setdefault(r["label"], []).extend(r.get("examples", []))
        return out
