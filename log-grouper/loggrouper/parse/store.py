"""Versioned store for parser specs and (later) OCSF mapping specs. Same shape as the rule store:
JSON on disk, status (candidate|active|retired), origin, history, golden examples."""
import datetime
import json
import os


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class SpecStore:
    def __init__(self, path, filename, key):
        self.path, self.file, self.key = path, os.path.join(path, filename), key
        os.makedirs(path, exist_ok=True)
        if os.path.exists(self.file):
            with open(self.file) as f:
                self.data = json.load(f)
        else:
            self.data = {"version": 0, key: [], "rejected": []}

    @property
    def items(self):
        return self.data[self.key]

    def save(self):
        self.data["version"] += 1
        self.data["updated"] = now()
        tmp = self.file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.file)

    def by_id(self, i):
        return next((x for x in self.items if x["id"] == i), None)

    def active(self, label=None):
        return [x for x in self.items if x.get("status", "active") == "active" and (label is None or x["label"] == label)]

    def next_id(self, prefix):
        n = max([int(x["id"][len(prefix):]) for x in self.items if x["id"].startswith(prefix)
                 and x["id"][len(prefix):].isdigit()] or [0])
        return f"{prefix}{n + 1:05d}"

    def reject(self, spec, reason, origin):
        self.data["rejected"].append({"spec": spec, "reason": reason, "origin": origin, "at": now()})


class ParserStore(SpecStore):
    def __init__(self, path):
        super().__init__(path, "parsers.json", "parsers")

    def ordered(self, label):
        """Active parsers of a label in selection order (first `when` match wins)."""
        return sorted(self.active(label), key=lambda p: (p.get("order", 1000), p["id"]))

    def all_ordered(self):
        out = []
        for label in sorted({p["label"] for p in self.active()}):
            out += self.ordered(label)
        return out


class MappingStore(SpecStore):
    def __init__(self, path):
        super().__init__(path, "mappings.json", "mappings")

    def for_parser(self, parser_id):
        return next((m for m in self.active() if m["parser_id"] == parser_id), None)
