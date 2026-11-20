"""Peel transport envelopes (collector JSON, syslog relays) to reach the payload the device produced."""
import json
import re

DEFAULT_WRAPPERS = {
    # JSON envelopes: if the object has these keys, descend into `field`.
    "json_envelopes": [
        {"name": "filebeat", "requires": ["@timestamp", "message"], "field": "message"},
        {"name": "event_original", "requires": ["event"], "field": "event.original"},
        {"name": "rawmsg", "requires": ["rawmsg"], "field": "rawmsg"},
    ],
    # Syslog relays: only peel when the relay hostname matches (so device syslog headers are kept).
    "relay_hosts": r"collector-\d+|relay\S*|syslog-ng\S*|rsyslog\S*|logstash\S*",
    "max_layers": 6,
}


def _get(d, path):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return None
        d = d[part]
    return d


class Unwrapper:
    def __init__(self, cfg=None):
        cfg = {**DEFAULT_WRAPPERS, **(cfg or {})}
        self.envs = cfg["json_envelopes"]
        self.max_layers = cfg["max_layers"]
        self.relay = re.compile(
            r"^<\d{1,3}>(?:\d )?(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (?:"
            + cfg["relay_hosts"] + r") ")

    def __call__(self, line):
        s, layers = line, []
        for _ in range(self.max_layers):
            t = s.strip()
            if t.startswith("{"):
                try:
                    d = json.loads(t)
                except ValueError:
                    d = None
                if isinstance(d, dict):
                    hit = False
                    for e in self.envs:
                        if all(k in d for k in e["requires"]):
                            v = _get(d, e["field"])
                            if isinstance(v, str):
                                layers.append(e["name"]); s = v; hit = True
                                break
                    if hit:
                        continue
            m = self.relay.match(s)
            if m:
                layers.append("relay"); s = s[m.end():]
                continue
            break
        return s, layers
