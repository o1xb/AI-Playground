"""Peel transport envelopes (collector JSON, syslog relays) to reach the payload the device produced."""
import json
import re

DEFAULT_WRAPPERS = {
    # JSON envelopes: if the object has these keys, descend into `field`.
    "json_envelopes": [
        {"name": "filebeat", "requires": ["@timestamp", "message"], "field": "message"},
        {"name": "event_original", "requires": ["event"], "field": "event.original"},
        {"name": "rawmsg", "requires": ["rawmsg"], "field": "rawmsg"},
        # REST/API pagers that repeat page metadata on every event: descend into the event object.
        {"name": "api_page", "requires": ["data", "metadata"], "field": "data", "object": True},
        {"name": "api_page", "requires": ["data", "meta"], "field": "data", "object": True},
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


# Device syslog header: <PRI>[version ]timestamp [host] -- stripped only as a *fallback view*, so
# ^-anchored rules can still match while rules keyed on the header keep seeing the full payload.
_SYSLOG_HDR = re.compile(
    r"^(?:<\d{1,3}>)?(?:\d )?"
    r"(?:(?:[A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d+)?)"
    r"|(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?))"
    r"(?: [A-Za-z0-9][\w.:-]*)?:? ")
_PRI_ONLY = re.compile(r"^<\d{1,3}>(?:(?:\d{1,3}\.){3}\d{1,3}:? |[\w.-]+: )?")


def strip_header(s):
    m = _SYSLOG_HDR.match(s)
    if m and m.end() < len(s):
        return s[m.end():]
    m = _PRI_ONLY.match(s)
    if m:
        return s[m.end():]
    return None


class Unwrapper:
    def __init__(self, cfg=None):
        cfg = {**DEFAULT_WRAPPERS, **(cfg or {})}
        self.envs = cfg["json_envelopes"]
        self.max_layers = cfg["max_layers"]
        self.relay = re.compile(
            r"^<\d{1,3}>(?:\d )?(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (?:"
            + cfg["relay_hosts"] + r") ")

    def views(self, line):
        """Texts to try, in order: innermost payload, payload without syslog header, then each outer
        layer (vendor signal sometimes sits only in an envelope, e.g. an API page's `links`)."""
        payload, layers, outer = self._peel(line)
        out = [payload]
        h = strip_header(payload)
        if h:
            out.append(h)
        out += [o for o in reversed(outer) if o not in out]
        return payload, layers, out

    def __call__(self, line):
        payload, layers, _ = self._peel(line)
        return payload, layers

    def _peel(self, line):
        s, layers, outer = line, [], []
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
                            if e.get("object") and isinstance(v, dict) and v:
                                v = json.dumps(v)
                            if isinstance(v, str):
                                outer.append(s); layers.append(e["name"]); s = v; hit = True
                                break
                    if hit:
                        continue
            m = self.relay.match(s)
            if m:
                layers.append("relay"); s = s[m.end():]
                continue
            break
        return s, layers, outer
