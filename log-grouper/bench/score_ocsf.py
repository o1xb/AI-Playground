"""Score extraction + OCSF mapping on the held-out test split against Elastic's expected ECS output.

For each test line: route label -> our parser -> our OCSF mapping -> OCSF event. Then, for each ECS
field Elastic extracted, check whether our OCSF event carries the same value in the corresponding
OCSF attribute(s). Also reports parse rate and OCSF schema validity.

  python3 bench/score_ocsf.py <bench dir>/test.jsonl <parser+mapping store dir> [report.json]
"""
import collections
import datetime as dt
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from loggrouper.ocsf.mapping import apply_mapping, prepare
from loggrouper.ocsf.schema import Schema
from loggrouper.parse.executor import run_parser, select_parser
from loggrouper.parse.store import MappingStore, ParserStore
from loggrouper.parse.validate import FAILURE_TAGS

# ECS field -> OCSF attribute candidates (any match counts)
PAIRS = {
    "source.ip": ["src_endpoint.ip"],
    "source.port": ["src_endpoint.port"],
    "destination.ip": ["dst_endpoint.ip"],
    "destination.port": ["dst_endpoint.port"],
    "source.mac": ["src_endpoint.mac"],
    "destination.mac": ["dst_endpoint.mac"],
    "network.transport": ["connection_info.protocol_name"],
    "user.name": ["actor.user.name", "user.name", "src_endpoint.owner.name"],
    "source.user.name": ["actor.user.name", "user.name"],
    "url.original": ["url.url_string", "http_request.url.url_string"],
    "url.domain": ["url.hostname", "http_request.url.hostname", "dst_endpoint.hostname", "dst_endpoint.domain"],
    "http.request.method": ["http_request.http_method"],
    "http.response.status_code": ["http_response.code"],
    "dns.question.name": ["query.hostname"],
    "source.bytes": ["traffic.bytes_out"],
    "destination.bytes": ["traffic.bytes_in"],
    "network.bytes": ["traffic.bytes"],
    "observer.hostname": ["device.hostname", "device.name"],
    "rule.name": ["firewall_rule.name", "policy.name", "rule.name"],
    "@timestamp": ["time"],
}


def get(d, path):
    cur = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, dict) and path in cur:      # ECS docs sometimes use dotted keys
            return cur[path]
        else:
            return None
    return cur


def norm(field, v):
    if v is None:
        return None
    if isinstance(v, list):
        return [norm(field, x) for x in v]
    s = str(v).strip()
    if field.endswith(".ip"):
        try:
            return str(ipaddress.ip_address(s.split("%")[0]))
        except ValueError:
            return s.lower()
    if field.endswith(".mac"):
        return s.lower().replace("-", ":")
    if field.endswith((".port", ".bytes", "status_code")):
        try:
            return int(float(s))
        except ValueError:
            return s
    return s.lower()


def ts_seconds(v):
    if isinstance(v, (int, float)):
        return int(v // 1000)
    try:
        return int(dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def main():
    test, store_dir = sys.argv[1], sys.argv[2]
    parsers, maps, schema = ParserStore(store_dir), MappingStore(store_dir), Schema()
    prepared = {m["parser_id"]: prepare(m, schema) for m in maps.active()}
    per = collections.defaultdict(lambda: {"lines": 0, "parsed": 0, "mapped": 0, "valid": 0,
                                           "fields": collections.Counter(), "match": collections.Counter(),
                                           "wrong": collections.Counter(), "examples_wrong": []})
    classes = collections.defaultdict(collections.Counter)
    for line in open(test):
        r = json.loads(line)
        lab = r["label"]
        s = per[lab]
        s["lines"] += 1
        p = select_parser(parsers.ordered(lab), r["message"])
        if p is None:
            continue
        ev = run_parser(p, r["message"])
        if FAILURE_TAGS & set(ev.get("tags", [])):
            continue
        s["parsed"] += 1
        m = prepared.get(p["id"])
        if m is None:
            continue
        o = apply_mapping(m, ev)
        s["mapped"] += 1
        classes[lab][o["class_uid"]] += 1
        s["valid"] += not schema.validate(o)[0]
        exp = r["expected"]
        for ecs, cands in PAIRS.items():
            ev_v = get(exp, ecs)
            if ev_v in (None, "", []):
                continue
            s["fields"][ecs] += 1
            got = [get(o, c) for c in cands]
            got = [g for g in got if g not in (None, "", [])]
            if ecs == "@timestamp":
                e_s = ts_seconds(ev_v)
                ok = any(ts_seconds(g) is not None and e_s is not None and abs(ts_seconds(g) - e_s) <= 1 for g in got)
            else:
                e_n = norm(ecs, ev_v)
                e_set = set(e_n) if isinstance(e_n, list) else {e_n}
                ok = any((set(norm(ecs, g)) if isinstance(g, list) else {norm(ecs, g)}) & e_set for g in got)
            if ok:
                s["match"][ecs] += 1
            elif got:
                s["wrong"][ecs] += 1
                if len(s["examples_wrong"]) < 3:
                    s["examples_wrong"].append({"field": ecs, "expected": ev_v, "got": got[:2]})
    tot = collections.Counter()
    rows = []
    for lab, s in sorted(per.items(), key=lambda kv: -kv[1]["lines"]):
        f, mt, wr = sum(s["fields"].values()), sum(s["match"].values()), sum(s["wrong"].values())
        tot.update({"lines": s["lines"], "parsed": s["parsed"], "mapped": s["mapped"], "valid": s["valid"],
                    "fields": f, "match": mt, "wrong": wr})
        rows.append({"label": lab, "lines": s["lines"], "parse_rate": round(s["parsed"] / s["lines"], 3),
                     "mapped_rate": round(s["mapped"] / s["lines"], 3),
                     "ocsf_valid_rate": round(s["valid"] / max(1, s["mapped"]), 3),
                     "field_recall": round(mt / f, 3) if f else None,
                     "field_precision": round(mt / (mt + wr), 3) if mt + wr else None,
                     "classes": dict(classes[lab]),
                     "per_field": {k: f"{s['match'][k]}/{v} (wrong {s['wrong'][k]})" for k, v in s["fields"].items()},
                     "examples_wrong": s["examples_wrong"]})
    summary = {"lines": tot["lines"], "parse_rate": round(tot["parsed"] / max(1, tot["lines"]), 3),
               "mapped_rate": round(tot["mapped"] / max(1, tot["lines"]), 3),
               "ocsf_valid_rate": round(tot["valid"] / max(1, tot["mapped"]), 3),
               "field_recall": round(tot["match"] / max(1, tot["fields"]), 3),
               "field_precision": round(tot["match"] / max(1, tot["match"] + tot["wrong"]), 3),
               "ecs_fields_compared": tot["fields"]}
    report = {"summary": summary, "labels": rows}
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w") as f:
            json.dump(report, f, indent=1, default=str)
    print(json.dumps(summary))
    for r in rows:
        print(f"{r['label']:24s} lines={r['lines']:4d} parse={r['parse_rate']:.2f} mapped={r['mapped_rate']:.2f} "
              f"valid={r['ocsf_valid_rate']:.2f} recall={r['field_recall']} precision={r['field_precision']} classes={r['classes']}")


if __name__ == "__main__":
    main()
