"""Build a mixed, realistically-wrapped test stream + hidden answer key from Elastic integration test logs.

  git clone --depth 1 --filter=blob:none --no-checkout https://github.com/elastic/integrations.git ei
  cd ei && git sparse-checkout init --no-cone
  printf '/packages/%s/data_stream/*/_dev/test/pipeline/test-*.log\n' cisco_asa panw ... > .git/info/sparse-checkout
  git checkout HEAD
  python3 -I build_stream.py ei/packages out_dir --seed 7 [--exclude-key earlier/labels.jsonl --exclude-stream earlier.dump]

Writes out_dir/stream.dump (feed this to the grouper) and out_dir/answer_key/labels.jsonl (keep it away from agents).
Wrapping: ~40% raw, 25% syslog relay header, 30% Filebeat JSON envelope, 5% truncated.
"""
import argparse, datetime, glob, json, os, random, re
from collections import Counter

HEAVY = {"cisco_asa", "cisco_ftd", "fortinet_fortigate", "panw", "checkpoint", "juniper_srx", "sonicwall_firewall",
         "pfsense", "sophos", "watchguard_firebox", "f5_bigip", "zscaler_zia", "system", "iptables", "cisco_ios", "suricata"}


def first_line_pattern(logfile):
    """elastic-package multiline config: test-X.log-config.yml, else test-common-config.yml."""
    d = os.path.dirname(logfile)
    for cfg in (logfile + "-config.yml", os.path.join(d, "test-common-config.yml")):
        if os.path.exists(cfg):
            txt = open(cfg).read()
            if "multiline" in txt:
                m = re.search(r"first_line_pattern:\s*(['\"])(.*?)\1\s*$", txt, re.M)
                if m:
                    pat = m.group(2)
                    return pat.encode().decode("unicode_escape") if m.group(1) == '"' else pat
    return None


def records(logfile):
    """Whole records, as a shipper would deliver them (multiline assembled), not raw file lines."""
    pat = first_line_pattern(logfile)
    rx = re.compile(pat) if pat else None
    out, cur = [], None
    for l in open(logfile, errors="replace"):
        l = l.rstrip("\r\n")
        if rx is None:
            out.append(l); continue
        if rx.search(l) or cur is None:
            if cur is not None:
                out.append(cur)
            cur = l
        else:
            cur += "\n" + l
    if cur is not None:
        out.append(cur)
    return out


def lines(pkgdir, pkg):
    out = []
    for f in sorted(glob.glob(f"{pkgdir}/{pkg}/data_stream/*/_dev/test/pipeline/test-*.log")):
        ds = f.split("/data_stream/")[1].split("/")[0]
        for l in records(f):
            if len(l.strip()) >= 15:
                out.append((ds, l))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pkgdir"); ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--cap-heavy", type=int, default=150); ap.add_argument("--cap", type=int, default=40)
    ap.add_argument("--exclude-payloads", help="payloads.txt from an earlier build: leave those records out")
    ap.add_argument("--packages", help="comma-separated package subset (default: all in pkgdir)")
    a = ap.parse_args()
    R = random.Random(a.seed)
    skip = {json.loads(l) for l in open(a.exclude_payloads)} if a.exclude_payloads else set()
    rows = []
    pkgs = a.packages.split(",") if a.packages else sorted(os.listdir(a.pkgdir))
    for pkg in pkgs:
        L = [(ds, l) for ds, l in lines(a.pkgdir, pkg) if l not in skip]
        R.shuffle(L)
        rows += [(pkg, ds, l) for ds, l in L[:a.cap_heavy if pkg in HEAVY else a.cap]]
    R.shuffle(rows)
    os.makedirs(a.out + "/answer_key", exist_ok=True)
    t0 = datetime.datetime(2026, 11, 20, 9, 0, 0)
    tc = Counter()
    with open(a.out + "/stream.dump", "w") as out, open(a.out + "/answer_key/labels.jsonl", "w") as key, \
            open(a.out + "/answer_key/payloads.txt", "w") as pay:
        for i, (pkg, ds, l) in enumerate(rows, 1):
            pay.write(json.dumps(l) + "\n")
            r = R.random(); ts = t0 + datetime.timedelta(milliseconds=i * 137)
            multiline = "\n" in l
            if multiline:
                try:                      # pretty-printed JSON: ship compact, like a JSON codec would
                    l = json.dumps(json.loads(l)); multiline = False
                except ValueError:
                    pass
            if multiline:                 # other multiline records only survive inside an envelope
                r = 0.99
            if r < 0.05 and len(l) > 80:
                l = l[:int(len(l) * R.uniform(.4, .9))]; tr = "truncated"
            elif r < 0.45 and not multiline:
                tr = "raw"
            elif r < 0.70 and not multiline:
                tr = "relay"; l = f"<{R.choice([13, 14, 134, 189])}>{ts.strftime('%b %d %H:%M:%S')} collector-0{R.randint(1, 4)} {l}"
            else:
                tr = "filebeat"
                l = json.dumps({"@timestamp": ts.isoformat() + "Z", "agent": {"type": "filebeat", "version": "8.15.0"},
                                "input": {"type": R.choice(["udp", "tcp", "kafka"])},
                                "log": {"source": {"address": f"10.20.{R.randint(0, 9)}.{R.randint(2, 250)}:514"}},
                                "message": l})
            tc[tr] += 1
            out.write(l + "\n")
            key.write(json.dumps({"line": i, "vendor": pkg, "data_stream": ds, "transport": tr,
                                  "seen_vendor": True}) + "\n")
    print(len(rows), "lines,", len({p for p, _, _ in rows}), "vendors,", dict(tc))


if __name__ == "__main__":
    main()
