"""Parser-author agent: writes one parser spec per message format of each label, validated on the
label's samples and checked against real Logstash before activation."""
import collections
import hashlib
import json
import os
import time

from ..agent_runtime import CodeTools, load_prompts, run_tool_agent
from ..templates import shape
from ..unwrap import Unwrapper
from .executor import select_parser
from .logstash import conformance
from .store import ParserStore
from .validate import (FAILURE_TAGS, claimed, flatten, golden_regressions, metrics, output_of,
                       pick_golden, verdict)

MAX_SAMPLES_PER_LABEL = 2000


def load_samples(groups_dir, labels=None):
    """groups/<label>.jsonl records (grouper output) -> {label: [unwrapped payloads]} (deduplicated)."""
    u = Unwrapper()
    out = {}
    for fn in sorted(os.listdir(groups_dir)):
        label = fn[:-6]
        if labels and label not in labels:
            continue
        seen = {}
        with open(os.path.join(groups_dir, fn)) as f:
            for line in f:
                rec = json.loads(line)
                p = rec.get("message") or u(rec["raw"])[0]
                seen.setdefault(p, None)
                if len(seen) >= MAX_SAMPLES_PER_LABEL:
                    break
        out[label] = list(seen)
    return out


def _cid(label, shp):
    return "f" + hashlib.sha1(f"{label}|{shp}".encode()).hexdigest()[:6]


class ParserTools(CodeTools):
    def __init__(self, store_path, groups_dir, labels=None, logstash_home=None, enable_code=False,
                 workspace=None, sandbox_backend="unshare", max_submits=12, drafts_path=None):
        self.store = ParserStore(store_path)
        self.samples = load_samples(groups_dir, labels)
        self.logstash_home = logstash_home
        self.max_submits, self.submits = max_submits, 0
        self.drafts = []
        self.drafts_path = drafts_path
        if drafts_path and os.path.exists(drafts_path):
            with open(drafts_path) as f:
                d = json.load(f)
            self.drafts, self.submits = d["drafts"], d["submits"]
        self.reports = []
        self._init_code(enable_code, workspace, sandbox_backend, [store_path, groups_dir])
        if enable_code:
            self._write_workspace()

    # ---------------------------------------------------------------- helpers
    def _persist(self):
        if self.drafts_path:
            with open(self.drafts_path, "w") as f:
                json.dump({"drafts": self.drafts, "submits": self.submits}, f)

    def _write_workspace(self):
        ws = self.workspace
        os.makedirs(os.path.join(ws, "samples"), exist_ok=True)
        for label, msgs in self.samples.items():
            with open(os.path.join(ws, "samples", f"{label}.jsonl"), "w") as f:
                f.writelines(json.dumps(m) + "\n" for m in msgs)
        with open(os.path.join(ws, "parsers.json"), "w") as f:
            json.dump(self.store.active(), f, indent=1)
        with open(os.path.join(ws, "README.txt"), "w") as f:
            f.write("This directory is the cwd and persists between calls; /tmp inside the sandbox does not.\n"
                    "samples/<label>.jsonl  one JSON string per line: the unwrapped message\n"
                    "parsers.json           active parser specs\n"
                    "lib/loggrouper         from loggrouper.parse.executor import run_parser; "
                    "from loggrouper.parse.validate import metrics\n")

    def _status(self, label):
        """-> (parsed_ok, failing, unparsed) message lists under the current active parsers."""
        ps = self.store.ordered(label)
        ok, failing, unparsed = [], [], []
        for m in self.samples.get(label, []):
            p = select_parser(ps, m)
            if p is None:
                unparsed.append(m)
            elif FAILURE_TAGS & set(output_of(p, m)["tags"]):
                failing.append(m)
            else:
                ok.append(m)
        return ok, failing, unparsed

    def _spec(self, spec_json):
        spec = json.loads(spec_json) if isinstance(spec_json, str) else spec_json
        if not isinstance(spec, dict) or "label" not in spec or not isinstance(spec.get("steps"), list):
            raise ValueError("spec needs at least {label, format, steps: [...]}")
        if spec["label"] not in self.samples:
            raise ValueError(f"unknown label {spec['label']}")
        return spec

    def _placed(self, spec, before=""):
        """The label's parser list with this spec inserted where it would go."""
        ps = [p for p in self.store.ordered(spec["label"]) if p["id"] != spec.get("id")]
        ps += [d["spec"] for d in self.drafts if d["spec"]["label"] == spec["label"] and d["spec"] is not spec
               and d["spec"].get("id") != spec.get("id")]
        ps.sort(key=lambda p: p.get("order", 1000))
        if spec.get("fallback"):
            if spec.get("when"):
                raise ValueError("a fallback parser must not have `when` (it catches whatever no other parser takes)")
            spec["order"] = 99999
        elif before:
            b = next((p for p in ps if p["id"] == before), None)
            if b is None:
                raise ValueError(f"unknown parser id {before}")
            spec["order"] = b.get("order", 1000) - 0.5
        elif "order" not in spec:
            spec["order"] = max([p.get("order", 1000) for p in ps] or [990]) + 10
        ps.append(spec)
        ps.sort(key=lambda p: (p.get("order", 1000), p.get("id", "~")))
        return ps

    # ---------------------------------------------------------------- read tools
    def overview(self) -> str:
        """Start here. Per label: samples, active parsers, and how many samples parse cleanly today."""
        rows = ["label | samples | parsers | parsed_ok | failing | no_parser"]
        for label in sorted(self.samples):
            ok, bad, none = self._status(label)
            rows.append(f"{label} | {len(self.samples[label])} | {len(self.store.ordered(label))} | "
                        f"{len(ok)} | {len(bad)} | {len(none)}")
        return "\n".join(rows)

    def label_overview(self, label: str, limit: int = 25, width: int = 160) -> str:
        """Message formats (shape clusters) of a label that are not parsed cleanly yet, plus its active
        parsers and how they perform. Cluster ids are stable."""
        if label not in self.samples:
            return f"ERROR: unknown label {label}"
        ok, bad, none = self._status(label)
        cl = collections.OrderedDict()
        for m in bad + none:
            cl.setdefault(shape(m, tokens=5), []).append(m)
        lines = [f"{label}: {len(self.samples[label])} samples, {len(ok)} parsed ok, {len(bad)} failing, "
                 f"{len(none)} without parser", "", "UNPARSED FORMATS (id | count | shape | example):"]
        for shp, ms in sorted(cl.items(), key=lambda kv: -len(kv[1]))[:limit]:
            lines.append(f"{_cid(label, shp)} | {len(ms)} | {shp[:70]} | {ms[0][:width]!r}")
        lines += ["", "ACTIVE PARSERS (id | format | when | claimed | parse_rate):"]
        ps = self.store.ordered(label)
        for p in ps:
            mm = metrics(p, claimed(ps, p, self.samples[label]))
            lines.append(f"{p['id']} | {p.get('format')} | {p.get('when')!r} | {mm['samples']} | {mm['parse_rate']}")
        return "\n".join(lines)

    def get_samples(self, label: str, format_id: str = "", n: int = 5, max_chars: int = 1500,
                    only_unparsed: bool = True) -> str:
        """Sample messages of a label, optionally of one unparsed format (id from label_overview)."""
        if label not in self.samples:
            return f"ERROR: unknown label {label}"
        if only_unparsed:
            ok, bad, none = self._status(label)
            pool = bad + none
        else:
            pool = self.samples[label]
        if format_id:
            pool = [m for m in pool if _cid(label, shape(m, tokens=5)) == format_id]
        step = max(1, len(pool) // max(1, n))
        return json.dumps([m[:max_chars] for m in pool[::step][:n]], indent=1)

    def list_parsers(self, label: str) -> str:
        """Active parser specs of a label, in selection order."""
        return json.dumps([{k: p[k] for k in ("id", "label", "format", "when", "steps", "field_types", "order")
                            if k in p} for p in self.store.ordered(label)], indent=1)

    def try_parser(self, spec_json: str, before: str = "", show: int = 3) -> str:
        """Dry-run a parser spec (JSON string: {label, format, when?, steps, field_types}) on the samples it
        would claim at its position (appended, or before parser `before`). Returns metrics, the validator's
        verdict, failures and a few outputs."""
        try:
            spec = self._spec(spec_json)
            ps = self._placed(spec, before)
        except (ValueError, KeyError) as e:
            return f"ERROR: {e}"
        msgs = claimed(ps, spec, self.samples[spec["label"]])
        try:
            m = metrics(spec, msgs)
            if spec.get("fallback"):
                m["fallback_standalone"] = metrics(spec, self.samples[spec["label"]])
        except Exception as e:  # noqa: BLE001 - surface spec errors (bad grok, bad op) to the agent
            return f"ERROR running spec: {type(e).__name__}: {e}"
        m["verdict"] = verdict(m["fallback_standalone"] if spec.get("fallback") else m, spec) or "ok"
        m["outputs"] = [{"message": x[:300], "output": output_of(spec, x)} for x in msgs[:show]]
        return json.dumps(m, indent=1, default=str)[:12000]

    # ---------------------------------------------------------------- proposals
    def propose_parser(self, spec_json: str, rationale: str, before: str = "") -> str:
        """Draft a new parser (same spec as try_parser). It must already pass the validator on its samples."""
        try:
            spec = self._spec(spec_json)
            ps = self._placed(spec, before)
            m = metrics(spec, claimed(ps, spec, self.samples[spec["label"]]))
            if spec.get("fallback"):
                m = metrics(spec, self.samples[spec["label"]])
        except Exception as e:  # noqa: BLE001
            return f"ERROR: {type(e).__name__}: {e}"
        v = verdict(m, spec)
        if v:
            return f"ERROR: not drafted - {v}. Fix it with try_parser first."
        spec.pop("id", None)
        self.drafts.append({"spec": spec, "rationale": rationale, "kind": "new"})
        self._persist()
        return (f"drafted #{len(self.drafts) - 1}: claims {m['samples']} samples, parse_rate {m['parse_rate']} "
                f"(counted with the active parsers and earlier drafts; later drafts placed before it can take some)")

    def propose_parser_update(self, parser_id: str, spec_json: str, rationale: str) -> str:
        """Replace an active parser's spec (e.g. to fix failures). Golden examples must still pass, unless
        the new output is strictly richer (then they are re-pinned)."""
        old = self.store.by_id(parser_id)
        if not old:
            return f"ERROR: unknown parser {parser_id}"
        try:
            spec = self._spec(spec_json)
        except ValueError as e:
            return f"ERROR: {e}"
        spec["id"], spec["order"] = parser_id, old.get("order", 1000)
        self.drafts.append({"spec": spec, "rationale": rationale, "kind": "update"})
        self._persist()
        return f"drafted update of {parser_id}"

    def logstash_check(self, spec_json: str, before: str = "", n: int = 40) -> str:
        """Run a draft spec in REAL Logstash (with the label's active parsers) on up to n of the samples it
        would claim, and compare with the Python executor field by field. Takes ~15 s; does not use a
        submit. Use it before proposing parsers with kv/date/grok edge cases."""
        if not self.logstash_home:
            return "ERROR: no Logstash configured"
        try:
            spec = self._spec(spec_json)
            ps = self._placed(spec, before)
        except (ValueError, KeyError) as e:
            return f"ERROR: {e}"
        spec.setdefault("id", "draft")
        msgs = claimed(ps, spec, self.samples[spec["label"]])[:max(1, min(n, 200))]
        try:
            r = conformance(ps, [(spec["label"], m) for m in msgs], self.logstash_home)
        except Exception as e:  # noqa: BLE001
            return f"ERROR: Logstash run failed: {str(e)[:800]}"
        out = {"checked": r["checked"], "identical": r["identical"], "diffs": []}
        for dd in r["diffs"][:5]:
            fa, fb = flatten(dd["python"]), flatten(dd["logstash"])
            keys = sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))
            out["diffs"].append({"message": dd["message"][:300],
                                 "fields": {k: {"python": fa.get(k), "logstash": fb.get(k)} for k in keys[:10]}})
        return json.dumps(out, indent=1, default=str)[:12000]

    def retire_parser(self, parser_id: str, reason: str) -> str:
        """Retire an active parser (e.g. a wrong or experimental one). Its samples fall to the next matching
        parser or become unparsed. Refused if it would break other parsers' golden examples."""
        p = self.store.by_id(parser_id)
        if not p or p.get("status", "active") != "active":
            return f"ERROR: no active parser {parser_id}"
        p["status"] = "retired"
        broken = golden_regressions(self.store.ordered(p["label"]))
        if broken:
            p["status"] = "active"
            return f"ERROR: retiring would break golden examples: {broken[:2]}"
        p.setdefault("history", []).append({"retired": reason, "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        self.store.save()
        if self.enable_code:
            self._write_workspace()
        return f"retired {parser_id}"

    def submit(self) -> str:
        """Validate drafts in context (position, other parsers' golden examples), run accepted ones through
        real Logstash and compare with the Python executor, then activate. Returns verdicts. Each parser is
        accepted or rejected on its own. Budget: max_submits per session (remaining count is reported)."""
        if self.submits >= self.max_submits:
            return "ERROR: submit limit reached; finish with your summary"
        self.submits += 1
        origin = f"parser-agent:{time.strftime('%Y%m%dT%H%M%S')}"
        accepted, rejected = [], []
        next_n = int(self.store.next_id("p")[1:])
        for d in self.drafts:
            spec = d["spec"]
            label = spec["label"]
            if d["kind"] == "new":
                spec["id"] = f"p{next_n:05d}"       # unique within the batch too
                next_n += 1
            old = self.store.by_id(spec["id"]) if d["kind"] == "update" else None
            ps = [p for p in self.store.ordered(label) if p["id"] != spec["id"]]
            ps += [a[1] for a in accepted if a[1]["label"] == label and a[1]["id"] != spec["id"]] + [spec]
            ps.sort(key=lambda p: (p.get("order", 1000), p["id"]))
            msgs = claimed(ps, spec, self.samples[label])
            m = metrics(spec, msgs)
            if spec.get("fallback"):            # judged standalone on every sample of the label
                m = metrics(spec, self.samples[label])
                msgs_for_check = self.samples[label]
            else:
                msgs_for_check = msgs
            reason = verdict(m, spec)
            if not reason:
                spec["golden"] = pick_golden(spec, msgs)     # fallback: only lines it really receives
                if old:
                    # updated parser: its old golden samples must keep working (fields may be added)
                    for g in old.get("golden", []):
                        o = output_of(spec, g["message"])
                        if FAILURE_TAGS & set(o["tags"]) or not set(flatten(g["output"]["vendor"])) <= set(flatten(o["vendor"])):
                            reason = "update loses fields on a golden example"
                            break
                if not reason:
                    broken = [b for b in golden_regressions(ps) if b["parser"] != spec["id"]]
                    if broken:
                        reason = f"breaks golden examples of other parsers: {broken[:2]}"
            if reason:
                self.store.reject(spec, reason, origin)
                rejected.append({"label": label, "format": spec.get("format"), "reason": reason})
                continue
            accepted.append((d, spec, old, msgs, m))
        # real Logstash check, one run for all accepted parsers
        conf = None
        if accepted and self.logstash_home:
            samples = []
            for _, spec, _, msgs, _ in accepted:
                samples += [(spec["label"], x) for x in msgs[:40]] + [(spec["label"], g["message"]) for g in spec["golden"]]
                if spec.get("fallback"):        # run the fallback alone too, so Logstash sees it parse
                    samples += [("__fallback__" + spec["label"], x) for x in self.samples[spec["label"]][:30]]
            pset = {p["id"]: p for p in self.store.active() if p["label"] in {s["label"] for _, s, _, _, _ in accepted}}
            for _, spec, _, _, _ in accepted:
                pset[spec["id"]] = spec
                if spec.get("fallback"):
                    pset[spec["id"] + "_alone"] = dict(spec, id=spec["id"] + "_alone", label="__fallback__" + spec["label"])
            try:
                conf = conformance(sorted(pset.values(), key=lambda p: (p["label"], p.get("order", 1000), p["id"])),
                                   samples, self.logstash_home)
            except Exception as e:  # noqa: BLE001
                conf = {"error": str(e)[:500], "diffs": []}
        bad_ids = set()
        if conf and conf.get("diffs"):
            for dd in conf["diffs"]:
                pid = dd["python"].get("loggrouper", {}).get("parser")
                bad_ids.add(pid)
                bad_ids.add(str(pid).removesuffix("_alone"))
        if conf and conf.get("error"):
            bad_ids = {s["id"] for _, s, _, _, _ in accepted}
        done = []
        for d, spec, old, msgs, m in accepted:
            if spec["id"] in bad_ids:
                dd = next((x for x in conf["diffs"] if x["python"].get("loggrouper", {}).get("parser") == spec["id"]), None)
                if conf.get("error") or dd is None:
                    why = conf.get("error") or "Logstash check failed"
                else:
                    fa, fb = flatten(dd["python"]), flatten(dd["logstash"])
                    keys = sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k))
                    why = ("Logstash output differs from the Python executor on " + dd["message"][:160] + " | " +
                           "; ".join(f"{k}: python={json.dumps(fa.get(k))[:60]} logstash={json.dumps(fb.get(k))[:60]}" for k in keys[:8]))
                self.store.reject(spec, why, origin)
                rejected.append({"label": spec["label"], "format": spec.get("format"), "reason": why})
                continue
            spec.update(status="active", origin=origin, rationale=d["rationale"],
                        metrics={k: m[k] for k in ("samples", "parse_rate", "coverage_mean", "distinct_fields", "date_rate")})
            if old:
                spec["history"] = old.get("history", []) + [{"origin": origin, "previous_steps": old["steps"]}]
                self.store.items[self.store.items.index(old)] = spec
            else:
                self.store.items.append(spec)
            done.append({"id": spec["id"], "label": spec["label"], "format": spec.get("format"),
                         "claims": m["samples"], "parse_rate": m["parse_rate"], "coverage": m["coverage_mean"]})
        self.store.save()
        self.drafts = []
        self._persist()
        if self.enable_code:
            self._write_workspace()
        rep = {"accepted": done, "rejected": rejected, "submits_left": self.max_submits - self.submits,
               "logstash_check": None if conf is None else {"checked": conf.get("checked"), "identical": conf.get("identical"),
                                                            "error": conf.get("error")}}
        self.reports.append(rep)
        return json.dumps(rep, indent=1)

    def tool_functions(self):
        return self.code_tool_functions() + [self.overview, self.label_overview, self.get_samples, self.list_parsers,
                                             self.try_parser, self.logstash_check, self.propose_parser,
                                             self.propose_parser_update, self.retire_parser, self.submit]


def run_parser_agent(store_path, groups_dir, labels=None, logstash_home=None, enable_code=True, **kw):
    tools = ParserTools(store_path, groups_dir, labels=labels, logstash_home=logstash_home, enable_code=enable_code)
    out = run_tool_agent(tools, load_prompts("parser_agent.md", *(["parser_code_tools.md"] if enable_code else [])),
                         "Write parsers for the labels in `overview` until each label's samples parse cleanly. "
                         "Finish with a short summary.", **kw)
    out["reports"] = tools.reports
    return out
