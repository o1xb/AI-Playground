import json
import os
import unittest

from loggrouper.parse.compiler import compile_filter, grok_for_logstash, NeedsEscapes, _q
from loggrouper.parse.executor import Grok, dissect, kv, parse_date, run_parser

HERE = os.path.dirname(__file__)


class ExecutorTest(unittest.TestCase):
    def test_grok(self):
        g = Grok("%{IP:vendor.src_ip}:%{INT:vendor.port:int} (?<vendor.word>\\w+)")
        self.assertEqual(g.match("from 10.0.0.1:443 hello"),
                         {"vendor.src_ip": "10.0.0.1", "vendor.port": 443, "vendor.word": "hello"})

    def test_dissect(self):
        self.assertEqual(dissect("a  b c d", "%{x->} %{y} %{+y}"), {"x": "a", "y": "b c d"})
        self.assertIsNone(dissect("abc", "%{x}:%{y}"))

    def test_kv_logstash_semantics(self):
        self.assertEqual(kv('a="x y" OUT= MAC=1:2'), {"a": "x y", "OUT": "MAC=1:2"})

    def test_date(self):
        self.assertEqual(parse_date("2018/11/30 16:09:07", ["yyyy/MM/dd HH:mm:ss"]), "2018-11-30T16:09:07.000Z")
        self.assertEqual(parse_date("1587230269", ["UNIX"]), "2020-04-18T17:17:49.000Z")
        self.assertIsNone(parse_date("1587230269052907555", ["UNIX"]))   # nanoseconds: fails, as in Logstash

    def test_run_parser_tags(self):
        ev = run_parser({"id": "x", "steps": [{"json": {"target": "vendor"}}]}, "{not json")
        self.assertIn("_jsonparsefailure", ev["tags"])


class CompilerTest(unittest.TestCase):
    def test_raw_strings(self):
        self.assertEqual(_q(r"\[x\]"), r'"\[x\]"')          # no escape processing in Logstash strings
        self.assertEqual(_q('say "hi"'), "'say \"hi\"'")
        with self.assertRaises(NeedsEscapes):
            _q("both ' and \"")

    def test_grok_fields(self):
        self.assertEqual(grok_for_logstash("%{INT:vendor.a:int}"), "%{INT:[vendor][a]:int}")

    def test_filter_compiles(self):
        fx = json.load(open(os.path.join(HERE, "fixtures_conformance.json")))
        text = compile_filter(fx["specs"])
        self.assertTrue(text.startswith("filter {") and text.count("{") == text.count("}"))


@unittest.skipUnless(os.environ.get("LOGSTASH_HOME"), "set LOGSTASH_HOME to run the Logstash conformance test")
class ConformanceTest(unittest.TestCase):
    def test_python_matches_logstash(self):
        from loggrouper.parse.logstash import conformance
        fx = json.load(open(os.path.join(HERE, "fixtures_conformance.json")))
        r = conformance(fx["specs"], [tuple(s) for s in fx["samples"]], os.environ["LOGSTASH_HOME"])
        self.assertEqual(r["diffs"], [])


if __name__ == "__main__":
    unittest.main()


class FailureLoopTest(unittest.TestCase):
    def test_dead_letter_feeds_samples(self):
        import tempfile
        from loggrouper.parse.agent import load_samples
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "groups"))
        with open(os.path.join(d, "groups", "acme_fw.jsonl"), "w") as f:
            f.write(json.dumps({"raw": "ACME known line", "label": "acme_fw"}) + "\n")
        with open(os.path.join(d, "failures.jsonl"), "w") as f:
            f.write(json.dumps({"message": "ACME new message type", "loggrouper": {"label": "acme_fw"},
                                "tags": ["_noparser"]}) + "\n")
            f.write("not json\n")
        s = load_samples(os.path.join(d, "groups"), failures=os.path.join(d, "failures.jsonl"))
        self.assertEqual(s["acme_fw"], ["ACME new message type", "ACME known line"])
