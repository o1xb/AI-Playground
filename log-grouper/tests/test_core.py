import io
import json
import tempfile
import unittest

from loggrouper.learn import apply_candidates
from loggrouper.rules import RuleStore, prefilter
from loggrouper.sources import _records
from loggrouper.unwrap import Unwrapper, strip_header


class PrefilterTest(unittest.TestCase):
    def test_literals(self):
        self.assertEqual(prefilter({"pattern": r"%ASA-\d|CiscoASA"})[0], ("%ASA-", "CiscoASA"))
        # common-prefix factoring: "a"|"b" parses as '"' + BRANCH
        self.assertIsNotNone(prefilter({"pattern": r'"netskope"|"nsdeviceuid"'}))
        self.assertIsNone(prefilter({"pattern": r"%[A-Z]+-\d-"}))      # no literal of 3+ chars
        lits, ci = prefilter({"pattern": "pfsense", "flags": "i"})
        self.assertTrue(ci)
        self.assertEqual(lits, ("pfsense",))


class UnwrapTest(unittest.TestCase):
    def test_views(self):
        u = Unwrapper()
        p, layers, views = u.views('<134>Nov 20 09:00:01 collector-02 Nov 30 16:09:08 PA-220 1,2018/11/30,TRAFFIC')
        self.assertEqual(layers, ["relay"])
        self.assertEqual(views[1], "1,2018/11/30,TRAFFIC")
        p, layers, views = u.views('{"data":{"x":1},"metadata":{"links":"api.amp.cisco.com"}}')
        self.assertEqual(layers, ["api_page"])
        self.assertIn("amp.cisco.com", views[-1])          # envelope kept as a fallback view

    def test_header(self):
        self.assertEqual(strip_header("<190>10.1.1.1 1,2023/01/01"), "1,2023/01/01")


class FramingTest(unittest.TestCase):
    def test_first_line_pattern(self):
        f = io.BytesIO(b"[**] a\nb\nc\n[**] d\n")
        self.assertEqual(list(_records(f, r"^\[\*\*\]")), ["[**] a\nb\nc", "[**] d"])


class ValidationTest(unittest.TestCase):
    def test_regression_and_collision(self):
        d = tempfile.mkdtemp()
        st = RuleStore(d)
        st.add({"label": "acme_fw", "pattern": r"ACME-FW", "priority": 10, "examples": ["ACME-FW deny"]}, "t")
        st.save()
        packet = {"clusters": [{"cluster_id": "c0", "shape": "s", "examples": ["ACME-FW deny", "zeta event"]}]}
        cand = {"rules": [
            {"label": "other_thing", "pattern": "deny", "explains_clusters": ["c0"]},       # collides
            {"label": "zeta_app", "pattern": r"^zeta ", "explains_clusters": ["c0"]},        # fine
        ]}
        rep = apply_candidates(st, packet, [], cand, "test")
        self.assertEqual([r["label"] for r in rep["accepted"]], ["zeta_app"])
        self.assertIn("collides", rep["rejected"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
