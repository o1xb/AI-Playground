import json
import os
import unittest

from loggrouper.ocsf.mapping import apply_mapping, cast, prepare
from loggrouper.ocsf.schema import Schema

HERE = os.path.dirname(__file__)


class SchemaTest(unittest.TestCase):
    def setUp(self):
        self.s = Schema()

    def test_class_and_required(self):
        name, c = self.s.cls(4001)
        self.assertEqual(name, "network_activity")
        req = sorted(k for k, a in c["attributes"].items() if a["requirement"] == "required" and not a.get("profile"))
        self.assertEqual(req, ["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"])

    def test_validate(self):
        ev = {"class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
              "time": 1700000000000, "metadata": {"version": "1.4.0", "product": {"vendor_name": "X", "name": "Y"}},
              "dst_endpoint": {"ip": "10.0.0.300"}, "action_id": 9, "bogus": 1}
        errs, _ = self.s.validate(ev)
        self.assertTrue(any("invalid IP" in e for e in errs))
        self.assertTrue(any("action_id" in e for e in errs))
        self.assertIn("unknown attribute bogus", errs)


class MappingTest(unittest.TestCase):
    def test_apply(self):
        spec = prepare({"id": "m", "parser_id": "p", "class_uid": 4001, "fields": [
            {"to": "activity_id", "from": "vendor.sub", "map": {"start": 1}, "default": 6},
            {"to": "src_endpoint.port", "from": "vendor.sport", "type": "integer"},
            {"to": "action_id", "from": "vendor.act", "map": {"ALLOW": 1}},
            {"to": "metadata.product.vendor_name", "value": "V"}, {"to": "metadata.product.name", "value": "P"}]})
        o = apply_mapping(spec, {"message": "m", "vendor": {"sub": "start", "sport": "443", "act": "allow", "x": 1},
                                 "@timestamp": "2020-01-01T00:00:00.123Z"})
        self.assertEqual((o["activity_id"], o["type_uid"], o["src_endpoint"]["port"], o["action_id"]), (1, 400101, 443, 1))
        self.assertEqual((o["activity_name"], o["action"], o["time"]), ("Open", "Allowed", 1577836800123))
        self.assertEqual(o["unmapped"], {"x": 1})
        self.assertEqual(Schema().validate(o)[0], [])

    def test_cast(self):
        self.assertEqual(cast("0x1f", "integer"), (False, None))     # no hex surprises (Ruby Float() parity)
        self.assertEqual(cast("1587230269", "timestamp_ms"), (True, 1587230269000))
        self.assertEqual(cast("1587230269052907555", "timestamp_ms"), (True, 1587230269052))


@unittest.skipUnless(os.environ.get("LOGSTASH_HOME"), "set LOGSTASH_HOME to run the Logstash conformance test")
class OcsfConformanceTest(unittest.TestCase):
    def test_ruby_matches_python(self):
        from loggrouper.parse.logstash import ocsf_conformance
        fx = json.load(open(os.path.join(HERE, "fixtures_conformance.json")))
        sch = Schema()
        maps = {m["parser_id"]: prepare(m, sch) for m in fx["mappings"]}
        r = ocsf_conformance(fx["specs"], maps, [tuple(s) for s in fx["samples"]], os.environ["LOGSTASH_HOME"])
        self.assertGreater(r["checked"], 5)
        self.assertEqual(r["diffs"], [])


if __name__ == "__main__":
    unittest.main()
