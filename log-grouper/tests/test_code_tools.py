import os
import shutil
import tempfile
import unittest

from loggrouper.agent import LearnerTools
from loggrouper.engine import Engine
from loggrouper.rules import RuleStore


@unittest.skipUnless(shutil.which("unshare"), "needs unshare")
class CodeToolsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = tempfile.mkdtemp(dir=os.path.expanduser("~"))   # host dirs that must stay hidden
        cls.base = base
        cls.store = RuleStore(os.path.join(base, "rules"))
        cls.store.add({"label": "cisco_asa", "pattern": r"%ASA-\d", "priority": 10, "examples": ["%ASA-6-1 x"]}, "t")
        cls.store.save()
        cls.eng = Engine(cls.store, os.path.join(base, "out"), os.path.join(base, "state"))
        cls.eng.process_batch(0, ["%ASA-6-302013: Built", "ACME[1]: action=deny", "ACME[2]: action=allow"])
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-must-not-leak"
        cls.t = LearnerTools(cls.store, cls.eng, enable_code=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)
        shutil.rmtree(cls.t.workspace, ignore_errors=True)

    def test_workspace_and_library(self):
        out = self.t.run_python(
            "import json\nfrom loggrouper.templates import shape\n"
            "rows=[json.loads(l) for l in open('residue.jsonl')]\n"
            "print(len(rows), sorted({shape(r['payload']) for r in rows}))")
        self.assertTrue(out.startswith("exit=0"), out)
        self.assertIn("2 [", out)

    def test_isolation(self):
        out = self.t.run_python(
            "import os, socket\n"
            f"print('store visible:', os.path.exists({self.store.path!r}) and bool(os.listdir({self.store.path!r})))\n"
            "print('key:', os.environ.get('ANTHROPIC_API_KEY'))\n"
            "try:\n    socket.create_connection(('1.1.1.1', 443), timeout=2); print('net: open')\n"
            "except OSError: print('net: blocked')\n")
        self.assertIn("store visible: False", out)
        self.assertIn("key: None", out)
        self.assertIn("net: blocked", out)

    def test_timeout_and_bash(self):
        self.assertIn("exit=124", self.t.run_python("while True: pass", timeout=2))
        out = self.t.run_bash("grep -c ACME residue.jsonl; ls")
        self.assertIn("2\n", out); self.assertIn("packet.json", out)

    def test_tools_registered(self):
        names = [f.__name__ for f in self.t.tool_functions()]
        self.assertIn("run_python", names)
        self.assertNotIn("run_python", [f.__name__ for f in LearnerTools(self.store, self.eng).tool_functions()])


if __name__ == "__main__":
    unittest.main()
