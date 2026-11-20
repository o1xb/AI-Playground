"""End-to-end test of the learner agent's API loop against a local mock of the Messages API.

The mock plays the model with a fixed script (overview -> get_cluster -> test_pattern -> propose_rule
-> submit -> end_turn). Everything else is real: the anthropic SDK's tool runner, tool dispatch,
the regex sandbox, the validator and the rule store.
"""
import json
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from loggrouper.engine import Engine
from loggrouper.rules import RuleStore

LINES = [
    "<134>Nov 20 10:00:01 gw1 ACMEWALL[42]: action=deny src=10.0.0.1 dst=10.0.0.2 proto=tcp",
    "<134>Nov 20 10:00:02 gw1 ACMEWALL[42]: action=allow src=10.0.0.3 dst=10.0.0.4 proto=udp",
    "<134>Nov 20 10:00:03 gw2 ACMEWALL[43]: action=deny src=10.0.0.5 dst=10.0.0.6 proto=tcp",
    "%ASA-6-302013: Built outbound TCP connection 1 for outside:1.1.1.1/80 to inside:2.2.2.2/1000",
]


class Script:
    def __init__(self):
        self.step = 0
        self.requests = []
        self.cluster = None

    def reply(self, body):
        self.requests.append(body)
        msgs = body["messages"]
        last = msgs[-1]["content"]
        results = [b for b in last if isinstance(b, dict) and b.get("type") == "tool_result"] if isinstance(last, list) else []
        text = results[0]["content"] if results else ""
        if isinstance(text, list):
            text = "".join(t.get("text", "") for t in text)
        self.step += 1
        if self.step == 1:
            return self._tool("overview", {})
        if self.step == 2:
            self.cluster = re.search(r"^(c\d{3}) \|", text, re.M).group(1)
            return self._tool("get_cluster", {"cluster_id": self.cluster})
        if self.step == 3:
            return self._tool("test_pattern", {"pattern": r"ACMEWALL\[\d+\]: action=", "label": "acme_wall"})
        if self.step == 4:
            assert '"residue_lines_matched": 3' in text, text
            return self._tool("propose_rule", {"label": "acme_wall", "pattern": r"ACMEWALL\[\d+\]: action=",
                                               "explains_clusters": [self.cluster], "format": "kv",
                                               "rationale": "ACMEWALL program tag", "confidence": "high"})
        if self.step == 5:
            assert "drafted rule #0" in text, text
            return self._tool("submit", {})
        assert '"accepted"' in text, text
        return {"id": "msg_end", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "content": [{"type": "text", "text": "Added acme_wall."}], "stop_reason": "end_turn",
                "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 5}}

    def _tool(self, name, inp):
        return {"id": f"msg_{self.step}", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
                "content": [{"type": "tool_use", "id": f"toolu_{self.step}", "name": name, "input": inp}],
                "stop_reason": "tool_use", "stop_sequence": None,
                "usage": {"input_tokens": 100, "output_tokens": 20}}


def serve(script):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            out = json.dumps(script.reply(body)).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class AgentLoopTest(unittest.TestCase):
    def test_loop(self):
        import anthropic
        from loggrouper.agent import run_learner_agent

        d = tempfile.mkdtemp()
        store = RuleStore(os.path.join(d, "rules"))
        store.add({"label": "cisco_asa", "pattern": r"%ASA-\d-\d{6}", "priority": 10,
                   "examples": [LINES[3]]}, "test")
        store.save()
        eng = Engine(store, os.path.join(d, "out"), os.path.join(d, "state"))
        eng.process_batch(0, LINES)
        self.assertEqual(len(eng.load_residual()), 3)

        script = Script()
        srv = serve(script)
        client = anthropic.Anthropic(api_key="test", base_url=f"http://127.0.0.1:{srv.server_port}", max_retries=0)
        out = run_learner_agent(store, eng, client=client, log=lambda *a: None)
        srv.shutdown()

        self.assertEqual(out["accepted"], 1)
        self.assertEqual(out["summary"], "Added acme_wall.")
        self.assertEqual(len(eng.load_residual()), 0)            # residue drained by the new rule
        self.assertIn("acme_wall", RuleStore(os.path.join(d, "rules")).labels())
        first = script.requests[0]                               # request shape the SDK sent
        self.assertEqual(first["model"], "claude-opus-5-5")
        self.assertEqual(first["fallbacks"], "default")
        self.assertEqual({t["name"] for t in first["tools"]} >= {"overview", "submit", "test_pattern"}, True)


if __name__ == "__main__":
    unittest.main()
