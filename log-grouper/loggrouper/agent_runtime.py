"""Shared runtime for the tool-using agents (grouping learner, parser author, OCSF mapper).

An agent = a tools object (plain methods returning strings) + a system prompt. This runs it on the
Claude API with the SDK tool runner, and gives every agent the same optional sandboxed code tools.
"""
import json
import os
import shutil
import tempfile

DEFAULT_MODEL = "claude-opus-5-5"


class CodeTools:
    """Mixin: sandboxed run_python / run_bash over a workspace the subclass fills (`_write_workspace`)."""

    def _init_code(self, enable_code, workspace, sandbox_backend, hide):
        self.enable_code = enable_code
        self.sandbox = None
        if enable_code:
            from .code_sandbox import Sandbox
            self.workspace = workspace or tempfile.mkdtemp(prefix="lg-agent-ws-")
            os.makedirs(self.workspace, exist_ok=True)
            self.sandbox = Sandbox(self.workspace, backend=sandbox_backend,
                                   hide=list(hide) + [os.path.expanduser("~"), "/tmp", "/var/tmp", "/root", "/home"])
            lib = os.path.join(self.workspace, "lib", "loggrouper")
            if not os.path.isdir(lib):
                shutil.copytree(os.path.dirname(os.path.abspath(__file__)), lib,
                                ignore=shutil.ignore_patterns("__pycache__"))

    def run_python(self, code: str, timeout: int = 60) -> str:
        """Run a Python 3 script in the sandboxed analysis workspace (cwd; see README.txt). No network; only
        the workspace is visible; your files there persist for the session. `import loggrouper` works
        (e.g. loggrouper.parse.executor.run_parser to test a parser spec on every sample). Analysis only:
        changes go through the propose/submit tools."""
        d = os.path.join(self.workspace, "_scripts")
        os.makedirs(d, exist_ok=True)
        n = len(os.listdir(d))
        with open(os.path.join(d, f"s{n:03d}.py"), "w") as f:
            f.write(code)
        rc, out = self.sandbox.run(["python3", "-s", "-B", f"_scripts/s{n:03d}.py"], timeout=min(max(timeout, 1), 300))
        return f"exit={rc}\n{out}"

    def run_bash(self, command: str, timeout: int = 60) -> str:
        """Run a bash command in the same sandboxed workspace (grep, sort | uniq -c, head, wc)."""
        rc, out = self.sandbox.run(["/bin/bash", "-c", command], timeout=min(max(timeout, 1), 300))
        return f"exit={rc}\n{out}"

    def code_tool_functions(self):
        return [self.run_python, self.run_bash] if self.enable_code else []


def run_tool_agent(tools, system, prompt, model=DEFAULT_MODEL, effort="high", max_iterations=80,
                   client=None, log=print):
    """Run one agent session; returns usage, final text and stop reason."""
    import anthropic
    from anthropic import beta_tool

    client = client or anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model=model,
        max_tokens=16000,
        max_iterations=max_iterations,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",            # security logs can trip safety classifiers; fall back instead of stopping
        thinking={"type": "adaptive"},
        output_config={"effort": effort},
        cache_control={"type": "ephemeral"},
        system=system,
        tools=[beta_tool(f) for f in tools.tool_functions()],
        messages=[{"role": "user", "content": prompt}],
    )
    usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0, "turns": 0}
    final = None
    for message in runner:
        usage["turns"] += 1
        for k in ("input_tokens", "output_tokens", "cache_read_input_tokens"):
            usage[k] += getattr(message.usage, k, 0) or 0
        for b in message.content:
            if b.type == "tool_use":
                log(f"[agent] {b.name}({json.dumps(b.input)[:160]})")
        if message.stop_reason == "refusal":
            log(f"[agent] refused: {getattr(message, 'stop_details', None)}")
        final = message
    summary = "".join(b.text for b in (final.content if final else []) if b.type == "text")
    return {"usage": usage, "summary": summary, "stop_reason": final.stop_reason if final else None}


def load_prompts(*names):
    base = os.path.join(os.path.dirname(__file__), "..", "prompts")
    parts = []
    for n in names:
        with open(os.path.join(base, n)) as f:
            parts.append(f.read())
    return "\n\n".join(parts)
