"""Sandboxed Bash/Python execution for the learner agent.

The agent reads untrusted log text, so anything it runs must be contained. Scripts are for
*analysis only*: they see a read-mostly snapshot (residue, samples, rules, the loggrouper library)
in a scratch workspace, have no network, no access to the host's rule store, outputs, home or
environment (API keys), and run under CPU/memory/file-size/time limits. Changes to the rule store
still go only through the agent's propose/submit tools and the validator.

Backends
  unshare  Linux user+mount+net+pid namespaces (no root, no daemon). Hides host paths with tmpfs.
  docker   `docker run --network none --read-only ...` per command. Recommended in production.
"""
import os
import resource
import shutil
import signal
import subprocess

MAX_OUTPUT = 20000


def _limits(cpu_s, mem_mb, fsize_mb):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb << 20, mem_mb << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_mb << 20, fsize_mb << 20))
        os.setsid()
    return apply


def _clip(s):
    if len(s) <= MAX_OUTPUT:
        return s
    return s[:MAX_OUTPUT // 2] + f"\n... [{len(s) - MAX_OUTPUT} chars cut] ...\n" + s[-MAX_OUTPUT // 2:]


class Sandbox:
    def __init__(self, workspace, backend="unshare", hide=(), image="python:3.13-slim",
                 cpu_s=60, mem_mb=1536, fsize_mb=200):
        self.ws = os.path.abspath(workspace)
        self.backend = backend
        self.hide = [os.path.abspath(p) for p in hide if p]
        self.image = image
        self.cpu_s, self.mem_mb, self.fsize_mb = cpu_s, mem_mb, fsize_mb
        if backend == "unshare" and not shutil.which("unshare"):
            raise RuntimeError("unshare not available; use backend='docker'")
        if backend not in ("unshare", "docker"):
            raise ValueError(backend)

    def _argv(self, argv):
        env = ["PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1"]
        if self.backend == "docker":
            return ["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
                    "--tmpfs", "/tmp:size=256m", "--memory", f"{self.mem_mb}m", "--pids-limit", "256",
                    "--cpus", "1", "--user", "65534:65534", "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "-v", f"{self.ws}:/work:rw", "-w", "/work",
                    *sum((["-e", e] for e in env + ["HOME=/work", "PYTHONPATH=/work/lib"]), []),
                    self.image, *argv]
        hides = " && ".join(f'mount -t tmpfs none "{p}"' for p in self.hide if os.path.isdir(p))
        script = ('mount -t tmpfs none /mnt && mkdir /mnt/work && mount --bind "$0" /mnt/work'
                  + (" && " + hides if hides else "") + ' && cd /mnt/work && exec env -i '
                  + " ".join(env) + ' HOME=/mnt/work PYTHONPATH=/mnt/work/lib "$@"')
        return ["unshare", "-rmnpf", "--mount-proc", "--", "/bin/sh", "-c", script, self.ws, *argv]

    def run(self, argv, timeout=60):
        """-> (exit_code, combined output). Exit code 124 on timeout."""
        p = subprocess.Popen(self._argv(argv), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                             preexec_fn=_limits(self.cpu_s, self.mem_mb, self.fsize_mb))
        try:
            out, _ = p.communicate(timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, _ = p.communicate()
            rc = 124
            out = (out or b"") + f"\n[killed after {timeout}s]".encode()
        return rc, _clip(out.decode("utf-8", "replace"))
