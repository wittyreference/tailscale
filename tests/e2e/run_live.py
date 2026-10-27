# ABOUTME: e2e launcher: runs the repo's tailnet CLI in production posture against the real API, as `python -I
# ABOUTME: tests/e2e/run_live.py ARGS…`, and raises before the CLI starts if a run could write or change MC's files.

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve()
SRC = HERE.parents[2] / "src"
# The two variables that put the CLI in test posture. e2e exists to exercise production, so a
# run with either one present, even empty, is refused rather than quietly pointed at loopback.
OVERRIDES = ("TAILNET_API_BASE", "TAILNET_HOME")
# `credentials forget token` only drops the cached read token, so the next read mints again,
# which E4 needs to count one mint. Every other credentials command is MC's: `set` needs a
# terminal, and `forget read|write` would remove the very credential the suite runs on.
_FORGET_TOKEN = ("credentials", "forget", "token")
# A live run may wait on the API, a policy validate and the TCP probes of every target.
TIMEOUT = 600


class LiveRefused(RuntimeError):
    """Raised before the CLI starts: this run could write to the tailnet, change MC's credentials,
    or leave production posture. The e2e suite is read-only by construction (§21.4)."""


class LiveRunFailed(RuntimeError):
    """A live run gave no envelope to judge: it hung, or its stdout was not one JSON object."""


def refuse(argv, environ):
    """Raise LiveRefused unless `argv` is a run the read-only suite may make against MC's tailnet.

    `--apply` is refused wherever it appears, inside a value too, because the CLI sends a
    write only with it and the suite never needs the word. A test-posture override is refused
    because the suite's point is the real API.
    """
    words = [str(word) for word in argv]
    if any("--apply" in word for word in words):
        raise LiveRefused(f"--apply appears in {words}: the e2e suite never sends a write")
    # The first word that is not an option is the command group; only --json comes before it.
    positional = [word for word in words if not word.startswith("-")]
    if positional[:1] == ["credentials"] and tuple(positional[:3]) != _FORGET_TOKEN:
        raise LiveRefused(f"{' '.join(positional)}: the e2e suite never changes MC's credentials; "
                          "only `credentials forget token` is allowed")
    present = [name for name in OVERRIDES if name in environ]
    if present:
        raise LiveRefused(f"{' and '.join(present)} set: run_live runs the CLI in production "
                          "posture only; unset it")


@dataclass(frozen=True)
class LiveRun:
    """One live CLI run: its arguments, exit status, output, process ID and parsed envelope.

    The process ID is the `pid` every audit line of that run carries (§13.3), so a test can
    pick out exactly the lines its own runs wrote, whatever else shares MC's log.
    """

    args: tuple
    exit: int
    stdout: str
    stderr: str
    pid: int
    envelope: dict | None

    @property
    def label(self):
        """The command as MC would type it, for the test report."""
        return "tailnet " + " ".join(self.args)

    @property
    def data(self):
        """The envelope's data, or an empty dict for a run without one."""
        return (self.envelope or {}).get("data") or {}


def run(args, *, json_mode=True, timeout=TIMEOUT, environ=None):
    """Run `tailnet ARGS` live through this launcher and return a LiveRun.

    With `json_mode` the run adds --json and its stdout must be exactly one envelope, or
    LiveRunFailed says what came back instead. The environment is the caller's own, checked
    by refuse() first, so production posture sees the real HOME, PATH and proxies.
    """
    environ = dict(os.environ if environ is None else environ)
    argv = [*args, "--json"] if json_mode else list(args)
    refuse(argv, environ)
    label = "tailnet " + " ".join(argv)
    with subprocess.Popen([sys.executable, "-I", str(HERE), *argv], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          env=environ) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise LiveRunFailed(f"`{label}` gave no answer within {timeout} s") from None
    envelope = None
    if json_mode:
        try:
            envelope = json.loads(out)
        except ValueError:
            raise LiveRunFailed(f"`{label}` exited {proc.returncode} without a JSON envelope on "
                                f"stdout; stderr ends: {err[-400:]!r}") from None
        if not isinstance(envelope, dict):
            raise LiveRunFailed(f"`{label}` printed JSON that is not an envelope")
    return LiveRun(tuple(args), proc.returncode, out, err, proc.pid, envelope)


def main(argv):
    """Check the arguments, then run the repo's CLI in this process and return its exit status."""
    refuse(argv, os.environ)
    # -I keeps PYTHONPATH and this directory off sys.path, so the package comes from the repo.
    sys.path.insert(0, str(SRC))
    from tailnet.cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
