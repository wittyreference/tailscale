# ABOUTME: The only module that runs the tailscale binary: local status, one ping, a preference, the version.
# ABOUTME: Production posture only; in test posture every call refuses before any process starts (§7.1).

import ipaddress
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

from tailnet.errors import LocalError
from tailnet.redact import redact

# The packaged location is preferred to a PATH lookup, so a `tailscale` planted earlier on
# PATH is not the one run (§11.3). Doctor reports which was used.
PREFERRED = "/usr/bin/tailscale"
# The two ping kinds the diagnose ladder uses (§15): TSMP crosses WireGuard without either
# host's OS stack, ICMP goes through the peer's stack [cliref ping].
PING_KINDS = ("tsmp", "icmp")
# `tailscale get` takes a `tailscale set` flag name [cliref L409-428]; only that shape is sent.
_PREF_NAME = re.compile(r"[a-z][a-z0-9-]*")
# Stderr is quoted in a failure message up to this many characters.
_EXCERPT = 200


class NotInTestPosture(RuntimeError):
    """Raised when anything asks localts to run tailscale in test posture: that is a bug.

    Test posture never runs the binary (D23), so callers check `posture.runs_tailscale`
    first; this is the backstop that makes a missed check fail loudly instead of reaching
    the real tailnet.
    """


class Failed(Exception):
    """tailscale ran but gave no usable answer: it timed out, could not start, or exited non-zero.

    There is no stable code for this; callers report `reason` as why the local view is
    unknown, which is the fail-closed answer for self detection.
    """

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PingResult:
    """One `tailscale ping`: its exit status and its redacted output, for diagnose to read."""

    exit: int
    output: str


def binary():
    """The tailscale binary to run: the packaged one if it is an executable file, else PATH's, else None."""
    if os.path.isfile(PREFERRED) and os.access(PREFERRED, os.X_OK):
        return PREFERRED
    return shutil.which("tailscale")


def ping_args(ip, kind, timeout):
    """The arguments for one ping of `kind` to a Tailscale address, waiting `timeout` whole seconds."""
    ipaddress.ip_address(ip)
    if kind not in PING_KINDS:
        raise ValueError(f"ping kind is one of {PING_KINDS}, not {kind!r}")
    if type(timeout) is not int or timeout < 1:
        raise ValueError(f"ping timeout is a whole number of seconds, not {timeout!r}")
    return ["ping", f"--{kind}", "--c=1", f"--timeout={timeout}s", ip]


def pref_args(name):
    """The arguments for reading one preference, such as accept-dns."""
    if not isinstance(name, str) or not _PREF_NAME.fullmatch(name):
        raise ValueError(f"a preference name is one lowercase flag name, not {name!r}")
    return ["get", name]


def _run(posture, args, timeout):
    """Run `tailscale ARGS` once; return (exit status, stdout, stderr), both redacted.

    Output is redacted before anyone sees it: status can carry a one-time login URL.
    """
    if not posture.runs_tailscale:
        raise NotInTestPosture(f"refusing to run `tailscale {' '.join(args)}` in test posture: "
                               "test runs never touch the real tailnet (DESIGN.md §7.1)")
    path = binary()
    if path is None:
        raise LocalError("TAILSCALE_CLI_MISSING",
                         f"no tailscale binary at {PREFERRED} or on PATH; the local view of "
                         "this host is unavailable")
    command = f"tailscale {' '.join(args)}"
    try:
        done = subprocess.run([path, *args], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Failed(f"`{command}` gave no answer within {timeout} s") from None
    except OSError as exc:
        raise Failed(f"could not run {path}: {exc.strerror}") from None
    out = redact(done.stdout.decode("utf-8", "replace"))
    err = redact(done.stderr.decode("utf-8", "replace"))
    return done.returncode, out, err


def _answer(posture, args, timeout):
    """Run a command whose non-zero exit means there is no answer; return its stdout."""
    code, out, err = _run(posture, args, timeout)
    if code != 0:
        said = err.strip()[:_EXCERPT] or "no message"
        raise Failed(f"`tailscale {' '.join(args)}` exited {code}: {said}")
    return out


def status_json(posture, timeout):
    """`tailscale status --json` as text, for selfnode to parse."""
    return _answer(posture, ["status", "--json"], timeout)


def ping(posture, ip, kind, timeout):
    """One `tailscale ping` of `kind`; its exit status is the result, so a non-zero one is not raised."""
    code, out, err = _run(posture, ping_args(ip, kind, timeout), timeout + 5)
    return PingResult(code, (out + err).strip())


def get_pref(posture, name, timeout):
    """One local preference as `tailscale get` prints it, such as accept-dns's true or false."""
    return _answer(posture, pref_args(name), timeout).strip()


def version(posture, timeout):
    """The first line of `tailscale version`: the client version doctor reports."""
    lines = _answer(posture, ["version"], timeout).splitlines()
    return lines[0].strip() if lines else ""
