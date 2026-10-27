# ABOUTME: What the e2e suite needs before any test runs (DESIGN.md §21.4): production posture, MC's read
# ABOUTME: credential passing §8.2, and a Running tailscale. Each missing piece is named, so the suite never skips.

from tailnet import credentials, localts, secure_files
from tailnet.errors import TailnetError
from tailnet.posture import Posture

OVERRIDES = ("TAILNET_API_BASE", "TAILNET_HOME")
_SET_READ = "MC runs `tailnet credentials set read` over SSH"


def override_problem(environ):
    """The test-posture overrides, if either is present: e2e is about the real API only."""
    present = [name for name in OVERRIDES if name in environ]
    if not present:
        return None
    return (f"production posture: {' and '.join(present)} {'is' if len(present) == 1 else 'are'} "
            "set, which points the CLI at a loopback test API; e2e runs against the real API, so "
            "unset them (they belong to `make test`)")


def credential_problem(posture):
    """Why MC's read credential would not load, or None when read.json and its secret pass §8.2.

    The secret file is opened through the same checks as the CLI's and closed unread, so
    the secret never enters this process. Its format is the CLI's to judge, in E1.
    """
    path = posture.config_dir / "read.json"
    try:
        meta = credentials.load_read_meta(posture)
    except TailnetError as exc:
        return f"the read credential: {path} fails its checks: {exc.code}: {exc.message}"
    if meta is None:
        return f"the read credential: {path} does not exist; {_SET_READ}"
    if meta.secret_path is None:
        return None
    try:
        with secure_files.open_private(meta.secret_path, max_bytes=credentials.CREDENTIAL_MAX):
            pass
    except FileNotFoundError:
        return f"the read credential's secret: {meta.secret_path} does not exist; {_SET_READ}"
    except TailnetError as exc:
        return f"the read credential's secret fails its checks: {exc.code}: {exc.message}"
    return None


def tailscale_problem(binary, read_status):
    """Why this host's tailscale cannot serve the suite, or None when it is Running with self known.

    `binary` is the path localts would run, or None. `read_status` returns `tailnet status
    --json`'s envelope; it is called only when a binary exists, because the suite's own
    process never runs tailscale and the status run is a child that does.
    """
    if binary is None:
        return (f"the tailscale CLI: there is none at {localts.PREFERRED} or on PATH; e2e runs on "
                "claude-factory, where tailscale is installed and Running")
    # Anything at all can go wrong in a child run (no envelope, a timeout, a bug); each is the
    # same missing piece, named with what happened.
    try:
        view = read_status()["data"]["self_local"]
        state, reason = view.get("backend_state"), view.get("reason") or view.get("error")
    except Exception as exc:  # noqa: BLE001
        return (f"tailscale's state: `tailnet status --json` gave no readable answer "
                f"({type(exc).__name__}: {exc})")
    if state != "Running":
        return (f"tailscale is not Running (BackendState {state or 'unknown'}: "
                f"{reason or 'no reason given'}); see `tailscale status` on claude-factory")
    if reason:
        return f"tailscale is Running, but this host cannot be identified: {reason}"
    return None


def problems(environ, *, read_status, real_home=None, find_binary=localts.binary):
    """Every missing piece, in the order MC would fix them; empty means e2e may run.

    An override stops the check at once: until it is gone neither posture is the one the
    suite tests, so nothing else is read. Otherwise the credential and tailscale are both
    checked, so one run names everything MC has to do.
    """
    stop = override_problem(environ)
    if stop is not None:
        return [stop]
    posture = Posture.from_env(environ, real_home=real_home)
    found = [credential_problem(posture), tailscale_problem(find_binary(), read_status)]
    return [problem for problem in found if problem is not None]


def message(found):
    """The text pytest.exit prints: each missing piece numbered, and that nothing was run."""
    lines = ["e2e cannot start, so nothing was run (DESIGN.md §21.4). Missing:"]
    lines += [f"  {number}. {problem}" for number, problem in enumerate(found, 1)]
    lines.append("e2e runs read-only on claude-factory, as mc, with MC's read credential and a "
                 "Running tailscale. It never skips: it stops with exit 3 until each is in place.")
    return "\n".join(lines)
