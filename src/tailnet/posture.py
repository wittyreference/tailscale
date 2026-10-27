# ABOUTME: Decides, once at start-up, whether this run is production or test posture, and owns every
# ABOUTME: path the CLI touches. The loopback override is the only way to point it at another API.

import ipaddress
import os
import pwd
import re
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from tailnet.errors import LocalError

PRODUCTION_API = "https://api.tailscale.com/api/v2"
API_PATH = "/api/v2"

# The whole override value, spelled exactly: http, one of the two loopback spellings, a port
# from 1 to 65535, and at most a bare trailing slash. Checked on the raw string because
# urllib.parse quietly strips tabs, newlines and leading spaces, so a parsed value can look
# clean when the text the operator typed was not.
_BASE = re.compile(r"http://(127\.0\.0\.1|localhost):([1-9][0-9]{0,4})/?")


def passwd_home():
    """The invoking user's home from the password database, never from $HOME.

    An environment change must not be able to move where the real credentials live, or a
    test run could be steered into reading them (§3.1, §7.2 rule 3).
    """
    return Path(pwd.getpwuid(os.geteuid()).pw_dir)


def all_loopback(addresses):
    """Say whether every address is a loopback address, and there is at least one.

    This is what `localhost` must resolve to before a test run may use it: a hosts file or
    resolver that answers anything else would send fixture traffic off the box.
    """
    if not addresses:
        return False
    for text in addresses:
        try:
            if not ipaddress.ip_address(text).is_loopback:
                return False
        except ValueError:
            return False
    return True


def _unsafe(message):
    """The one refusal every override rule shares: exit 3, nothing contacted, no fallback."""
    return LocalError("ENV_UNSAFE_OVERRIDE", message)


def _test_api_base(base):
    """Validate TAILNET_API_BASE (§7.2 rule 2) and return the API root it names."""
    match = _BASE.fullmatch(base)
    if match is None:
        # The value is not echoed: a refused URL may carry a password in its userinfo.
        raise _unsafe("TAILNET_API_BASE must be exactly http://127.0.0.1:PORT or "
                      "http://localhost:PORT (a port from 1 to 65535; no https, user, path, "
                      "query or fragment)")
    host, port = match.group(1), int(match.group(2))
    if port > 65535:
        raise _unsafe("TAILNET_API_BASE has a port above 65535")
    parts = urlsplit(base)
    # The pattern already pins every part; this cross-checks it against urllib's own reading,
    # which is what the HTTP layer will act on.
    if (parts.scheme, parts.hostname, parts.port, parts.username, parts.query,
            parts.fragment) != ("http", host, port, None, "", ""):
        raise _unsafe("TAILNET_API_BASE does not parse as a plain loopback URL")
    if host == "localhost":
        try:
            infos = socket.getaddrinfo("localhost", port, type=socket.SOCK_STREAM)
        except OSError:
            infos = []
        if not all_loopback([info[4][0] for info in infos]):
            raise _unsafe("TAILNET_API_BASE names localhost, but localhost does not resolve "
                          "to loopback addresses only on this machine")
    return f"http://{host}:{port}{API_PATH}"


# The directories posture builds under a test home; drafts after state, which holds it.
_TEST_DIRS = ("config", "state", "state/drafts", "claude")


def _inside(path, directory):
    """Say whether `path` is `directory` or below it, comparing whole path components."""
    return path == directory or directory in path.parents


def _test_home(home, real_dirs):
    """Validate TAILNET_HOME (§7.2 rule 3) and return it resolved.

    The resolved path is what every test path is built from, so a symlink re-pointed after
    this check cannot steer later reads into the real directories.
    """
    if not os.path.isabs(home):
        raise _unsafe(f"TAILNET_HOME must be an absolute path, not {home!r}")
    resolved = Path(os.path.realpath(home))
    for real in real_dirs:
        if _inside(resolved, real) or _inside(real, resolved):
            raise _unsafe(f"TAILNET_HOME {home} overlaps the real {real}: a test run must "
                          "never be able to read the real credentials")
    # Every test path is built under the resolved home without resolving again, and the
    # files are opened through their directories, which are followed. So a config/ or
    # state/ that links out (into the real directories, say) would send a test run there:
    # the real read.json read, test lines in the real audit log, the real files forgotten.
    # Checked in test posture only; a production ~/.config/tailnet may well be a link.
    for entry in _TEST_DIRS:
        try:
            linked = stat.S_ISLNK(os.lstat(resolved / entry).st_mode)
        except (FileNotFoundError, NotADirectoryError):
            # Not there, or under something that is not a directory: nothing to follow, and
            # whatever is in the way is refused where its files are opened.
            continue
        except OSError as exc:
            raise _unsafe(f"cannot check {resolved / entry}: {exc.strerror}") from None
        if linked:
            raise _unsafe(f"{resolved / entry} is a symlink; a test home's own directories "
                          "must be plain directories, so a test run cannot be led into the "
                          "real ones")
    return resolved


@dataclass(frozen=True)
class Posture:
    """Where this run's API calls go and where its files live, fixed for the whole run.

    Production is the default. Test posture exists so the suite can run the real CLI
    against a loopback server with its own files; it is entered only when both overrides
    are set and both pass §7.2, and a failed check refuses rather than falling back.
    """

    kind: str
    api_base: str
    config_dir: Path
    state_dir: Path
    drafts_dir: Path
    claude_settings: Path
    runs_tailscale: bool
    # The argument urllib's ProxyHandler takes: None means the environment's proxies
    # (production honours HTTPS_PROXY), {} means none at all, so test traffic and fixture
    # secrets cannot leave the box through a proxy.
    proxies: dict | None

    @classmethod
    def from_env(cls, environ, real_home=None):
        """Decide the posture from an environment mapping, checking the overrides first.

        `real_home` defaults to the password database's home; tests pass a temporary one.
        Nothing is read or contacted before the overrides have passed, apart from resolving
        `localhost` when the base names it.
        """
        home_dir = Path(real_home) if real_home is not None else passwd_home()
        real_config = home_dir / ".config" / "tailnet"
        real_state = home_dir / ".local" / "state" / "tailnet"
        # Presence is what counts: an exported-but-empty variable is still a request for
        # test posture, and quietly running production instead is the fallback §7.2 forbids.
        base = environ.get("TAILNET_API_BASE")
        home = environ.get("TAILNET_HOME")
        if base is None and home is None:
            claude_dir = environ.get("CLAUDE_CONFIG_DIR") or home_dir / ".claude"
            return cls(kind="production", api_base=PRODUCTION_API, config_dir=real_config,
                       state_dir=real_state, drafts_dir=real_state / "drafts",
                       claude_settings=Path(claude_dir) / "settings.json",
                       runs_tailscale=True, proxies=None)
        if base is None:
            raise LocalError("HOME_WITHOUT_BASE", "TAILNET_HOME is set without TAILNET_API_BASE; "
                             "set both for a test run, or neither for production")
        if home is None:
            raise _unsafe("TAILNET_API_BASE is set without TAILNET_HOME; set both for a test "
                          "run, or neither for production")
        api_base = _test_api_base(base)
        real_dirs = [Path(os.path.realpath(real_config)), Path(os.path.realpath(real_state))]
        test_home = _test_home(home, real_dirs)
        state = test_home / "state"
        return cls(kind="test", api_base=api_base, config_dir=test_home / "config",
                   state_dir=state, drafts_dir=state / "drafts",
                   claude_settings=test_home / "claude" / "settings.json",
                   runs_tailscale=False, proxies={})
