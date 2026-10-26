# ABOUTME: Repository-wide rules from CLAUDE.md, checked as tests so breaking one fails `make test`.
# ABOUTME: Covers ABOUTME headers and the loopback-only suite; later items add the write tripwires.

import socket
import subprocess
from pathlib import Path

import netguard
import pytest

REPO = Path(__file__).resolve().parents[2]

# DESIGN.md §4: code is *.py, *.sh, githooks/*, the Makefile and anything run through a
# shebang (the generated launcher is one). Data files and Markdown are exempt.
CODE_SUFFIXES = {".py", ".sh"}
CODE_NAMES = {"Makefile"}


def repo_files():
    """List every file git would commit: tracked ones plus untracked ones not ignored.

    Untracked files are included so a new file is held to the rules before its first
    commit, not after it.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO, capture_output=True, check=True,
    )
    paths = (REPO / name for name in listing.stdout.decode().split("\0") if name)
    return sorted(path for path in paths if path.is_file())


def is_code(path):
    """Say whether DESIGN.md §4 counts this file as executable code."""
    if path.suffix in CODE_SUFFIXES or path.name in CODE_NAMES:
        return True
    if path.parent.name == "githooks":
        return True
    with path.open("rb") as handle:
        return handle.read(2) == b"#!"


def has_two_aboutme_lines(path):
    """Say whether the file opens (after any shebang) with two non-empty ABOUTME lines."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    head = lines[:2]
    return len(head) == 2 and all(
        line.startswith("# ABOUTME: ") and line[len("# ABOUTME: "):].strip() for line in head
    )


def test_every_code_file_starts_with_two_aboutme_lines():
    code = [path for path in repo_files() if is_code(path)]
    # An empty listing would pass vacuously, so prove the walk saw this very file.
    assert Path(__file__).resolve() in code
    missing = [str(path.relative_to(REPO)) for path in code if not has_two_aboutme_lines(path)]
    assert missing == [], f"code files without two leading '# ABOUTME: ' lines: {missing}"


def test_default_suite_never_leaves_loopback():
    # tests/conftest.py installs netguard before any test runs, so it must be live here.
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): even a broken guard would send nothing real.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        with pytest.raises(netguard.NetguardViolation, match="loopback"):
            sock.connect(("192.0.2.1", 9))
    with pytest.raises(netguard.NetguardViolation, match="tailscale"):
        subprocess.run(["tailscale", "version"], check=False)
    # Loopback itself still works: that is where the seam lives.
    with socket.create_server(("127.0.0.1", 0)) as listener, \
            socket.create_connection(listener.getsockname(), timeout=2):
        pass
