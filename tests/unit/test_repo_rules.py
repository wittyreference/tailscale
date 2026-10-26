# ABOUTME: Repository-wide rules from CLAUDE.md, checked as tests so breaking one fails `make test`.
# ABOUTME: Covers the ABOUTME header on every code file; later items add the write-surface tripwires.

import subprocess
from pathlib import Path

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
