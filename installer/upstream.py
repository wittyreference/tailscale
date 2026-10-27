# ABOUTME: Fetches Tailscale's upstream skill at one pinned commit and proves the checkout is exactly that
# ABOUTME: commit, unmodified, before anything is copied from it (DESIGN.md §20.3). Every git call is here.

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

# The installable unit of tailscale/tailscale-skill is this directory; the licence (BSD-3)
# sits at the repository root and travels with every copy [up §1, §2].
SKILL_DIR = Path("skills") / "tailscale"
LICENSE = "LICENSE"
# A full commit id. An abbreviated one is a lookup the repository answers, and a later
# commit can make the same prefix ambiguous or point it elsewhere.
_PIN = re.compile(r"[0-9a-f]{40}")
LOCAL_TIMEOUT = 30
# A clone or fetch crosses the network to GitHub.
NETWORK_TIMEOUT = 300
# Variables that point git at another repository, work tree or index than the one named on
# its command line. Inherited from a hook or a shell that set them, they would aim a clone,
# a checkout or a HEAD check at the wrong place.
_REPOSITORY_VARIABLES = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_PREFIX",
    "GIT_IMPLICIT_WORK_TREE", "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE",
})


class UpstreamError(Exception):
    """The upstream step cannot go on: git failed, or the checkout is not the pinned content.

    The installer stops the upstream step on it and copies nothing (§20.3: "else abort").
    """


def git_environment(environ):
    """The environment git runs in: the caller's, without repository pointers, never prompting.

    GIT_TERMINAL_PROMPT=0 makes a clone that would ask for credentials fail at once: the
    upstream repository is public, so a prompt means something is wrong, and an agent's
    shell has nobody to answer it.
    """
    env = {name: value for name, value in environ.items() if name not in _REPOSITORY_VARIABLES}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(args, environ, *, timeout=LOCAL_TIMEOUT):
    """Run git with `args`; return (exit status, stdout, stderr) as text.

    git is looked up on the PATH the caller gives, so the installer and its tests decide
    which git runs. A git that is missing, hangs or cannot start is an UpstreamError.
    """
    program = shutil.which("git", path=environ.get("PATH", ""))
    if program is None:
        raise UpstreamError("git is not on PATH")
    try:
        # A path or message that is not UTF-8 is shown with replacement characters rather
        # than ending the run.
        done = subprocess.run([program, *[str(a) for a in args]], env=git_environment(environ),
                              stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise UpstreamError(f"`git {' '.join(map(str, args))}` gave no answer within "
                            f"{timeout} s") from None
    except OSError as exc:
        raise UpstreamError(f"could not run {program}: {exc.strerror}") from None
    return done.returncode, done.stdout, done.stderr


def _must(args, environ, what, *, timeout=LOCAL_TIMEOUT):
    """Run git and raise UpstreamError naming `what` failed, with git's last line, unless it exits 0."""
    code, out, err = git(args, environ, timeout=timeout)
    if code != 0:
        last = (err.strip().splitlines() or ["no message"])[-1]
        raise UpstreamError(f"could not {what}: git exited {code}: {last}")
    return out


def check_pin(pin):
    """Refuse a pin that is not a full 40-character commit id, before git is asked anything."""
    if not isinstance(pin, str) or not _PIN.fullmatch(pin):
        raise UpstreamError(f"the pin must be a full 40-character commit id, not {pin!r}")


def is_clone(directory):
    """Say whether `directory` is itself a git checkout, by its own .git, never a parent's.

    Asking git instead would walk up the tree, and a home directory kept in git (dotfiles)
    would answer for any folder below it.
    """
    directory = Path(directory)
    return not directory.is_symlink() and (directory / ".git").is_dir()


def head(clone, environ):
    """The commit a checkout's HEAD names, or None when it has none git can name."""
    code, out, _ = git(["-C", clone, "rev-parse", "--verify", "--quiet", "HEAD"], environ)
    return out.strip() if code == 0 and out.strip() else None


def has_commit(clone, pin, environ):
    """Say whether the clone already holds the pinned commit, so no fetch is needed."""
    check_pin(pin)
    code, _, _ = git(["-C", clone, "cat-file", "-e", f"{pin}^{{commit}}"], environ)
    return code == 0


def clone(url, destination, environ):
    """Clone `url` into `destination` without checking anything out yet (§20.3)."""
    Path(destination).parent.mkdir(parents=True, exist_ok=True)
    _must(["clone", "--quiet", "--no-checkout", url, destination], environ,
          f"clone {url}", timeout=NETWORK_TIMEOUT)


def fetch(url, clone_dir, environ):
    """Fetch `url`'s branches and tags into an existing clone, for a pin it does not hold yet.

    The refspec is spelled out because a fetch from a bare URL brings only the remote's
    HEAD, and a pin on another branch would never arrive.
    """
    _must(["-C", clone_dir, "fetch", "--quiet", "--tags", url,
           "+refs/heads/*:refs/remotes/origin/*"], environ, f"fetch {url}",
          timeout=NETWORK_TIMEOUT)


def checkout(clone_dir, pin, environ):
    """Check the pinned commit out on a detached HEAD; never a branch, which could move."""
    check_pin(pin)
    _must(["-c", "advice.detachedHead=false", "-C", clone_dir, "checkout", "--quiet",
           "--detach", pin], environ, f"check out {pin}")


def verify(clone_dir, pin, environ):
    """Prove the checkout is the pinned content: HEAD is the pin and nothing in it differs.

    HEAD alone is not enough, because the copy is taken from the files on disk: a changed,
    added or ignored file would be copied as if it came from the pin. Raises UpstreamError,
    and nothing is copied, unless both hold.
    """
    check_pin(pin)
    got = head(clone_dir, environ)
    if got != pin:
        raise UpstreamError(f"{clone_dir} is at {got or 'no commit'}, not the pin {pin}; "
                            "nothing was copied")
    changes = _must(["--no-optional-locks", "-C", clone_dir, "status", "--porcelain",
                     "--untracked-files=all", "--ignored"], environ,
                    f"read the status of {clone_dir}")
    if changes.strip():
        raise UpstreamError(f"{clone_dir} has local changes, so its files are not the pinned "
                            "content; nothing was copied")
    if not (Path(clone_dir) / SKILL_DIR).is_dir():
        raise UpstreamError(f"{clone_dir} at {pin} has no {SKILL_DIR}/ to copy")


def files(clone_dir):
    """The upstream skill as relative path -> bytes: skills/tailscale/ with LICENSE beside it.

    A symlink anywhere in it is refused rather than followed: copying its target would put
    whatever it points at (a file of MC's, say) into the skills directory.
    """
    root = Path(clone_dir) / SKILL_DIR
    found = {}
    for directory, subdirectories, names in os.walk(root):
        for name in sorted(subdirectories + names):
            path = Path(directory) / name
            if path.is_symlink():
                raise UpstreamError(f"{path} is a symlink; the upstream copy refuses to follow it")
        for name in names:
            path = Path(directory) / name
            found[path.relative_to(root).as_posix()] = path.read_bytes()
    license_path = Path(clone_dir) / LICENSE
    if license_path.is_symlink() or not license_path.is_file():
        raise UpstreamError(f"{license_path} is missing or not a regular file; the skill is "
                            "copied only with its licence")
    found[LICENSE] = license_path.read_bytes()
    return found


def describe(path, environ):
    """Say what a skills/tailscale the installer did not make is, for the report (§20.3).

    It is left alone either way; this only tells MC what is there: where a symlink points
    (an `npx skills` install is one), and the commit a checkout is at.
    """
    path = Path(path)
    parts = []
    if path.is_symlink():
        parts.append(f"a symlink to {os.readlink(path)}")
    if is_clone(path) or (path.is_symlink() and (path / ".git").is_dir()):
        try:
            parts.append(f"a git checkout at {head(path, environ) or 'no commit'}")
        except UpstreamError as exc:
            parts.append(f"a git checkout ({exc})")
    if parts:
        return ", ".join(parts)
    try:
        mode = os.lstat(path).st_mode
    except OSError as exc:
        return f"unreadable ({exc.strerror})"
    if stat.S_ISDIR(mode):
        return "a directory without tailnet's marker"
    return "a file, not a directory"
