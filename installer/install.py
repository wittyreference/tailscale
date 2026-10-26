# ABOUTME: Installs tailnet for MC: the CLI and its launcher, the pinned spec, both skills, the docs MCP
# ABOUTME: server and the settings rules (DESIGN.md §20). Every change goes through act(); a dry run makes none.

import argparse
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
# The wrapper runs this file with -I, which keeps the script's own directory and the current
# one off sys.path; the installer's modules and the tailnet package it installs are put
# there by name instead.
for _entry in (REPO / "installer", REPO / "src"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import settings_merge
import upstream

from tailnet import errors, gate, secure_files
from tailnet.doctor import (
    DOCS_MCP,
    DOCS_MCP_URL,
    MARKER,
    UPSTREAM_PIN,
    UPSTREAM_URL,
)
from tailnet.output import format_utc
from tailnet.redact import redact

# The launcher's first ABOUTME line doubles as its signature: a file at ~/.local/bin/tailnet
# without it is someone else's program and is never overwritten or removed.
LAUNCHER_ABOUT = ("# ABOUTME: Launcher for the tailnet CLI, written by tailnet's installer "
                  "(install-tailnet.sh).")
SPEC_FILES = ("tailscale-openapi.yaml", "SHA256SUMS")
# Claude Code's own CLI does the MCP registration; these are its documented forms for a
# remote HTTP server at user scope [pkg §8; up §7]. Tests check them as argument lists and
# never run them.
MCP_GET = ("claude", "mcp", "get", DOCS_MCP)
MCP_ADD = ("claude", "mcp", "add", "--transport", "http", "--scope", "user", DOCS_MCP,
           DOCS_MCP_URL)
MCP_REMOVE = ("claude", "mcp", "remove", DOCS_MCP, "--scope", "user")
MCP_LOGIN = f"claude mcp login {DOCS_MCP} --no-browser"
FILE_MODE = 0o644
DIR_MODE = 0o755
PRIVATE_MODE = 0o700
LAUNCHER_MODE = 0o755
# The launcher, the markers and the install record are a few hundred bytes each.
SMALL = 64 * 1024
# The pinned OpenAPI document is a few megabytes; anything far larger is not it.
SPEC_MAX = 64 * 1024 * 1024
PROGRAM_TIMEOUT = 60
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class StepError(Exception):
    """One step cannot go on; the installer stops that step, says why, and runs the others."""


@dataclass(frozen=True)
class Target:
    """Where an install goes: a home and a Claude directory, and every path built from them.

    `claude_config_dir` is CLAUDE_CONFIG_DIR made absolute, or None when it is unset. It
    decides how the two rules that guard the settings file are spelled, read exactly as
    gate.claude_dir reads it, so status and doctor look for the rules the installer wrote.
    """

    home: Path
    claude_dir: Path
    claude_config_dir: str | None = None

    @property
    def share(self):
        """The installer's own directory: the CLI package, the spec, the clone, the record."""
        return self.home / ".local" / "share" / "tailnet"

    @property
    def lib(self):
        """The installed copy of the tailnet package the launcher imports."""
        return self.share / "lib" / "tailnet"

    @property
    def launcher(self):
        """The `tailnet` command MC and the agent run."""
        return self.home / ".local" / "bin" / "tailnet"

    @property
    def spec(self):
        """The pinned OpenAPI spec, where the skill's references grep it."""
        return self.share / "spec"

    @property
    def record(self):
        """install.json: what this installer added, for --uninstall and doctor's L8."""
        return self.share / "install.json"

    @property
    def clone(self):
        """The upstream skill's clone, checked out at the pin."""
        return self.share / "upstream" / "tailscale-skill"

    @property
    def config(self):
        """The CLI's config directory: MC's credentials and protected list, never the installer's."""
        return self.home / ".config" / "tailnet"

    @property
    def state(self):
        """The CLI's state directory: the token cache, the audit log, the apply lock."""
        return self.home / ".local" / "state" / "tailnet"

    @property
    def drafts(self):
        """Where `policy draft` writes its draft directories."""
        return self.state / "drafts"

    @property
    def skill(self):
        """Our skill's directory in the Claude directory."""
        return self.claude_dir / "skills" / "tailnet"

    @property
    def upstream_copy(self):
        """The upstream skill's directory in the Claude directory."""
        return self.claude_dir / "skills" / "tailscale"

    @property
    def settings(self):
        """The Claude Code settings file whose rules put every --apply in front of MC."""
        return self.claude_dir / "settings.json"

    def rules(self):
        """The ask and deny strings for this Claude directory, from the package's rules.json."""
        return gate.rules_for(self.claude_config_dir)


def passwd_home():
    """The invoking user's home from the password database, where the CLI keeps its files."""
    return Path(pwd.getpwuid(os.geteuid()).pw_dir)


def target_from(environ):
    """The install target for this environment: HOME (else the password database) and the
    Claude directory, which is CLAUDE_CONFIG_DIR when set, as Claude Code itself reads it.
    """
    home = environ.get("HOME")
    home = Path(home) if home and os.path.isabs(home) else passwd_home()
    configured = environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        claude = Path(os.path.abspath(configured))
        return Target(home, claude, str(claude))
    return Target(home, home / ".claude", None)


@dataclass(frozen=True)
class Options:
    """What one run does: the command-line choices, and the upstream repository and pin.

    The upstream URL and pin are parameters so tests can point them at a local fixture
    repository; the command line always uses the pins doctor checks against.
    """

    dry_run: bool = False
    upstream: bool = True
    mcp: bool = True
    upstream_url: str = UPSTREAM_URL
    upstream_pin: str = UPSTREAM_PIN


# --- Files: exact modes, whole-file replacement, copies built beside their destination ---


def mode_of(path):
    """A path's permission bits, not following a symlink."""
    return stat.S_IMODE(os.lstat(path).st_mode)


def make_dirs(path, mode):
    """Create `path` and its missing parents, each created one set to exactly `mode`.

    Directories that already exist are left as they are. The umask is not trusted: a
    group-writable share directory would make secure_files refuse the install record.
    """
    path = Path(path)
    missing = []
    while not os.path.lexists(path):
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        os.mkdir(directory, mode)
        os.chmod(directory, mode)


def _fsync_directory(directory):
    """Make renames in `directory` durable: an entry is on disk only once its directory is."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, data, mode):
    """Create `path` (which must not exist) holding `data`, at exactly `mode`, synced."""
    fd = os.open(path, _CREATE, 0o600)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_path(path):
    """Remove a file, a link or a whole directory tree; a link is removed, never followed."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def write_file(path, data, mode):
    """Replace `path` with `data` at `mode` through a temp file and one rename."""
    path = Path(path)
    temp = path.with_name(f".{path.name}.tailnet-new")
    remove_path(temp)
    _write_new(temp, data, mode)
    os.replace(temp, path)
    _fsync_directory(path.parent)


def source_files(root):
    """A repository directory's files to copy, as relative path -> bytes; bytecode is skipped.

    A symlink is refused: the copy would carry its target, which nothing here vouches for.
    """
    root = Path(root)
    found = {}
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = sorted(d for d in subdirectories if d != "__pycache__")
        for name in subdirectories + names:
            if (Path(directory) / name).is_symlink():
                raise StepError(f"{Path(directory) / name} is a symlink; nothing was copied")
        for name in sorted(names):
            if not name.endswith(".pyc"):
                path = Path(directory) / name
                found[path.relative_to(root).as_posix()] = path.read_bytes()
    return found


def installed_tree(root):
    """What is installed at `root`, by relative path: (kind, mode, bytes); None if not a directory.

    Python's bytecode caches are left out: running the CLI writes them, and they are not
    part of what was installed.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        return None
    found = {".": ("dir", mode_of(root), None)}
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = [d for d in subdirectories if d != "__pycache__"]
        for name in subdirectories + [n for n in names if not n.endswith(".pyc")]:
            path = Path(directory) / name
            st = os.lstat(path)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(st.st_mode):
                found[relative] = ("link", 0, os.readlink(path).encode())
            elif stat.S_ISDIR(st.st_mode):
                found[relative] = ("dir", stat.S_IMODE(st.st_mode), None)
            else:
                found[relative] = ("file", stat.S_IMODE(st.st_mode), path.read_bytes())
    return found


def wanted_tree(files):
    """The tree install_tree would leave for `files`, in installed_tree's form."""
    found = {".": ("dir", DIR_MODE, None)}
    for relative, data in files.items():
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            found["/".join(parts[:depth])] = ("dir", DIR_MODE, None)
        found[relative] = ("file", FILE_MODE, data)
    return found


def install_tree(destination, files):
    """Put `files` at `destination` as a fresh copy: built beside it, renamed in, the old removed.

    Readers see the old tree or the new one. A copy, not a symlink, so an edit in the
    checkout never changes the installed CLI or a skill in the middle of a session (§20.2).
    Leftovers of an interrupted run are cleared first.
    """
    destination = Path(destination)
    parent = destination.parent
    new = parent / f".{destination.name}.new"
    old = parent / f".{destination.name}.old"
    remove_path(new)
    remove_path(old)
    make_dirs(new, DIR_MODE)
    for relative in sorted(files):
        path = new / relative
        make_dirs(path.parent, DIR_MODE)
        _write_new(path, files[relative], FILE_MODE)
    if os.path.lexists(destination):
        os.rename(destination, old)
    os.rename(new, destination)
    remove_path(old)
    _fsync_directory(parent)


def read_small_json(path):
    """A small JSON object the installer wrote: (object, None), or (None, why it is unusable).

    Missing is (None, None). A symlink is never followed, as doctor never follows one.
    """
    try:
        raw = secure_files.read_regular(path, SMALL)
    except FileNotFoundError:
        return None, None
    except secure_files.Unreadable as exc:
        return None, str(exc)
    except OSError as exc:
        return None, exc.strerror
    try:
        doc = json.loads(raw)
    except ValueError:
        return None, "it is not JSON"
    return (doc, None) if isinstance(doc, dict) else (None, "it is not a JSON object")


def whose(directory, key):
    """Whose a skill directory is: ("absent", None), ("ours", marker) or ("foreign", None).

    Ours means a real directory holding a regular `.tailnet-install` marker with `key`
    (`commit` for our skill, `pin` for the upstream copy). Anything else, a symlink above
    all, belongs to someone else and is never changed.
    """
    directory = Path(directory)
    if not os.path.lexists(directory):
        return "absent", None
    if directory.is_symlink() or not directory.is_dir():
        return "foreign", None
    marker, _ = read_small_json(directory / MARKER)
    if marker is None or key not in marker:
        return "foreign", None
    return "ours", marker


def marker_bytes(marker):
    """A marker file's bytes: small, indented JSON."""
    return (json.dumps(marker, indent=2) + "\n").encode()


def _reason(exc):
    """One line saying why a step stopped, from whatever it raised."""
    if isinstance(exc, OSError) and exc.filename:
        return f"{exc.filename}: {exc.strerror}"
    if isinstance(exc, errors.TailnetError):
        return exc.message
    return str(exc)


# --- The run ---


class Installer:
    """One run of the installer: the steps in order, each reporting what it did or would do.

    Every change goes through act(), which a dry run turns into a `would:` line; reads and
    read-only lookups (git's view of a checkout, `claude mcp get`) run either way. A step
    that cannot go on is STOPPED with its reason, and the others still run.
    """

    def __init__(self, target, options, *, environ, out, now=None, repo=REPO, python=None):
        self.target = target
        self.options = options
        self.environ = dict(environ)
        self.out = out
        self.now = now or datetime.now(timezone.utc)
        self.stamp = format_utc(self.now)
        self.repo = Path(repo)
        self.python = python or os.path.realpath(sys.executable)
        self.step = None
        self.reported = False
        self.changed = False
        self.stopped = []
        self.added = {"lib": False, "launcher": False, "spec": False, "skill": False,
                      "upstream_copy": False, "upstream_clone": False, "mcp": False}
        self.rules_added = {"ask": [], "deny": []}
        self.mcp_present = False
        self.commit = None
        self.dirty = None
        self.previous = None
        self.previous_problem = None

    # Reporting

    def say(self, line):
        """Print one line, redacted like everything else tailnet prints."""
        self.out.write(redact(line) + "\n")

    def act(self, description, fn):
        """Make one change, or in a dry run say it would be made; return whether it was made."""
        self.changed = self.reported = True
        if self.options.dry_run:
            self.say(f"would: {description}")
            return False
        fn()
        self.say(f"done: {description}")
        return True

    def tell(self, text):
        """Report the step's outcome when it is neither a change nor `no changes`."""
        self.reported = True
        self.say(f"{self.step}: {text}")

    def warn(self, text):
        """A warning for MC about something the installer leaves alone."""
        self.say(f"{self.step}: warning: {text}")

    def same(self, detail=None):
        """Report that the step found everything already in place."""
        self.reported = True
        self.say(f"{self.step}: no changes" + (f" ({detail})" if detail else ""))

    def stop(self, why):
        """Stop this step with nothing more changed, and say why."""
        self.reported = True
        self.stopped.append(self.step)
        self.say(f"{self.step}: STOPPED: {why}")

    def run(self):
        """Run every step in order; return 0, or 1 when any step stopped."""
        self.previous, self.previous_problem = read_small_json(self.target.record)
        self.commit, self.dirty = self.source_state()
        for name, step in self.steps():
            self.step, self.reported = name, False
            try:
                step()
            except (OSError, StepError, upstream.UpstreamError, errors.TailnetError,
                    secure_files.Unreadable, settings_merge.Unmergeable) as exc:
                self.stop(_reason(exc))
            if not self.reported:
                self.same()
        self.finish()
        return 1 if self.stopped else 0

    def steps(self):
        """The install, in order: local files first, then the skills, the rules, the record."""
        return [("directories", self.directories), ("lib", self.lib),
                ("launcher", self.launcher), ("spec", self.spec), ("skill", self.skill),
                ("upstream", self.upstream), ("settings", self.settings), ("mcp", self.mcp),
                ("path", self.path), ("record", self.record)]

    def source_state(self):
        """The checkout's commit and whether it has uncommitted changes; (None, None) unknown."""
        if not os.path.lexists(self.repo / ".git"):
            return None, None
        try:
            commit = upstream.head(self.repo, self.environ)
            code, out, _ = upstream.git(["--no-optional-locks", "-C", self.repo, "status",
                                         "--porcelain"], self.environ)
        except upstream.UpstreamError:
            return None, None
        return commit, (bool(out.strip()) if code == 0 else None)

    # Steps

    def directories(self):
        """The CLI's private directories: created 0700, or tightened, never loosened (§20.2)."""
        for path in (self.target.config, self.target.state, self.target.drafts):
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                self.act(f"create {path} (0700)",
                         lambda p=path: (make_dirs(p.parent, DIR_MODE),
                                         make_dirs(p, PRIVATE_MODE)))
                continue
            current = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                self.warn(f"{path} is a symlink; left alone (the CLI checks where it points "
                          "each time it uses it)")
            elif not stat.S_ISDIR(st.st_mode):
                raise StepError(f"{path} exists and is not a directory; left alone")
            elif st.st_uid != os.geteuid():
                raise StepError(f"{path} is owned by uid {st.st_uid}, not you; left alone")
            elif current & 0o077:
                self.act(f"tighten {path} from {current:04o} to {current & 0o700:04o}",
                         lambda p=path, m=current & 0o700: os.chmod(p, m))

    def lib(self):
        """The CLI package, rules.json with it, copied into place (§20.2)."""
        source = self.repo / "src" / "tailnet"
        files = source_files(source)
        if installed_tree(self.target.lib) != wanted_tree(files):
            self.act(f"copy {source} to {self.target.lib} (dirs 0755, files 0644)",
                     lambda: (make_dirs(self.target.lib.parent, DIR_MODE),
                              install_tree(self.target.lib, files)))
        self.added["lib"] = True

    def launcher_text(self):
        """The launcher: Python isolated, the installed package first on its path, then main()."""
        return "\n".join([
            f"#!{self.python} -I",
            LAUNCHER_ABOUT,
            ("# ABOUTME: -I keeps PYTHONPATH, the user site and the cwd out of a process that "
             "holds a secret."),
            "import sys",
            "",
            f"sys.path.insert(0, {str(self.target.lib.parent)!r})",
            "from tailnet.cli import main",
            "",
            "sys.exit(main())",
            "",
        ]).encode()

    def launcher(self):
        """~/.local/bin/tailnet, 0755; a file there that this installer did not write is left alone."""
        path = self.target.launcher
        if any(c.isspace() for c in self.python):
            raise StepError(f"Python's path {self.python!r} holds a space, which a #! line "
                            "cannot carry")
        text = self.launcher_text()
        write = (lambda: (make_dirs(path.parent, DIR_MODE),
                          write_file(path, text, LAUNCHER_MODE)))
        if not os.path.lexists(path):
            self.act(f"write the launcher {path} (0755)", write)
            self.added["launcher"] = True
            return
        try:
            current = secure_files.read_regular(path, SMALL)
        except secure_files.Unreadable as exc:
            raise StepError(f"{path}: {exc}; it is not this installer's launcher, so it was "
                            "left alone") from None
        lines = current.split(b"\n")
        if len(lines) < 2 or lines[1] != LAUNCHER_ABOUT.encode():
            raise StepError(f"{path} is not a launcher this installer wrote; left alone. Move "
                            "it aside and run the installer again")
        if current != text or mode_of(path) != LAUNCHER_MODE:
            self.act(f"replace the launcher {path} (0755)", write)
        self.added["launcher"] = True

    def spec(self):
        """The pinned OpenAPI spec and its checksum file, verified against each other (§20.2)."""
        source = self.repo / "spec"
        sums = {}
        for line in (source / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            if line.strip():
                digest, name = line.split()
                sums[name.lstrip("*")] = digest
        if sorted(sums) != ["tailscale-openapi.yaml"]:
            raise StepError(f"{source / 'SHA256SUMS'} does not pin exactly tailscale-openapi.yaml")
        data = {name: (source / name).read_bytes() for name in SPEC_FILES}
        if hashlib.sha256(data["tailscale-openapi.yaml"]).hexdigest() != sums[
                "tailscale-openapi.yaml"]:
            raise StepError(f"{source / 'tailscale-openapi.yaml'} does not match its "
                            "SHA256SUMS; nothing was copied")
        destination = self.target.spec
        placed = all(not (destination / n).is_symlink() and (destination / n).is_file()
                     and (destination / n).read_bytes() == data[n]
                     and mode_of(destination / n) == FILE_MODE for n in SPEC_FILES)
        if not placed:
            self.act(f"copy the pinned spec to {destination} (sha256 verified)",
                     lambda: self._copy_spec(data, sums))
        self.added["spec"] = True

    def _copy_spec(self, data, sums):
        """Write the spec files, then hash the copy on disk against the pin."""
        make_dirs(self.target.spec, DIR_MODE)
        for name in SPEC_FILES:
            write_file(self.target.spec / name, data[name], FILE_MODE)
        written = secure_files.read_regular(self.target.spec / "tailscale-openapi.yaml",
                                            SPEC_MAX)
        if hashlib.sha256(written).hexdigest() != sums["tailscale-openapi.yaml"]:
            raise StepError("the copied spec does not match its SHA256SUMS")

    def _skills_dir(self):
        """The Claude directory (0700 if this creates it; Claude Code keeps its login there)
        and its skills directory."""
        make_dirs(self.target.claude_dir, PRIVATE_MODE)
        make_dirs(self.target.claude_dir / "skills", DIR_MODE)

    def skill(self):
        """Our skill, copied with a marker naming the commit; a skill there without it stops the step."""
        path = self.target.skill
        owner, marker = whose(path, "commit")
        if owner == "foreign":
            raise StepError(f"{path} exists without tailnet's {MARKER} marker "
                            f"({upstream.describe(path, self.environ)}); left alone. Move it "
                            "aside and run the installer again")
        source = self.repo / "skill" / "tailnet"
        files = source_files(source)
        if owner == "ours" and (marker.get("commit"), marker.get("dirty")) == (
                self.commit, self.dirty):
            kept = {**files, MARKER: marker_bytes(marker)}
            if installed_tree(path) == wanted_tree(kept):
                self.added["skill"] = True
                return
        fresh = {"commit": self.commit, "dirty": self.dirty, "installed_at": self.stamp}
        self.act(f"copy {source} to {path} with its {MARKER} marker",
                 lambda: (self._skills_dir(),
                          install_tree(path, {**files, MARKER: marker_bytes(fresh)})))
        self.added["skill"] = True

    def upstream(self):
        """Tailscale's skill at the pin (§20.3); a skills/tailscale that is not ours is left alone."""
        if not self.options.upstream:
            self.tell("skipped (--no-upstream)")
            return
        url, pin = self.options.upstream_url, self.options.upstream_pin
        upstream.check_pin(pin)
        destination, clone = self.target.upstream_copy, self.target.clone
        owner, marker = whose(destination, "pin")
        if owner == "foreign":
            self.tell(f"{destination} is not tailnet's copy "
                      f"({upstream.describe(destination, self.environ)}); left alone, and "
                      "nothing was cloned")
            return
        pending = self._clone(url, pin, clone)
        copy = (f"copy {upstream.SKILL_DIR} and {upstream.LICENSE} at {pin} to {destination} "
                f"with its {MARKER} marker")
        current = owner == "ours" and marker.get("pin") == pin
        if pending and self.options.dry_run:
            # Nothing is cloned in a dry run, so there is nothing yet to verify or copy from.
            if not current:
                self.act(copy, None)
            return
        upstream.verify(clone, pin, self.environ)
        self.added["upstream_clone"] = True
        if not current:
            files = upstream.files(clone)
            self.act(copy, lambda: (self._skills_dir(), install_tree(
                destination, {**files, MARKER: marker_bytes({"pin": pin})})))
        self.added["upstream_copy"] = True

    def _clone(self, url, pin, clone):
        """Bring the clone to the pin; return whether anything had to be (or would be) done.

        A clone already at the pin is left for verify to judge. A pin the clone lacks is
        fetched; one it has is only checked out, so a re-run needs no network.
        """
        env = self.environ
        if not os.path.lexists(clone):
            self.act(f"clone {url} into {clone}", lambda: upstream.clone(url, clone, env))
            self.act(f"check out {pin} in {clone}", lambda: upstream.checkout(clone, pin, env))
            return True
        if not upstream.is_clone(clone):
            raise StepError(f"{clone} exists and is not a git clone; left alone")
        if upstream.head(clone, env) == pin:
            return False
        if not upstream.has_commit(clone, pin, env):
            self.act(f"fetch {url} into {clone}", lambda: upstream.fetch(url, clone, env))
        self.act(f"check out {pin} in {clone}", lambda: upstream.checkout(clone, pin, env))
        return True

    def settings(self):
        """The ask and deny rules, merged into the settings Claude Code reads (§20.4)."""
        outcome = settings_merge.merge_file(self.target.settings, self.target.rules(),
                                            now=self.now, dry_run=self.options.dry_run)
        for warning in outcome.warnings:
            self.warn(warning)
        if outcome.status == "aborted":
            raise StepError(f"{outcome.message}\nUntil the gate rule is in place, the CLI "
                            "refuses every --apply.")
        self.rules_added = outcome.added
        if outcome.status == "unchanged":
            return
        self.changed = self.reported = True
        self.say(("would: " if outcome.status == "would" else "done: ") + outcome.message)
        for line in outcome.diff.splitlines():
            self.say(line)

    def _claude(self, program, argv, *, must=False):
        """Run Claude Code's CLI with `argv`'s arguments; return (exit status, stdout)."""
        try:
            done = subprocess.run([program, *argv[1:]], env=self.environ,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=PROGRAM_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            raise StepError(f"`{' '.join(argv)}` gave no answer within {PROGRAM_TIMEOUT} s") \
                from None
        if must and done.returncode != 0:
            last = (done.stderr.strip().splitlines() or ["no message"])[-1]
            raise StepError(f"`{' '.join(argv)}` exited {done.returncode}: {last}")
        return done.returncode, done.stdout

    def mcp(self):
        """Tailscale's docs MCP server at user scope, through Claude Code's own CLI (§20.5)."""
        if not self.options.mcp:
            self.tell("skipped (--no-mcp)")
            return
        program = shutil.which("claude", path=self.environ.get("PATH", ""))
        if program is None:
            self.tell("skipped: claude is not on PATH; to register the docs server later, "
                      f"run: {' '.join(MCP_ADD)}")
            return
        code, out = self._claude(program, MCP_GET)
        if code == 0 and DOCS_MCP_URL in out:
            self.mcp_present = True
            return
        if code == 0:
            self.tell(f"{DOCS_MCP} is registered with another URL; left as it is (tailnet's is "
                      f"{DOCS_MCP_URL})")
            return
        if self.act(f"register the docs MCP server: {' '.join(MCP_ADD)}",
                    lambda: self._claude(program, MCP_ADD, must=True)):
            self.added["mcp"] = self.mcp_present = True

    def path(self):
        """Whether MC's login PATH finds the launcher; a warning only, dotfiles are never edited."""
        launcher = self.target.launcher
        if not launcher.is_file():
            self.tell("not checked: the launcher is not in place"
                      + (" yet (dry run)" if self.options.dry_run else ""))
            return
        bash = shutil.which("bash", path=self.environ.get("PATH", ""))
        if bash is None:
            self.tell("not checked: bash is not on PATH")
            return
        try:
            done = subprocess.run([bash, "-lc", "command -v tailnet"], env=self.environ,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=PROGRAM_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            self.tell(f"not checked: a login shell gave no answer within {PROGRAM_TIMEOUT} s")
            return
        found = done.stdout.strip()
        if found == str(launcher):
            self.tell(f"the login PATH finds {launcher}")
        else:
            self.reported = True
            self.warn(f"the login PATH finds {found or 'no tailnet'}, not {launcher}: add "
                      f"{launcher.parent} to PATH in your shell profile (the installer never "
                      "edits dotfiles)")

    def record(self):
        """install.json, 0600: the commit, and what was added, for --uninstall and doctor (§20.2)."""
        if self.previous_problem:
            raise StepError(f"{self.target.record} is unreadable ({self.previous_problem}); "
                            "left alone so its list of added rules survives. Move it aside to "
                            "start a new record")
        previous = self.previous or {}
        before = previous.get("added") if isinstance(previous.get("added"), dict) else {}
        added = {name: bool(flag or before.get(name) is True) for name, flag in self.added.items()}
        recorded = before.get("rules") if isinstance(before.get("rules"), dict) else {}
        added["rules"] = {key: list(dict.fromkeys(
            [r for r in recorded.get(key, []) if isinstance(r, str)]
            + self.rules_added[key])) for key in settings_merge.LISTS}
        kept = previous.get("installed_at") if not self.changed else None
        doc = {"v": 1, "commit": self.commit, "dirty": self.dirty,
               "installed_at": kept or self.stamp, "last_run": self.stamp,
               "claude_dir": str(self.target.claude_dir), "added": added}
        unchanged = ({k: v for k, v in doc.items() if k != "last_run"}
                     == {k: v for k, v in previous.items() if k != "last_run"})
        data = (json.dumps(doc, indent=2) + "\n").encode()
        write = (lambda: (make_dirs(self.target.share, DIR_MODE),
                          secure_files.write_private_atomic(self.target.record, data)))
        if not unchanged:
            self.act(f"write the install record {self.target.record} (0600)", write)
        elif not self.options.dry_run:
            write()
            self.same("last_run updated")

    def finish(self):
        """The closing lines: what a dry run did not do, what stopped, and MC's next steps."""
        self.say("")
        if self.options.dry_run:
            self.say("Dry run: nothing was written, cloned or registered.")
        if self.stopped:
            self.say(f"Stopped: {', '.join(self.stopped)}. Each STOPPED line above says why; "
                     "the other steps ran.")
        guide = self.target.skill if self.added["skill"] else self.repo / "skill" / "tailnet"
        steps = [
            (f"Create the read client in the Tailscale console (and the write client, if you "
             f"want writes), as {guide / 'references' / 'credentials.md'} describes."),
            "Over SSH, at a terminal: tailnet credentials set read",
            (f"Write the protected file {self.target.config / 'protected'} (doctor proposes "
             "its contents)."),
            "tailnet doctor",
        ]
        if self.mcp_present:
            steps.append(f"{MCP_LOGIN} (prints a URL to finish on your phone; needs a "
                         "terminal)")
        self.say("Next (MC):")
        for number, step in enumerate(steps, 1):
            self.say(f"  {number}. {step}")


def parse(argv, environ):
    """The installer's options; DRY_RUN set to anything but empty or 0 means --dry-run (§20.1).

    No option is ever abbreviated, as with every tailnet parser: `--dry` is refused rather
    than taken to mean something.
    """
    parser = argparse.ArgumentParser(
        prog="install-tailnet.sh", allow_abbrev=False,
        description="Install tailnet: the CLI, its skill, Tailscale's skill at the pin, the "
                    "docs MCP server and the Claude Code rules.")
    parser.add_argument("--dry-run", action="store_true",
                        help="say what would change, and change nothing")
    parser.add_argument("--no-upstream", action="store_true",
                        help="skip Tailscale's upstream skill")
    parser.add_argument("--no-mcp", action="store_true",
                        help="skip the Tailscale docs MCP server")
    args = parser.parse_args(argv)
    dry = args.dry_run or environ.get("DRY_RUN", "") not in ("", "0")
    return Options(dry_run=dry, upstream=not args.no_upstream, mcp=not args.no_mcp)


def main(argv=None):
    """Run the installer for the invoking user; refuse root, whose home is not MC's."""
    options = parse(sys.argv[1:] if argv is None else argv, os.environ)
    if os.geteuid() == 0:
        sys.stderr.write("install-tailnet: refusing to run as root: the credentials "
                         "directory, the launcher and the Claude Code settings would land in "
                         "root's home, not yours. Run it as yourself.\n")
        return 1
    target = target_from(os.environ)
    if target.home != passwd_home():
        sys.stderr.write(f"install-tailnet: warning: HOME is {target.home}, but your home in "
                         f"the password database is {passwd_home()}; the tailnet CLI keeps "
                         "its credentials and state under the latter, so this install is not "
                         "the one it reads.\n")
    return Installer(target, options, environ=os.environ, out=sys.stdout).run()


if __name__ == "__main__":
    sys.exit(main())
