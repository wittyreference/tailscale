# ABOUTME: Tests for the installer (DESIGN.md §20): the pinned upstream skill, every installed artifact and
# ABOUTME: its mode, dry run, idempotence and uninstall, run in a temporary HOME with a local upstream repo.

import io
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import install
import pytest
import upstream

from tailnet import doctor, gate

REPO = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 27, 9, 30, 0, tzinfo=timezone.utc)
MARKER = ".tailnet-install"

# Git for the fixture and for the installer runs with no system or global configuration,
# so the developer's own (a signing key, an LFS filter, URL rewrites) cannot reach a test.
GIT_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull}
SKILL_MD = "---\nname: tailscale\ndescription: fixture stand-in for the upstream skill\n---\n"


def environ_for(home):
    """The environment the installer and git see in a test: minimal, with this HOME."""
    return {**GIT_ENV, "HOME": str(home)}


def git(repo, *args, env):
    """Run git in a fixture repository and return its stdout; a failure fails the test."""
    done = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True,
                          text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def commit(repo, message, env):
    """Commit everything in a fixture repository as a fixture author; return the commit id."""
    git(repo, "add", "-A", env=env)
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "-q", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD", env=env)


@dataclass
class Fixture:
    """A local stand-in for tailscale/tailscale-skill: `pin` is its first commit, `later` its second."""

    url: str
    path: Path
    pin: str
    later: str
    env: dict


@pytest.fixture
def upstream_repo(tmp_path):
    """Build the stand-in repository: the upstream layout, LICENSE at the root, two commits."""
    env = environ_for(tmp_path)
    repo = tmp_path / "upstream-fixture"
    skill = repo / "skills" / "tailscale"
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text(SKILL_MD)
    (skill / "references" / "cli.md").write_text("# CLI\n")
    (repo / "LICENSE").write_text("BSD 3-Clause License (fixture)\n")
    (repo / "README.md").write_text("Not part of the skill.\n")
    git(repo, "init", "-q", "-b", "main", env=env)
    pin = commit(repo, "the pinned release", env)
    (skill / "references" / "cli.md").write_text("# CLI, moved on\n")
    later = commit(repo, "a later commit", env)
    return Fixture(str(repo), repo, pin, later, env)


def cloned(tmp_path, fixture, at):
    """A clone of the fixture checked out at one commit, made the way the installer makes it."""
    clone = tmp_path / "clone" / "tailscale-skill"
    upstream.clone(fixture.url, clone, fixture.env)
    upstream.checkout(clone, at, fixture.env)
    return clone


def test_upstream_verify_accepts_the_pinned_head(tmp_path, upstream_repo):
    clone = cloned(tmp_path, upstream_repo, upstream_repo.pin)
    upstream.verify(clone, upstream_repo.pin, upstream_repo.env)
    assert upstream.head(clone, upstream_repo.env) == upstream_repo.pin
    # What gets copied is skills/tailscale and the licence beside it, at the pinned content;
    # the repository's README is not part of the skill.
    files = upstream.files(clone)
    assert sorted(files) == ["LICENSE", "SKILL.md", "references/cli.md"]
    assert files["references/cli.md"] == b"# CLI\n"
    assert files["SKILL.md"] == SKILL_MD.encode()


def test_upstream_verify_refuses_a_head_that_is_not_the_pin(tmp_path, upstream_repo):
    env = upstream_repo.env
    clone = cloned(tmp_path, upstream_repo, upstream_repo.later)
    with pytest.raises(upstream.UpstreamError, match="not the pin"):
        upstream.verify(clone, upstream_repo.pin, env)
    # A short id is refused before git is asked, even one naming the commit HEAD is at: a
    # prefix is a lookup that can come to mean another commit.
    with pytest.raises(upstream.UpstreamError, match="40"):
        upstream.verify(clone, upstream_repo.later[:7], env)
    # At the pin but with a file changed or added, the checkout is no longer the pinned content.
    upstream.checkout(clone, upstream_repo.pin, env)
    skill_md = clone / "skills" / "tailscale" / "SKILL.md"
    skill_md.write_text("edited\n")
    with pytest.raises(upstream.UpstreamError, match="local changes"):
        upstream.verify(clone, upstream_repo.pin, env)
    skill_md.write_text(SKILL_MD)
    upstream.verify(clone, upstream_repo.pin, env)
    (clone / "skills" / "tailscale" / "extra.md").write_text("planted\n")
    with pytest.raises(upstream.UpstreamError, match="local changes"):
        upstream.verify(clone, upstream_repo.pin, env)
    # A commit the repository does not hold cannot be checked out.
    with pytest.raises(upstream.UpstreamError, match="check out"):
        upstream.checkout(clone, "0" * 40, env)


def test_a_symlink_in_the_upstream_skill_is_refused(tmp_path, upstream_repo):
    env = upstream_repo.env
    (upstream_repo.path / "skills" / "tailscale" / "secrets.md").symlink_to("/etc/passwd")
    pin = commit(upstream_repo.path, "a link out of the skill", env)
    clone = cloned(tmp_path, upstream_repo, pin)
    upstream.verify(clone, pin, env)
    # Copying it would put whatever it points at into ~/.claude/skills.
    with pytest.raises(upstream.UpstreamError, match="symlink"):
        upstream.files(clone)


def test_git_never_inherits_a_repository_from_the_environment(tmp_path, upstream_repo):
    env = upstream_repo.env
    clone = cloned(tmp_path, upstream_repo, upstream_repo.pin)
    # A GIT_DIR left in the environment (a hook, say) would point every call at another
    # repository; the installer's git calls drop it and never wait at a password prompt.
    aimed = {**env, "GIT_DIR": str(upstream_repo.path / ".git"),
             "GIT_WORK_TREE": str(upstream_repo.path)}
    assert upstream.head(clone, aimed) == upstream_repo.pin
    cleaned = upstream.git_environment(aimed)
    assert "GIT_DIR" not in cleaned and "GIT_WORK_TREE" not in cleaned
    assert cleaned["GIT_TERMINAL_PROMPT"] == "0"
    assert cleaned["GIT_CONFIG_GLOBAL"] == os.devnull
    # Without git on PATH the step says so rather than crashing.
    with pytest.raises(upstream.UpstreamError, match="git is not on PATH"):
        upstream.head(clone, {**env, "PATH": str(tmp_path / "empty")})


def test_a_foreign_upstream_skill_is_described_without_being_changed(tmp_path, upstream_repo):
    env = upstream_repo.env
    # What `npx skills` leaves: a relative symlink to its own canonical copy.
    canonical = tmp_path / "home" / ".agents" / "skills" / "tailscale"
    canonical.mkdir(parents=True)
    link = tmp_path / "home" / ".claude" / "skills" / "tailscale"
    link.parent.mkdir(parents=True)
    link.symlink_to(os.path.relpath(canonical, link.parent))
    assert upstream.describe(link, env) == "a symlink to ../../.agents/skills/tailscale"
    # A clone made by hand: its HEAD is named, so MC can compare it with the pin.
    clone = cloned(tmp_path, upstream_repo, upstream_repo.later)
    assert upstream.describe(clone, env) == f"a git checkout at {upstream_repo.later}"
    plain = tmp_path / "plain"
    plain.mkdir()
    assert upstream.describe(plain, env) == "a directory without tailnet's marker"


# --- The installer itself: a temporary HOME and CLAUDE_CONFIG_DIR, never the real ones ---


@dataclass
class Box:
    """A temporary machine to install into: a home, a Claude directory, and git's environment."""

    home: Path
    claude: Path
    target: "install.Target"
    env: dict


@pytest.fixture
def box(tmp_path):
    """An empty home (it always exists on a real machine) and a CLAUDE_CONFIG_DIR not yet made."""
    home = tmp_path / "home"
    home.mkdir(mode=0o755)
    claude = tmp_path / "claude"
    target = install.Target(home=home, claude_dir=claude, claude_config_dir=str(claude))
    return Box(home, claude, target, environ_for(home))


@pytest.fixture(autouse=True)
def never_runs_claude(syscalls):
    """Fail any test here that starts Claude Code's CLI: the MCP step is tested as an argv."""
    yield
    started = [args for event, args in syscalls.processes() if event == "subprocess.Popen"]
    names = {os.path.basename(os.fsdecode(word)) for args in started
             for word in [args[0], *(args[1] or [])[:1]] if word is not None}
    assert "claude" not in names


def run_installer(box, fixture=None, *, now=NOW, pin=None, environ=None, **options):
    """Run the installer in-process against the box; return (exit code, what it printed).

    Upstream comes from the local fixture repository, or is skipped when there is none, and
    the docs MCP step is skipped unless a test asks for it, so claude never runs.
    """
    settings = {"upstream": fixture is not None, "mcp": False, **options}
    if fixture is not None:
        settings.update(upstream_url=fixture.url, upstream_pin=pin or fixture.pin)
    out = io.StringIO()
    installer = install.Installer(box.target, install.Options(**settings),
                                  environ=environ or box.env, out=out, now=now)
    return installer.run(), out.getvalue()


def snapshot(*roots):
    """Every path under `roots` with its type, mode and bytes (or link target), for exact compares."""
    seen = {}
    for root in roots:
        if not os.path.lexists(root):
            continue
        seen[str(root)] = ("dir", stat.S_IMODE(os.lstat(root).st_mode))
        for directory, subdirectories, names in os.walk(root):
            for name in subdirectories + names:
                path = Path(directory) / name
                st = os.lstat(path)
                if stat.S_ISLNK(st.st_mode):
                    seen[str(path)] = ("link", os.readlink(path))
                elif stat.S_ISDIR(st.st_mode):
                    seen[str(path)] = ("dir", stat.S_IMODE(st.st_mode))
                else:
                    seen[str(path)] = ("file", stat.S_IMODE(st.st_mode), path.read_bytes())
    return seen


def mode(path):
    """A path's permission bits, not following a symlink."""
    return stat.S_IMODE(os.lstat(path).st_mode)


def source_tree(root):
    """The files the installer copies from a repo directory, by relative path: no bytecode."""
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}


def repo_head():
    """The commit the installer records: the checkout's HEAD."""
    return git(REPO, "rev-parse", "HEAD", env=environ_for(REPO))


def test_install_into_an_empty_home_creates_every_artifact_with_its_mode(box, upstream_repo):
    code, out = run_installer(box, upstream_repo)
    assert code == 0, out
    target = box.target
    # The CLI package is a copy of src/tailnet, rules.json included: dirs 0755, files 0644.
    expected = source_tree(REPO / "src" / "tailnet")
    assert source_tree(target.lib) == expected and "rules.json" in expected
    assert target.lib == box.home / ".local" / "share" / "tailnet" / "lib" / "tailnet"
    for path in [target.lib, *target.lib.rglob("*")]:
        assert mode(path) == (0o755 if path.is_dir() else 0o644), path
    assert mode(target.launcher) == 0o755
    assert target.launcher == box.home / ".local" / "bin" / "tailnet"
    # The pinned spec and its checksum file, verified on copy.
    for name in ("tailscale-openapi.yaml", "SHA256SUMS"):
        copied = target.share / "spec" / name
        assert copied.read_bytes() == (REPO / "spec" / name).read_bytes()
        assert mode(copied) == 0o644
    # The private directories are 0700, and the installer creates no credential, no
    # protected file and no audit log in them: those are MC's and the CLI's.
    for directory in (target.config, target.state, target.drafts):
        assert mode(directory) == 0o700
    assert list(target.config.iterdir()) == []
    assert sorted(p.name for p in target.state.iterdir()) == ["drafts"]
    assert list(target.drafts.iterdir()) == []
    # Our skill, copied with a marker naming the commit it came from.
    marker = json.loads((target.skill / MARKER).read_text())
    assert marker == {"commit": repo_head(), "dirty": marker["dirty"],
                      "installed_at": "2026-10-26T12:00:00Z"}
    assert isinstance(marker["dirty"], bool)
    assert {k: v for k, v in source_tree(target.skill).items() if k != MARKER} == source_tree(
        REPO / "skill" / "tailnet")
    # The upstream skill at the pin, with its licence and a marker naming the pin.
    assert json.loads((target.upstream_copy / MARKER).read_text()) == {"pin": upstream_repo.pin}
    assert (target.upstream_copy / "LICENSE").read_text().startswith("BSD 3-Clause")
    assert (target.upstream_copy / "SKILL.md").read_text() == SKILL_MD
    assert upstream.head(target.clone, box.env) == upstream_repo.pin
    # Every rule is in the settings Claude Code reads, and nothing was loosened: no allow rule.
    assert gate.missing_rules(target.settings, str(box.claude)) == []
    assert mode(target.settings) == 0o600 and mode(box.claude) == 0o700
    assert "allow" not in json.loads(target.settings.read_text())["permissions"]
    # The install record says what was added, for --uninstall and doctor's L8.
    record = json.loads(target.record.read_text())
    assert mode(target.record) == 0o600
    assert record["commit"] == marker["commit"] and record["dirty"] == marker["dirty"]
    assert record["installed_at"] == record["last_run"] == "2026-10-26T12:00:00Z"
    rules = gate.rules_for(str(box.claude))
    assert record["added"] == {"lib": True, "launcher": True, "spec": True, "skill": True,
                               "upstream_copy": True, "upstream_clone": True, "mcp": False,
                               "rules": {"ask": rules["ask"], "deny": rules["deny"]}}
    assert doctor.install_markers(box.claude, target.share)["skill"]["ok"] is True
    # It ends with MC's next steps, in order.
    tail = out[out.index("Next (MC):"):]
    steps = ["references/credentials.md", "tailnet credentials set read", "protected",
             "tailnet doctor"]
    assert [tail.index(step) for step in steps] == sorted(tail.index(step) for step in steps)


def test_a_second_install_changes_nothing(box, upstream_repo):
    code, _ = run_installer(box, upstream_repo, now=NOW)
    assert code == 0
    before = snapshot(box.home, box.claude)
    code, out = run_installer(box, upstream_repo, now=LATER)
    assert code == 0, out
    after = snapshot(box.home, box.claude)
    record = str(box.target.record)
    first, second = json.loads(before.pop(record)[2]), json.loads(after.pop(record)[2])
    # Every byte stays in place except the record's last_run.
    assert before == after
    assert first.pop("last_run") == "2026-10-26T12:00:00Z"
    assert second.pop("last_run") == "2026-10-27T09:30:00Z"
    assert first == second
    for step in ("directories", "lib", "launcher", "spec", "skill", "upstream", "settings",
                 "record"):
        assert f"{step}: no changes" in out, step
    assert "done:" not in out and "would:" not in out


def test_dry_run_writes_nothing(box, upstream_repo, tmp_path, syscalls):
    before = snapshot(tmp_path)
    code, out = run_installer(box, upstream_repo, dry_run=True)
    assert code == 0, out
    assert snapshot(tmp_path) == before
    # Every change is announced instead, the settings change as a diff of the JSON.
    for step in ("create " + str(box.target.config), "copy " + str(REPO / "src" / "tailnet"),
                 "write the launcher", "clone " + upstream_repo.url, "add 10 rules"):
        assert f"would: {step}" in out, step
    assert f'+      "{gate.rules()["gate"]}",' in out
    assert "nothing was written" in out
    # Only read-only lookups ran: git asked about the checkout's commit and state, and
    # nothing was cloned, fetched or checked out.
    commands = [[os.fsdecode(w) for w in args[1]] for event, args in syscalls.processes()
                if event == "subprocess.Popen"]
    assert commands and all(os.path.basename(c[0]) == "git" for c in commands)
    assert not [c for c in commands if {"clone", "fetch", "checkout"} & set(c)]
    # A dry run over a finished install has nothing to announce.
    run_installer(box, upstream_repo)
    before = snapshot(tmp_path)
    code, out = run_installer(box, upstream_repo, dry_run=True, now=LATER)
    assert code == 0 and snapshot(tmp_path) == before
    assert "would:" not in out


def test_the_launcher_runs_python_isolated_and_has_aboutme_lines(box, tmp_path):
    code, out = run_installer(box)
    assert code == 0, out
    launcher = box.target.launcher
    lines = launcher.read_text().splitlines()
    assert lines[0] == f"#!{os.path.realpath(sys.executable)} -I"
    assert all(line.startswith("# ABOUTME: ") and len(line) > 20 for line in lines[1:3])
    assert f"sys.path.insert(0, {str(box.target.lib.parent)!r})" in lines
    # -I keeps PYTHONPATH out: a module planted there to shadow the standard library is
    # never imported, and the CLI that answers is the installed copy, which Python compiles.
    poison = tmp_path / "poison"
    poison.mkdir()
    (poison / "argparse.py").write_text("raise SystemExit('PYTHONPATH reached the launcher')\n")
    done = subprocess.run([str(launcher), "--help"], capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(box.home), "LANG": "C.UTF-8",
                               "PYTHONPATH": str(poison)}, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("usage: tailnet")
    assert (box.target.lib / "__pycache__").is_dir()
    # A later install compares what it copies, not Python's bytecode: still no changes.
    code, out = run_installer(box)
    assert "lib: no changes" in out and "launcher: no changes" in out


def test_a_foreign_tailscale_skill_is_left_alone(box, upstream_repo):
    canonical = box.home / ".agents" / "skills" / "tailscale"
    canonical.mkdir(parents=True)
    (canonical / "SKILL.md").write_text("installed by npx skills\n")
    link = box.claude / "skills" / "tailscale"
    link.parent.mkdir(parents=True)
    link.symlink_to(canonical)
    before = snapshot(canonical)
    code, out = run_installer(box, upstream_repo)
    # It is MC's choice to have it; the installer says what it is and installs the rest.
    assert code == 0, out
    assert link.is_symlink() and os.readlink(link) == str(canonical)
    assert snapshot(canonical) == before
    assert f"a symlink to {canonical}" in out and "left alone" in out
    assert not os.path.lexists(box.target.clone)
    added = json.loads(box.target.record.read_text())["added"]
    assert (added["upstream_copy"], added["upstream_clone"], added["skill"]) == (False, False, True)


def test_a_foreign_tailnet_skill_stops_the_step(box, upstream_repo):
    theirs = box.claude / "skills" / "tailnet"
    theirs.mkdir(parents=True)
    (theirs / "SKILL.md").write_text("someone else's tailnet skill\n")
    # A marker that is a symlink is not ours either: it could point at anything.
    (theirs / MARKER).symlink_to(box.home)
    before = snapshot(theirs)
    code, out = run_installer(box, upstream_repo)
    assert code == 1
    assert snapshot(theirs) == before
    assert f"skill: STOPPED: {theirs}" in out and "left alone" in out
    # The other steps still ran, and the record does not claim the skill.
    assert gate.missing_rules(box.target.settings, str(box.claude)) == []
    assert box.target.lib.is_dir()
    assert json.loads(box.target.record.read_text())["added"]["skill"] is False


def test_a_foreign_launcher_is_left_alone(box):
    launcher = box.target.launcher
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\necho another tailnet\n")
    launcher.chmod(0o755)
    code, out = run_installer(box)
    assert code == 1
    assert launcher.read_text() == "#!/bin/sh\necho another tailnet\n"
    assert "launcher: STOPPED" in out and "left alone" in out
    assert json.loads(box.target.record.read_text())["added"]["launcher"] is False


def test_install_tightens_but_never_loosens_the_private_directories(box):
    target = box.target
    target.config.mkdir(parents=True, mode=0o755)
    target.config.chmod(0o755)
    target.drafts.mkdir(parents=True)
    target.state.chmod(0o750)
    target.drafts.chmod(0o500)
    code, out = run_installer(box)
    assert code == 0, out
    assert (mode(target.config), mode(target.state), mode(target.drafts)) == (0o700, 0o700, 0o500)
    assert f"done: tighten {target.config} from 0755 to 0700" in out


def test_a_new_pin_is_fetched_checked_out_and_copied(box, upstream_repo):
    run_installer(box, upstream_repo)
    skill = upstream_repo.path / "skills" / "tailscale"
    (skill / "SKILL.md").write_text(SKILL_MD + "\nA newer release.\n")
    newer = commit(upstream_repo.path, "a newer release", upstream_repo.env)
    code, out = run_installer(box, upstream_repo, pin=newer)
    assert code == 0, out
    for step in ("fetch", "check out", "copy"):
        assert f"done: {step}" in out, step
    assert upstream.head(box.target.clone, box.env) == newer
    assert json.loads((box.target.upstream_copy / MARKER).read_text()) == {"pin": newer}
    assert (box.target.upstream_copy / "SKILL.md").read_text().endswith("A newer release.\n")


def test_the_mcp_add_command_is_composed_exactly():
    assert install.MCP_ADD == ("claude", "mcp", "add", "--transport", "http", "--scope", "user",
                               "tailscale-docs", "https://tailscale.mcp.kapa.ai/")
    assert install.MCP_GET == ("claude", "mcp", "get", "tailscale-docs")
    assert install.MCP_REMOVE == ("claude", "mcp", "remove", "tailscale-docs", "--scope", "user")
    assert install.MCP_LOGIN == "claude mcp login tailscale-docs --no-browser"
    # The installer registers the same server and URL doctor's L8 looks for.
    assert install.MCP_ADD[-2:] == (doctor.DOCS_MCP, doctor.DOCS_MCP_URL)
    assert install.MCP_GET[-1] == install.MCP_REMOVE[3] == doctor.DOCS_MCP


def test_a_missing_claude_skips_the_docs_mcp_step_with_a_message(box, tmp_path):
    # A PATH holding git and nothing else: claude cannot be found, so nothing can run it.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").symlink_to(shutil.which("git", path=GIT_ENV["PATH"]))
    code, out = run_installer(box, environ={**box.env, "PATH": str(bin_dir)}, mcp=True)
    assert code == 0, out
    assert "mcp: skipped: claude is not on PATH" in out
    assert " ".join(install.MCP_ADD) in out
    assert json.loads(box.target.record.read_text())["added"]["mcp"] is False


def test_the_wrapper_refuses_root_and_runs_the_installer_isolated(box, tmp_path):
    env = {**box.env, "CLAUDE_CONFIG_DIR": str(box.claude)}
    before = snapshot(tmp_path)
    wrapper = subprocess.run(["bash", str(REPO / "install-tailnet.sh"), "--dry-run", "--no-upstream",
                              "--no-mcp"], capture_output=True, text=True, env=env, timeout=120,
                             check=False)
    direct = subprocess.run([sys.executable, "-I", str(REPO / "installer" / "install.py"),
                             "--dry-run", "--no-upstream", "--no-mcp"], capture_output=True,
                            text=True, env=env, timeout=120, check=False)
    assert snapshot(tmp_path) == before
    if os.geteuid() == 0:
        # As root, credentials and settings would land in root's home, not MC's.
        for done in (wrapper, direct):
            assert done.returncode == 1 and "refusing to run as root" in done.stderr
            assert done.stdout == ""
    else:
        for done in (wrapper, direct):
            assert done.returncode == 0, done.stderr
            assert f"would: create {box.target.config}" in done.stdout
            assert "nothing was written" in done.stdout
    # An unknown or abbreviated option is refused before anything else happens.
    for bad in (["--dry"], ["--uninstal"], ["--force"]):
        done = subprocess.run([sys.executable, "-I", str(REPO / "installer" / "install.py"),
                               *bad], capture_output=True, text=True, env=env, timeout=60,
                              check=False)
        assert done.returncode == 2, bad


def test_the_make_targets_run_the_wrapper():
    # `make -n` prints each recipe without running it: MC's entry points are the wrapper's.
    done = subprocess.run(["make", "-n", "-C", str(REPO), "install", "install-dry-run"],
                          capture_output=True, text=True, timeout=60, check=False,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    assert done.returncode == 0, done.stderr
    recipes = [line for line in done.stdout.splitlines() if not line.startswith("make")]
    assert recipes == ["./install-tailnet.sh", "./install-tailnet.sh --dry-run"]
    assert os.access(REPO / "install-tailnet.sh", os.X_OK)
