# ABOUTME: Tests for the installer (DESIGN.md §20): the pinned upstream skill, every installed artifact and
# ABOUTME: its mode, dry run, idempotence and uninstall, run in a temporary HOME with a local upstream repo.

import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

import install
import pytest
import upstream
from test_skill import permits

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
    if settings.get("uninstall"):
        settings.pop("upstream")
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
        if not os.path.isdir(root) or os.path.islink(root):
            seen[str(root)] = ("path", stat.S_IMODE(os.lstat(root).st_mode),
                               os.readlink(root) if os.path.islink(root)
                               else Path(root).read_bytes())
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
                               "rules": {str(target.settings): {"ask": rules["ask"],
                                                                "deny": rules["deny"]}}}
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


def test_no_make_target_runs_the_installer_past_its_ask_rule():
    # Claude Code matches a Bash rule against the command text the agent writes, never what
    # make runs beneath it, so a `make install` would replace the guard's code, and a `make
    # uninstall` take out every gate and deny rule, with no `Bash(*install-tailnet*)` prompt
    # (D29). A target may run the installer only as a dry run, which changes nothing, or
    # under a name an ask rule matches. `make -n` prints each recipe without running it.
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    targets = re.search(r"^\.PHONY:(.*)$", makefile, flags=re.MULTILINE).group(1).split()
    ask = gate.rules()["ask"]
    runs = {}
    for target in targets:
        done = subprocess.run(["make", "-n", "-C", str(REPO), target], capture_output=True,
                              text=True, timeout=60, check=False,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        assert done.returncode == 0, done.stderr
        recipes = [line for line in done.stdout.splitlines() if not line.startswith("make")]
        if any("install-tailnet" in line or "install.py" in line for line in recipes):
            runs[target] = recipes
    assert runs == {"install-dry-run": ["./install-tailnet.sh --dry-run"]}
    for target, recipes in runs.items():
        assert (all(line.endswith(" --dry-run") for line in recipes)
                or any(permits(rule, f"make {target}") for rule in ask)), target
    # The command the README gives for an install is one the ask rule does match.
    assert any(permits(rule, "./install-tailnet.sh") for rule in ask)
    assert os.access(REPO / "install-tailnet.sh", os.X_OK)


# --- Uninstall: reverse install.json, and never touch what is MC's ---


def mc_files(box):
    """Lay out what MC and the CLI keep after an install: credentials, the protected list, the
    token cache, the audit log, the apply lock and a draft. Secrets are assembled at runtime."""
    target = box.target
    for name, text in (("read.json", '{"client_id": "k1", "secret": "file:read.secret"}'),
                       ("read.secret", "test-client-" + "read0001"),
                       ("write.json", '{"client_id": "k2", "secret": "file:write.secret"}'),
                       ("write.secret", "test-client-" + "write001"),
                       ("read-token.json", '{"token": "x"}'),
                       ("protected", "self nAbc123\n")):
        (target.config / name).write_text(text)
        (target.config / name).chmod(0o600)
    (target.state / "audit.jsonl").write_text('{"event": "token.mint"}\n')
    (target.state / "apply.lock").write_text("")
    draft = target.drafts / "draft-20261026T120000Z"
    draft.mkdir()
    (draft / "candidate.hujson").write_text("{}\n")
    return snapshot(target.config, target.state)


def test_uninstall_never_touches_credentials_protected_audit_or_drafts(box, upstream_repo):
    run_installer(box, upstream_repo)
    kept = mc_files(box)
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 0, out
    assert snapshot(box.target.config, box.target.state) == kept
    # MC is told where they are, and that deleting files revokes nothing.
    tail = out[out.index("Left in place"):]
    for path in (box.target.config, box.target.state / "audit.jsonl", box.target.drafts):
        assert str(path) in tail
    assert "not revocation" in tail and "Trust credentials" in tail and "Revoke" in tail


def test_uninstall_reverses_the_install_record(box, upstream_repo):
    run_installer(box, upstream_repo)
    target = box.target
    # MC edits one of our rules and adds one of their own after the install.
    settings = json.loads(target.settings.read_text())
    ask = settings["permissions"]["ask"]
    ask[ask.index("Bash(*install-tailnet*)")] = "Bash(*install-tailnet.sh*)"
    ask.append("Bash(git push*)")
    target.settings.write_text(json.dumps(settings))
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 0, out
    for path in (target.launcher, target.lib, target.spec, target.skill, target.upstream_copy,
                 target.clone, target.record, target.share):
        assert not os.path.lexists(path), path
    # Only the rules the record lists come out; the edited one is reported and left.
    permissions = json.loads(target.settings.read_text())["permissions"]
    assert permissions == {"ask": ["Bash(*install-tailnet.sh*)", "Bash(git push*)"], "deny": []}
    assert "Bash(*install-tailnet*)" in out and "left to MC" in out
    assert (box.claude / "settings.json.tailnet-bak-20261027T093000Z").is_file()
    # With the record gone there is nothing left to reverse, and nothing changes.
    before = snapshot(box.home, box.claude)
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 0 and snapshot(box.home, box.claude) == before
    assert f"no install record at {target.record}" in out


def test_uninstall_leaves_what_is_not_ours(box, upstream_repo):
    run_installer(box, upstream_repo)
    target = box.target
    # Since the install, the launcher was replaced by another program, and the skill's
    # marker was removed: neither is the installer's to remove now.
    target.launcher.write_text("#!/bin/sh\necho another tailnet\n")
    (target.skill / MARKER).unlink()
    foreign = snapshot(target.launcher, target.skill)
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 0, out
    assert snapshot(target.launcher, target.skill) == foreign
    assert "launcher: left alone" in out and "skill: left alone" in out
    assert not os.path.lexists(target.lib) and not os.path.lexists(target.upstream_copy)


def test_uninstall_dry_run_removes_nothing(box, upstream_repo, tmp_path):
    run_installer(box, upstream_repo)
    before = snapshot(tmp_path)
    code, out = run_installer(box, uninstall=True, dry_run=True, now=LATER)
    assert code == 0, out
    assert snapshot(tmp_path) == before
    for step in (f"remove the launcher {box.target.launcher}", f"remove {box.target.lib}",
                 f"remove {box.target.skill}", f"remove the clone {box.target.clone}",
                 "remove 10 rules"):
        assert f"would: {step}" in out, step


def test_uninstall_keeps_the_record_when_a_step_stops(box):
    run_installer(box)
    target = box.target
    # A settings file MC broke cannot be edited safely, so the rules stay, and so does the
    # record that lists them: a later uninstall can still take them out.
    target.settings.write_text("{not json")
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 1
    assert "settings: STOPPED" in out and "Remove these rules from" in out
    assert target.record.is_file() and "record: kept" in out
    assert target.settings.read_text() == "{not json"


MC_ASK = "Bash(*api.tailscale.com*)"
MC_DENY = "Read(~/.config/tailnet/**)"


def default_claude(box):
    """The same home with CLAUDE_CONFIG_DIR unset: ~/.claude, already holding two of tailnet's
    exact strings that MC wrote by hand, a deny over the credentials among them."""
    claude = box.home / ".claude"
    claude.mkdir(mode=0o700)
    (claude / "settings.json").write_text(json.dumps(
        {"permissions": {"ask": [MC_ASK], "deny": [MC_DENY]}}))
    return replace(box, claude=claude, target=install.Target(box.home, claude, None))


def ours(settings):
    """The permission lists of a settings file."""
    return json.loads(settings.read_text())["permissions"]


@pytest.mark.parametrize("installs, uninstalls", [
    (("default", "alt"), ("default", "alt")),
    (("alt", "default"), ("default", "alt")),
    (("alt", "default"), ("alt", "default")),
])
def test_uninstall_takes_out_only_the_rules_added_to_its_own_settings_file(box, installs,
                                                                           uninstalls):
    boxes = {"default": default_claude(box), "alt": box}
    default, alt = boxes["default"], boxes["alt"]
    for name in installs:
        code, out = run_installer(boxes[name])
        assert code == 0, out
    record = json.loads(box.target.record.read_text())
    # Each settings file's additions are recorded against that file: the two MC wrote by hand
    # in ~/.claude were never added there, though the alternate directory needed them.
    rules = record["added"]["rules"]
    assert sorted(rules) == sorted([str(default.target.settings), str(alt.target.settings)])
    assert MC_ASK not in rules[str(default.target.settings)]["ask"]
    assert MC_DENY not in rules[str(default.target.settings)]["deny"]
    assert rules[str(alt.target.settings)] == alt.target.rules()
    first, then = (boxes[name] for name in uninstalls)
    then_before = then.target.settings.read_bytes()
    # The first uninstall takes out only what was added to its own file: MC's own ask and
    # deny rules in ~/.claude stay, the other file is not touched, and the record is kept,
    # without the finished file, so a run with the other Claude directory can finish it.
    code, out = run_installer(first, uninstall=True, now=LATER)
    assert code == 1, out
    assert ours(default.target.settings)["ask"][0] == MC_ASK
    assert ours(default.target.settings)["deny"][0] == MC_DENY
    assert then.target.settings.read_bytes() == then_before
    assert "settings: STOPPED" in out and str(then.target.settings) in out
    assert ("CLAUDE_CONFIG_DIR unset" if then is default else f"CLAUDE_CONFIG_DIR={alt.claude}"
            ) in out
    kept = json.loads(box.target.record.read_text())["added"]["rules"]
    assert kept == {str(then.target.settings): rules[str(then.target.settings)]}
    code, out = run_installer(then, uninstall=True, now=LATER)
    assert code == 0, out
    assert ours(alt.target.settings) == {"ask": [], "deny": []}
    assert ours(default.target.settings) == {"ask": [MC_ASK], "deny": [MC_DENY]}
    assert not os.path.lexists(box.target.record)
    for path in (default.target.skill, alt.target.skill, box.target.lib, box.target.launcher):
        assert not os.path.lexists(path), path


def test_a_record_with_rules_in_one_list_is_read_as_its_claude_directory_s(box):
    # A record written before the rules were keyed by settings file names one Claude
    # directory, the one its rules were added to when only one was ever used.
    run_installer(box)
    record = json.loads(box.target.record.read_text())
    record["added"]["rules"] = box.target.rules()
    box.target.record.write_text(json.dumps(record))
    code, out = run_installer(box, uninstall=True, now=LATER)
    assert code == 0, out
    assert ours(box.target.settings) == {"ask": [], "deny": []}
    assert not os.path.lexists(box.target.record)


def test_uninstall_without_claude_says_how_to_remove_the_docs_server(box, tmp_path):
    run_installer(box)
    record = json.loads(box.target.record.read_text())
    record["added"]["mcp"] = True
    box.target.record.write_text(json.dumps(record))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    code, out = run_installer(box, uninstall=True, mcp=True, now=LATER,
                              environ={**box.env, "PATH": str(bin_dir)})
    assert code == 0, out
    assert f"mcp: not removed: claude is not on PATH; run: {' '.join(install.MCP_REMOVE)}" in out
