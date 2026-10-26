# ABOUTME: Tests for the installer (DESIGN.md §20): the pinned upstream skill, every installed artifact and
# ABOUTME: its mode, dry run, idempotence and uninstall, run in a temporary HOME with a local upstream repo.

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import upstream

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
