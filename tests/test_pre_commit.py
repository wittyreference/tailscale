# ABOUTME: Tests for githooks/pre-commit: the identity guard and the staged-diff secret scan.
# ABOUTME: Each case builds a throwaway git repo, stages real files, and runs the real hook script.

import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "githooks" / "pre-commit"
REPO = HOOK.parent.parent
PERSONAL = "mc8805@outlook.com"


def key(kind, body="kAbc123CNTRL-" + "q7" * 16):
    """Build a key-shaped string at runtime.

    A literal would trip the very hook under test the moment this file is staged
    (CLAUDE.md invariant 14), so every key here is assembled from parts.
    """
    return "tskey-" + kind + "-" + body


def make_repo(tmp_path, email):
    """Create a throwaway repo and return the environment its git commands must run under."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    # GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM point at nothing so the host's own identity
    # cannot leak into a case that is meant to have none.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    if email is not None:
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", email], check=True, env=env)
        # The hook asks git for the full identity, which needs a name; without one git falls
        # back to the account's passwd entry, which may be empty on the machine running this.
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True, env=env)
    return env


def stage(tmp_path, env, files):
    """Write each file and add it to the index, as a commit would see it."""
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        subprocess.run(["git", "-C", str(tmp_path), "add", "--", name], check=True, env=env)


def commit(tmp_path, env):
    """Commit the index without hooks, to give a later staged diff something to differ from."""
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.name=t", "commit", "-q", "-m", "base"],
                   check=True, env=env)


def hook(tmp_path, env):
    """Run the real hook in the throwaway repo."""
    # Unchecked on purpose: a refusal (exit 1) is the outcome most cases assert on.
    return subprocess.run([str(HOOK)], cwd=tmp_path, env=env, capture_output=True, text=True,
                          check=False)


def run_hook(tmp_path, email, staged=None):
    """Build a repo under the given identity, stage the given files, and run the hook."""
    env = make_repo(tmp_path, email)
    stage(tmp_path, env, staged or {})
    return hook(tmp_path, env)


def assert_never_echoed(result, secret):
    """The hook names where a secret is, never what it is: output is a transcript."""
    output = result.stdout + result.stderr
    assert secret not in output
    assert secret.split("-", 2)[2] not in output


def test_the_personal_identity_is_allowed(tmp_path):
    result = run_hook(tmp_path, PERSONAL)
    assert result.returncode == 0, result.stderr


def test_a_missing_identity_is_refused(tmp_path):
    result = run_hook(tmp_path, None)
    assert result.returncode == 1
    assert "no git identity" in result.stderr


@pytest.mark.parametrize("email", ["mc@twilio.com", "MC@Twilio.COM", "mc@corp.twilio.com"])
def test_a_twilio_identity_is_refused_in_any_case_or_subdomain(tmp_path, email):
    result = run_hook(tmp_path, email)
    assert result.returncode == 1
    assert "work identity" in result.stderr


def commit_through_hook(tmp_path, env, *flags, config=()):
    """Run a real `git commit` with the hook armed, as MC's clone runs it.

    Git settles the commit's author and committer from --author, the GIT_*_EMAIL variables
    and the author.email and committer.email keys before user.email, and hands that identity
    to the hook; only a real commit exercises it.
    """
    stage(tmp_path, env, {"a.txt": "a\n"})
    settings = ["-c", f"core.hooksPath={HOOK.parent}", "-c", "user.name=t"]
    for item in config:
        settings += ["-c", item]
    return subprocess.run(["git", "-C", str(tmp_path), *settings, "commit", "-q", "-m", "x",
                           *flags], env=env, capture_output=True, text=True, check=False)


@pytest.mark.parametrize("flags,variables,config", [
    (["--author=MC <mc@twilio.com>"], {}, ()),
    ([], {"GIT_AUTHOR_EMAIL": "mc@twilio.com"}, ()),
    ([], {"GIT_COMMITTER_EMAIL": "mc@corp.twilio.com"}, ()),
    ([], {}, ("author.email=MC@Twilio.com",)),
    ([], {}, ("committer.email=mc@twilio.com",)),
], ids=["author-flag", "author-variable", "committer-variable", "author-key", "committer-key"])
def test_a_twilio_identity_the_commit_is_made_with_is_refused(tmp_path, flags, variables, config):
    # user.email is the personal address in every case; the identity git stamps is not.
    env = make_repo(tmp_path, PERSONAL)
    result = commit_through_hook(tmp_path, {**env, **variables}, *flags, config=config)
    assert result.returncode != 0, "the commit was made"
    assert "work identity" in result.stderr
    log = subprocess.run(["git", "-C", str(tmp_path), "log", "--oneline"], env=env,
                         capture_output=True, text=True, check=False)
    assert log.stdout == ""


def test_a_commit_as_the_personal_identity_goes_through_the_armed_hook(tmp_path):
    env = make_repo(tmp_path, PERSONAL)
    result = commit_through_hook(tmp_path, env)
    assert result.returncode == 0, result.stderr


def test_the_hook_refuses_twilio_only_so_another_address_passes(tmp_path):
    # CLAUDE.md says what the hook enforces: an unset identity and twilio.com are refused, in
    # the author and the committer; it does not pin mc8805, so another address passes (A72).
    result = run_hook(tmp_path, "someone-else@example.com")
    assert result.returncode == 0, result.stderr
    claude_md = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    [row] = [line for line in claude_md.splitlines() if line.startswith("| Commit identity |")]
    assert "refuses anything else" not in row
    for words in ("twilio.com", "author", "committer", "unset"):
        assert words in row, words


def test_a_staged_oauth_client_secret_is_refused(tmp_path):
    secret = key("client")
    result = run_hook(tmp_path, PERSONAL, {"app/config.py": f'# config\n\nSECRET = "{secret}"\n'})
    assert result.returncode == 1
    assert "app/config.py:3" in result.stderr
    assert_never_echoed(result, secret)


def test_a_staged_api_token_is_refused(tmp_path):
    token = key("api")
    result = run_hook(tmp_path, PERSONAL, {"notes.md": f"curl -H 'Authorization: Bearer {token}'\n"})
    assert result.returncode == 1
    assert "notes.md:1" in result.stderr
    assert_never_echoed(result, token)


@pytest.mark.parametrize("kind", ["auth", "scim", "webhook"])
def test_every_other_documented_key_kind_is_refused(tmp_path, kind):
    secret = key(kind)
    result = run_hook(tmp_path, PERSONAL, {"keys.txt": secret + "\n"})
    assert result.returncode == 1
    assert "keys.txt:1" in result.stderr
    assert_never_echoed(result, secret)


def test_a_prefix_without_a_key_is_allowed(tmp_path):
    prose = ("Client secrets begin tskey-client- and API tokens tskey-api-…; "
             "`tskey-auth-` keys are out of scope.\n")
    result = run_hook(tmp_path, PERSONAL, {"README.md": prose})
    assert result.returncode == 0, result.stderr


def test_runtime_built_fixture_secrets_are_not_staged_literals(tmp_path):
    source = 'SECRET = "tskey-" + "client-" + "kAbc123CNTRL-" + "q7" * 16\n'
    result = run_hook(tmp_path, PERSONAL, {"tests/fixture.py": source})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("kind,body", [
    ("api", "x" * 5),
    ("auth", "x" * 12 + "-" + "x" * 32),
    ("client", "x" * 12 + "-" + "x" * 32),
])
def test_an_all_x_documentation_placeholder_is_allowed(tmp_path, kind, body):
    # The pinned OpenAPI spec carries exactly these shapes (spec 25, 28, 5784, 6626) and
    # must stay byte-identical to its sha256, so the scan has to let them through.
    line = f'curl -u "{key(kind, body)}:" https://api.tailscale.com/api/v2/\n'
    result = run_hook(tmp_path, PERSONAL, {"spec.yaml": line})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("body", ["xxxxk1xxxx", "x" * 12 + "-" + "x" * 31 + "q", "XXXXXXXX", "x_x"])
def test_a_key_that_is_not_only_lowercase_x_runs_is_refused(tmp_path, body):
    result = run_hook(tmp_path, PERSONAL, {"doc.md": key("client", body) + "\n"})
    assert result.returncode == 1
    assert "doc.md:1" in result.stderr


def test_the_reported_line_is_the_line_number_in_the_staged_file(tmp_path):
    env = make_repo(tmp_path, PERSONAL)
    lines = [f"line {n}" for n in range(1, 11)]
    stage(tmp_path, env, {"a.txt": "\n".join(lines) + "\n"})
    commit(tmp_path, env)
    lines[6] += " " + key("client")
    lines.insert(2, "inserted above, so the key moves from line 7 to line 8")
    stage(tmp_path, env, {"a.txt": "\n".join(lines) + "\n"})
    result = hook(tmp_path, env)
    assert result.returncode == 1
    assert "a.txt:8" in result.stderr
    assert "a.txt:3" not in result.stderr


def test_an_added_line_that_starts_with_plus_signs_is_still_scanned(tmp_path):
    # In a diff, an added line "++ x" prints as "+++ x", which looks like a file header.
    secret = key("client")
    result = run_hook(tmp_path, PERSONAL, {"plus.txt": f"first\n++ {secret}\n"})
    assert result.returncode == 1
    assert "plus.txt:2" in result.stderr
    assert_never_echoed(result, secret)


def test_removing_a_key_is_allowed(tmp_path):
    env = make_repo(tmp_path, PERSONAL)
    stage(tmp_path, env, {"old.txt": "keep\n" + key("client") + "\n"})
    commit(tmp_path, env)
    stage(tmp_path, env, {"old.txt": "keep\n"})
    result = hook(tmp_path, env)
    assert result.returncode == 0, result.stderr


def test_every_file_in_this_repo_passes_the_scan(tmp_path):
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO, capture_output=True, check=True,
    )
    env = make_repo(tmp_path, PERSONAL)
    copied = 0
    for name in filter(None, listing.stdout.decode().split("\0")):
        source = REPO / name
        if source.is_file():
            (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, tmp_path / name)
            copied += 1
    assert copied > 1
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, env=env)
    result = hook(tmp_path, env)
    assert result.returncode == 0, result.stderr
