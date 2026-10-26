# ABOUTME: Tests for githooks/pre-commit, the identity guard that keeps work email off this repo.
# ABOUTME: Each case builds a throwaway git repo, sets an identity, and runs the real hook script.

import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "githooks" / "pre-commit"


def run_hook(tmp_path, email):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    # GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM point at nothing so the host's own identity
    # cannot leak into a case that is meant to have none.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    if email is not None:
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", email], check=True, env=env)
    return subprocess.run([str(HOOK)], cwd=tmp_path, env=env, capture_output=True, text=True)


def test_the_personal_identity_is_allowed(tmp_path):
    result = run_hook(tmp_path, "mc8805@outlook.com")
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
