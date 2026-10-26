# ABOUTME: Tests for the e2e harness (DESIGN.md §21.4, §21.5): the preflight that stops the suite with exit 3,
# ABOUTME: the launchers that refuse writes and test posture, `make e2e` and the manual checks it prints.

import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
from credfiles import write_role

from tailnet.posture import Posture

REPO = Path(__file__).resolve().parents[2]
E2E = REPO / "tests" / "e2e"
# An override set on purpose in every child process below: if a refusal these tests expect were
# ever missing, the child would land in test posture against a closed loopback port instead of
# reaching the real API from the default suite.
CLOSED_LOOPBACK = "http://127.0.0.1:9"


def load(name):
    """Import one of the e2e harness's modules by its path, under a name no other module uses."""
    spec = importlib.util.spec_from_file_location(f"e2e_{name}", E2E / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_live():
    """The e2e launcher, imported as the e2e conftest imports it."""
    return load("run_live")


@pytest.fixture(scope="module")
def preflight():
    """The e2e preflight checks."""
    return load("preflight")


def child_env(tmp_path, **extra):
    """An environment for a child process that holds both test overrides, so nothing it starts
    can reach production."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8",
           "HOME": str(tmp_path), "TAILNET_API_BASE": CLOSED_LOOPBACK,
           "TAILNET_HOME": str(tmp_path / "tn")}
    env.update(extra)
    return env


def never(*_args, **_kwargs):
    """Stands in for a step a test proves is never reached."""
    raise AssertionError("this step must not run")


# --- run_live.py: the only way the e2e suite runs the CLI ---


@pytest.mark.parametrize("argv", [
    ["device", "disable-key-expiry", "nAbc1CNTRL", "--apply", "--reason", "r"],
    ["--json", "device", "tag", "nAbc1CNTRL", "--add", "tag:fleet", "--apply"],
    ["device", "tag", "nAbc1CNTRL", "--add", "tag:fleet", "--reason", "x --apply"],
    ["device", "list", "--apply=yes"],
])
def test_run_live_refuses_apply_wherever_it_appears(run_live, argv):
    with pytest.raises(run_live.LiveRefused, match="--apply"):
        run_live.refuse(argv, {})


@pytest.mark.parametrize("argv", [
    ["credentials", "set", "read"],
    ["credentials", "set", "write"],
    ["credentials", "forget", "read"],
    ["--json", "credentials", "forget", "write"],
])
def test_run_live_refuses_commands_that_change_mc_s_credentials(run_live, argv):
    with pytest.raises(run_live.LiveRefused, match="credentials"):
        run_live.refuse(argv, {})


@pytest.mark.parametrize("argv", [
    ["credentials", "forget", "token"],
    ["--json", "credentials", "forget", "token"],
    ["device", "list", "--json"],
    ["device", "disable-key-expiry", "nAbc1CNTRL"],
    ["policy", "draft", "--name", "credentials"],
])
def test_run_live_allows_reads_dry_runs_and_dropping_the_token_cache(run_live, argv):
    run_live.refuse(argv, {})


@pytest.mark.parametrize("name", ["TAILNET_API_BASE", "TAILNET_HOME"])
def test_run_live_refuses_a_test_posture_override_even_when_empty(run_live, name):
    with pytest.raises(run_live.LiveRefused, match=name):
        run_live.refuse(["device", "list"], {name: ""})


def test_the_launcher_raises_on_apply_before_the_cli_starts(tmp_path):
    done = subprocess.run(
        [sys.executable, "-I", str(E2E / "run_live.py"), "device", "disable-key-expiry",
         "nAbc1CNTRL", "--apply", "--reason", "r"],
        capture_output=True, text=True, env=child_env(tmp_path), timeout=60, check=False)
    assert done.returncode != 0
    assert "LiveRefused" in done.stderr and "--apply" in done.stderr
    # The CLI never ran: in test posture its first act is the TEST POSTURE banner.
    assert "TEST POSTURE" not in done.stderr
    assert done.stdout == ""
    assert not (tmp_path / "tn").exists()


def test_the_ping_helper_refuses_test_posture_before_running_anything(tmp_path):
    done = subprocess.run([sys.executable, "-I", str(E2E / "ping_live.py"), "100.64.0.1"],
                          capture_output=True, text=True, env=child_env(tmp_path), timeout=60,
                          check=False)
    assert done.returncode != 0
    assert "TAILNET_API_BASE" in done.stderr and "production" in done.stderr
    assert done.stdout == ""


# --- preflight.py: what the conftest checks before any test runs ---


def production(tmp_path):
    """A production posture whose real home is a temporary directory."""
    return Posture.from_env({}, real_home=tmp_path / "home")


def running(state="Running", reason=None):
    """A `tailnet status --json` envelope reduced to the local view the preflight reads."""
    def read():
        """The envelope, as the conftest's status run would return it."""
        return {"data": {"self_local": {"run": True, "backend_state": state, "online": True,
                                        "reason": reason, "error": None}}}
    return read


def test_an_override_stops_the_preflight_before_anything_else_is_checked(preflight, tmp_path):
    found = preflight.problems({"TAILNET_API_BASE": CLOSED_LOOPBACK, "TAILNET_HOME": "/x"},
                               real_home=tmp_path / "home", find_binary=never,
                               read_status=never)
    assert len(found) == 1
    assert "TAILNET_API_BASE" in found[0] and "TAILNET_HOME" in found[0]
    assert "production" in found[0]


def test_a_missing_read_credential_names_the_set_command(preflight, tmp_path):
    found = preflight.problems({}, real_home=tmp_path / "home",
                               find_binary=lambda: "/usr/bin/tailscale", read_status=running())
    [problem] = found
    assert str(production(tmp_path).config_dir / "read.json") in problem
    assert "tailnet credentials set read" in problem and "over SSH" in problem


def test_an_unsafe_read_credential_is_named_with_mc_s_fix(preflight, tmp_path):
    write_role(production(tmp_path), "read").chmod(0o644)
    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale",
                                   read_status=running())
    assert "CREDENTIAL_UNSAFE" in problem and "chmod 600" in problem


def test_a_missing_secret_file_is_named_without_opening_anything_else(preflight, tmp_path):
    posture = production(tmp_path)
    write_role(posture, "read")
    (posture.config_dir / "read.secret").unlink()
    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale",
                                   read_status=running())
    assert str(posture.config_dir / "read.secret") in problem
    assert "tailnet credentials set read" in problem


def test_an_unsafe_secret_file_is_named_with_mc_s_fix(preflight, tmp_path):
    posture = production(tmp_path)
    write_role(posture, "read")
    (posture.config_dir / "read.secret").chmod(0o640)
    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale",
                                   read_status=running())
    assert "read.secret" in problem and "chmod 600" in problem


def test_a_missing_tailscale_binary_is_named_and_nothing_is_run(preflight, tmp_path):
    write_role(production(tmp_path), "read")
    [problem] = preflight.problems({}, real_home=tmp_path / "home", find_binary=lambda: None,
                                   read_status=never)
    assert "tailscale CLI" in problem and "/usr/bin/tailscale" in problem


@pytest.mark.parametrize("state", ["Stopped", "NeedsLogin", None])
def test_a_backend_that_is_not_running_is_named(preflight, tmp_path, state):
    write_role(production(tmp_path), "read")
    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale",
                                   read_status=running(state, reason="backend not running"))
    assert "not Running" in problem and "backend not running" in problem


def test_a_running_backend_whose_self_is_offline_is_named(preflight, tmp_path):
    write_role(production(tmp_path), "read")
    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale",
                                   read_status=running(reason="this host is offline"))
    assert "this host is offline" in problem


def test_a_status_run_that_gives_no_answer_is_named(preflight, tmp_path):
    write_role(production(tmp_path), "read")

    def broken():
        """A status run whose output was not an envelope."""
        raise RuntimeError("no JSON envelope on stdout")

    [problem] = preflight.problems({}, real_home=tmp_path / "home",
                                   find_binary=lambda: "/usr/bin/tailscale", read_status=broken)
    assert "no JSON envelope" in problem


def test_every_missing_piece_is_named_in_one_run(preflight, tmp_path):
    found = preflight.problems({}, real_home=tmp_path / "home", find_binary=lambda: None,
                               read_status=never)
    assert len(found) == 2
    assert "read.json" in found[0] and "tailscale CLI" in found[1]


def test_a_ready_droplet_has_no_problems(preflight, tmp_path):
    write_role(production(tmp_path), "read")
    assert preflight.problems({}, real_home=tmp_path / "home",
                              find_binary=lambda: "/usr/bin/tailscale",
                              read_status=running()) == []


def test_the_message_numbers_each_piece_and_says_nothing_ran(preflight):
    text = preflight.message(["the read credential", "the tailscale CLI"])
    assert "1. the read credential" in text and "2. the tailscale CLI" in text
    assert "nothing was run" in text and "never skips" in text


# --- The manual checks and the no-skip rule ---


def test_the_manual_checks_are_m1_to_m4():
    done = subprocess.run([sys.executable, "-I", str(E2E / "manual_checks.py")],
                          capture_output=True, text=True, timeout=60, check=True)
    text = done.stdout
    for label in ("M1.", "M2.", "M3.", "M4."):
        assert text.count(label) == 1, label
    m1, m2, m3, m4 = (text.index(label) for label in ("M1.", "M2.", "M3.", "M4."))
    assert m1 < m2 < m3 < m4
    assert "--dangerously-skip-permissions" in text[m1:m2] and "disable-key-expiry" in text[m1:m2]
    assert "auto mode" in text[m2:m3]
    assert "/tailnet" in text[m3:m4] and "Manual" in text[m3:m4]
    assert "claude mcp login tailscale-docs --no-browser" in text[m4:]


def test_nothing_in_the_e2e_suite_can_skip():
    # A skipped live test reads as green to someone glancing at a phone; the suite fails instead.
    files = sorted(E2E.glob("*.py"))
    assert E2E / "run_live.py" in files
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        names |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert not names & {"skip", "skipif", "xfail", "importorskip"}, path.name
