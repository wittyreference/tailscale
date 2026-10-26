# ABOUTME: Tests for `tailnet status`, the local-only view the skill injects when it loads (DESIGN.md §17):
# ABOUTME: every section, no API call, no secret opened, at most six brief lines, and always exit 0.

import json
import sys
import threading

import pytest
from credfiles import WRITE_SCOPE, access_token, write_cache, write_role

from tailnet import __version__, audit, cli, gate
from tailnet.posture import Posture

SECTIONS = {"version", "posture", "mode", "credentials", "token_cache", "protected", "gate",
            "self_local", "last_doctor", "open_questions", "audit"}


@pytest.fixture
def posture(loopback, tmp_path, monkeypatch):
    """Test posture at the seam, for the in-process CLI and for laying out its files."""
    environ = {"TAILNET_API_BASE": loopback.base_url, "TAILNET_HOME": str(tmp_path / "tn")}
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    # main() installs redacting excepthooks; put the originals back afterwards.
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    posture = Posture.from_env(environ, real_home=tmp_path / "real")
    posture.config_dir.mkdir(mode=0o700, parents=True)
    return posture


def install_rules(posture, *, without=()):
    """The settings file a full install leaves, minus the rules named in `without`."""
    expected = gate.rules_for(gate.claude_dir(posture, {}))
    path = posture.claude_settings
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": {
        "ask": [r for r in expected["ask"] if r not in without],
        "deny": [r for r in expected["deny"] if r not in without]}}))
    return expected


def configure(posture):
    """A fully set-up test home: both clients, a cached token, the list, the rules, a doctor run."""
    write_role(posture, "read")
    write_role(posture, "write")
    write_cache(posture, access_token("cached01"), expires_in=41 * 60 + 30)
    path = posture.config_dir / "protected"
    path.write_text("self nFactory1CNTRL\nspec5\npi5\n")
    path.chmod(0o600)
    install_rules(posture)
    audit.append(posture, {"event": "doctor.run",
                           "counts": {"pass": 20, "warn": 2, "fail": 0, "info": 3, "skip": 1},
                           "settled": {}, "mints_this_run": 0, "audit_events_caused": [],
                           "questions": ["protected-list", "fleet-key-expiry"]})


def status(capsys, *flags):
    """Run `tailnet status` in-process; return (exit code, stdout, stderr)."""
    code = cli.main(["status", *flags])
    out, err = capsys.readouterr()
    return code, out, err


def data_of(capsys, *flags):
    """Run `tailnet --json status`; return (exit code, the envelope's data)."""
    code, out, _ = status(capsys, "--json", *flags)
    env = json.loads(out)
    assert (env["command"], env["exit"], env["outcome"]) == ("status", 0, "ok")
    return code, env["data"]


def test_status_reports_every_section_without_the_api_or_a_secret(posture, loopback, capsys,
                                                                  syscalls):
    configure(posture)
    syscalls.events.clear()
    code, data = data_of(capsys)
    assert code == 0
    assert set(data) == SECTIONS
    assert (data["version"], data["posture"], data["mode"]) == (__version__, "test", "two-client")
    read, write = data["credentials"]
    assert (read["role"], read["client_id"], read["secret"], read["secret_file"]) == (
        "read", "kRead0001CNTRL", "file", True)
    assert (write["client_id"], write["tags"], write["secret_file"]) == (
        "kWrite0001CNTRL", ["tag:fleet"], True)
    assert write["granted_scope"] == WRITE_SCOPE
    assert data["token_cache"]["usable"] is True and data["token_cache"]["minutes_left"] == 41
    assert data["protected"] == {"state": "answered", "self_node_id": "nFactory1CNTRL",
                                 "entries": 2, "error": None}
    assert data["gate"]["present"] is True and data["gate"]["missing"] == []
    assert data["gate"]["total"] == 10
    assert data["self_local"]["run"] is False
    assert data["last_doctor"]["ran"] is True
    assert data["last_doctor"]["counts"]["warn"] == 2
    assert data["open_questions"] == ["protected-list", "fleet-key-expiry"]
    assert data["audit"]["lines"] == 1
    # Local only: no request, and neither secret was opened (§17, D20).
    assert loopback.requests == []
    assert syscalls.named("read.secret") == [] and syscalls.named("write.secret") == []
    assert syscalls.processes() == []


def test_the_brief_view_is_at_most_six_lines(posture, capsys):
    configure(posture)
    code, out, err = status(capsys, "--brief")
    assert code == 0
    lines = out.splitlines()
    assert len(lines) <= 6
    assert lines[0].startswith(f"tailnet {__version__} · test posture (as of ")
    assert lines[1] == ("credentials: two-client (read kRead0001CNTRL; write kWrite0001CNTRL, "
                        "secret present) · read token cached, 41 min left")
    assert lines[2] == ("protected: answered (2 entries, self nFactory1CNTRL) · gate rules: "
                        "10/10 present")
    assert lines[3] == "self (local view): not run (test posture)"
    assert lines[4].startswith("last doctor: ") and lines[4].endswith(
        " · 0 FAIL, 2 WARN · 2 questions for MC")
    assert lines[5] == f"audit: {audit.log_path(posture)} (1 line)"
    # The cached token is read for its expiry and shown nowhere.
    assert access_token("cached01") not in out + err


def test_missing_gate_rules_are_named(posture, capsys):
    expected = install_rules(posture, without=())
    settings_rule = next(r for r in expected["ask"] if r.startswith("Edit("))
    install_rules(posture, without=(settings_rule,))
    code, out, _ = status(capsys, "--brief")
    assert code == 0
    assert f"gate rules: 9/10 present (MISSING: {settings_rule})" in out
    code, data = data_of(capsys)
    assert (data["gate"]["present"], data["gate"]["missing"]) == (True, [settings_rule])
    install_rules(posture, without=(gate.rules()["gate"],))
    code, data = data_of(capsys)
    assert data["gate"]["present"] is False


def test_an_empty_home_still_answers_with_what_mc_does_next(posture, capsys):
    code, out, _ = status(capsys, "--brief")
    assert code == 0
    assert "credentials: none (no read client)" in out
    assert "protected: unanswered" in out and "gate rules: 0/10 present" in out
    assert "last doctor: never run" in out
    code, out, _ = status(capsys, "--json")
    env = json.loads(out)
    # The full view says who acts next; the brief one has no room for it.
    whats = [step.get("do") or step.get("run") for step in env["next"]]
    assert "tailnet credentials set read" in whats
    assert any("install-tailnet" in what for what in whats)


def test_single_client_mode_says_the_separate_secret_lever_is_absent(posture, capsys):
    write_role(posture, "read", granted_scope="devices:core policy_file:read")
    code, out, _ = status(capsys, "--brief")
    assert code == 0
    assert "credentials: single-client" in out and "L2 absent" in out


def test_every_source_broken_still_exits_0_and_says_why(posture, capsys):
    configure(posture)
    for name in ("read.json", "read-token.json", "protected"):
        (posture.config_dir / name).chmod(0o644)
    audit.log_path(posture).chmod(0o644)
    code, data = data_of(capsys)
    assert code == 0
    assert data["mode"] == "unknown"
    assert data["credentials"][0]["error"].startswith("CREDENTIAL_UNSAFE")
    assert data["token_cache"]["usable"] is False
    assert data["token_cache"]["error"].startswith("CREDENTIAL_UNSAFE")
    assert data["protected"]["state"] == "unreadable"
    assert data["last_doctor"]["error"].startswith("AUDIT_UNWRITABLE")
    assert data["audit"]["error"].startswith("AUDIT_UNWRITABLE")
    # status only reports: the unsafe token cache is left for the next read to remove.
    assert (posture.config_dir / "read-token.json").exists()


def test_an_unsafe_override_still_exits_0_and_reports_the_refusal(loopback, capsys, monkeypatch,
                                                                 tmp_path):
    # A non-zero exit would abort the skill's injection of this status [SK L772-774], so
    # status answers 0 and says plainly that neither posture holds.
    monkeypatch.setenv("TAILNET_API_BASE", loopback.base_url + "/api")
    monkeypatch.setenv("TAILNET_HOME", str(tmp_path / "tn"))
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    code = cli.main(["--json", "status", "--brief"])
    env = json.loads(capsys.readouterr().out)
    assert (code, env["exit"], env["posture"]) == (0, 0, "unknown")
    assert env["data"]["posture_error"]["code"] == "ENV_UNSAFE_OVERRIDE"
    assert [w["code"] for w in env["warnings"]] == ["ENV_UNSAFE_OVERRIDE"]
    code = cli.main(["status", "--brief"])
    out = capsys.readouterr().out
    assert code == 0 and len(out.splitlines()) <= 6 and "ENV_UNSAFE_OVERRIDE" in out
    # Every other command still refuses with exit 3.
    assert cli.main(["dns"]) == 3
    capsys.readouterr()
    assert loopback.requests == []


def test_a_cache_that_is_not_json_is_reported_not_used(posture, capsys):
    write_role(posture, "read")
    cache = posture.config_dir / "read-token.json"
    cache.write_text("not json")
    cache.chmod(0o600)
    code, data = data_of(capsys)
    assert code == 0
    assert data["token_cache"]["usable"] is False
    assert "not a JSON object" in data["token_cache"]["error"]
