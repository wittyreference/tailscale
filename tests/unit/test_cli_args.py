# ABOUTME: Tests for the CLI contract in DESIGN.md §5: how every exit code in the §5.3 table is produced,
# ABOUTME: and the grammar: no abbreviations, --json anywhere, --reason with --apply, exactly 14 commands.

import json
import re
import runpy
import sys
import threading

import pytest

from tailnet import cli, errors
from tailnet.output import Envelope

# §5.3, row by row: exit code, how a command produces it, the outcome agents branch on, and
# the error kind the envelope carries (None when there is no error).
EXIT_TABLE = [
    (0, lambda: Envelope(command="status", posture="production"), "ok", None),
    (1, lambda: Envelope.from_error("status", "production", RuntimeError("a bug")), "error",
     "internal"),
    (2, lambda: errors.UsageError("REASON_REQUIRED", "--apply needs --reason"), "error", "usage"),
    (3, lambda: errors.LocalError("CREDENTIAL_MISSING", "no read.json"), "error", "local"),
    (4, lambda: errors.ApiError("API_SERVER", "502", http_status=502), "error", "api"),
    (5, lambda: errors.Refused("CONFIRM_MISMATCH", "token differs"), "refused", "refused"),
    (6, lambda: errors.Unconfirmed("WRITE_UNCONFIRMED", "re-read differs"), "unconfirmed",
     "unconfirmed"),
    (7, lambda: errors.Rejected("WRITE_REJECTED", "400"), "rejected", "rejected"),
    (8, lambda: errors.Negative("POLICY_TEST_FAILED", "drop"), "negative", "negative"),
]


def as_envelope(made):
    """Turn whatever a table row produced into the envelope the CLI would print."""
    if isinstance(made, Envelope):
        return made
    return Envelope.from_error("device tag", "production", made)


def test_every_exit_code_in_the_table_is_reachable():
    assert [row[0] for row in EXIT_TABLE] == list(range(9))
    for exit_code, produce, outcome, kind in EXIT_TABLE:
        env = as_envelope(produce())
        assert (env.exit, env.outcome, env.ok) == (exit_code, outcome, exit_code == 0)
        assert (env.error or {}).get("kind") == kind
        assert errors.EXIT_NAMES[exit_code]


@pytest.mark.parametrize("cls,exit_code", [
    (errors.UsageError, 2), (errors.LocalError, 3), (errors.ApiError, 4), (errors.Refused, 5),
    (errors.Unconfirmed, 6), (errors.Rejected, 7), (errors.Negative, 8),
])
def test_each_error_class_carries_its_table_exit(cls, exit_code):
    code = min(errors.STABLE_CODES[exit_code])
    assert cls(code, "m").exit == exit_code


# §3.2: the command set is exactly these. A new command needs a recorded MC need first
# (CLAUDE.md invariant 10), then this set changes with it.
DESIGNED = {
    "status", "doctor", "device list", "device tag", "device disable-key-expiry", "policy get",
    "policy draft", "policy validate", "policy diff", "policy test", "dns", "diagnose",
    "credentials set", "credentials forget",
}
TAG = ["device", "tag", "pi5", "--add", "tag:fleet"]
DISABLE = ["device", "disable-key-expiry", "pi5"]


@pytest.fixture(autouse=True)
def test_posture(monkeypatch, tmp_path):
    """Every run here is test posture, and the hooks main() installs are put back afterwards."""
    monkeypatch.setenv("TAILNET_API_BASE", "http://127.0.0.1:9")
    monkeypatch.setenv("TAILNET_HOME", str(tmp_path / "tn"))
    monkeypatch.delenv("TAILNET_DEBUG", raising=False)
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    return tmp_path / "tn"


def run(capsys, *argv):
    """Run the CLI in-process; return (exit code, stdout, stderr)."""
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def run_json(capsys, *argv):
    """Run with --json first; return (exit code, the one envelope stdout held)."""
    code, out, _ = run(capsys, "--json", *argv)
    return code, json.loads(out)


def leaves():
    """Every leaf command of the real parser, by its words."""
    return cli.leaves(cli.build_parser())


def option_strings(parser):
    """Every option string a parser accepts."""
    return {opt for action in parser._actions for opt in action.option_strings}


def test_abbreviated_flags_are_usage_errors(capsys):
    # A prefix that argparse completed would slip --appl past the ask rule *--apply* (L3).
    for flag in (["--appl"], ["--confi", "retag:pi5"], ["--rea", "why"], ["--jso"]):
        code, env = run_json(capsys, *TAG, *flag)
        assert (code, env["error"]["code"]) == (2, "USAGE"), flag
        assert flag[0] in env["error"]["message"]
    for words, parser in cli.walk(cli.build_parser()):
        assert parser.allow_abbrev is False, words


def test_apply_has_no_value_form(capsys):
    code, env = run_json(capsys, *TAG, "--apply=yes", "--reason", "drop the lab tag")
    assert (code, env["error"]["code"]) == (2, "USAGE")


@pytest.mark.parametrize("command", [TAG, DISABLE])
def test_apply_requires_reason(capsys, command):
    for extra in ([], ["--reason", "   "], ["--reason", ""]):
        code, env = run_json(capsys, *command, "--apply", *extra)
        assert (code, env["error"]["code"]) == (2, "REASON_REQUIRED"), extra
        assert env["outcome"] == "error"


@pytest.mark.parametrize("reason", ["<why>", "  <why> ", "<WHY>", "drop the lab tag <why>"])
def test_the_reason_placeholder_is_refused(capsys, reason):
    # The dry run prints the apply line with --reason "<why>"; pasted unedited, it says nothing.
    code, env = run_json(capsys, *TAG, "--apply", "--reason", reason)
    assert (code, env["error"]["code"]) == (2, "REASON_PLACEHOLDER")


def test_a_reason_is_one_to_two_hundred_characters(capsys):
    code, env = run_json(capsys, *TAG, "--apply", "--reason", "r" * 201)
    assert (code, env["error"]["code"]) == (2, "USAGE")
    # Exactly 200 passes the grammar and reaches the command itself.
    code, env = run_json(capsys, *TAG, "--apply", "--reason", "r" * 200)
    assert (code, env["error"]["code"]) == (1, "INTERNAL")


def test_apply_exists_only_on_the_two_write_commands():
    writes = {"device tag", "device disable-key-expiry"}
    for flag in ("--apply", "--confirm", "--reason"):
        assert {name for name, parser in leaves().items()
                if flag in option_strings(parser)} == writes, flag


def test_device_tag_takes_exactly_one_device(capsys):
    for argv in (["device", "tag", "pi5", "spec5", "--add", "tag:fleet"],
                 ["device", "tag", "--add", "tag:fleet"],
                 ["device", "tag", "pi5"]):
        code, env = run_json(capsys, *argv)
        assert (code, env["error"]["code"]) == (2, "USAGE"), argv
    # One device and one change is the whole grammar; the command itself is not built yet.
    code, env = run_json(capsys, "device", "tag", "pi5", "--remove", "tag:lab")
    assert (code, env["error"]["code"]) == (1, "INTERNAL")
    # disable-key-expiry takes several (§12.5); the test home has no read credential, so the
    # dry run stops at its first pre-read.
    code, env = run_json(capsys, "device", "disable-key-expiry", "pi5", "spec5", "nomad-b")
    assert (code, env["command"], env["error"]["code"]) == (3, "device disable-key-expiry",
                                                            "CREDENTIAL_MISSING")


def test_no_flag_accepts_a_secret_a_base_url_a_tailnet_or_force():
    # §5.1: secrets come only from MC's 0600 files, the API only from the posture rule, and a
    # guard refusal is final for the CLI.
    forbidden = re.compile(r"secret|token|key|passw|client|cred|base|url|endpoint|host|home"
                           r"|tailnet|force|api|insecure|verify", re.IGNORECASE)
    for words, parser in cli.walk(cli.build_parser()):
        for option in option_strings(parser):
            assert not forbidden.search(option), (words, option)


def test_json_is_accepted_before_and_after_the_subcommand(capsys):
    # The test home holds no read credential, so the command stops at exit 3 before any
    # request; what matters here is that every placement gives one envelope.
    for argv in (["--json", "device", "list"], ["device", "--json", "list"],
                 ["device", "list", "--json"]):
        code, out, _ = run(capsys, *argv)
        env = json.loads(out)
        assert (code, env["command"], env["schema"]) == (3, "device list", "tailnet.v1"), argv
        assert env["error"]["code"] == "CREDENTIAL_MISSING"
        # The parsed value agrees: a sub-parser's default never overwrites an earlier --json.
        assert cli.build_parser().parse_args(argv).json is True, argv
    # Without it, the human view: a verdict line ending with its time.
    code, out, _ = run(capsys, "device", "list")
    assert code == 3
    assert out.startswith("LOCAL: CREDENTIAL_MISSING: ") and "(as of " in out


def test_a_usage_error_with_json_is_still_exactly_one_envelope(capsys):
    code, out, _ = run(capsys, "--json", "device", "rename", "pi5")
    env = json.loads(out)
    assert (code, env["exit"], env["ok"], env["error"]["code"]) == (2, 2, False, "USAGE")
    assert env["next"][0]["who"] == "agent" and "--help" in env["next"][0]["run"]


def test_the_command_set_is_exactly_the_designed_fourteen():
    assert set(leaves()) == DESIGNED
    assert len(DESIGNED) == 14
    # Every leaf dispatches somewhere, and nothing dispatches that is not a leaf.
    assert set(cli.HANDLERS) == DESIGNED


def test_a_command_not_built_yet_names_the_item_that_builds_it(capsys):
    code, env = run_json(capsys, "doctor")
    assert (code, env["error"]["code"], env["outcome"]) == (1, "INTERNAL", "error")
    assert "not built yet" in env["error"]["message"] and "§29 item 25" in env["error"]["message"]


def test_test_posture_announces_itself_on_every_run(capsys, test_posture):
    code, out, err = run(capsys, "--json", "device", "rename")
    assert code == 2
    assert err.startswith(f"TEST POSTURE: API http://127.0.0.1:9, home {test_posture.resolve()}. "
                          "Nothing here touches the real tailnet.\n")
    assert json.loads(out)["posture"] == "test"


def test_an_unsafe_override_refuses_before_anything_else(capsys, monkeypatch):
    monkeypatch.setenv("TAILNET_API_BASE", "http://10.0.0.1:9")
    for argv in (["dns"], ["device", "rename"]):
        code, env = run_json(capsys, *argv)
        assert (code, env["error"]["code"]) == (3, "ENV_UNSAFE_OVERRIDE"), argv
        # Neither posture holds: the override was refused, and nothing falls back.
        assert env["posture"] == "unknown"


def test_a_bug_is_still_one_redacted_envelope_and_exits_1(capsys, monkeypatch):
    secret = "tskey-" + "client-" + "kCli1CNTRL-" + "b" * 24

    def broken(posture, args):
        raise RuntimeError(f"bug holding {secret}")

    monkeypatch.setitem(cli.HANDLERS, "dns", broken)
    code, out, err = run(capsys, "--json", "dns")
    env = json.loads(out)
    assert (code, env["error"]["code"], env["error"]["kind"]) == (1, "INTERNAL", "internal")
    assert secret not in out + err
    assert "RuntimeError: bug holding tskey-…[REDACTED]" in env["error"]["message"]
    assert "Traceback" not in err
    monkeypatch.setenv("TAILNET_DEBUG", "1")
    code, out, err = run(capsys, "--json", "dns")
    assert code == 1
    assert "Traceback" in err and secret not in err


def test_help_prints_the_grammar_and_exits_0(capsys):
    code, out, _ = run(capsys, "--help")
    assert code == 0
    assert out.startswith("usage: tailnet")


def test_python_dash_m_tailnet_runs_the_cli(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tailnet", "--json", "dns"])
    with pytest.raises(SystemExit) as stop:
        runpy.run_module("tailnet", run_name="__main__", alter_sys=True)
    # The test home holds no read credential, so dns stops at exit 3 before any request.
    assert stop.value.code == 3
    env = json.loads(capsys.readouterr().out)
    assert (env["command"], env["error"]["code"]) == ("dns", "CREDENTIAL_MISSING")
