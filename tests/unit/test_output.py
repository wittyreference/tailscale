# ABOUTME: Tests for tailnet.output: the tailnet.v1 JSON envelope, human output and warnings (§5.4).
# ABOUTME: Everything is checked as written to real stdout and stderr, after redaction.

import io
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

import tailnet
from tailnet import errors, output
from tailnet.output import Envelope


def key():
    """A key-shaped string built at runtime (CLAUDE.md invariant 14)."""
    return "tskey-" + "client-" + "kAbc123CNTRL-" + "q7" * 12


def test_json_mode_prints_exactly_one_envelope_with_every_field(capsys):
    env = Envelope(command="device list", posture="test", data={"devices": []},
                   request_ids=["REQ-1"])
    output.emit(env, json_mode=True)
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert list(doc) == ["schema", "command", "cli_version", "posture", "measured_at", "ok",
                         "exit", "outcome", "data", "warnings", "error", "next", "request_ids"]
    assert doc["schema"] == "tailnet.v1"
    assert doc["cli_version"] == tailnet.__version__
    assert (doc["ok"], doc["exit"], doc["outcome"], doc["error"]) == (True, 0, "ok", None)
    assert doc["request_ids"] == ["REQ-1"]


def test_an_error_still_prints_exactly_one_envelope(capsys):
    nxt = [{"who": "agent", "run": "tailnet device list --json", "why": "see what landed"}]
    err = errors.Unconfirmed("WRITE_UNCONFIRMED", "do not re-apply", request_id="REQ-9", next=nxt)
    output.emit(Envelope.from_error("device tag", "production", err), json_mode=True)
    doc = json.loads(capsys.readouterr().out)
    assert (doc["ok"], doc["exit"], doc["outcome"]) == (False, 6, "unconfirmed")
    assert doc["error"] == {"code": "WRITE_UNCONFIRMED", "kind": "unconfirmed",
                            "message": "do not re-apply", "http_status": None,
                            "request_id": "REQ-9"}
    assert doc["next"] == nxt
    assert doc["request_ids"] == ["REQ-9"]


def test_measured_at_is_utc_iso_8601_with_z():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", output.now_utc())
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", Envelope("status", "test").measured_at)
    eastern = datetime(2026, 10, 26, 21, 2, 3, 456000, tzinfo=timezone(timedelta(hours=-4)))
    assert output.format_utc(eastern) == "2026-10-27T01:02:03Z"


def test_an_unexpected_exception_is_internal_and_its_message_redacted(capsys):
    env = Envelope.from_error("status", "production", RuntimeError("crashed near " + key()))
    assert (env.exit, env.outcome, env.error["kind"], env.error["code"]) == (
        1, "error", "internal", "INTERNAL")
    output.emit(env, json_mode=True)
    out = capsys.readouterr().out
    assert key() not in out
    assert json.loads(out)["error"]["message"] == "RuntimeError: crashed near tskey-…[REDACTED]"


def test_emit_redacts_the_final_serialised_text(capsys):
    env = Envelope("device list", "production",
                   data={"note": key(), "token": {"access_token": "opaque-value-0001"}})
    output.emit(env, json_mode=True)
    out = capsys.readouterr().out
    assert key() not in out
    assert "opaque-value-0001" not in out
    output.emit(env, json_mode=False)
    assert key() not in capsys.readouterr().out


def test_human_output_starts_with_the_verdict_and_the_time_and_ends_with_who_acts(capsys):
    env = Envelope("device tag", "production", outcome="dry-run",
                   headline="DRY RUN: nothing changed", lines=["device tag  pi5  nAbc456CNTRL"],
                   next=[{"who": "agent", "run": "tailnet device tag nAbc456CNTRL --apply",
                          "why": "applies this plan; MC is prompted"},
                         {"who": "mc", "do": "chmod 600 ~/.config/tailnet/read.json",
                          "why": "the file is group-readable", "needs": "terminal"},
                         {"who": "ask_mc", "question": {"id": "MC7", "text": "Disable key expiry?",
                                                        "options": [], "safe_default": "no"}}])
    output.emit(env, json_mode=False)
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == f"DRY RUN: nothing changed (as of {env.measured_at})"
    assert lines[1] == "device tag  pi5  nAbc456CNTRL"
    assert lines[2:] == [
        "Next (agent): tailnet device tag nAbc456CNTRL --apply",
        "  why: applies this plan; MC is prompted",
        "Next (MC, terminal): chmod 600 ~/.config/tailnet/read.json",
        "  why: the file is group-readable",
        "Next (ask MC): Disable key expiry?",
    ]


def test_a_human_error_verdict_names_the_exit_and_the_code(capsys):
    err = errors.Refused("CONFIRM_MISMATCH", "the confirm token is retag:pi5")
    env = Envelope.from_error("device tag", "production", err)
    output.emit(env, json_mode=False)
    first = capsys.readouterr().out.splitlines()[0]
    assert first == f"REFUSED: CONFIRM_MISMATCH: the confirm token is retag:pi5 (as of {env.measured_at})"


def test_warnings_go_to_stderr_prefixed_tailnet_and_are_redacted(capsys):
    warning = output.warn("TAGGED_KEY_EXPIRY_ON", "pi5 keeps its key expiry near " + key(),
                          source="TAGS L84")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ("tailnet: TAGGED_KEY_EXPIRY_ON: pi5 keeps its key expiry near "
                            "tskey-…[REDACTED] [TAGS L84]\n")
    # Redacted on the way in too, so a warning copied anywhere else is already safe.
    assert warning == {"code": "TAGGED_KEY_EXPIRY_ON",
                       "message": "pi5 keeps its key expiry near tskey-…[REDACTED]",
                       "source": "TAGS L84"}


@pytest.mark.parametrize("exit_code,outcome", [
    (0, "refused"), (0, "error"), (5, "ok"), (8, "error"), (2, "negative"), (0, "bogus")])
def test_an_envelope_whose_exit_and_outcome_disagree_is_a_bug(exit_code, outcome):
    with pytest.raises(ValueError):
        Envelope("status", "test", exit=exit_code, outcome=outcome)


@pytest.mark.parametrize("outcome", ["ok", "dry-run", "noop", "applied"])
def test_every_success_outcome_exits_0(outcome):
    assert Envelope("device tag", "test", outcome=outcome).ok


def test_a_command_s_own_text_goes_to_stdout_exactly_and_its_verdict_to_stderr():
    # policy get's bytes (§14.1): a carriage return, a non-ASCII character and a byte that is
    # not UTF-8 all come out as they went in; only a secret's shape is redacted.
    raw = "// MC’s note\r\n".encode() + key().encode("ascii") + b"\n\xff"
    env = Envelope(command="policy get", posture="test", headline="OK: the live policy",
                   lines=["etag: abc"], stdout_text=raw.decode("utf-8", "surrogateescape"))
    stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    stderr = io.StringIO()
    output.emit(env, json_mode=False, stream=stdout, err_stream=stderr)
    assert stdout.buffer.getvalue() == ("// MC’s note\r\ntskey-…[REDACTED]\n".encode()
                                        + b"\xff")
    assert re.fullmatch(r"OK: the live policy \(as of [0-9TZ:-]+\)\netag: abc\n",
                        stderr.getvalue())
    # It is never part of the JSON envelope; the command puts the text in its data instead.
    json_out = io.StringIO()
    output.emit(env, json_mode=True, stream=json_out)
    assert "stdout_text" not in json.loads(json_out.getvalue())
