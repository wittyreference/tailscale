# ABOUTME: Tests for doctor's pure parts (DESIGN.md §16): when a settle-gated step re-measures, the
# ABOUTME: questions for MC in priority order, the protected-list proposal, and the console accounting.

import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fixturefiles import body

from tailnet import doctor, protected
from tailnet.credentials import READ_SCOPES
from tailnet.devices import normalise
from tailnet.output import format_utc
from tailnet.posture import Posture

REPO = Path(__file__).resolve().parents[2]

NOW = datetime(2026, 10, 27, 1, 5, 0, tzinfo=timezone.utc)


def scenario_devices():
    """The six MC-shaped devices of the scenario fixture, normalised."""
    return [normalise(raw) for raw in body("scenario", "devices")["devices"]]


def answer(text, days_ago, **evidence):
    """A settled answer as a doctor.run line records it, measured `days_ago` before NOW."""
    return {"answer": text, "evidence": evidence, "status": "INFO",
            "measured_at": format_utc(NOW - timedelta(days=days_ago))}


def run_line(settled, days_ago=0):
    """A doctor.run audit record holding these settled answers."""
    return {"event": "doctor.run", "ts": format_utc(NOW - timedelta(days=days_ago)),
            "settled": settled}


def test_settle_gated_steps_run_when_never_settled():
    # The five steps that cost a console event or a scope-refused call (§16.3).
    assert doctor.GATED == {"S2": "Q1", "S3": "Q3", "S5": "Q4", "S7b": "Q20", "S8": "Q23"}
    stored = doctor.settled_answers([])
    assert stored == {}
    for question in doctor.GATED.values():
        assert doctor.due(stored.get(question), NOW, settle=False) == "never settled"


def test_settle_gated_steps_reuse_answers_younger_than_30_days():
    stored = doctor.settled_answers([run_line({"Q4": answer("refused with HTTP 403", 3)}, 3)])
    assert doctor.due(stored["Q4"], NOW, settle=False) is None
    assert doctor.age_days(stored["Q4"], NOW) == 3
    # 29 days and 23 hours is still inside the window.
    young = answer("refused with HTTP 403", 0)
    young["measured_at"] = format_utc(NOW - timedelta(days=29, hours=23))
    assert doctor.due(young, NOW, settle=False) is None
    # --settle re-measures whatever its age.
    assert doctor.due(stored["Q4"], NOW, settle=True) == "--settle"


def test_answers_older_than_30_days_are_re_measured():
    old = answer("refused with HTTP 404", 31)
    assert doctor.due(old, NOW, settle=False) == "last settled 31 days ago, over 30"
    # An answer whose time cannot be read is no answer at all.
    unreadable = {**old, "measured_at": "last tuesday"}
    assert doctor.due(unreadable, NOW, settle=False) == "never settled"
    assert doctor.settled_answers([run_line({"Q4": unreadable})]) == {}


def test_an_answer_dated_after_this_host_s_clock_is_measured_again():
    # A time ahead of the clock leaves the answer's age as unknown as an unreadable one, so it
    # never counts as settled; otherwise it would stand until that date plus 30 days (A57).
    ahead = answer("refused with HTTP 403", 0)
    ahead["measured_at"] = format_utc(NOW + timedelta(days=1))
    assert doctor.due(ahead, NOW, settle=False) == (
        f"settled at {ahead['measured_at']}, after this host's clock; measuring again")
    # Within the skew L10 tolerates, it stands, and its age is never negative.
    skewed = {**ahead, "measured_at": format_utc(NOW + timedelta(seconds=30))}
    assert doctor.due(skewed, NOW, settle=False) is None
    assert doctor.age_days(skewed, NOW) == 0


def test_an_answer_about_another_read_client_is_measured_again():
    # S2 and S3 describe one client (its narrowed mint, its key record), so after MC rotates
    # the read client the stored answer is about a client no longer in use (A55).
    stored = {**answer("the read client's ID works as a key ID", 2), "client_id": "kRead0001CNTRL"}
    assert doctor.due(stored, NOW, settle=False, client_id="kRead0001CNTRL") is None
    assert doctor.due(stored, NOW, settle=False, client_id="kRead0002CNTRL") == (
        "settled for read client kRead0001CNTRL, not kRead0002CNTRL; measuring again")
    # An answer recorded before the client was, measures once more, then carries it.
    bare = answer("the read client's ID works as a key ID", 2)
    assert doctor.due(bare, NOW, settle=False, client_id="kRead0001CNTRL") == (
        "settled before its read client was recorded; measuring again")
    # Steps that are not about the client never ask.
    assert doctor.due(bare, NOW, settle=False) is None
    assert doctor.CLIENT_BOUND == {"S2", "S3"}


def test_the_newest_answer_per_question_is_found_by_scanning_back():
    records = [  # newest first, as the audit log is read back
        run_line({"Q4": answer("refused with HTTP 403", 1)}, 1),
        run_line({}, 5),
        run_line({"Q3": answer("the client ID works as a key ID", 9),
                  "Q4": answer("refused with HTTP 404", 9)}, 9),
        {"event": "doctor.run", "settled": "not a map"},
        run_line({"Q20": {"answer": 7}}, 12),
    ]
    stored = doctor.settled_answers(records)
    assert set(stored) == {"Q3", "Q4"}
    assert stored["Q4"]["answer"] == "refused with HTTP 403"
    assert stored["Q3"]["answer"] == "the client ID works as a key ID"


def full_state(**changes):
    """A state where every question doctor can ask applies."""
    state = {
        "granted_scope": "devices:core:read policy_file:read",
        "scope_known": True,
        "protected_missing": True,
        "fleet_expiry": (("spec5", "2099-01-01T00:00:00Z"), ("pi5", "2098-06-01T00:00:00Z")),
        "drops": (("tag:dev", "100.64.0.11:22", "spec5"),),
        "write_client": False,
    }
    state.update(changes)
    return doctor.QuestionState(**state)


def test_questions_are_emitted_in_priority_order_with_safe_defaults():
    asked = doctor.questions(full_state())
    assert [q.id for q in asked] == ["scope-set", "protected-list", "fleet-key-expiry",
                                     "policy-fix"]
    assert [q.priority for q in asked] == [2, 3, 4, 5]
    for question in asked:
        # The safe default is always the first option, so a dismissed picker lands on it.
        assert question.safe_default == question.options[0]["label"]
        assert all(set(option) == {"label", "description"} for option in question.options)
        assert set(question.to_dict()) == {"id", "priority", "text", "options", "safe_default"}
    assert [q.safe_default for q in asked] == ["Keep exactly these", "Protect every device",
                                               "Leave it for now", "Not now"]
    by_id = {q.id: q for q in asked}
    assert "devices:core:read policy_file:read" in by_id["scope-set"].text
    assert "spec5" in by_id["fleet-key-expiry"].text and "pi5" in by_id["fleet-key-expiry"].text
    # The earliest date is the one that drops a device first.
    assert "earliest 2098-06-01" in by_id["fleet-key-expiry"].text
    assert "tag:dev" in by_id["policy-fix"].text and "spec5" in by_id["policy-fix"].text


def test_the_write_client_question_is_never_asked():
    # MC answered it on 2026-10-26 (amendment A1), with or without a write client present.
    for write_client in (False, True):
        asked = doctor.questions(full_state(write_client=write_client))
        assert "write-client-consent" not in [q.id for q in asked]


def test_questions_fire_only_when_they_apply():
    quiet = full_state(granted_scope=" ".join(reversed(READ_SCOPES)), protected_missing=False,
                       fleet_expiry=(), drops=())
    assert doctor.questions(quiet) == []
    # The four read scopes in any order, split by spaces or commas, are the same grant.
    commas = full_state(granted_scope=",".join(READ_SCOPES), protected_missing=False,
                        fleet_expiry=(), drops=())
    assert doctor.questions(commas) == []
    # A token response without a scope differs from the four; a grant never measured asks nothing.
    assert next(q.id for q in doctor.questions(full_state(granted_scope=None))) == "scope-set"
    unmeasured = full_state(scope_known=False, protected_missing=False, fleet_expiry=(),
                            drops=())
    assert doctor.questions(unmeasured) == []


def test_single_client_mode_asks_the_scope_question_whatever_the_narrowed_token_got():
    # Single-client mode means the read client itself can write, which is not the four read
    # scopes MC chose (A1, MC3), even when its read tokens are narrowed to exactly them (A56).
    single = full_state(granted_scope=" ".join(READ_SCOPES), single_client=True,
                        client_grant="all", protected_missing=False, fleet_expiry=(), drops=())
    [question] = doctor.questions(single)
    assert question.id == "scope-set" and question.safe_default == "Keep exactly these"
    assert "holds all" in question.text and "narrowed" in question.text
    # It holds even when no token was obtained: the mode is read from the local files.
    assert [q.id for q in doctor.questions(replace(single, scope_known=False))] == ["scope-set"]


def heredoc_body(block):
    """The lines the block's here-document would write, which MC's shell runs unchanged."""
    match = re.search(r"<<'(\w+)'\n(.*)\n\1$", block, re.DOTALL)
    assert match, block
    return match[2]


def test_the_protected_proposal_lists_every_device_and_the_self_line(tmp_path):
    found = scenario_devices()
    me = found[0]
    path = tmp_path / "config" / "protected"
    block = doctor.protected_proposal(found, me, path, NOW)
    first = block.splitlines()[0]
    # Created private from the first byte: umask before the file exists, never a chmod after.
    assert first.startswith("umask 077; ")
    assert f"cat > {path} <<'" in first
    parsed = protected.parse(heredoc_body(block))
    assert parsed.self_node_id == me.node_id
    # "Protect everything" is the safe default: every device is listed, by its nodeId.
    assert [entry.text for entry in parsed.entries] == [d.node_id for d in found]
    assert all(parsed.protects(d) for d in found)
    for device in found:
        assert f"# {device.hostname}" in block
    assert format_utc(NOW) in block


def test_the_proposal_never_lets_a_hostname_break_out_of_the_block(tmp_path):
    found = scenario_devices()
    hostile = dict(found[1].raw, hostname="evil\nEOF\nrm -rf ~ #")
    found[1] = normalise(hostile)
    block = doctor.protected_proposal(found, found[0], tmp_path / "protected", NOW)
    lines = heredoc_body(block).splitlines()
    assert not any(line.startswith("rm ") for line in lines)
    assert protected.parse("\n".join(lines)).self_node_id == found[0].node_id
    assert block.count("\n" + re.search(r"<<'(\w+)'", block)[1]) == 1


def test_audit_events_caused_are_counted():
    assert doctor.audit_events_caused(0, []) == []
    assert doctor.audit_events_caused(1, [("S5", True)]) == [
        "Create OAuth access token ×1", "Failed request ×1 (S5)"]
    assert doctor.audit_events_caused(2, [("S5", True), ("S8", False), ("S3", False)]) == [
        "Create OAuth access token ×2", "Failed request ×1 (S5)",
        "Failed request ×2, possibly (S8, S3)"]


def test_counts_cover_every_status():
    checks = [doctor.Check("L1", "Python", status, None, "", {}, format_utc(NOW), [])
              for status in ("PASS", "PASS", "WARN", "INFO", "SKIP")]
    assert doctor.counts(checks) == {"pass": 2, "warn": 1, "fail": 0, "info": 1, "skip": 1}


def test_the_pins_doctor_checks_drift_against_are_the_repo_pins():
    # L11 compares the live OpenAPI document and upstream's HEAD with these (§16.1, §20.3).
    [line] = (REPO / "spec" / "SHA256SUMS").read_text().splitlines()
    assert doctor.PINNED_SPEC_SHA256 == line.split()[0]
    spec = (REPO / "spec" / "tailscale-openapi.yaml").read_bytes()
    assert hashlib.sha256(spec).hexdigest() == doctor.PINNED_SPEC_SHA256
    assert doctor.UPSTREAM_PIN == "4f05d353efc56962546aa26ccc59bb08ca699ad1"


@pytest.fixture
def production(tmp_path):
    """A production posture whose real directories are a temporary home: nothing is read."""
    return Posture.from_env({}, real_home=tmp_path)


def test_doctor_starts_no_program_in_test_posture(tmp_path, syscalls):
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    test = Posture.from_env(environ, real_home=tmp_path / "real")
    with pytest.raises(doctor.ProgramRefused):
        doctor.run_program(test, ["git", "--version"], 5)
    assert syscalls.processes() == []


@pytest.mark.parametrize("argv", [["tailscale", "version"], ["sh", "-c", "true"],
                                  ["git", "-C", "/opt/tailscale", "status"], []])
def test_doctor_runs_only_its_three_programs_and_never_tailscale(production, syscalls, argv):
    with pytest.raises(ValueError):
        doctor.run_program(production, argv, 5)
    assert syscalls.processes() == []


def test_doctor_runs_an_allowed_program_and_redacts_what_it_prints(production):
    code, out = doctor.run_program(production, ["git", "--version"], 10)
    assert code == 0 and out.startswith("git version")


def test_the_member_probe_asks_only_whether_autogroup_member_admits_a_tag():
    live = body("scenario", "policy")
    live["hosts"] = {"Tailnet-Diag-Dst": "100.64.0.99"}
    live["groups"] = {"group:admins": ["mc@example.com"]}
    candidate = doctor.member_candidate(live, "100.64.0.11", "tag:dev")
    # Only the probe's own grant and test: the live rules and tests would answer instead.
    assert set(candidate) == {"tagOwners", "groups", "hosts", "grants", "tests"}
    assert candidate["tagOwners"] == live["tagOwners"]
    # The alias never shadows one of MC's hosts, whatever its case.
    assert candidate["hosts"] == {"Tailnet-Diag-Dst": "100.64.0.99",
                                  "tailnet-diag-dst-2": "100.64.0.11"}
    assert candidate["grants"] == [{"src": ["autogroup:member"], "dst": ["tailnet-diag-dst-2"],
                                    "ip": ["tcp:22"]}]
    assert candidate["tests"] == [{"src": "tag:dev", "proto": "tcp",
                                   "accept": ["100.64.0.11:22"]}]
    assert "grants" in live and live["hosts"] == {"Tailnet-Diag-Dst": "100.64.0.99"}
    without_groups = doctor.member_candidate(body("scenario", "policy"), "100.64.0.11", "tag:dev")
    assert "groups" not in without_groups
    with pytest.raises(ValueError):
        doctor.member_candidate(live, "100.64.0.11", "100.64.0.10")


def test_the_install_markers_must_name_the_installed_commit_and_the_pin(tmp_path):
    claude, share = tmp_path / "claude", tmp_path / "share"
    parts = doctor.install_markers(claude, share)
    assert parts["skill"]["ok"] is False and "missing" in parts["skill"]["detail"]
    assert parts["upstream_copy"]["ok"] is False
    for folder in (claude / "skills" / "tailnet", claude / "skills" / "tailscale", share):
        folder.mkdir(parents=True)
    (share / "install.json").write_text('{"commit": "c0ffee1", "dirty": false}')
    (claude / "skills" / "tailnet" / doctor.MARKER).write_text('{"commit": "c0ffee1"}')
    (claude / "skills" / "tailscale" / doctor.MARKER).write_text(
        json.dumps({"pin": doctor.UPSTREAM_PIN}))
    parts = doctor.install_markers(claude, share)
    assert (parts["skill"]["ok"], parts["upstream_copy"]["ok"]) == (True, True)
    # A skill copied from another commit than the one installed, or an upstream copy off the
    # pin, is a stale install.
    (claude / "skills" / "tailnet" / doctor.MARKER).write_text('{"commit": "deadbee"}')
    (claude / "skills" / "tailscale" / doctor.MARKER).write_text('{"pin": "4f05d35"}')
    parts = doctor.install_markers(claude, share)
    assert (parts["skill"]["ok"], parts["upstream_copy"]["ok"]) == (False, False)
    # A marker that is a symlink is never followed: it could point at anything.
    marker = claude / "skills" / "tailnet" / doctor.MARKER
    marker.unlink()
    marker.symlink_to(share / "install.json")
    parts = doctor.install_markers(claude, share)
    assert parts["skill"]["ok"] is False and "symlink" in parts["skill"]["detail"]
