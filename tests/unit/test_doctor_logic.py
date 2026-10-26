# ABOUTME: Tests for doctor's pure parts (DESIGN.md §16): when a settle-gated step re-measures, the
# ABOUTME: questions for MC in priority order, the protected-list proposal, and the console accounting.

import re
from datetime import datetime, timedelta, timezone

from fixturefiles import body

from tailnet import doctor, protected
from tailnet.credentials import READ_SCOPES
from tailnet.devices import normalise
from tailnet.output import format_utc

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
