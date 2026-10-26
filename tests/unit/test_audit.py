# ABOUTME: Tests for tailnet.audit, the local JSONL narrative of every write, mint and credential change
# ABOUTME: (DESIGN.md §13): one redacted line per record, appended only, read back newest first.

import json
import os
import pwd
import re
import socket
import stat

import pytest

import tailnet
from tailnet import audit, errors, secure_files
from tailnet.posture import Posture
from tailnet.redact import REDACTOR

COMMON = ["v", "ts", "event", "cli_version", "posture", "host", "user", "pid", "argv"]


@pytest.fixture
def posture(tmp_path):
    """A test posture whose state directory does not exist yet."""
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    return Posture.from_env(environ, real_home=tmp_path / "real")


def key():
    """A key-shaped string built at runtime (CLAUDE.md invariant 14)."""
    return "tskey-" + "client-" + "kAud1tCNTRL-" + "z" * 24


def log_lines(posture):
    """The log's raw lines, without the final empty piece after the last newline."""
    lines = (posture.state_dir / "audit.jsonl").read_bytes().split(b"\n")
    assert lines.pop() == b""
    return lines


def test_records_are_single_redacted_json_lines(posture):
    argv = ["device", "tag", "nAbc456CNTRL", "--reason", "two\nlines"]
    audit.append(posture, {"event": "write", "op": "device.tag", "reason": f"pasted {key()}"},
                 argv=argv)
    audit.append(posture, {"event": "token.mint", "role": "read"}, argv=["doctor"])
    lines = log_lines(posture)
    assert len(lines) == 2
    first, second = (json.loads(line) for line in lines)
    assert list(first)[:len(COMMON)] == COMMON
    assert first["v"] == 1
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", first["ts"])
    assert (first["event"], first["cli_version"], first["posture"]) == (
        "write", tailnet.__version__, "test")
    assert first["host"] == socket.gethostname()
    assert first["user"] == pwd.getpwuid(os.geteuid()).pw_name
    assert first["pid"] == os.getpid()
    # A newline inside a field stays escaped, so the record is still one line.
    assert first["argv"] == argv
    assert first["op"] == "device.tag"
    assert first["reason"] == "pasted tskey-…[REDACTED]"
    assert (second["event"], second["role"], second["argv"]) == ("token.mint", "read", ["doctor"])


def test_the_log_is_created_0600_and_opened_append_only(posture, syscalls):
    old_umask = os.umask(0)
    try:
        audit.append(posture, {"event": "doctor.run"}, argv=[])
    finally:
        os.umask(old_umask)
    log = posture.state_dir / "audit.jsonl"
    assert stat.S_IMODE(posture.state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    [flags] = syscalls.open_flags("audit.jsonl")
    assert flags & (os.O_WRONLY | os.O_APPEND) == os.O_WRONLY | os.O_APPEND
    assert flags & (os.O_TRUNC | os.O_RDWR) == 0


def test_existing_lines_are_never_rewritten(posture, syscalls):
    audit.append(posture, {"event": "credential.set", "role": "read"}, argv=[])
    log = posture.state_dir / "audit.jsonl"
    before, inode = log.read_bytes(), log.stat().st_ino
    audit.append(posture, {"event": "credential.forget", "role": "write"}, argv=[])
    audit.last(posture, "credential.set")
    audit.count_lines(posture)
    after = log.read_bytes()
    assert after.startswith(before) and len(after) > len(before)
    # The same file, grown in place: not a copy renamed over it.
    assert log.stat().st_ino == inode
    # Reading back opens it read-only; writing only ever appends.
    for flags in syscalls.open_flags("audit.jsonl"):
        assert flags & os.O_TRUNC == 0
        assert flags & os.O_ACCMODE in (os.O_RDONLY, os.O_WRONLY)
        if flags & os.O_ACCMODE == os.O_WRONLY:
            assert flags & os.O_APPEND
    assert not [event for event, _ in syscalls.named("audit.jsonl")
                if event in ("os.remove", "os.rename")]


def test_last_returns_the_newest_matching_event(posture):
    assert audit.last(posture, "doctor.run") is None
    # Enough records to span several read blocks, so the backwards scan crosses boundaries.
    for n in range(120):
        audit.append(posture, {"event": "doctor.run", "n": n, "pad": "p" * 1500}, argv=[])
        audit.append(posture, {"event": "write", "n": n}, argv=[])
    # A torn or foreign line is skipped, never fatal.
    secure_files.append_locked(posture.state_dir / "audit.jsonl", b"not json at all\n")
    newest = audit.last(posture, "doctor.run")
    assert newest["n"] == 119 and newest["event"] == "doctor.run"
    assert audit.last(posture, "write")["n"] == 119
    assert audit.last(posture, "credential.set") is None
    with pytest.raises(ValueError):
        audit.last(posture, "doctor.runs")


def test_count_lines_counts_every_record(posture):
    assert audit.count_lines(posture) == 0
    for _ in range(3):
        audit.append(posture, {"event": "token.mint"}, argv=[])
    assert audit.count_lines(posture) == 3


def test_no_record_contains_a_registered_secret(posture):
    secret = "test-client-" + 'audit"0007'
    REDACTOR.add_secret(secret)
    audit.append(posture, {"event": "credential.set", "role": "read", "client_id": "kAud1tCNTRL",
                           "note": f"secret {secret}", "nested": {"list": [secret]}},
                 argv=["credentials", "set", secret])
    raw = (posture.state_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert secret not in raw
    assert json.dumps(secret)[1:-1] not in raw
    record = json.loads(raw)
    assert record["note"] == "secret [REDACTED]"
    assert record["nested"] == {"list": ["[REDACTED]"]}
    assert record["client_id"] == "kAud1tCNTRL"


@pytest.mark.parametrize("event", [
    {"event": "writes"}, {"op": "device.tag"}, {"event": "write", "ts": "2020-01-01T00:00:00Z"},
    {"event": "write", "posture": "production"},
])
def test_an_unknown_event_or_a_forged_common_field_is_refused(posture, event):
    with pytest.raises(ValueError):
        audit.append(posture, event, argv=[])
    assert not (posture.state_dir / "audit.jsonl").exists()


def test_an_unsafe_log_is_refused_on_read_back(posture):
    audit.append(posture, {"event": "doctor.run"}, argv=[])
    (posture.state_dir / "audit.jsonl").chmod(0o644)
    for read_back in (lambda: audit.last(posture, "doctor.run"), lambda: audit.count_lines(posture)):
        with pytest.raises(errors.LocalError) as caught:
            read_back()
        assert caught.value.code == "AUDIT_UNWRITABLE"


def test_a_state_directory_that_cannot_be_made_is_audit_unwritable(posture):
    # A regular file where the state directory belongs: the log can never be written.
    posture.state_dir.parent.mkdir(parents=True)
    posture.state_dir.write_bytes(b"")
    with pytest.raises(errors.LocalError) as caught:
        audit.append(posture, {"event": "write"}, argv=[])
    assert caught.value.code == "AUDIT_UNWRITABLE"
    assert str(posture.state_dir) in caught.value.message
