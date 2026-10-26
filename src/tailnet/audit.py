# ABOUTME: The local JSONL audit log: one redacted line per write attempt, mint, credential change and
# ABOUTME: doctor run, appended only, and read back newest first for doctor's settled answers (§13).

import json
import os
import pwd
import socket
import sys
from datetime import datetime, timezone

from tailnet import __version__, secure_files
from tailnet.errors import LocalError
from tailnet.redact import redact

# §13.2. A record under any other name would be one no reader looks for, so a typo is
# refused rather than written.
EVENTS = frozenset({"write", "token.mint", "credential.set", "credential.forget", "doctor.run"})

# Fields every record carries, in this order (§13.3). An event may not supply its own
# value for one: a forged time or posture would make the narrative lie.
COMMON_FIELDS = ("v", "ts", "event", "cli_version", "posture", "host", "user", "pid", "argv")

# Every failure to use the log is reported under this code: a log that cannot be read back
# safely fails the same checks that stop it being written (§5.5).
_CODE = "AUDIT_UNWRITABLE"
_BLOCK = 64 * 1024


def log_path(posture):
    """Where this posture's audit log lives: the state directory, outside every repository."""
    return posture.state_dir / "audit.jsonl"


def _timestamp():
    """The record time in UTC to the millisecond, so records within one second still order."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def append(posture, event, *, argv=None):
    """Append one record for `event` (a dict naming its "event") to the posture's log.

    The common fields come first, then the event's own. The whole serialised line is
    redacted before it is written, so no record can hold a registered secret or a
    secret-shaped string, whichever field it arrived in. `argv` defaults to this process's
    command line. Raises LocalError(AUDIT_UNWRITABLE) when the line cannot be written.
    """
    name = event.get("event")
    if name not in EVENTS:
        raise ValueError(f"{name!r} is not an audit event (DESIGN.md §13.2)")
    forged = [field for field in COMMON_FIELDS if field in event and field != "event"]
    if forged:
        raise ValueError(f"an event may not set the common fields {forged}")
    record = {
        "v": 1, "ts": _timestamp(), "event": name, "cli_version": __version__,
        "posture": posture.kind, "host": socket.gethostname(),
        "user": pwd.getpwuid(os.geteuid()).pw_name, "pid": os.getpid(),
        "argv": list(sys.argv[1:] if argv is None else argv),
    }
    record.update((key, value) for key, value in event.items() if key != "event")
    # json.dumps escapes newlines inside strings, so the record is one line however its
    # fields were typed.
    line = redact(json.dumps(record)) + "\n"
    state_dir(posture)
    secure_files.append_locked(log_path(posture), line.encode("utf-8"), code=_CODE)


def state_dir(posture):
    """The posture's state directory, made 0700 if it is missing; the log and apply lock live here.

    Parent directories get the default mode; the state directory itself is 0700 (§13.1), and
    a umask can only narrow that.
    """
    try:
        posture.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        # The same answer as a log that will not open: a write that cannot be recorded is
        # not sent (C9), whichever part of the path is in the way.
        raise LocalError(_CODE, f"cannot create {posture.state_dir}: {exc.strerror}") from None
    return posture.state_dir


def check_writable(posture):
    """C9: show the log would take a line now, without writing one; AUDIT_UNWRITABLE if not.

    The write flow asks this before it sends anything, so a write is never sent that the
    narrative could not record (§12.2, invariant 6).
    """
    state_dir(posture)
    secure_files.check_appendable(log_path(posture), code=_CODE)


def _lines_newest_first(fd, size):
    """Yield the file's lines from the last to the first, reading backwards in blocks.

    The log only grows, and the answer wanted is almost always near its end, so reading
    from the end keeps a years-old log cheap to consult.
    """
    position, carry = size, b""
    while position > 0:
        start = max(0, position - _BLOCK)
        block = os.pread(fd, position - start, start) + carry
        position = start
        lines = block.split(b"\n")
        # The first piece may be the end of a line that starts in an earlier block.
        carry = lines.pop(0)
        for line in reversed(lines):
            if line:
                yield line
    if carry:
        yield carry


def last(posture, event_name):
    """Return the newest record of `event_name`, or None when there is none.

    Lines that do not parse (a torn write, a hand edit) are skipped: the narrative is
    consulted, never trusted to be well formed. Doctor reads its settled answers this way
    instead of keeping a second state file (D3).
    """
    if event_name not in EVENTS:
        raise ValueError(f"{event_name!r} is not an audit event (DESIGN.md §13.2)")
    try:
        with secure_files.open_private(log_path(posture), code=_CODE) as (fd, st):
            for line in _lines_newest_first(fd, st.st_size):
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, ValueError):
                    continue
                if isinstance(record, dict) and record.get("event") == event_name:
                    return record
    except FileNotFoundError:
        return None
    return None


def count_lines(posture):
    """Count the records in the log; a log not yet written has none."""
    try:
        with secure_files.open_private(log_path(posture), code=_CODE) as (fd, _):
            count = 0
            while True:
                block = os.read(fd, _BLOCK)
                if not block:
                    return count
                count += block.count(b"\n")
    except FileNotFoundError:
        return 0
