# ABOUTME: Tests for tailnet.secure_files, the only code that opens credential, protected, token and
# ABOUTME: audit files: ssh-style refusals, atomic 0600 writes and locked appends (DESIGN.md §8.2, §8.5, §13.1).

import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tailnet import errors, secure_files

EUID = os.geteuid()
SRC = Path(__file__).resolve().parents[2] / "src"
LIMIT = 4096


def sentinel():
    """File contents a refusal must never echo, assembled at runtime like every fixture secret."""
    return "test-client-" + "sentinel0042"


def private_file(directory, name="read.json", content=None, mode=0o600):
    """Write a file with an exact mode, whatever the umask, and return its path."""
    if content is None:
        content = sentinel()
    if isinstance(content, str):
        content = content.encode()
    path = Path(directory) / name
    path.write_bytes(content)
    path.chmod(mode)
    return path


def refused(path, max_bytes=LIMIT, **kwargs):
    """Read expecting a refusal; return the LocalError."""
    with pytest.raises(errors.LocalError) as caught:
        secure_files.read_private(path, max_bytes, **kwargs)
    return caught.value


def stat_result(mode=stat.S_IFREG | 0o600, nlink=1, uid=EUID, size=10):
    """A constructed stat result, so ownership can be tested without a second account."""
    return os.stat_result((mode, 1, 1, nlink, uid, 0, size, 0, 0, 0))


def test_a_0600_file_owned_by_me_is_read(tmp_path):
    path = private_file(tmp_path, content=b'{"v": 1}\n')
    assert secure_files.read_private(path, LIMIT) == b'{"v": 1}\n'


def test_a_group_readable_file_is_refused_with_the_chmod_fix(tmp_path):
    path = private_file(tmp_path, mode=0o640)
    exc = refused(path)
    assert exc.code == "CREDENTIAL_UNSAFE"
    assert exc.message == (f"refusing to read {path}: mode 0640 lets group/other access it; "
                           f"MC runs: chmod 600 {path}")
    assert len(exc.next) == 1
    step = exc.next[0]
    assert (step["who"], step["do"], step["needs"]) == ("mc", f"chmod 600 {path}", "terminal")
    assert "revoke" in step["why"]


def test_an_other_readable_file_is_refused(tmp_path):
    exc = refused(private_file(tmp_path, mode=0o604))
    assert "mode 0604 lets group/other access it" in exc.message


def test_a_group_writable_file_is_refused(tmp_path):
    # Not readable by the group, but swappable by it, which is as bad for a secret.
    exc = refused(private_file(tmp_path, mode=0o620))
    assert "mode 0620 lets group/other access it" in exc.message


def test_the_caller_names_the_refusal_code(tmp_path):
    exc = refused(private_file(tmp_path, mode=0o644), code="PROTECTED_MALFORMED")
    assert exc.code == "PROTECTED_MALFORMED"


def test_a_symlink_is_refused(tmp_path):
    target = private_file(tmp_path, name="real.json")
    link = tmp_path / "read.json"
    link.symlink_to(target)
    exc = refused(link)
    assert "symlink" in exc.message


def test_a_hard_link_is_refused(tmp_path):
    path = private_file(tmp_path)
    os.link(path, tmp_path / "copy.json")
    exc = refused(path)
    assert "2 hard links" in exc.message


def test_a_fifo_is_refused_without_blocking(tmp_path):
    # Opening a FIFO for reading waits for a writer; a refusal must come back at once.
    fifo = tmp_path / "read.json"
    os.mkfifo(fifo, 0o600)
    assert "not a regular file" in refused(fifo).message


def test_a_file_owned_by_another_uid_is_refused():
    assert secure_files.check_private_stat(stat_result(), EUID) == []
    other = EUID + 1
    assert secure_files.check_private_stat(stat_result(uid=other), EUID) == [
        f"owned by uid {other}, not you"]
    problems = secure_files.check_private_stat(
        stat_result(mode=stat.S_IFREG | 0o644, nlink=3, uid=other), EUID)
    assert problems == [f"owned by uid {other}, not you",
                        "mode 0644 lets group/other access it", "it has 3 hard links"]
    assert secure_files.check_private_stat(stat_result(mode=stat.S_IFLNK | 0o777), EUID)[0] == (
        "it is a symlink")


def as_another_uid(monkeypatch):
    """Have secure_files see an euid that owns nothing here, so real files read as another's.

    The checks compare each owner with os.geteuid() at the moment of the call, so this arranges
    a file and a directory owned by someone else without a second account or root.
    """
    monkeypatch.setattr(secure_files.os, "geteuid", lambda: EUID + 1)


def test_a_file_and_directory_owned_by_another_uid_are_refused_on_read(tmp_path, monkeypatch):
    # The pure check proves the rule; this proves the open path judges the file and its directory
    # against the caller's euid, not against the owner it is looking at (§8.2 items 3 and 6).
    directory = tmp_path / "config"
    directory.mkdir(mode=0o700)
    path = private_file(directory)
    assert secure_files.check_parent(path, EUID + 1) == [
        f"its directory {directory} is owned by uid {EUID}, not you"]
    as_another_uid(monkeypatch)
    exc = refused(path)
    assert exc.code == "CREDENTIAL_UNSAFE"
    assert exc.message == (f"refusing to read {path}: owned by uid {EUID}, not you; "
                           f"its directory {directory} is owned by uid {EUID}, not you")


def test_an_atomic_write_refuses_a_directory_owned_by_another_uid(tmp_path, monkeypatch):
    # Whoever owns the directory can swap the file after it lands, so nothing is written there.
    path = private_file(tmp_path, name="read.secret", content=b"old")
    as_another_uid(monkeypatch)
    with pytest.raises(errors.LocalError) as caught:
        secure_files.write_private_atomic(path, b"new")
    assert caught.value.code == "CREDENTIAL_UNSAFE"
    assert f"its directory {tmp_path} is owned by uid {EUID}, not you" in caught.value.message
    assert path.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["read.secret"]


@pytest.mark.parametrize("call", [
    lambda log: secure_files.append_locked(log, b"{}\n"),
    lambda log: secure_files.check_appendable(log),
], ids=["append_locked", "check_appendable"])
def test_a_log_owned_by_another_uid_is_refused_and_left_as_it_was(tmp_path, monkeypatch, call):
    # A log another account owns could be swapped or read back with planted lines (A11).
    log = private_file(tmp_path, name="audit.jsonl", content=b"keep\n")
    as_another_uid(monkeypatch)
    with pytest.raises(errors.LocalError) as caught:
        call(log)
    assert caught.value.code == "AUDIT_UNWRITABLE"
    assert caught.value.message == f"refusing to append to {log}: owned by uid {EUID}, not you"
    assert log.read_bytes() == b"keep\n"


def test_a_group_writable_parent_directory_is_refused(tmp_path):
    directory = tmp_path / "config"
    directory.mkdir()
    path = private_file(directory)
    directory.chmod(0o770)
    exc = refused(path)
    assert f"its directory {directory} has mode 0770, writable by group/other" in exc.message
    assert {"who": "mc", "do": f"chmod go-w {directory}", "needs": "terminal"}.items() <= (
        exc.next[0].items())
    assert secure_files.check_parent(path, EUID) == [
        f"its directory {directory} has mode 0770, writable by group/other"]
    # Only write bits matter for the directory: reading a listing cannot swap a file.
    directory.chmod(0o750)
    assert secure_files.read_private(path, LIMIT) == sentinel().encode()
    assert secure_files.check_parent(path, EUID) == []


def test_an_oversized_file_is_refused(tmp_path):
    exact = private_file(tmp_path, name="exact.json", content=b"x" * LIMIT)
    assert len(secure_files.read_private(exact, LIMIT)) == LIMIT
    exc = refused(private_file(tmp_path, content=b"x" * (LIMIT + 1)))
    assert f"over the {LIMIT}-byte limit" in exc.message


def test_a_missing_file_is_left_to_the_caller(tmp_path):
    # Absence means different things to different callers: no credential, an unanswered
    # protected list, a token to mint. So it is not a refusal here.
    with pytest.raises(FileNotFoundError):
        secure_files.read_private(tmp_path / "read.json", LIMIT)
    with pytest.raises(FileNotFoundError):
        secure_files.read_private(tmp_path / "absent" / "read.json", LIMIT)


def test_atomic_write_is_0600_under_umask_000(tmp_path):
    path = private_file(tmp_path, content=b"old", mode=0o644)
    old_umask = os.umask(0)
    try:
        secure_files.write_private_atomic(path, b"new contents\n")
    finally:
        os.umask(old_umask)
    assert path.read_bytes() == b"new contents\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["read.json"]


def test_atomic_write_replaces_by_rename_through_an_exclusive_temp_file(tmp_path, syscalls):
    path = tmp_path / "read.secret"
    secure_files.write_private_atomic(path, b"s\n")
    creates = [args for event, args in syscalls.events
               if event == "open" and isinstance(args[0], str) and args[0] != str(tmp_path)]
    assert len(creates) == 1
    flags = creates[0][2]
    for flag in (os.O_WRONLY, os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW):
        assert flags & flag == flag
    renames = [args for event, args in syscalls.events if event == "os.rename"]
    assert [(src, dst) for src, dst, *_ in renames] == [(creates[0][0], "read.secret")]


def test_atomic_write_leaves_no_partial_file_on_error(tmp_path):
    # A real failure after the temp file is written: the target is a directory, so the
    # final rename cannot replace it.
    (tmp_path / "read.json").mkdir()
    with pytest.raises(OSError):
        secure_files.write_private_atomic(tmp_path / "read.json", b"data")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["read.json"]
    # A failure mid-write leaves the old file exactly as it was.
    path = private_file(tmp_path, name="read.secret", content=b"old")
    with pytest.raises(TypeError):
        secure_files.write_private_atomic(path, "text, not bytes")
    assert path.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["read.json", "read.secret"]


def test_an_atomic_write_told_not_to_replace_leaves_an_existing_file_alone(tmp_path):
    # `policy get --out` must never replace a file (A68): the whole file still lands at once,
    # but by a link that fails when the name is taken, so a file made after any check survives.
    path = private_file(tmp_path, name="authorized_keys", content=b"ssh-ed25519 AAAA mc\n")
    with pytest.raises(FileExistsError):
        secure_files.write_private_atomic(path, b"// policy\n", replace=False)
    assert path.read_bytes() == b"ssh-ed25519 AAAA mc\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["authorized_keys"]
    fresh = tmp_path / "policy.hujson"
    secure_files.write_private_atomic(fresh, b"// policy\n", replace=False)
    assert fresh.read_bytes() == b"// policy\n" and stat.S_IMODE(fresh.stat().st_mode) == 0o600
    assert fresh.stat().st_nlink == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["authorized_keys", "policy.hujson"]


def test_atomic_write_refuses_a_directory_others_can_write(tmp_path):
    directory = tmp_path / "config"
    directory.mkdir(mode=0o700)
    directory.chmod(0o777)
    with pytest.raises(errors.LocalError) as caught:
        secure_files.write_private_atomic(directory / "read.secret", b"s")
    assert caught.value.code == "CREDENTIAL_UNSAFE"
    assert list(directory.iterdir()) == []


def calls_during(action, *watched):
    """Run `action` and return the watched builtins it called, in order, by name.

    sys.setprofile reports each call of a C function from Python code, which is how a test
    can count os.write calls without replacing os.write.
    """
    names = {id(fn): f"{fn.__module__}.{fn.__name__}" for fn in watched}
    seen = []

    def profile(frame, event, arg):
        if event == "c_call" and id(arg) in names:
            seen.append(names[id(arg)])

    sys.setprofile(profile)
    try:
        action()
    finally:
        sys.setprofile(None)
    return seen


def test_append_is_one_write_under_an_exclusive_lock(tmp_path, syscalls):
    log = tmp_path / "audit.jsonl"
    line = b'{"event": "write"}\n'
    calls = calls_during(lambda: secure_files.append_locked(log, line),
                         os.write, os.fsync, fcntl.flock)
    assert calls == ["fcntl.flock", "posix.write", "posix.fsync", "fcntl.flock"]
    locks = [args[1] for event, args in syscalls.events if event == "fcntl.flock"]
    assert locks == [fcntl.LOCK_EX, fcntl.LOCK_UN]
    assert log.read_bytes() == line

    # A lock held elsewhere holds the append back until it is released.
    holder = os.open(log, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    failures = []

    def append():
        try:
            secure_files.append_locked(log, line)
        except Exception as exc:  # noqa: BLE001 - reported to the test below
            failures.append(exc)

    worker = threading.Thread(target=append)
    try:
        worker.start()
        worker.join(timeout=0.3)
        assert worker.is_alive()
        assert log.read_bytes() == line
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
        worker.join(timeout=5)
    assert failures == []
    assert log.read_bytes() == line * 2


def test_append_opens_append_only_without_following_links(tmp_path, syscalls):
    log = tmp_path / "audit.jsonl"
    secure_files.append_locked(log, b"{}\n")
    [flags] = syscalls.open_flags("audit.jsonl")
    for flag in (os.O_WRONLY, os.O_APPEND, os.O_CREAT, os.O_NOFOLLOW, os.O_CLOEXEC):
        assert flags & flag == flag
    assert flags & (os.O_TRUNC | os.O_RDWR) == 0
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_append_refuses_a_symlinked_or_shared_log(tmp_path):
    elsewhere = private_file(tmp_path, name="elsewhere", content=b"keep\n")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(elsewhere)
    with pytest.raises(errors.LocalError) as caught:
        secure_files.append_locked(link, b"{}\n")
    assert caught.value.code == "AUDIT_UNWRITABLE"
    assert elsewhere.read_bytes() == b"keep\n"
    link.unlink()
    shared = private_file(tmp_path, name="audit.jsonl", content=b"", mode=0o666)
    with pytest.raises(errors.LocalError) as caught:
        secure_files.append_locked(shared, b"{}\n")
    assert "mode 0666" in caught.value.message
    assert shared.read_bytes() == b""


@pytest.mark.parametrize("line", [b"no newline", b"two\nlines\n", "text\n"])
def test_append_takes_exactly_one_line_of_bytes(tmp_path, line):
    with pytest.raises((ValueError, TypeError)):
        secure_files.append_locked(tmp_path / "audit.jsonl", line)
    assert not (tmp_path / "audit.jsonl").exists()


APPENDER = """
import json, sys
from tailnet import secure_files
path, worker, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
for n in range(count):
    record = {"worker": worker, "n": n, "pad": worker * 6000}
    secure_files.append_locked(path, (json.dumps(record) + "\\n").encode())
"""


def test_concurrent_appends_never_interleave(tmp_path):
    log = tmp_path / "audit.jsonl"
    workers, count = "abcd", 150
    env = {"PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")}
    procs = [subprocess.Popen([sys.executable, "-c", APPENDER, str(log), w, str(count)], env=env)
             for w in workers]
    assert [proc.wait(timeout=60) for proc in procs] == [0] * len(workers)
    lines = log.read_bytes().split(b"\n")
    assert lines.pop() == b""
    records = [json.loads(line) for line in lines]
    assert len(records) == len(workers) * count
    for worker in workers:
        mine = [r["n"] for r in records if r["worker"] == worker]
        assert mine == list(range(count))
        assert all(r["pad"] == worker * 6000 for r in records if r["worker"] == worker)


def test_error_messages_never_contain_file_contents(tmp_path):
    cases = []
    cases.append(private_file(tmp_path, name="mode.json", mode=0o644))
    cases.append(private_file(tmp_path, name="big.json",
                              content=sentinel() + "x" * LIMIT))
    linked = private_file(tmp_path, name="linked.json")
    os.link(linked, tmp_path / "linked-copy.json")
    cases.append(linked)
    target = private_file(tmp_path, name="target.json")
    (tmp_path / "symlink.json").symlink_to(target)
    cases.append(tmp_path / "symlink.json")
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    cases.append(private_file(shared_dir))
    shared_dir.chmod(0o777)
    for path in cases:
        exc = refused(path)
        assert sentinel() not in str(exc), path
        assert sentinel() not in json.dumps(exc.next), path


def test_a_parent_that_is_not_a_directory_is_refused_not_a_crash(tmp_path):
    # A file where the config directory belongs: refused with the caller's code, rather
    # than escaping as an OSError the CLI would report as a bug.
    blocker = private_file(tmp_path, name="config")
    exc = refused(blocker / "read.json")
    assert exc.code == "CREDENTIAL_UNSAFE"
    assert str(blocker / "read.json") in exc.message


INTERRUPTED = """
import os, signal, sys
from tailnet import secure_files

def interrupt(event, args):
    # The signal arrives after the secret is in its temp file, before the rename: SIGHUP
    # when the SSH session from MC's phone drops, and the kernel ends the process at once.
    if event == "os.rename" and str(args[0]).endswith(".tmp"):
        os.kill(os.getpid(), getattr(signal, sys.argv[2]))

sys.addaudithook(interrupt)
secure_files.write_private_atomic(sys.argv[1], b"held-until-renamed\\n")
"""


@pytest.mark.parametrize("signame", ["SIGHUP", "SIGTERM", "SIGKILL"])
def test_a_signal_between_writing_and_renaming_never_strands_an_unfound_copy(tmp_path, signame):
    target = tmp_path / "write.secret"
    env = {"PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "")}
    child = subprocess.run([sys.executable, "-c", INTERRUPTED, str(target), signame], env=env,
                           capture_output=True, timeout=60, check=False)
    assert child.returncode == -getattr(signal, signame), child.stderr
    if signame != "SIGKILL":
        # Held back until the rename: the process still ends, but with the file whole.
        assert [path.name for path in tmp_path.iterdir()] == ["write.secret"]
        assert target.read_bytes() == b"held-until-renamed\n"
        return
    # SIGKILL cannot be held: the copy stays under its temp name, and is found by that name.
    [left] = secure_files.temp_leftovers(target)
    assert [path.name for path in tmp_path.iterdir()] == [left.name]
    assert left.read_bytes() == b"held-until-renamed\n"
    assert secure_files.remove_temp_leftovers(target) == [left.name]
    assert list(tmp_path.iterdir()) == []


def test_a_log_can_be_checked_for_appending_without_writing_to_it(tmp_path, syscalls):
    # C9: the write flow asks before it sends whether its one line will have somewhere to go.
    log = tmp_path / "audit.jsonl"
    secure_files.check_appendable(log)
    [flags] = syscalls.open_flags("audit.jsonl")
    assert flags & (os.O_APPEND | os.O_NOFOLLOW) == os.O_APPEND | os.O_NOFOLLOW
    assert flags & (os.O_TRUNC | os.O_RDWR) == 0
    assert log.read_bytes() == b"" and stat.S_IMODE(log.stat().st_mode) == 0o600
    log.chmod(0o644)
    with pytest.raises(errors.LocalError) as caught:
        secure_files.check_appendable(log)
    assert caught.value.code == "AUDIT_UNWRITABLE" and "mode 0644" in caught.value.message


def bounded(call, unblock, seconds=5):
    """Run `call` in a thread; return (what it raised, whether it had to be unblocked).

    A regression here would hang the suite, so a call still running after `seconds` is
    released by `unblock` and reported, rather than waited on forever.
    """
    raised = []

    def attempt():
        """Keep whatever the call raised for the test thread to judge."""
        try:
            call()
        except BaseException as exc:  # noqa: BLE001 - every outcome goes back to the test
            raised.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(seconds)
    hung = worker.is_alive()
    if hung:
        unblock()
        worker.join(seconds)
    return raised, hung


@pytest.mark.parametrize("call", [
    lambda log: secure_files.append_locked(log, b"{}\n"),
    lambda log: secure_files.check_appendable(log),
], ids=["append_locked", "check_appendable"])
def test_a_fifo_at_the_log_path_is_refused_without_waiting_for_a_reader(tmp_path, call):
    # Opening a FIFO for writing waits for a reader, before the regular-file check can run:
    # every token mint, forget and --apply (C9) would hang on one planted at the log path.
    log = tmp_path / "audit.jsonl"
    os.mkfifo(log, 0o600)
    readers = []

    def unblock():
        """Open the read end, which lets a blocked writer's open return."""
        readers.append(os.open(log, os.O_RDONLY | os.O_NONBLOCK))

    try:
        raised, hung = bounded(lambda: call(log), unblock)
    finally:
        for fd in readers:
            os.close(fd)
    assert not hung, "opening the log waited for a FIFO reader"
    [exc] = raised
    assert isinstance(exc, errors.LocalError) and exc.code == "AUDIT_UNWRITABLE"
    assert "not a regular file" in exc.message


def test_the_apply_lock_is_exclusive_and_never_waits(tmp_path):
    lock = tmp_path / "apply.lock"
    with secure_files.lock_exclusive(lock, code="AUDIT_UNWRITABLE"):
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
        # A second holder is told at once rather than queued behind the first (LOCK_NB).
        with pytest.raises(secure_files.Busy), \
                secure_files.lock_exclusive(lock, code="AUDIT_UNWRITABLE"):
            pass
        # Another process sees it held too: flock locks are shared through the file, not the fd.
        probe = ("import fcntl, os, sys\n"
                 "fd = os.open(sys.argv[1], os.O_RDWR)\n"
                 "try:\n"
                 "    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                 "except BlockingIOError:\n"
                 "    sys.exit(7)\n")
        held = subprocess.run([sys.executable, "-I", "-c", probe, str(lock)], check=False)
        assert held.returncode == 7
    # Released on exit, so the next apply may take it.
    with secure_files.lock_exclusive(lock, code="AUDIT_UNWRITABLE"):
        pass


def test_the_apply_lock_never_follows_a_symlink(tmp_path):
    target = private_file(tmp_path, name="elsewhere", content=b"keep\n")
    (tmp_path / "apply.lock").symlink_to(target)
    with pytest.raises(errors.LocalError) as caught, \
            secure_files.lock_exclusive(tmp_path / "apply.lock", code="AUDIT_UNWRITABLE"):
        pass
    assert caught.value.code == "AUDIT_UNWRITABLE"
    assert target.read_bytes() == b"keep\n"


def test_a_plain_read_takes_any_mode_but_never_a_symlink_a_fifo_or_too_much(tmp_path):
    # A policy draft or a file the agent names holds no secret, so its mode is not checked:
    # an editor may rewrite it with another one. Reading it must still be safe: nothing
    # behind a symlink, nothing that blocks or never ends, nothing larger than the limit.
    path = private_file(tmp_path, "policy.hujson", "{}", mode=0o644)
    assert secure_files.read_regular(path, 2) == b"{}"
    link = tmp_path / "link.hujson"
    link.symlink_to(path)
    fifo = tmp_path / "fifo.hujson"
    os.mkfifo(fifo, 0o600)
    for target, why in ((link, "it is a symlink"), (fifo, "it is not a regular file"),
                        (tmp_path, "it is not a regular file"),
                        (path, "it is 2 bytes, over the 1-byte limit")):
        with pytest.raises(secure_files.Unreadable) as caught:
            secure_files.read_regular(target, 1 if target == path else 10)
        assert str(caught.value) == why
    with pytest.raises(FileNotFoundError):
        secure_files.read_regular(tmp_path / "missing.hujson", 10)
