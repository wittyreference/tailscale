# ABOUTME: Tests for tailnet.secure_files, the only code that opens credential, protected, token and
# ABOUTME: audit files: ssh-style refusals, atomic 0600 writes and locked appends (DESIGN.md §8.2, §8.5, §13.1).

import fcntl
import json
import os
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
