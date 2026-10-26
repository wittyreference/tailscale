# ABOUTME: The only code that opens credential, protected, token and audit files: ssh StrictModes-style
# ABOUTME: refusals on read, atomic 0600 writes, and one-line appends under an exclusive lock.

import fcntl
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path

from tailnet.errors import LocalError

# Every open closes on exec, so no file this module opens can leak into a child process
# (localts runs tailscale). O_NONBLOCK makes opening a FIFO return at once rather than wait
# for a writer; on a regular file it changes nothing.
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_APPEND_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC

# Any group or other bit refuses a file, not only the read bits: a group-writable file can
# be swapped for one an attacker wrote (§8.2 item 4).
_PRIVATE_MASK = 0o077
# A directory only needs its write bits closed: whoever can write it can rename or replace
# the files inside, while reading a listing exposes no contents (§8.2 item 6).
_DIRECTORY_MASK = 0o022


def check_private_stat(st, euid):
    """List why a file with this stat result may not hold a secret; empty means it may.

    Pure, so every rule is testable over a constructed stat result, including ownership by
    another account, which a test cannot arrange for real without root.
    """
    problems = []
    if stat.S_ISLNK(st.st_mode):
        problems.append("it is a symlink")
    elif not stat.S_ISREG(st.st_mode):
        problems.append("it is not a regular file")
    if st.st_uid != euid:
        problems.append(f"owned by uid {st.st_uid}, not you")
    mode = stat.S_IMODE(st.st_mode)
    if mode & _PRIVATE_MASK and not stat.S_ISLNK(st.st_mode):
        problems.append(f"mode {mode:04o} lets group/other access it")
    if st.st_nlink != 1:
        # Another name for the same file is another way in that these checks never see.
        problems.append(f"it has {st.st_nlink} hard links")
    return problems


def _parent_problems(directory, st, euid):
    """List why this directory may not hold private files."""
    if not stat.S_ISDIR(st.st_mode):
        return [f"its directory {directory} is not a directory"]
    problems = []
    if st.st_uid != euid:
        problems.append(f"its directory {directory} is owned by uid {st.st_uid}, not you")
    mode = stat.S_IMODE(st.st_mode)
    if mode & _DIRECTORY_MASK:
        problems.append(f"its directory {directory} has mode {mode:04o}, writable by group/other")
    return problems


def check_parent(path, euid):
    """List why the directory holding `path` may not hold private files; empty means it may."""
    directory = Path(path).parent
    return _parent_problems(directory, os.stat(directory), euid)


def _fixes(path, problems):
    """The commands MC runs to clear the refusals that one command can clear.

    An unsafe mode may already have exposed the secret, so MC is told, not just the agent
    (AE §5): the fix is in MC's hands and so is the decision to revoke.
    """
    path = Path(path)
    steps = []
    if any(p.startswith("mode ") for p in problems):
        steps.append({"who": "mc", "do": f"chmod 600 {path}",
                      "why": "group or other could read or swap it; if anyone else could have "
                             "read it, revoke the client in the console",
                      "needs": "terminal"})
    if any("writable by group/other" in p for p in problems):
        steps.append({"who": "mc", "do": f"chmod go-w {path.parent}",
                      "why": "whoever can write the directory can replace the files in it",
                      "needs": "terminal"})
    return steps


def _refuse(verb, path, problems, code):
    """Build the refusal for a file that failed its checks; it never includes file contents."""
    steps = _fixes(path, problems)
    message = f"refusing to {verb} {path}: " + "; ".join(problems)
    if steps:
        message += "; MC runs: " + " && ".join(step["do"] for step in steps)
    return LocalError(code, message, next=steps)


@contextmanager
def open_private(path, *, max_bytes=None, code="CREDENTIAL_UNSAFE"):
    """Open a private file read-only after the §8.2 checks; yield its descriptor and stat.

    Every check that matters runs on the opened descriptor, and the file is opened relative
    to its already-checked directory, so nothing can be swapped in between check and read.
    A missing file raises FileNotFoundError: what absence means is the caller's to decide.
    Any refusal raises LocalError with `code` and never quotes the file. `max_bytes`, when
    given, refuses a larger file in the same message as any other problem.
    """
    path = Path(path)
    euid = os.geteuid()
    dir_fd = os.open(path.parent, _DIR_FLAGS)
    try:
        problems = _parent_problems(path.parent, os.fstat(dir_fd), euid)
        link_stat = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISREG(link_stat.st_mode):
            # Not opened at all: a symlink could point anywhere, a FIFO could block.
            raise _refuse("read", path, check_private_stat(link_stat, euid) + problems, code)
        try:
            fd = os.open(path.name, _READ_FLAGS, dir_fd=dir_fd)
        except FileNotFoundError:
            # Gone since the lstat: absence is still the caller's to judge.
            raise
        except OSError as exc:
            raise LocalError(code, f"cannot read {path}: {exc.strerror}") from None
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        problems = check_private_stat(st, euid) + problems
        if max_bytes is not None and st.st_size > max_bytes:
            problems.append(f"it is {st.st_size} bytes, over the {max_bytes}-byte limit")
        if problems:
            raise _refuse("read", path, problems, code)
        yield fd, st
    finally:
        os.close(fd)


def read_private(path, max_bytes, *, code="CREDENTIAL_UNSAFE"):
    """Read a private file whole, after the §8.2 checks, and return its bytes.

    The limit is §8.2 item 7's: credentials, token caches and the protected list are all
    small, so a file over its limit is refused rather than read.
    """
    with open_private(path, max_bytes=max_bytes, code=code) as (fd, _):
        data = _read_at_most(fd, max_bytes + 1)
    if len(data) > max_bytes:
        # It grew between fstat and read; the limit holds on what was actually read.
        raise _refuse("read", path, [f"it grew past the {max_bytes}-byte limit"], code)
    return data


def _read_at_most(fd, limit):
    """Read until end of file or `limit` bytes, whichever comes first."""
    chunks, total = [], 0
    while total < limit:
        chunk = os.read(fd, limit - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def write_private_atomic(path, data, *, code="CREDENTIAL_UNSAFE"):
    """Replace `path` with `data` as a 0600 file, all at once (§8.5).

    Readers see the old file or the new one, never a half-written secret: the bytes go to
    an exclusive temp file in the same directory, are synced, and are renamed over the
    target. A directory others can write is refused first, because they could swap the
    file after it lands. On any error the temp file is removed and the error re-raised.
    """
    path = Path(path)
    dir_fd = os.open(path.parent, _DIR_FLAGS)
    try:
        problems = _parent_problems(path.parent, os.fstat(dir_fd), os.geteuid())
        if problems:
            raise _refuse("write", path, problems, code)
        temp = f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        fd = os.open(temp, _CREATE_FLAGS, 0o600, dir_fd=dir_fd)
        try:
            # The create mode is filtered by the umask; fchmod pins the result to 0600.
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(temp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            raise
        # The rename is durable only once the directory entry itself is on disk.
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def append_locked(path, line, *, code="AUDIT_UNWRITABLE"):
    """Append one line to a private log with one write under an exclusive lock (§13.1).

    O_APPEND puts every write at the current end, the lock keeps concurrent CLI processes
    from interleaving, and one write of one whole line means a reader never sees half a
    record. The file is never opened any other way, so nothing here can rewrite history.
    Any failure raises LocalError with `code`: a record that cannot be written is the
    caller's reason to stop.
    """
    if not isinstance(line, bytes):
        raise TypeError("append_locked takes bytes")
    if not line.endswith(b"\n") or line.count(b"\n") != 1:
        raise ValueError("append_locked takes exactly one line, ending in a newline")
    path = Path(path)
    try:
        fd = os.open(path, _APPEND_FLAGS, 0o600)
    except OSError as exc:
        raise LocalError(code, f"cannot append to {path}: {exc.strerror}") from None
    try:
        problems = check_private_stat(os.fstat(fd), os.geteuid())
        if problems:
            raise _refuse("append to", path, problems, code)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            written = os.write(fd, line)
            if written != len(line):
                raise LocalError(code, f"short write to {path}: {written} of {len(line)} bytes")
            os.fsync(fd)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError as exc:
            raise LocalError(code, f"cannot append to {path}: {exc.strerror}") from None
    finally:
        os.close(fd)
