# ABOUTME: Shared pytest setup: installs netguard in the test process before any test runs, and
# ABOUTME: provides the loopback API seam and a recorder of the real file syscalls code makes.

import os
import sys

import netguard
import pytest
from loopback import Loopback

# Installed at import, before collection, so no test module can open a socket or start a
# process ahead of the guard (DESIGN.md §21.1).
netguard.install()


class Syscalls:
    """The audited file calls made while one test runs, in order, as (event, args) pairs.

    Python raises an audit event for os.open ("open", with the flags), fcntl.flock, unlink,
    rename and every way of starting a process. Recording them lets a test check how a file
    was really opened, locked and removed (append-only, no follow, secret before metadata),
    and that a code path started no program, without replacing any of it.
    """

    # The events that start another program, whichever way it is started.
    PROCESS_EVENTS = frozenset({"subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn",
                                "os.system"})
    WATCHED = frozenset({"open", "fcntl.flock", "os.remove", "os.rename"}) | PROCESS_EVENTS

    def __init__(self):
        self.events = []

    def named(self, basename):
        """Every recorded event whose path, or either rename path, ends in `basename`."""
        hits = []
        for event, args in self.events:
            paths = args[:2] if event == "os.rename" else args[:1]
            if any(isinstance(p, (str, bytes)) and os.path.basename(os.fsdecode(p)) == basename
                   for p in paths):
                hits.append((event, args))
        return hits

    def processes(self):
        """Every attempt to start a program, in order: proof a code path ran nothing."""
        return [(event, args) for event, args in self.events if event in self.PROCESS_EVENTS]

    def open_flags(self, basename):
        """The flags of every os.open of a file with this basename, in order."""
        return [args[2] for event, args in self.named(basename) if event == "open"]


_RECORDERS = []


def _record(event, args):
    """Feed watched audit events to every recorder a running test holds."""
    # Audit hooks cannot be removed, so this one stays installed for the whole run and
    # does nothing while no test is recording.
    if event in Syscalls.WATCHED:
        for recorder in _RECORDERS:
            recorder.events.append((event, args))


sys.addaudithook(_record)


@pytest.fixture
def syscalls():
    """A Syscalls recorder that is live for the duration of the test."""
    recorder = Syscalls()
    _RECORDERS.append(recorder)
    yield recorder
    _RECORDERS.remove(recorder)


@pytest.fixture
def loopback():
    """A running loopback API seam. Teardown fails the test if any request went unanswered."""
    with Loopback() as server:
        yield server
    assert server.unexpected == [], f"loopback requests the test did not route: {server.unexpected}"
