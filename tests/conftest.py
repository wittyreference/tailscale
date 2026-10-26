# ABOUTME: Shared pytest setup: installs netguard in the test process before any test runs, and
# ABOUTME: provides the loopback API seam as a fixture that fails its test on any unrouted request.

import netguard
import pytest
from loopback import Loopback

# Installed at import, before collection, so no test module can open a socket or start a
# process ahead of the guard (DESIGN.md §21.1).
netguard.install()


@pytest.fixture
def loopback():
    """A running loopback API seam. Teardown fails the test if any request went unanswered."""
    with Loopback() as server:
        yield server
    assert server.unexpected == [], f"loopback requests the test did not route: {server.unexpected}"
