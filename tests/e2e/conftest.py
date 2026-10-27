# ABOUTME: e2e harness: before any test, stops the run with exit 3 naming every missing piece, never a skip;
# ABOUTME: then runs the repo CLI live through run_live.py and puts each run's time and request IDs in the report.

import os
import re

import preflight
import pytest
import run_live

from tailnet.posture import Posture

# The human view ends its verdict line with this (§5.4), so a run without --json still has a time.
_AS_OF = re.compile(r"\(as of (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\)")


@pytest.fixture(scope="session", autouse=True)
def droplet():
    """Stop the whole suite, exit 3, unless this is the droplet with MC's read credential (§21.4).

    A skip would read as green to someone glancing at a phone, and a suite that cannot reach
    the real API proves nothing, so a missing piece ends the run loudly instead. The netguard
    from tests/conftest.py still holds this process: every live call happens in a child.
    """
    found = preflight.problems(os.environ, read_status=lambda: run_live.run(["status"]).envelope)
    if found:
        pytest.exit(preflight.message(found), returncode=3)


@pytest.fixture(scope="session")
def production(droplet):
    """The production posture the live CLI runs in, for reading MC's audit log and statting files.

    Decided after the preflight, so no test-posture override can be in the environment.
    """
    return Posture.from_env(os.environ)


@pytest.fixture(scope="session")
def doctor_report(droplet):
    """One `tailnet doctor --settle --json` for the whole suite (E1, E14).

    `--settle` re-measures the steps that cost MC console events (a mint, S5's deliberate
    "Failed request"), so the suite runs it once rather than once per test that reads it.
    """
    return run_live.run(["doctor", "--settle"])


def note(node, label, value):
    """Add one measurement to a test's report: what ran, and when it was measured."""
    node.user_properties.append((label, value))


def note_run(node, run):
    """Record a live run's exit, measured_at and request IDs (§21.4: every test records them)."""
    env = run.envelope or {}
    at = env.get("measured_at")
    if at is None:
        found = _AS_OF.search(run.stdout + run.stderr)
        at = found.group(1) if found else "not shown"
    ids = ", ".join(env.get("request_ids") or []) or "none"
    note(node, run.label, f"exit {run.exit} · measured_at {at} · request_ids {ids}")


@pytest.fixture
def live(request):
    """Run `tailnet ARGS --json` live and record it; `json_mode=False` keeps the human output."""
    def call(*args, **kwargs):
        """One live run, recorded in this test's report."""
        done = run_live.run(list(args), **kwargs)
        note_run(request.node, done)
        return done

    return call


@pytest.fixture
def record_run(request):
    """Record a run made outside this test, such as the suite's one doctor run."""
    return lambda run: note_run(request.node, run)


@pytest.fixture
def measure(request):
    """Record a measurement that is not a CLI envelope (a ping, an install) in the report."""
    return lambda label, value: note(request.node, label, value)


def pytest_terminal_summary(terminalreporter):
    """Print every test's measurements at the end, so MC can quote each value with its time."""
    rows = {}
    for reports in terminalreporter.stats.values():
        for report in reports:
            properties = getattr(report, "user_properties", None)
            if properties:
                rows[report.nodeid] = list(properties)
    if not rows:
        return
    terminalreporter.section("e2e measurements: each run's time and request IDs")
    for nodeid, properties in rows.items():
        terminalreporter.write_line(nodeid)
        for label, value in properties:
            terminalreporter.write_line(f"  {label}: {value}")
