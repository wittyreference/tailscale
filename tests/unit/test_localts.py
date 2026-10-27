# ABOUTME: Tests for tailnet.localts, the only code that runs the tailscale binary: it refuses in test
# ABOUTME: posture before any process starts, finds no binary loudly, and composes each command exactly.

import sys

import pytest

from tailnet import errors, localts
from tailnet.posture import Posture


@pytest.fixture
def test_posture(tmp_path):
    """Test posture: tailscale is never run here (§7.1)."""
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    return Posture.from_env(environ, real_home=tmp_path / "real")


@pytest.fixture
def production(tmp_path, monkeypatch):
    """Production posture on a machine where no tailscale binary can be found.

    The packaged path points at a file that does not exist and PATH holds one empty
    directory, so the real lookup runs and finds nothing; no stand-in binary is involved.
    """
    empty = tmp_path / "bin"
    empty.mkdir()
    monkeypatch.setattr(localts, "PREFERRED", str(tmp_path / "usr-bin" / "tailscale"))
    monkeypatch.setenv("PATH", str(empty))
    return Posture.from_env({}, real_home=tmp_path / "home")


CALLS = [
    ("status_json", lambda p: localts.status_json(p, timeout=3)),
    ("ping", lambda p: localts.ping(p, "100.64.0.11", "tsmp", timeout=3)),
    ("get_pref", lambda p: localts.get_pref(p, "accept-dns", timeout=3)),
    ("version", lambda p: localts.version(p, timeout=3)),
]


@pytest.mark.parametrize("name,call", CALLS)
def test_every_call_refuses_in_test_posture_before_any_process_starts(test_posture, syscalls,
                                                                      name, call):
    with pytest.raises(localts.NotInTestPosture, match="test posture"):
        call(test_posture)
    assert syscalls.processes() == []


@pytest.mark.parametrize("name,call", CALLS)
def test_a_missing_binary_is_tailscale_cli_missing(production, syscalls, name, call):
    assert localts.binary() is None
    with pytest.raises(errors.LocalError) as caught:
        call(production)
    assert (caught.value.exit, caught.value.code) == (3, "TAILSCALE_CLI_MISSING")
    assert syscalls.processes() == []


def test_the_packaged_binary_is_preferred_over_any_on_path(production, monkeypatch):
    # /usr/bin/tailscale wins when it is an executable file, so a tailscale planted earlier
    # on PATH is never the one run (§11.3). The interpreter stands in for an executable file
    # that exists; nothing here runs it.
    monkeypatch.setattr(localts, "PREFERRED", sys.executable)
    assert localts.binary() == sys.executable


def test_commands_are_composed_exactly():
    assert localts.ping_args("100.64.0.11", "tsmp", 3) == [
        "ping", "--tsmp", "--c=1", "--timeout=3s", "100.64.0.11"]
    assert localts.ping_args("fd7a:115c:a1e0::b", "icmp", 5) == [
        "ping", "--icmp", "--c=1", "--timeout=5s", "fd7a:115c:a1e0::b"]
    assert localts.pref_args("accept-dns") == ["get", "accept-dns"]


@pytest.mark.parametrize("ip,kind,timeout", [
    ("spec5", "tsmp", 3),                 # a name: the probe ladder addresses by IP only
    ("100.64.0.11; reboot", "tsmp", 3),
    ("100.64.0.11", "disco", 3),          # only the two kinds §15 uses
    ("100.64.0.11", "tsmp", 0),
    ("100.64.0.11", "tsmp", "3s"),
])
def test_a_ping_with_anything_but_an_address_kind_and_whole_seconds_is_refused(ip, kind,
                                                                              timeout):
    with pytest.raises(ValueError):
        localts.ping_args(ip, kind, timeout)


@pytest.mark.parametrize("name", ["", "Accept-DNS", "accept dns", "--json", "all;id"])
def test_a_preference_name_is_one_lowercase_flag_name(name):
    with pytest.raises(ValueError):
        localts.pref_args(name)
