# ABOUTME: Tests for tailnet.dns's local half: this host's accept-dns and MagicDNS lookup are read only in
# ABOUTME: production, a missing binary is reported rather than fatal, and a failure's cause is never asserted.

import pytest

from tailnet import dns, localts
from tailnet.posture import Posture


def test_lookup_reports_the_addresses_a_name_resolves_to():
    # localhost is answered from the hosts file, never over the network, so this is a real
    # lookup that stays on the box.
    resolves, addresses, error = dns.lookup("localhost")
    assert (resolves, error) == (True, None)
    assert set(addresses) & {"127.0.0.1", "::1"}
    # A failing lookup is only reachable through a resolver, which netguard keeps off the
    # box; the warning it leads to is tested from a constructed view below.


def test_the_local_view_is_not_run_in_test_posture(tmp_path, syscalls):
    posture = Posture.from_env({"TAILNET_API_BASE": "http://127.0.0.1:9",
                                "TAILNET_HOME": str(tmp_path / "tn")}, real_home=tmp_path / "r")
    assert dns.local_view(posture) == {"accept_dns": None, "self_dnsname": None,
                                       "resolves": None, "addresses": [],
                                       "error": "not run: test posture"}
    assert syscalls.processes() == []


def test_production_without_tailscale_reports_why_once_and_looks_nothing_up(tmp_path, monkeypatch,
                                                                           syscalls):
    monkeypatch.setattr(localts, "PREFERRED", str(tmp_path / "no" / "tailscale"))
    monkeypatch.setenv("PATH", str(tmp_path))
    view = dns.local_view(Posture.from_env({}, real_home=tmp_path / "home"))
    assert (view["accept_dns"], view["self_dnsname"], view["resolves"]) == (None, None, None)
    assert view["error"].startswith("TAILSCALE_CLI_MISSING")
    # Both local reads fail for the one reason, which is said once.
    assert view["error"].count("TAILSCALE_CLI_MISSING") == 1
    assert syscalls.processes() == []


@pytest.mark.parametrize("accept_dns,mentioned", [(False, True), (True, False), (None, False)])
def test_an_unresolved_name_names_accept_dns_off_without_claiming_it_is_the_cause(accept_dns,
                                                                                mentioned):
    view = {"accept_dns": accept_dns, "self_dnsname": "claude-factory.tail0000.ts.net.",
            "resolves": False, "addresses": [], "error": "gaierror: no such name"}
    code, message, source = dns.unresolved_warning(view)
    assert (code, source) == ("MAGICDNS_UNRESOLVED", "critic F3.6")
    assert "claude-factory.tail0000.ts.net." in message
    # accept-dns=false is a documented reason a node ignores the tailnet's DNS; whether it
    # is this failure's cause is an inference, so the message says it is not established.
    assert ("accept-dns is false" in message) is mentioned
    if mentioned:
        assert "not established" in message
    assert dns.unresolved_warning({**view, "resolves": True}) is None
    assert dns.unresolved_warning({**view, "resolves": None}) is None
