# ABOUTME: Tests for diagnose's pure half: the verdict ladder of DESIGN.md §15 row by row, the source
# ABOUTME: identities, the in-memory ssh candidate, and the TCP probe over real loopback sockets.

import argparse
import contextlib
import json
import socket
import sys
import threading
from dataclasses import replace

import pytest
from fixturefiles import body, raw_text

from tailnet import devices, diagnose
from tailnet.diagnose import Facts
from tailnet.errors import UsageError

# A destination every gate lets through, reached from a tagged source by IPv4 on port 22.
OPEN_ROAD = Facts(mode="self", port=22, source_tagged=True, online=True, key_expired=False,
                  blocks_incoming=False)
FROM = replace(OPEN_ROAD, mode="from")


def code(facts, **changes):
    """The verdict code for `facts` with some fields changed."""
    return diagnose.verdict(replace(facts, **changes)).code


def inventory():
    """The scenario's six devices, normalised, by hostname."""
    found = [devices.normalise(raw) for raw in body("scenario", "devices")["devices"]]
    return {device.hostname: device for device in found}


def test_source_down_stops_everything():
    # Step 0 failing in self mode decides every destination, whatever else looks fine.
    healthy = {"tcp": "open", "ssh_enabled": False, "network_allowed": True, "path_ok": True}
    assert code(OPEN_ROAD, source_up=False, **healthy) == "SOURCE_DOWN"
    assert "SOURCE_DOWN" in diagnose.EARLY
    # --from never checks this host, so its health cannot decide anything there.
    assert code(FROM, source_up=False, ssh_enabled=False, network_allowed=True) == "ALLOWED"


def test_an_unresolved_or_same_device_stops_at_step_one():
    for found in ("NOT_FOUND", "AMBIGUOUS"):
        assert code(OPEN_ROAD, source_found=found, tcp="open", ssh_enabled=False) == found
        assert code(OPEN_ROAD, dest_found=found, tcp="open", ssh_enabled=False) == found
    assert code(FROM, dest_found="SAME_DEVICE", network_allowed=True) == "SAME_DEVICE"
    # The source is resolved before the destination: without it nothing can be judged.
    assert code(OPEN_ROAD, source_found="NOT_FOUND", dest_found="AMBIGUOUS") == "NOT_FOUND"
    assert {"NOT_FOUND", "AMBIGUOUS", "SAME_DEVICE"} <= diagnose.EARLY


def test_an_expired_key_is_reported_first():
    # Every gate holds at once; the expired key is the first, and the one MC must fix (P9).
    found = diagnose.verdict(replace(OPEN_ROAD, key_expired=True, online=False,
                                     blocks_incoming=True, network_allowed=False))
    assert found.code == "KEY_EXPIRED"
    assert "re-authenticat" in found.explanation
    assert "KEY_EXPIRED" in diagnose.EARLY


def test_an_offline_destination_stops_before_probes():
    found = diagnose.verdict(replace(OPEN_ROAD, online=False, last_seen="2026-10-20T12:00:00Z",
                                     tcp="open", network_allowed=True, ssh_enabled=False))
    assert found.code == "DEST_OFFLINE"
    # lastSeen is reported as given, and its absence is never read as anything [spec 4548].
    assert "2026-10-20T12:00:00Z" in found.explanation
    assert "not given" in diagnose.verdict(replace(OPEN_ROAD, online=False)).explanation
    assert "DEST_OFFLINE" in diagnose.EARLY
    # An unknown connection state is not a gate.
    assert code(OPEN_ROAD, online=None, tcp="open", ssh_enabled=False) == "OPEN"


def test_shields_up_is_reported_before_probes():
    assert code(OPEN_ROAD, blocks_incoming=True, tcp="open", ssh_enabled=False) == "SHIELDS_UP"
    assert "SHIELDS_UP" in diagnose.EARLY


def test_tsmp_failure_is_a_path_problem_not_policy():
    found = diagnose.verdict(replace(OPEN_ROAD, path_ok=False, network_allowed=True,
                                     tcp="timeout", ssh_enabled=False))
    assert found.code == "PATH_DOWN"
    assert "not policy" in found.explanation
    # An unanswered policy test leaves the failed ping as the evidence there is.
    assert code(OPEN_ROAD, path_ok=False, network_allowed=None, tcp="timeout",
                ssh_enabled=False) == "PATH_DOWN"
    # In test posture the pings are not run (path_ok None), so the gate is skipped.
    assert code(OPEN_ROAD, path_ok=None, network_allowed=False) == "POLICY_DROP"
    # PATH_DOWN is not a gate: the probes and the policy test still run and are reported.
    assert "PATH_DOWN" not in diagnose.EARLY


def test_a_tsmp_failure_beside_a_named_drop_is_the_policy_not_connectivity():
    # A policy that lets neither device reach the other trims each from the other's netmap
    # [device-visibility L77-80], and TSMP needs the peer there ("no matching peer"), so a
    # named drop explains the failed ping too (A52).
    found = diagnose.verdict(replace(OPEN_ROAD, path_ok=False, network_allowed=False,
                                     tcp="timeout", ssh_enabled=False))
    assert found.code == "POLICY_DROP"
    assert "netmap" in found.explanation
    # A destination this host's netmap does not list is never a path fault: without a named
    # drop it stays unexplained, with what is known said.
    trimmed = replace(OPEN_ROAD, path_ok=False, in_netmap=False, tcp="timeout",
                      ssh_enabled=False)
    assert code(trimmed, network_allowed=False) == "POLICY_DROP"
    for allowed in (True, None):
        found = diagnose.verdict(replace(trimmed, network_allowed=allowed))
        assert found.code == "INCONCLUSIVE", allowed
        assert "netmap does not list" in found.explanation
    # A listed peer whose ping failed is still connectivity.
    assert code(trimmed, in_netmap=True, network_allowed=True) == "PATH_DOWN"


def test_an_open_port_on_plain_ssh_is_open():
    assert code(OPEN_ROAD, tcp="open", ssh_enabled=False) == "OPEN"
    # An open port is evidence on its own; the policy answer does not have to be in.
    assert code(OPEN_ROAD, tcp="open", ssh_enabled=False, network_allowed=None) == "OPEN"
    # On a Tailscale SSH host tailscaled accepts the TCP connection itself, so an open :22
    # proves nothing until the ssh section admits the source in accept mode.
    assert code(OPEN_ROAD, tcp="open", ssh_enabled=True, network_allowed=True,
                ssh_user="spec5", ssh_admitted="accept") == "OPEN"
    assert code(OPEN_ROAD, tcp="open", ssh_enabled=True, network_allowed=True,
                ssh_user="spec5", ssh_admitted=None) == "INCONCLUSIVE"
    assert code(OPEN_ROAD, tcp="open", ssh_enabled=None) == "INCONCLUSIVE"
    assert "OPEN" in diagnose.REACHABLE


def test_a_port_other_than_22_never_consults_tailscale_ssh():
    # Tailscale SSH claims :22 only [tsssh L40], so on any other port the host's own service
    # answers, and sshEnabled, known or not, does not enter the verdict.
    for ssh_enabled in (True, False, None):
        assert code(OPEN_ROAD, port=443, tcp="open", ssh_enabled=ssh_enabled) == "OPEN"
        assert code(FROM, port=443, network_allowed=True, ssh_enabled=ssh_enabled) == "ALLOWED"
        assert code(OPEN_ROAD, port=443, tcp="timeout", network_allowed=True,
                    ssh_enabled=ssh_enabled) == "HOST_SIDE_DROP"


def test_check_only_admission_for_a_user_is_admitted_check_mode():
    user = replace(FROM, source_tagged=False, ssh_enabled=True, ssh_user="spec5",
                   ssh_admitted="check")
    found = diagnose.verdict(replace(user, network_allowed=True))
    assert found.code == "ADMITTED_CHECK_MODE"
    assert "browser" in found.explanation
    assert "ADMITTED_CHECK_MODE" in diagnose.REACHABLE
    # In self mode the open port is the evidence that the network path holds.
    assert code(user, mode="self", tcp="open") == "ADMITTED_CHECK_MODE"
    assert code(user, mode="self", tcp="timeout", network_allowed=True) == (
        "TS_SSH_TIMEOUT_UNEXPLAINED")
    # The network rule is necessary (§15.2 step 6): an ssh rule cannot make a dropped port
    # reachable, so a drop is never reported as admitted.
    assert code(user, network_allowed=False) == "POLICY_DROP"


def test_check_only_admission_for_a_tagged_source_is_flagged():
    found = diagnose.verdict(replace(FROM, ssh_enabled=True, network_allowed=True,
                                     ssh_user="spec5", ssh_admitted="check"))
    assert found.code == "TS_SSH_CHECK_FOR_TAGGED"
    # "An SSH access rule from a tagged device cannot be in check mode" [tsssh L218].
    assert "tagged" in found.explanation and "MC6" in found.explanation
    assert "TS_SSH_CHECK_FOR_TAGGED" not in diagnose.REACHABLE


def test_ssh_denied_both_ways_is_ts_ssh_policy():
    found = diagnose.verdict(replace(FROM, ssh_enabled=True, network_allowed=True,
                                     ssh_user="spec5", ssh_admitted="denied"))
    assert found.code == "TS_SSH_POLICY"
    assert "spec5" in found.explanation


def test_a_missing_ssh_user_is_unverified():
    for facts in (FROM, replace(OPEN_ROAD, tcp="open")):
        found = diagnose.verdict(replace(facts, ssh_enabled=True, network_allowed=True))
        assert found.code == "TS_SSH_UNVERIFIED"
        assert "--ssh-user" in found.explanation


def test_a_validate_drop_is_a_policy_drop():
    for facts in (FROM, replace(OPEN_ROAD, tcp="timeout")):
        found = diagnose.verdict(replace(facts, network_allowed=False, ssh_enabled=False))
        assert found.code == "POLICY_DROP"
        # A policy-dropped SYN gets a TSMP reject and no RST, so it looks like a timeout.
        assert "timeout" in found.explanation
    # On a Tailscale SSH host the ssh section needs a rule as well, unless it already admits.
    ts_ssh = replace(FROM, network_allowed=False, ssh_enabled=True, ssh_user="spec5")
    for admitted in ("denied", None):
        found = diagnose.verdict(replace(ts_ssh, ssh_admitted=admitted))
        assert found.code == "POLICY_DROP" and "ssh section" in found.explanation
    found = diagnose.verdict(replace(ts_ssh, ssh_admitted="accept"))
    assert found.code == "POLICY_DROP" and "ssh section" not in found.explanation


def test_a_reset_or_an_open_port_beside_a_named_drop_is_a_contradiction_not_a_drop():
    # A Tailscale policy drop never produces an RST and never lets a connection open (TSMP
    # reject, no RST [wrap.go:1234-1252]), so a probe that got either proves the SYN passed
    # the filter: the identity test does not represent this host's traffic (A53).
    refused = diagnose.verdict(replace(OPEN_ROAD, tcp="refused", network_allowed=False,
                                       ssh_enabled=False))
    assert refused.code == "INCONCLUSIVE"
    assert "reset" in refused.explanation and "srcPosture" in refused.explanation
    # sshd may simply be down, so MC still gets the on-host block.
    assert refused.on_host is True
    for ssh_enabled in (True, None):
        opened = diagnose.verdict(replace(OPEN_ROAD, tcp="open", network_allowed=False,
                                          ssh_enabled=ssh_enabled, ssh_user="spec5",
                                          ssh_admitted="denied"))
        assert opened.code == "INCONCLUSIVE", ssh_enabled
        assert "accepted a TCP connection" in opened.explanation and not opened.on_host
    # A timeout is what a drop looks like, and --from mode has no probe to contradict it.
    assert code(OPEN_ROAD, tcp="timeout", network_allowed=False, ssh_enabled=False) == (
        "POLICY_DROP")
    assert code(FROM, network_allowed=False, ssh_enabled=False) == "POLICY_DROP"


def test_from_mode_with_policy_allow_is_allowed():
    assert code(FROM, network_allowed=True, ssh_enabled=False) == "ALLOWED"
    assert code(FROM, network_allowed=True, ssh_enabled=True, ssh_user="spec5",
                ssh_admitted="accept") == "ALLOWED"
    # Tailscale SSH on and its admission unknown: allowed is not established.
    assert code(FROM, network_allowed=True, ssh_enabled=True, ssh_user="spec5",
                ssh_admitted=None) == "INCONCLUSIVE"
    assert code(FROM, network_allowed=None, ssh_enabled=False) == "INCONCLUSIVE"
    # No local probe answers in --from mode, whatever the facts carry.
    assert code(FROM, network_allowed=None, ssh_enabled=False, tcp="open") == "INCONCLUSIVE"
    assert "ALLOWED" in diagnose.REACHABLE


def test_a_reset_with_policy_allow_is_refused_by_host():
    found = diagnose.verdict(replace(OPEN_ROAD, tcp="refused", network_allowed=True,
                                     ssh_enabled=False))
    assert found.code == "REFUSED_BY_HOST"
    assert "REFUSED_BY_HOST" in diagnose.HOST_SIDE
    assert code(OPEN_ROAD, tcp="refused", network_allowed=None) == "INCONCLUSIVE"


def test_a_timeout_with_allow_on_openssh_is_host_side():
    found = diagnose.verdict(replace(OPEN_ROAD, tcp="timeout", network_allowed=True,
                                     ssh_enabled=False))
    assert found.code == "HOST_SIDE_DROP"
    # Propagation timing is unverified, so a re-run is suggested before the host is blamed.
    assert "re-run" in found.explanation
    assert "HOST_SIDE_DROP" in diagnose.HOST_SIDE


def test_a_timeout_with_allow_on_tailscale_ssh_is_unexplained():
    facts = replace(OPEN_ROAD, tcp="timeout", network_allowed=True, ssh_enabled=True,
                    ssh_user="spec5")
    for admitted in ("accept", "check"):
        found = diagnose.verdict(replace(facts, ssh_admitted=admitted, source_tagged=False))
        assert found.code == "TS_SSH_TIMEOUT_UNEXPLAINED"
        assert "TS_SSH_TIMEOUT_UNEXPLAINED" in diagnose.HOST_SIDE
    # The ssh section is asked only after the handshake, so its answer, known or not, never
    # decides a timeout: the row holds whatever it said (A50).
    assert code(facts, ssh_admitted=None) == "TS_SSH_TIMEOUT_UNEXPLAINED"


def test_a_timeout_on_a_tailscale_ssh_host_is_never_blamed_on_the_ssh_section():
    # tailscaled completes the :22 handshake itself and asks the ssh section only at SSH
    # login [tsssh L61, L118], so a denying ssh section shows as an open port and a refused
    # login, never as a timeout. Its answer is a second blocker beside the verdict (A50).
    spec5 = replace(OPEN_ROAD, tcp="timeout", network_allowed=True, ssh_enabled=True,
                    ssh_user="spec5")
    denied = diagnose.verdict(replace(spec5, ssh_admitted="denied"))
    assert denied.code == "TS_SSH_TIMEOUT_UNEXPLAINED"
    assert "cannot cause a timeout" in denied.explanation
    assert "also refuse it as spec5" in denied.explanation
    unasked = diagnose.verdict(replace(spec5, ssh_user=None))
    assert unasked.code == "TS_SSH_TIMEOUT_UNEXPLAINED" and "--ssh-user" in unasked.explanation
    # The droplet is tagged: a check-only rule can never admit it, which is MC's MC6.
    tagged = diagnose.verdict(replace(spec5, ssh_admitted="check"))
    assert tagged.code == "TS_SSH_TIMEOUT_UNEXPLAINED" and "MC6" in tagged.explanation
    assert "TS_SSH_TIMEOUT_UNEXPLAINED" in diagnose.HOST_SIDE
    # A reset or a probe error is not the ssh section's doing either.
    assert code(spec5, tcp="refused", ssh_admitted="denied") == "REFUSED_BY_HOST"
    assert code(spec5, tcp="error:EHOSTUNREACH", ssh_admitted="denied") == "INCONCLUSIVE"
    # An open port is where the ssh section's answer decides, as it does in --from mode.
    for facts in (replace(spec5, tcp="open"), replace(spec5, mode="from", tcp=None)):
        assert code(facts, ssh_admitted="denied") == "TS_SSH_POLICY"
        assert code(facts, ssh_admitted="check") == "TS_SSH_CHECK_FOR_TAGGED"
        assert code(facts, ssh_user=None) == "TS_SSH_UNVERIFIED"
    # A dropped network keeps its own verdict: the drop explains the timeout.
    assert code(spec5, network_allowed=False, ssh_admitted="check") == "TS_SSH_CHECK_FOR_TAGGED"
    assert code(spec5, network_allowed=False, ssh_admitted="denied") == "POLICY_DROP"


def test_unknown_ssh_enabled_is_inconclusive_with_both_hypotheses():
    found = diagnose.verdict(replace(OPEN_ROAD, tcp="timeout", network_allowed=True,
                                     ssh_enabled=None, ssh_host_keys=True))
    assert found.code == "INCONCLUSIVE"
    assert "if Tailscale SSH is on" in found.explanation
    assert "if it is off" in found.explanation
    # The peer's host keys in the local status are a weak hint, said to be one.
    assert "weak hint" in found.explanation
    # Probe errors are inconclusive too, and named.
    errored = diagnose.verdict(replace(OPEN_ROAD, tcp="error:EHOSTUNREACH", network_allowed=True,
                                       ssh_enabled=False))
    assert errored.code == "INCONCLUSIVE" and "error:EHOSTUNREACH" in errored.explanation


def test_icmp_success_is_never_port_evidence():
    # ICMP passes whenever any port is open between the pair [pol TL;DR 1; filter.go:520].
    for base in ({"tcp": "timeout", "network_allowed": None, "ssh_enabled": False},
                 {"tcp": "timeout", "network_allowed": True, "ssh_enabled": False},
                 {"tcp": None, "network_allowed": None, "ssh_enabled": False},
                 {"tcp": "refused", "network_allowed": False, "ssh_enabled": False}):
        found = {code(OPEN_ROAD, icmp_ok=icmp, **base) for icmp in (True, False, None)}
        assert len(found) == 1, base
        assert found != {"OPEN"}


def test_only_open_admitted_check_and_allowed_are_reachable():
    assert diagnose.REACHABLE == {"OPEN", "ADMITTED_CHECK_MODE", "ALLOWED"}
    assert diagnose.HOST_SIDE == {"REFUSED_BY_HOST", "HOST_SIDE_DROP",
                                  "TS_SSH_TIMEOUT_UNEXPLAINED"}
    assert not diagnose.REACHABLE & diagnose.EARLY


def test_sources_are_identities_never_ip_addresses():
    found = inventory()
    # A tagged identity is the union of its tags [pol (b)]; the registering user is not it.
    assert diagnose.identities(found["claude-factory"]) == ("tag:dev",)
    assert diagnose.identities(found["albini"]) == ("mc@example.com",)
    # Whatever the API put in `user`, an address is never a source [spec 2533-2540].
    for user in ("100.64.0.10", "fd7a:115c:a1e0::a", "", None):
        raw = dict(found["albini"].raw, user=user)
        assert diagnose.identities(devices.normalise(raw)) == ()
    for src in ("100.64.0.10", "fd7a:115c:a1e0::a", "*", "autogroup:member", ""):
        with pytest.raises(ValueError):
            diagnose.network_tests(src, "100.64.0.11", 22)
        with pytest.raises(ValueError):
            diagnose.ssh_candidate({}, "100.64.0.11", src, "spec5", "accept")
    assert diagnose.network_tests("tag:dev", "100.64.0.11", 22) == [
        {"src": "tag:dev", "proto": "tcp", "accept": ["100.64.0.11:22"]}]
    # The destination is an address: a name would be looked up, and MagicDNS failed there.
    with pytest.raises(ValueError):
        diagnose.network_tests("tag:dev", "spec5", 22)


def test_the_ssh_candidate_strips_tests_and_ssh_tests_and_adds_a_host_alias():
    live = body("scenario", "policy")
    live["sshTests"] = [{"src": "mc@example.com", "dst": ["tag:fleet"], "accept": ["root"]}]
    live["hosts"] = {"example-host-1": "100.100.100.100"}
    before = repr(live)
    candidate = diagnose.ssh_candidate(live, "100.64.0.11", "tag:dev", "spec5", "accept")
    # Only the probe runs: the live policy's own tests would otherwise decide the answer.
    assert "tests" not in candidate
    assert candidate["sshTests"] == [{"src": "tag:dev", "dst": ["tailnet-diag-dst"],
                                      "accept": ["spec5"]}]
    # sshTests.dst takes host aliases, not raw IPs [pol (c)].
    assert candidate["hosts"] == {"example-host-1": "100.100.100.100",
                                  "tailnet-diag-dst": "100.64.0.11"}
    # Everything else is the live policy untouched, and the live copy itself is unchanged.
    for key in ("tagOwners", "grants", "ssh"):
        assert candidate[key] == live[key]
    assert repr(live) == before
    check = diagnose.ssh_candidate(live, "100.64.0.11", "mc@example.com", "spec5", "check")
    assert check["sshTests"] == [{"src": "mc@example.com", "dst": ["tailnet-diag-dst"],
                                  "check": ["spec5"]}]
    # A policy with no hosts section gets one.
    bare = diagnose.ssh_candidate({"ssh": []}, "100.64.0.12", "tag:dev", "mc", "accept")
    assert bare["hosts"] == {"tailnet-diag-dst": "100.64.0.12"}
    for mode in ("deny", "Accept", ""):
        with pytest.raises(ValueError):
            diagnose.ssh_candidate(live, "100.64.0.11", "tag:dev", "spec5", mode)
    for user in ("", None):
        with pytest.raises(ValueError):
            diagnose.ssh_candidate(live, "100.64.0.11", "tag:dev", user, "accept")
    for shape in ([], {"hosts": ["not", "a", "map"]}):
        with pytest.raises(TypeError):
            diagnose.ssh_candidate(shape, "100.64.0.11", "tag:dev", "spec5", "accept")


def test_the_alias_name_avoids_existing_hosts_keys():
    live = {"hosts": {"tailnet-diag-dst": "100.64.0.1", "Tailnet-Diag-Dst-2": "100.64.0.2"}}
    candidate = diagnose.ssh_candidate(live, "100.64.0.11", "tag:dev", "spec5", "accept")
    # The first free name is used, compared without case, so MC's entry is never replaced.
    assert candidate["hosts"]["tailnet-diag-dst"] == "100.64.0.1"
    assert candidate["hosts"]["Tailnet-Diag-Dst-2"] == "100.64.0.2"
    assert candidate["hosts"]["tailnet-diag-dst-3"] == "100.64.0.11"
    assert candidate["sshTests"][0]["dst"] == ["tailnet-diag-dst-3"]


def _serve_banner(listener, banner):
    """Accept one connection on `listener`, send `banner`, and close it."""
    connection, _ = listener.accept()
    with connection:
        connection.sendall(banner)


@pytest.mark.skipif(sys.platform != "linux",
                    reason="a full listen(0) backlog drops SYNs silently on Linux only")
def test_tcp_probe_distinguishes_open_refused_timeout():
    with contextlib.ExitStack() as stack:
        # open: a listener that greets like sshd; its banner bytes are kept raw.
        listener = stack.enter_context(socket.create_server(("127.0.0.1", 0)))
        server = threading.Thread(target=_serve_banner,
                                  args=(listener, b"SSH-2.0-OpenSSH_9.6\r\n"))
        server.start()
        probe = diagnose.tcp_probe("127.0.0.1", listener.getsockname()[1], 2)
        server.join()
        assert (probe.result, probe.banner) == ("open", "SSH-2.0-OpenSSH_9.6\r\n")
        # A listener that says nothing is still open, with no banner.
        quiet = stack.enter_context(socket.create_server(("127.0.0.1", 0)))
        probe = diagnose.tcp_probe("127.0.0.1", quiet.getsockname()[1], 2, banner_timeout=0.1)
        assert (probe.result, probe.banner) == ("open", None)
        # refused: a bound port with no listener answers the SYN with an RST.
        bound = stack.enter_context(socket.socket())
        bound.bind(("127.0.0.1", 0))
        assert diagnose.tcp_probe("127.0.0.1", bound.getsockname()[1], 2).result == "refused"
        # timeout: once a listen(0) backlog holds a connection, Linux drops further SYNs
        # without an answer, which is what a policy-dropped SYN looks like from the source.
        full = stack.enter_context(socket.socket())
        full.bind(("127.0.0.1", 0))
        full.listen(0)
        stack.enter_context(socket.create_connection(full.getsockname(), timeout=2))
        probe = diagnose.tcp_probe("127.0.0.1", full.getsockname()[1], 0.3)
        assert (probe.result, probe.banner) == ("timeout", None)
    # Only an address is probed: a name would be resolved first, and MagicDNS failed there.
    with pytest.raises(ValueError):
        diagnose.tcp_probe("localhost", 22, 1)


def status(**changes):
    """The synthetic running status as text, with top-level or Self fields changed."""
    doc = body("status", "self-running")
    for key, value in changes.items():
        target, key = (doc["Self"], key[5:]) if key.startswith("Self_") else (doc, key)
        target[key] = value
    return json.dumps(doc, indent=2)


def test_source_health_needs_a_running_online_backend():
    assert diagnose.source_health(raw_text("status", "self-running")) is None
    assert diagnose.netmap_note(raw_text("status", "self-running")) is None
    # A stopped backend still lists stale peers [mc §5], so each condition is its own.
    for text, words in ((status(BackendState="Stopped"), "BackendState"),
                        (status(Self_Online=False), "Online"),
                        ("tailscaled is not running", "JSON")):
        reason = diagnose.source_health(text)
        assert reason is not None and words in reason, text


def test_a_healthy_host_whose_policy_leaves_it_no_peers_is_still_a_source():
    # The netmap holds only devices the policy lets this host reach or be reached by
    # [device-visibility L37-42], so a Running, online host can see no peer at all. That
    # is a warning naming the policy, never SOURCE_DOWN, and the ladder still asks the
    # API, whose network test then names the drop (A52).
    for peers in ({}, None):
        text = status(Peer=peers)
        assert diagnose.source_health(text) is None
        note = diagnose.netmap_note(text)
        assert note is not None and "no peers" in note and "policy" in note


def test_whether_this_host_s_netmap_lists_a_peer_is_found_by_address():
    spec5 = ("100.64.0.11", "fd7a:115c:a1e0::b")
    text = raw_text("status", "self-running")
    assert diagnose.peer_listed(text, spec5) is True
    assert diagnose.peer_listed(text, ("100.64.0.13",)) is False
    assert diagnose.peer_listed(status(Peer=None), spec5) is False
    # A status that cannot be read says nothing either way.
    assert diagnose.peer_listed("not JSON", spec5) is None
    assert diagnose.peer_listed(None, spec5) is None


def test_a_peer_s_ssh_host_keys_are_found_by_address():
    spec5 = ("100.64.0.11", "fd7a:115c:a1e0::b")
    text = raw_text("status", "self-running")
    assert diagnose.peer_has_host_keys(text, spec5) is False
    doc = json.loads(text)
    [peer] = doc["Peer"].values()
    peer["sshHostKeys"] = ["ssh-ed25519 AAAA"]
    assert diagnose.peer_has_host_keys(json.dumps(doc), spec5) is True
    # Not a peer this host knows, or a status that cannot be read: no hint at all.
    assert diagnose.peer_has_host_keys(text, ("100.64.0.13",)) is None
    assert diagnose.peer_has_host_keys("not JSON", spec5) is None


def test_the_on_host_block_names_the_destination_port_and_source():
    block = diagnose.on_host_block("pi5", 2222, "claude-factory", "100.64.0.10").splitlines()
    assert block == [
        "# On pi5, while the agent retries from claude-factory:",
        ("tailscale metrics print | grep -E 'inbound_dropped_packets_total'   "
         "# reason=\"acl\" rising → Tailscale policy drop (client ≥ 1.78)"),
        ("sudo journalctl -u tailscaled --since '-10min' | grep -E 'Drop: TCP\\{[^}]*:2222\\}'   "
         "# \"no rules matched\""),
        ("sudo timeout 20 tcpdump -ni tailscale0 -c 5 'tcp port 2222 and src host 100.64.0.10'   "
         "# SYN seen → passed Tailscale's filter"),
        ("sudo ufw status verbose ; tailscale get ssh ; tailscale get shields-up ; "
         "tailscale get netfilter-mode"),
    ]
    # Without a source address the capture filters on the port alone.
    bare = diagnose.on_host_block("pi5", 22, "claude-factory", None).splitlines()
    assert "'tcp port 22'" in bare[3] and "src host" not in bare[3]


def test_the_on_host_block_for_a_tailscale_ssh_timeout_drops_what_cannot_see_port_22():
    # While Tailscale SSH takes :22, tailscaled's netstack consumes the SYN after the filter
    # [tsssh L63, L118], so it is never written to tailscale0 and never reaches the host
    # firewall: an empty capture there would read as a Tailscale drop when it is not (A51).
    found = inventory()
    me = diagnose.Source("self", found["claude-factory"], self_source="line")

    def block(code):
        """The block MC is handed for one host-side verdict on spec5:22."""
        [step] = [s for s in diagnose.next_steps(code, found["spec5"], port=22, user="spec5",
                                                 source=me, ids=("tag:dev",),
                                                 inventory=list(found.values()))
                  if s["who"] == "mc"]
        return step["do"].splitlines()

    ts_ssh = block("TS_SSH_TIMEOUT_UNEXPLAINED")
    assert not [line for line in ts_ssh if "tcpdump" in line and not line.startswith("#")]
    assert not [line for line in ts_ssh if "ufw" in line and not line.startswith("#")]
    # The lines that still tell a policy drop apart stay, with `tailscale get ssh`.
    assert ts_ssh[0] == "# On spec5, while the agent retries from claude-factory:"
    assert "inbound_dropped_packets_total" in ts_ssh[1] and "journalctl" in ts_ssh[2]
    assert any("netstack" in line for line in ts_ssh if line.startswith("#"))
    assert ts_ssh[-1].startswith("tailscale get ssh")
    # The plain OpenSSH verdicts keep the capture and the firewall check.
    for code in ("HOST_SIDE_DROP", "REFUSED_BY_HOST"):
        lines = block(code)
        assert any(line.startswith("sudo timeout 20 tcpdump -ni tailscale0") for line in lines)
        assert lines[-1].startswith("sudo ufw status verbose")


def test_a_port_or_ssh_user_outside_the_rules_is_a_usage_error():
    def args(port=22, ssh_user=None):
        """The parsed arguments check_args reads."""
        return argparse.Namespace(port=port, ssh_user=ssh_user)

    assert diagnose.check_args(args()) == (22, None)
    assert diagnose.check_args(args(65535, "spec5")) == (65535, "spec5")
    for bad in (args(port=0), args(port=65536), args(port=-22), args(ssh_user=""),
                args(ssh_user="<user>"), args(ssh_user="a b"), args(ssh_user="*"),
                args(ssh_user="-oProxyCommand=x"), args(ssh_user="x" * 65)):
        with pytest.raises(UsageError) as refused:
            diagnose.check_args(bad)
        assert refused.value.code == "USAGE"


def test_next_steps_name_who_acts_for_each_verdict():
    found = inventory()
    every = list(found.values())
    me = diagnose.Source("self", found["claude-factory"], self_source="line")
    pi5 = found["pi5"]

    def steps(code, dest=pi5, port=22, user=None, source=me, ids=("tag:dev",)):
        """next_steps for one verdict against the scenario's inventory."""
        return diagnose.next_steps(code, dest, port=port, user=user, source=source, ids=ids,
                                   inventory=every)

    # An open :22 leaves only ssh itself to try, as the user when one was given.
    assert [s["run"] for s in steps("OPEN", user="mc")] == ["ssh -v mc@100.64.0.13"]
    assert [s["run"] for s in steps("OPEN")] == ["ssh -v 100.64.0.13"]
    assert steps("OPEN", port=443) == []
    # The rerun line holds a placeholder that check_args refuses, so it cannot run unedited.
    [rerun] = steps("TS_SSH_UNVERIFIED", source=diagnose.Source("from", found["albini"]),
                    ids=("mc@example.com",))
    assert rerun["run"] == ("tailnet diagnose nPi5x001CNTRL --port 22 --ssh-user <user> "
                            "--from nAlbini1CNTRL")
    [draft] = steps("POLICY_DROP", dest=found["spec5"])
    assert draft["run"] == "tailnet policy draft --name allow-tcp-22"
    assert "from tag:dev to spec5 on tcp:22" in draft["why"]
    mc, disable = steps("KEY_EXPIRED")
    assert (mc["who"], mc["needs"]) == ("mc", "terminal")
    assert disable["run"] == "tailnet device disable-key-expiry nPi5x001CNTRL"
    assert [s["run"] for s in steps("NOT_FOUND", dest=None)] == ["tailnet device list"]
    # Verdicts with nothing left to do for anyone.
    for code in ("ALLOWED", "ADMITTED_CHECK_MODE", "DEST_OFFLINE", "INCONCLUSIVE"):
        assert steps(code) == [], code
    # Host-side: MC's block first, then the retry, then each user-owned device via --from.
    block, retry, *others = steps("HOST_SIDE_DROP", port=22, user="mc")
    assert (block["who"], block["needs"]) == ("mc", "terminal")
    assert block["do"].startswith("# On pi5, while the agent retries from claude-factory:")
    assert retry["run"] == "tailnet diagnose nPi5x001CNTRL --port 22"
    assert [s["run"] for s in others] == [
        "tailnet diagnose nPi5x001CNTRL --port 22 --from nAlbini1CNTRL --ssh-user mc",
        "tailnet diagnose nPi5x001CNTRL --port 22 --from nPhone01CNTRL --ssh-user mc"]
