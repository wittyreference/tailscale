# ABOUTME: Tests for tailnet.selfnode: reading `tailscale status --json`, joining this host to exactly one
# ABOUTME: API device by Tailscale IP, and failing closed whenever who-am-I is not certain (§11.3, D6).

import json

import pytest
from fixturefiles import body, raw_text

from tailnet import devices, localts, protected, selfnode
from tailnet.posture import Posture


def status(**changes):
    """The synthetic running status as text, with top-level or Self fields changed (None drops one)."""
    doc = body("status", "self-running")
    for key, value in changes.items():
        target, key = (doc["Self"], key[5:]) if key.startswith("Self_") else (doc, key)
        if value is None:
            target.pop(key, None)
        else:
            target[key] = value
    return json.dumps(doc, indent=2)


def inventory():
    """The scenario's six devices, normalised; the droplet is nFactory1CNTRL at 100.64.0.10."""
    return [devices.normalise(raw) for raw in body("scenario", "devices")["devices"]]


def line(node_id="nFactory1CNTRL"):
    """A protected list whose self line names `node_id`."""
    return protected.parse(f"self {node_id}\nspec5\n")


def test_parse_reads_self_ips_id_and_tags_from_indented_json():
    text = raw_text("status", "self-running")
    # The real binary indents and puts a space after each colon [mc §5]; the fixture's file
    # does too, and it is parsed exactly as written.
    assert '\n  "BackendState": "Running"' in text
    local = selfnode.parse_status(text)
    assert local.usable and local.reason is None
    assert (local.backend_state, local.online) == ("Running", True)
    assert local.ips == ("100.64.0.10", "fd7a:115c:a1e0::a")
    assert (local.id, local.hostname, local.dns_name) == (
        "nFactory1CNTRL", "claude-factory", "claude-factory.tail0000.ts.net.")
    assert local.tags == ("tag:dev",)


@pytest.mark.parametrize("state", ["Stopped", "NeedsLogin", "Starting", "NoState", None])
def test_a_backend_not_running_is_unknown(state):
    # A stopped backend still reports a stale peer list [mc §5], so nothing it says is used.
    local = selfnode.parse_status(status(BackendState=state))
    assert not local.usable and "BackendState" in local.reason
    found = selfnode.decide(local, inventory(), None)
    assert (found.known, found.refusal, found.device) == (False, "SELF_UNKNOWN", None)


@pytest.mark.parametrize("online", [False, None])
def test_self_offline_is_unknown(online):
    local = selfnode.parse_status(status(Self_Online=online))
    assert not local.usable and "Online" in local.reason
    assert selfnode.decide(local, inventory(), None).known is False


@pytest.mark.parametrize("text", ["", "not json", "[]", json.dumps({"BackendState": "Running"}),
                                  status(Self_TailscaleIPs=[]),
                                  status(Self_TailscaleIPs=["not an address"])])
def test_a_status_without_a_usable_self_is_unknown(text):
    local = selfnode.parse_status(text)
    assert not local.usable and local.reason
    assert selfnode.decide(local, inventory(), None).refusal == "SELF_UNKNOWN"


def test_self_joins_by_tailscale_ip_and_records_id_agreement():
    found = selfnode.decide(selfnode.parse_status(status()), inventory(), None)
    assert (found.known, found.source, found.refusal) == (True, "live", None)
    assert found.device.node_id == "nFactory1CNTRL"
    assert found.id_agrees is True
    # That Self.ID and the API's nodeId are one string is an inference, so a difference is
    # recorded, never a reason to refuse (J1 must_fix).
    other_id = selfnode.decide(selfnode.parse_status(status(Self_ID="n9999CNTRL")),
                               inventory(), None)
    assert (other_id.known, other_id.id_agrees) == (True, False)
    assert other_id.device.node_id == "nFactory1CNTRL"
    # Joining on the IPv6 address alone works too.
    v6 = selfnode.decide(selfnode.parse_status(status(Self_TailscaleIPs=["fd7a:115c:a1e0::a"])),
                         inventory(), None)
    assert v6.known and v6.device.node_id == "nFactory1CNTRL"


def test_no_ip_match_means_another_tailnet():
    local = selfnode.parse_status(status(Self_TailscaleIPs=["100.99.0.1"]))
    found = selfnode.decide(local, inventory(), None)
    assert (found.known, found.refusal) == (False, "SELF_UNKNOWN")
    assert "another tailnet" in found.reason


def test_two_ip_matches_mean_unknown():
    twins = inventory()
    clone = devices.normalise({**twins[0].raw, "nodeId": "nClone01CNTRL", "hostname": "clone",
                               "addresses": ["100.64.0.10"]})
    found = selfnode.decide(selfnode.parse_status(status()), twins + [clone], None)
    assert (found.known, found.refusal) == (False, "SELF_UNKNOWN")
    assert "nFactory1CNTRL" in found.reason and "nClone01CNTRL" in found.reason


def test_a_disagreeing_self_line_refuses():
    local = selfnode.parse_status(status())
    found = selfnode.decide(local, inventory(), line("nSpec5x1CNTRL"))
    assert (found.known, found.refusal) == (False, "SELF_LINE_DISAGREES")
    assert "nSpec5x1CNTRL" in found.reason and "nFactory1CNTRL" in found.reason
    agreed = selfnode.decide(local, inventory(), line("nFactory1CNTRL"))
    assert (agreed.known, agreed.refusal) == (True, None)


def test_test_posture_takes_self_from_the_line_and_never_runs_tailscale(tmp_path, syscalls):
    posture = Posture.from_env({"TAILNET_API_BASE": "http://127.0.0.1:9",
                                "TAILNET_HOME": str(tmp_path / "tn")}, real_home=tmp_path / "r")
    found = selfnode.resolve_self(posture, inventory(), line("nFactory1CNTRL"))
    assert (found.known, found.source, found.id_agrees) == (True, "line", None)
    assert found.device.hostname == "claude-factory"
    # No self line means unknown: every --apply then refuses in test posture (§11.3).
    unanswered = selfnode.resolve_self(posture, inventory(), None)
    assert (unanswered.known, unanswered.refusal) == (False, "SELF_UNKNOWN")
    assert "self line" in unanswered.reason
    # The line must name exactly one API device.
    stray = selfnode.resolve_self(posture, inventory(), line("nGone001CNTRL"))
    assert (stray.known, stray.refusal) == (False, "SELF_UNKNOWN")
    assert syscalls.processes() == []


def test_production_without_a_tailscale_binary_is_unknown_and_says_why(tmp_path, monkeypatch,
                                                                      syscalls):
    monkeypatch.setattr(localts, "PREFERRED", str(tmp_path / "no" / "tailscale"))
    monkeypatch.setenv("PATH", str(tmp_path))
    posture = Posture.from_env({}, real_home=tmp_path / "home")
    found = selfnode.resolve_self(posture, inventory(), line())
    assert (found.known, found.refusal) == (False, "SELF_UNKNOWN")
    assert found.reason.startswith("TAILSCALE_CLI_MISSING")
    assert syscalls.processes() == []


def test_self_node_reports_itself_for_the_envelope():
    found = selfnode.decide(selfnode.parse_status(status()), inventory(), None)
    assert found.to_dict() == {"known": True, "nodeId": "nFactory1CNTRL",
                               "hostname": "claude-factory", "source": "live",
                               "id_agrees": True, "reason": None}
