# ABOUTME: Tests for tailnet.devices: resolving a DEVICE argument to exactly one device, the fields derived
# ABOUTME: from the API's Device, its warnings, and the never-truncated table (DESIGN.md §5.1, §11.1-11.2).

from datetime import datetime, timedelta, timezone

import pytest
from fixturefiles import body

from tailnet import devices, errors

# Every derivation that depends on time takes it as an argument, so these tests never read
# the clock and never change with the calendar.
NOW = datetime(2026, 10, 27, 1, 2, 3, tzinfo=timezone.utc)
AS_OF = "2026-10-27T01:02:03Z"


def spec_example():
    """The spec's per-field Device examples as one API object [spec 4461-4822]."""
    return body("api", "device")


def raw(node_id="nTest001CNTRL", **fields):
    """A small, coherent API Device; `fields` override or add keys (None removes one)."""
    doc = {"nodeId": node_id, "id": "5001", "hostname": "box", "name": "box.tail0000.ts.net",
           "addresses": ["100.64.1.1", "fd7a:115c:a1e0::1:1"], "user": "mc@example.com",
           "tags": [], "os": "linux", "clientVersion": "v1.102.3", "connectedToControl": True,
           "keyExpiryDisabled": False, "expires": "2099-01-01T00:00:00Z", "authorized": True,
           "isExternal": False, "isEphemeral": False, "blocksIncomingConnections": False,
           "updateAvailable": False, "sshEnabled": False}
    for key, value in fields.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


def inventory():
    """Three devices that differ on every reference form the resolver accepts."""
    phone = raw("nPhone01CNTRL", id="1006", hostname="Michaels-iPhone",
                name="iphone192.tail0000.ts.net",
                addresses=["100.64.0.21", "fd7a:115c:a1e0::15"])
    pi5 = raw("nPi5x001CNTRL", id="1004", hostname="pi5", name="pi5.tail0000.ts.net",
              addresses=["100.64.0.13", "fd7a:115c:a1e0::d"])
    return [devices.normalise(spec_example()), devices.normalise(phone), devices.normalise(pi5)]


def refusal(arg, found):
    """Resolve expecting a refusal; return it."""
    with pytest.raises(errors.Refused) as caught:
        devices.resolve(arg, found)
    return caught.value


@pytest.mark.parametrize("arg,node_id", [
    ("n292kg92CNTRL", "n292kg92CNTRL"),                      # nodeId
    ("92960230385", "n292kg92CNTRL"),                        # the legacy numeric id
    ("PANGOLIN", "n292kg92CNTRL"),                           # hostname, ignoring case
    ("michaels-iphone", "nPhone01CNTRL"),                    # a hostname unlike its name
    ("pangolin.tailfe8c.ts.net", "n292kg92CNTRL"),           # the full MagicDNS name
    ("pangolin.tailfe8c.ts.net.", "n292kg92CNTRL"),          # ... with its trailing dot
    ("IPHONE192", "nPhone01CNTRL"),                          # the name's first label
    ("100.87.74.78", "n292kg92CNTRL"),                       # Tailscale IPv4
    ("fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e", "n292kg92CNTRL"),  # Tailscale IPv6
    ("FD7A:115C:A1E0::D", "nPi5x001CNTRL"),                  # IPv6 in another spelling
])
def test_resolve_by_each_reference_form(arg, node_id):
    assert devices.resolve(arg, inventory()).node_id == node_id


@pytest.mark.parametrize("arg", [
    "pango", "pangolin.tailfe8c", "tailfe8c.ts.net", "n292kg92", "9296023038", "100.87.74",
    "100.87.74.7", "fd7a:115c:a1e0", "iphone", "pi", "", "  ", "*",
])
def test_a_substring_never_matches(arg):
    stop = refusal(arg, inventory())
    assert (stop.exit, stop.code) == (5, "DEVICE_NOT_FOUND")
    assert stop.next and stop.next[0]["run"] == "tailnet device list"


def test_an_ambiguous_argument_lists_the_candidates():
    # One device's hostname and another's first label are both "pi5": ambiguity is absence's
    # twin, so the resolver names both and picks neither.
    twin = devices.normalise(raw("nOther01CNTRL", id="2001", hostname="lab-pi",
                                 name="pi5.tail1111.ts.net", addresses=["100.64.9.9"]))
    stop = refusal("pi5", inventory() + [twin])
    assert (stop.exit, stop.code) == (5, "DEVICE_AMBIGUOUS")
    for expected in ("nPi5x001CNTRL", "pi5", "100.64.0.13", "nOther01CNTRL", "lab-pi",
                     "100.64.9.9"):
        assert expected in stop.message
    # The way out is a nodeId, which is never ambiguous.
    assert devices.resolve("nOther01CNTRL", inventory() + [twin]).hostname == "lab-pi"


def test_online_comes_from_connected_to_control_not_last_seen():
    connected = devices.normalise(raw(connectedToControl=True, lastSeen="2020-01-01T00:00:00Z"))
    assert connected.control() == {"online": True, "last_seen": "2020-01-01T00:00:00Z",
                                   "last_seen_kind": "online"}
    gone = devices.normalise(raw(connectedToControl=False,
                                 lastSeen=(NOW - timedelta(minutes=1)).strftime(
                                     "%Y-%m-%dT%H:%M:%SZ")))
    assert gone.control()["online"] is False
    assert gone.control()["last_seen_kind"] == "at"
    # The spec's own examples pair connectedToControl true with a lastSeen; it is online.
    assert devices.normalise(spec_example()).control()["online"] is True


def test_missing_last_seen_while_disconnected_is_never_seen():
    never = devices.normalise(raw(connectedToControl=False, lastSeen=None))
    assert never.control() == {"online": False, "last_seen": None, "last_seen_kind": "never"}
    # lastSeen is omitted while connected [spec 4548], so its absence never means stale.
    online = devices.normalise(raw(connectedToControl=True, lastSeen=None))
    assert online.control() == {"online": True, "last_seen": None, "last_seen_kind": "online"}
    # Without connectedToControl nothing is known, and nothing is guessed.
    unknown = devices.normalise(raw(connectedToControl=None, lastSeen=None))
    assert unknown.control() == {"online": None, "last_seen": None, "last_seen_kind": None}


def test_key_expiry_days_left_uses_injected_now():
    device = devices.normalise(raw(expires="2026-11-06T01:02:03Z"))
    assert device.key_expiry(NOW) == {"disabled": False, "expires": "2026-11-06T01:02:03Z",
                                      "days_left": 10, "expired": False}
    later = NOW + timedelta(days=11)
    assert device.key_expiry(later)["days_left"] == -1
    assert device.key_expiry(later)["expired"] is True
    # Fractional seconds and offsets are read as the instants they are.
    nanos = devices.normalise(raw(expires="2026-11-06T03:02:03.123456789+02:00"))
    assert nanos.key_expiry(NOW)["days_left"] == 10
    # A disabled expiry has no countdown, whatever date the API still reports.
    off = devices.normalise(raw(keyExpiryDisabled=True, expires="2020-01-01T00:00:00Z"))
    assert off.key_expiry(NOW) == {"disabled": True, "expires": "2020-01-01T00:00:00Z",
                                   "days_left": None, "expired": False}
    unreadable = devices.normalise(raw(expires="soon"))
    assert unreadable.key_expiry(NOW)["days_left"] is None
    assert unreadable.key_expiry(NOW)["expired"] is None


def codes(device, now=NOW):
    """The warning codes a device raises, in order."""
    return [code for code, _, _ in devices.warnings(device, now)]


def test_a_tagged_device_with_expiry_on_is_flagged():
    soon = (NOW + timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tagged = devices.normalise(raw(tags=["tag:fleet"], expires=soon))
    [tag_warning, soon_warning] = devices.warnings(tagged, NOW)
    code, message, source = tag_warning
    assert (code, source) == ("TAGGED_KEY_EXPIRY_ON", "TAGS L84")
    assert "12 days" in message and "nTest001CNTRL" in message
    assert soon_warning[0] == "KEY_EXPIRES_SOON"
    # Far from expiry it is still flagged: retagging never turned expiry off [TAGS L84].
    assert codes(devices.normalise(raw(tags=["tag:fleet"]))) == ["TAGGED_KEY_EXPIRY_ON"]
    assert codes(devices.normalise(raw(tags=["tag:fleet"], keyExpiryDisabled=True))) == []
    # A user-owned device's expiry is its owner's re-login cycle, not a fleet hazard.
    assert codes(devices.normalise(raw(tags=[]))) == []
    expired = devices.normalise(raw(expires="2026-10-01T00:00:00Z"))
    assert codes(expired) == ["KEY_EXPIRED"]
    lapsed = devices.normalise(raw(tags=["tag:fleet"], expires="2026-10-01T00:00:00Z"))
    [(code, message, _), expired_warning] = devices.warnings(lapsed, NOW)
    assert (code, expired_warning[0]) == ("TAGGED_KEY_EXPIRY_ON", "KEY_EXPIRED")
    assert "already passed" in message and "in -" not in message


def test_cloned_node_state_and_blocked_incoming_are_warned_with_their_sources():
    found = devices.warnings(devices.normalise(raw(multipleConnections=True,
                                                   blocksIncomingConnections=True)), NOW)
    assert [(code, source) for code, _, source in found] == [
        ("MULTIPLE_CONNECTIONS", "spec 4575-4581"), ("BLOCKS_INCOMING", "spec 4594")]
    assert "SoC serial" in found[0][1]


def test_absent_ssh_enabled_is_unknown_not_false():
    assert devices.normalise(raw(sshEnabled=None)).tailscale_ssh() is None
    assert devices.normalise(raw(sshEnabled=False)).tailscale_ssh() is False
    assert devices.normalise(raw(sshEnabled=True)).tailscale_ssh() is True
    row = devices.render_table([devices.normalise(raw(sshEnabled=None))], NOW)[1]
    assert row.split()[6] == "?"


def test_the_owner_is_the_tags_when_tagged_else_the_user():
    assert devices.normalise(raw(tags=["tag:fleet", "tag:lab"])).owner() == {
        "kind": "tag", "value": "tag:fleet,tag:lab"}
    assert devices.normalise(raw(tags=[])).owner() == {"kind": "user", "value": "mc@example.com"}
    # External devices carry no tags [spec 4728-4739]; they are owned by their user.
    assert devices.normalise(raw(tags=None, isExternal=True)).owner()["kind"] == "user"


def test_the_spec_example_normalises_with_every_field_and_keeps_the_raw_object():
    example = spec_example()
    doc = devices.normalise(example).to_dict(NOW)
    assert doc["raw"] == example
    assert set(doc) == {
        "nodeId", "id", "hostname", "name", "addresses", "ipv4", "ipv6", "user", "tags",
        "owner", "os", "client_version", "online", "last_seen", "last_seen_kind", "key_expiry",
        "tailscale_ssh", "authorized", "external", "ephemeral", "blocks_incoming",
        "multiple_connections", "update_available", "self", "protected", "raw"}
    assert (doc["ipv4"], doc["ipv6"]) == ("100.87.74.78", "fd7a:115c:a1e0:ac82:4843:ca90:697d:c36e")
    assert doc["owner"] == {"kind": "tag", "value": "tag:golink"}
    assert doc["key_expiry"]["expired"] is True
    assert doc["multiple_connections"] is True
    # Self and protection are not the device list's to guess.
    assert (doc["self"], doc["protected"]) == (None, None)


@pytest.mark.parametrize("broken", [
    "not an object", raw(nodeId=None), raw(nodeId=""), raw(nodeId=7), raw(tags="tag:fleet"),
    raw(tags=["tag:fleet", 3]), raw(addresses="100.64.1.1"), raw(addresses=[None]),
])
def test_a_device_without_usable_identity_or_ownership_is_a_bad_response(broken):
    # nodeId, addresses and tags decide what a write targets and who owns it, so a value of
    # the wrong shape stops the command rather than being read as empty.
    with pytest.raises(errors.ApiError) as caught:
        devices.normalise(broken)
    assert caught.value.code == "API_BAD_RESPONSE"


def test_the_table_prints_n_of_n():
    found = [devices.normalise(device) for device in body("scenario", "devices")["devices"]]
    lines = devices.render_table(found, NOW)
    assert lines[0].split() == ["HOSTNAME", "NODE", "ID", "IPV4", "OWNER/TAGS", "ONLINE", "KEY",
                                "EXPIRY", "TS-SSH", "FLAGS"]
    assert len(lines) == len(found) + 2
    assert lines[-1] == f"6 of 6 devices (the API does not paginate) (as of {AS_OF})"
    rows = {line.split()[0]: line.split() for line in lines[1:-1]}
    assert rows["claude-factory"][1:] == ["nFactory1CNTRL", "100.64.0.10", "tag:dev", "yes",
                                          "off", "no", "-"]
    assert rows["nomad-b"][4:] == ["no", f"{(datetime(2099, 1, 1, tzinfo=timezone.utc) - NOW).days}d",
                                   "yes", "update"]
    assert rows["pi5"][6] == "?"
    assert rows["Michaels-iPhone"][3] == "mc@example.com"


def test_the_table_flags_self_protected_external_and_the_warnings():
    device = devices.normalise(raw(isExternal=True, multipleConnections=True,
                                   blocksIncomingConnections=True, updateAvailable=True))
    marked = devices.annotate(device, is_self=True, protected="pi5 (a nodeId survives a rename)")
    assert marked.flags() == ["self", "protected", "external", "multi-conn", "blocks-in",
                              "update"]
    assert devices.render_table([marked], NOW)[1].split()[-1] == \
        "self,protected,external,multi-conn,blocks-in,update"
    assert marked.to_dict(NOW)["self"] is True
    expired = devices.normalise(raw(expires="2026-10-01T00:00:00Z"))
    assert devices.render_table([expired], NOW)[1].split()[5] == "EXPIRED"
