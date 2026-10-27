# ABOUTME: Who am I: reads `tailscale status --json` and joins this host to exactly one API device by its
# ABOUTME: Tailscale IPs, failing closed; in test posture self is the protected file's self line instead.

import ipaddress
import json
from dataclasses import dataclass

from tailnet import localts
from tailnet.errors import LocalError

# §11.3: long enough for a busy daemon, short enough that a hung one does not stall a write.
STATUS_TIMEOUT = 10


@dataclass(frozen=True)
class LocalStatus:
    """What the local tailscale says about this host, and why it cannot identify self, if it cannot.

    `reason` is None only when the backend is Running, Self is online and has Tailscale
    IPs: a stopped backend still reports a stale peer list [mc §5], so anything less is not
    trusted for who-am-I.
    """

    backend_state: str | None
    online: bool | None
    ips: tuple
    id: str | None
    hostname: str | None
    dns_name: str | None
    tags: tuple
    reason: str | None

    @property
    def usable(self):
        """Whether this status may be used to find self."""
        return self.reason is None


@dataclass(frozen=True)
class SelfNode:
    """The answer to "which device is this host?", and how sure it is.

    `known` is True only for exactly one device the rules accept. When it is False,
    `refusal` is the guard's code for it (SELF_UNKNOWN, or SELF_LINE_DISAGREES when MC's
    self line names another device) and `reason` says why in words. `source` is "live" for
    the IP join, "line" for test posture's self line. `id_agrees` records whether the API's
    nodeId equals the local Self.ID; that they are one string is an inference, so it is
    recorded and never required.
    """

    known: bool
    device: object
    source: str | None
    id_agrees: bool | None
    reason: str | None
    refusal: str | None

    def to_dict(self):
        """The envelope's view of self: never the whole device, which the listing already has."""
        device = self.device
        return {"known": self.known, "nodeId": device.node_id if device else None,
                "hostname": device.hostname if device else None, "source": self.source,
                "id_agrees": self.id_agrees, "reason": self.reason}


def _unknown(reason, device=None, source=None, id_agrees=None, refusal="SELF_UNKNOWN"):
    """A SelfNode that refuses every --apply, with the reason it gives."""
    return SelfNode(False, device, source, id_agrees, reason, refusal)


def _unusable(reason):
    """A LocalStatus that says only why it cannot be used."""
    return LocalStatus(None, None, (), None, None, None, (), reason)


def _address(text):
    """An IP address object, or None when the text is not one."""
    try:
        return ipaddress.ip_address(text)
    except (TypeError, ValueError):
        return None


def _text(doc, key):
    """A string field of the status, or None when it is absent or not a string."""
    value = doc.get(key)
    return value if isinstance(value, str) else None


def parse_status(text):
    """Read `tailscale status --json` text into a LocalStatus; pure, so every rule is testable.

    Field names are ipnstate's: BackendState [ipnstate:43], Self.ID [:239],
    Self.TailscaleIPs [:255], Self.Tags, Self.Online [:280].
    """
    try:
        doc = json.loads(text)
    except ValueError:
        return _unusable("`tailscale status --json` did not print JSON")
    if not isinstance(doc, dict):
        return _unusable("`tailscale status --json` did not print a JSON object")
    state = doc.get("BackendState")
    me = doc.get("Self")
    if not isinstance(me, dict):
        return LocalStatus(state, None, (), None, None, None, (),
                           f"the status has no Self (BackendState {state!r})")
    raw_ips = me.get("TailscaleIPs")
    ips = tuple(raw_ips) if isinstance(raw_ips, list) else ()
    tags = me.get("Tags")
    online = me.get("Online") if isinstance(me.get("Online"), bool) else None
    if state != "Running":
        reason = (f"BackendState is {state!r}, not 'Running': a stopped backend still reports "
                  "a stale peer list")
    elif online is not True:
        reason = "Self.Online is not true: this host is not connected to the tailnet now"
    elif not ips or not all(isinstance(ip, str) and _address(ip) for ip in ips):
        reason = "Self.TailscaleIPs is empty or not a list of addresses"
    else:
        reason = None
    return LocalStatus(
        backend_state=state if isinstance(state, str) else None, online=online, ips=ips,
        id=_text(me, "ID"), hostname=_text(me, "HostName"), dns_name=_text(me, "DNSName"),
        tags=tuple(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else (),
        reason=reason)


def _candidates(local, devices):
    """Every API device that holds one of this host's Tailscale addresses."""
    mine = {_address(ip) for ip in local.ips} - {None}
    return [d for d in devices if mine & {_address(a) for a in d.addresses}]


def join(local, devices):
    """The one API device whose addresses meet this host's Tailscale IPs, or None (D6).

    None covers both zero matches (the read credential belongs to another tailnet) and
    several (unknown); decide() tells the two apart for its reason.
    """
    if not local.usable:
        return None
    found = _candidates(local, devices)
    return found[0] if len(found) == 1 else None


def decide(local, devices, protected):
    """Production self detection from a parsed status (§11.3 steps 2-4); pure.

    Exactly one device must share this host's Tailscale IPs. When MC's protected file has a
    self line, it must name that same device, or every --apply refuses with
    SELF_LINE_DISAGREES until MC re-records it.
    """
    if not local.usable:
        return _unknown(local.reason)
    found = _candidates(local, devices)
    addresses = ", ".join(local.ips)
    if not found:
        return _unknown(f"no API device holds this host's Tailscale addresses ({addresses}): "
                        "the read credential may belong to another tailnet")
    if len(found) > 1:
        names = "; ".join(f"{d.node_id} {d.hostname or '?'}" for d in found)
        return _unknown(f"{len(found)} API devices hold this host's Tailscale addresses "
                        f"({addresses}): {names}")
    device = found[0]
    id_agrees = device.node_id == local.id
    if protected is not None and protected.self_node_id != device.node_id:
        return _unknown(f"the protected file's self line names {protected.self_node_id}, but this "
                        f"host is {device.node_id} ({device.hostname or '?'}) by its Tailscale "
                        "addresses: MC re-records the self line",
                        device, "live", id_agrees, "SELF_LINE_DISAGREES")
    return SelfNode(True, device, "live", id_agrees, None, None)


def from_line(devices, protected):
    """Test-posture self detection: the protected file's self line, naming exactly one device.

    Test posture never runs tailscale (D23), so the line is the only source; without one
    self is unknown and every --apply refuses there (§11.3).
    """
    if protected is None:
        return _unknown("test posture takes self from the protected file's self line, and there "
                        "is no protected file")
    found = [d for d in devices if d.node_id == protected.self_node_id]
    if len(found) != 1:
        return _unknown(f"the self line names {protected.self_node_id}, which matches "
                        f"{len(found)} API devices, not exactly one")
    return SelfNode(True, found[0], "line", None, None, None)


def resolve_self(posture, devices, protected):
    """Find self for this posture: the live IP join in production, the self line in test posture.

    Never raises for an unknown self: every failure, a missing binary included, becomes a
    SelfNode that refuses --apply and says why, so read commands still answer.
    """
    if not posture.runs_tailscale:
        return from_line(devices, protected)
    try:
        text = localts.status_json(posture, timeout=STATUS_TIMEOUT)
    except LocalError as exc:
        return _unknown(f"{exc.code}: {exc.message}")
    except localts.Failed as exc:
        return _unknown(exc.reason)
    return decide(parse_status(text), devices, protected)
