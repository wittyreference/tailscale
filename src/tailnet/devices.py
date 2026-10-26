# ABOUTME: The device inventory: the API's Device normalised, a DEVICE argument resolved to exactly one
# ABOUTME: device, the warnings a listing raises, the never-truncated table, and `tailnet device list`.

import ipaddress
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from tailnet import api, output, protected, selfnode
from tailnet.errors import ApiError, LocalError, Refused
from tailnet.output import Envelope, format_utc

# A key closer than this to expiry is worth a warning before it lapses and the device has
# to re-authenticate (§11.2).
SOON_DAYS = 30
# The API's date-times are RFC 3339. Python 3.10's fromisoformat reads neither the "Z" nor
# the nanoseconds Go can emit, so the parts are taken apart here.
_TIME = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)")
_FOOTER = "{n} of {n} devices (the API does not paginate) (as of {at})"
_COLUMNS = ("HOSTNAME", "NODE ID", "IPV4", "OWNER/TAGS", "ONLINE", "KEY EXPIRY", "TS-SSH", "FLAGS")


def parse_time(text):
    """An aware datetime for an API date-time string, or None when it is not one."""
    if not isinstance(text, str):
        return None
    match = _TIME.fullmatch(text)
    if match is None:
        return None
    stamp, fraction, zone = match.groups()
    micro = (fraction or "")[:6].ljust(6, "0")
    offset = "+00:00" if zone == "Z" else zone
    try:
        return datetime.fromisoformat(f"{stamp}.{micro}{offset}")
    except ValueError:
        return None


def _bad(message):
    """A device the API sent in a shape the CLI cannot act on safely."""
    return ApiError("API_BAD_RESPONSE", message)


def _text(raw, key):
    """A display field: its string, or None when absent or not a string."""
    value = raw.get(key)
    return value if isinstance(value, str) else None


def _flag(raw, key):
    """A boolean field: True or False as sent, None when absent or not a boolean."""
    value = raw.get(key)
    return value if isinstance(value, bool) else None


def _strings(raw, key, node_id):
    """A list-of-strings field that decides targeting or ownership; absent means empty.

    These fields are never read leniently: a tag list that is not a list could make a
    tagged device look user-owned, which changes what a write would do to it.
    """
    value = raw.get(key, [])
    if not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
        raise _bad(f"device {node_id}: {key} is not a list of strings")
    return tuple(value)


def _address(text):
    """An IP address object for comparing spellings, or None when the text is not one."""
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


@dataclass(frozen=True)
class Device:
    """One device as the CLI reasons about it: the API's fields under stable names, plus the raw object.

    Every derived answer that depends on time takes `now`, so the same device gives the same
    answers in a test whatever the date. `is_self` and `protected` are None until the caller
    has resolved self and read MC's protected file; the list never guesses either.
    """

    node_id: str
    id: str | None
    hostname: str | None
    name: str | None
    addresses: tuple
    ipv4: str | None
    ipv6: str | None
    user: str | None
    tags: tuple
    os: str | None
    client_version: str | None
    connected: bool | None
    last_seen: str | None
    key_expiry_disabled: bool | None
    expires: str | None
    ssh_enabled: bool | None
    authorized: bool | None
    external: bool | None
    ephemeral: bool | None
    blocks_incoming: bool | None
    multiple_connections: bool
    update_available: bool | None
    raw: dict = field(repr=False, compare=False)
    is_self: bool | None = None
    protected: str | None = None

    def first_label(self):
        """The MagicDNS name's first label, which is what people usually call the device."""
        return self.name.split(".", 1)[0] if self.name else None

    def label(self):
        """How messages name a device: hostname and nodeId, so a rename never hides which one."""
        return f"{self.hostname or '?'} ({self.node_id})"

    def named_by(self, arg):
        """Whether `arg` names this device by any reference form in §5.1, compared whole.

        The DEVICE resolver and MC's protected list both ask this, so an entry protects
        exactly what the same text as a DEVICE argument would target (amendment A59).
        """
        if arg in (self.node_id, self.id):
            return True
        folded = arg.lower()
        if self.hostname and folded == self.hostname.lower():
            return True
        if self.name and folded.removesuffix(".") == self.name.lower().removesuffix("."):
            return True
        label = self.first_label()
        if label and folded == label.lower():
            return True
        ip = _address(arg)
        return ip is not None and any(_address(text) == ip for text in self.addresses)

    def owner(self):
        """Who owns it: its tags when it has any, else the user who registered it [spec 4496, 4728]."""
        if self.tags:
            return {"kind": "tag", "value": ",".join(self.tags)}
        return {"kind": "user", "value": self.user}

    def control(self):
        """Whether it is online, from connectedToControl, never inferred from lastSeen.

        lastSeen is omitted both while a device is connected and when it was never online
        [spec 4543-4548], so a missing lastSeen means "never" only when the device is known
        to be disconnected, and nothing at all when connectedToControl is missing too.
        """
        if self.connected is True:
            kind = "online"
        elif self.last_seen is not None:
            kind = "at"
        elif self.connected is False:
            kind = "never"
        else:
            kind = None
        return {"online": self.connected, "last_seen": self.last_seen, "last_seen_kind": kind}

    def key_expiry(self, now):
        """The node key's expiry as of `now`: whether it is off, the date, whole days left, expired.

        A disabled expiry has no countdown whatever date the API still reports. Days left
        round down, so a key with 29.9 days left counts as 29.
        """
        if self.key_expiry_disabled:
            return {"disabled": True, "expires": self.expires, "days_left": None,
                    "expired": False}
        when = parse_time(self.expires)
        if when is None:
            return {"disabled": self.key_expiry_disabled, "expires": self.expires,
                    "days_left": None, "expired": None}
        return {"disabled": self.key_expiry_disabled, "expires": self.expires,
                "days_left": (when - now) // timedelta(days=1), "expired": when <= now}

    def tailscale_ssh(self):
        """Whether Tailscale SSH is on: True, False, or None when the API did not say (critic Q12).

        An absent sshEnabled is unknown, never false: treating it as false would send a
        diagnosis down the plain-OpenSSH branch on a guess.
        """
        return self.ssh_enabled

    def flags(self):
        """The short markers the table's FLAGS column shows, in a fixed order."""
        marks = [("self", self.is_self is True), ("protected", self.protected is not None),
                 ("external", self.external is True),
                 ("multi-conn", self.multiple_connections),
                 ("blocks-in", self.blocks_incoming is True),
                 ("update", self.update_available is True)]
        return [name for name, on in marks if on]

    def to_dict(self, now):
        """The normalised JSON object (§11.2), with the untouched API object under `raw`."""
        return {
            "nodeId": self.node_id, "id": self.id, "hostname": self.hostname, "name": self.name,
            "addresses": list(self.addresses), "ipv4": self.ipv4, "ipv6": self.ipv6,
            "user": self.user, "tags": list(self.tags), "owner": self.owner(), "os": self.os,
            "client_version": self.client_version, **self.control(),
            "key_expiry": self.key_expiry(now), "tailscale_ssh": self.tailscale_ssh(),
            "authorized": self.authorized, "external": self.external,
            "ephemeral": self.ephemeral, "blocks_incoming": self.blocks_incoming,
            "multiple_connections": self.multiple_connections,
            "update_available": self.update_available, "self": self.is_self,
            "protected": self.protected, "raw": self.raw,
        }


def normalise(raw):
    """Turn one API Device object into a Device; a shape the CLI cannot act on is a bad response.

    nodeId, addresses and tags are checked strictly because writes target by nodeId, self
    is found by address and ownership comes from tags. Display fields are read leniently:
    a missing version string is shown as unknown, not treated as a fault.
    """
    if not isinstance(raw, dict):
        raise _bad("a device in the list is not a JSON object")
    node_id = raw.get("nodeId")
    if not isinstance(node_id, str) or not node_id:
        raise _bad("a device in the list has no nodeId")
    addresses = _strings(raw, "addresses", node_id)
    parsed = [_address(text) for text in addresses]
    ipv4 = next((text for text, ip in zip(addresses, parsed) if ip and ip.version == 4), None)
    ipv6 = next((text for text, ip in zip(addresses, parsed) if ip and ip.version == 6), None)
    return Device(
        node_id=node_id, id=_text(raw, "id"), hostname=_text(raw, "hostname"),
        name=_text(raw, "name"), addresses=addresses, ipv4=ipv4, ipv6=ipv6,
        user=_text(raw, "user"), tags=_strings(raw, "tags", node_id), os=_text(raw, "os"),
        client_version=_text(raw, "clientVersion"), connected=_flag(raw, "connectedToControl"),
        last_seen=_text(raw, "lastSeen"), key_expiry_disabled=_flag(raw, "keyExpiryDisabled"),
        expires=_text(raw, "expires"), ssh_enabled=_flag(raw, "sshEnabled"),
        authorized=_flag(raw, "authorized"), external=_flag(raw, "isExternal"),
        ephemeral=_flag(raw, "isEphemeral"),
        blocks_incoming=_flag(raw, "blocksIncomingConnections"),
        # The field is omitted unless several devices hold the node key now [spec 4575-4581].
        multiple_connections=raw.get("multipleConnections") is True,
        update_available=_flag(raw, "updateAvailable"), raw=raw)


def annotate(device, *, is_self, protected):
    """The same device marked with what self detection and MC's protected file say about it."""
    return replace(device, is_self=is_self, protected=protected)


def resolve(arg, devices):
    """The one device `arg` names, by nodeId, id, hostname, name, first label or Tailscale IP.

    Matching is exact on whole values and never by substring or prefix. No match and
    several matches are both refusals: "ambiguity is absence's twin", so the resolver names
    every candidate and picks none, and the way out is a nodeId (§5.1).
    """
    arg = arg.strip() if isinstance(arg, str) else ""
    found = [device for device in devices if device.named_by(arg)] if arg else []
    if len(found) == 1:
        return found[0]
    listing = {"who": "agent", "run": "tailnet device list",
               "why": "shows every device's nodeId, hostname and addresses"}
    if not found:
        raise Refused("DEVICE_NOT_FOUND",
                      f"{arg!r} names no device by nodeId, id, hostname, MagicDNS name, its first "
                      "label or Tailscale address; matching is exact, never by substring",
                      next=[listing])
    candidates = "; ".join(f"{d.node_id} {d.hostname or '?'} {d.ipv4 or '-'}" for d in found)
    raise Refused("DEVICE_AMBIGUOUS",
                  f"{arg!r} names {len(found)} devices: {candidates}; name one by its nodeId",
                  next=[listing])


def warnings(device, now):
    """The listing's warnings for one device as (code, message, source), in a fixed order."""
    found = []
    name = device.label()
    expiry = device.key_expiry(now)
    days = expiry["days_left"]
    if expiry["expired"]:
        when = f"on {device.expires}, already passed"
    elif days is not None:
        when = f"in {days} days ({device.expires})"
    else:
        when = f"on {device.expires!r}, a date the CLI cannot read"
    rejoin = "it must re-authenticate to rejoin the tailnet"
    if device.tags and device.key_expiry_disabled is False:
        # Retagging never turned expiry off, so a fleet box drops off the tailnet when its
        # old key lapses (P9) unless someone disables it.
        message = (f"{name} is tagged ({','.join(device.tags)}) but its key expiry is still "
                   f"on: its key expires {when}, and then {rejoin}")
        found.append(("TAGGED_KEY_EXPIRY_ON", message, "TAGS L84"))
    if expiry["expired"] is True:
        found.append(("KEY_EXPIRED", f"{name}: its key expired {device.expires}; {rejoin}",
                      "spec 4555"))
    elif days is not None and days < SOON_DAYS:
        found.append(("KEY_EXPIRES_SOON", f"{name}: its key expires {when}", "spec 4555"))
    if device.multiple_connections:
        message = (f"{name}: node key in use twice: cloned node state; identify the box by SoC "
                   "serial")
        found.append(("MULTIPLE_CONNECTIONS", message, "spec 4575-4581"))
    if device.blocks_incoming:
        message = f"{name} blocks every incoming connection over Tailscale, pings included"
        found.append(("BLOCKS_INCOMING", message, "spec 4594"))
    return found


def _yes_no(value):
    """A boolean for the table: yes, no, or ? when the API did not say."""
    return "?" if value is None else ("yes" if value else "no")


def _expiry_cell(device, now):
    """The KEY EXPIRY cell: off, EXPIRED, whole days left, or ? when unreadable."""
    expiry = device.key_expiry(now)
    if expiry["disabled"]:
        return "off"
    if expiry["expired"]:
        return "EXPIRED"
    return "?" if expiry["days_left"] is None else f"{expiry['days_left']}d"


def render_table(devices, now):
    """The human inventory: one row per device, ending with the N of N line and its time.

    Every device is printed; the footer says how many there are so a reader can see the
    listing is whole (MC's MESH-39 lesson: a list as long as its print limit was truncated).
    """
    rows = [list(_COLUMNS)]
    for d in devices:
        owner = ",".join(d.tags) if d.tags else (d.user or "?")
        rows.append([d.hostname or "?", d.node_id, d.ipv4 or "-", owner, _yes_no(d.connected),
                     _expiry_cell(d, now), _yes_no(d.tailscale_ssh()),
                     ",".join(d.flags()) or "-"])
    widths = [max(len(row[i]) for row in rows) for i in range(len(_COLUMNS))]
    lines = ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip()
             for row in rows]
    lines.append(_FOOTER.format(n=len(devices), at=format_utc(now)))
    return lines


def _marked(posture, found):
    """Mark each device as self or not and protected or not, as far as can be known.

    Returns the marked devices, the SelfNode, the protected file's state ("answered",
    "unanswered" or "unreadable"), the warnings raised and MC's next steps. A list is a read,
    so a self that is unknown or a protected file that cannot be read is reported, not fatal;
    the write guard makes its own decision from the same sources.
    """
    raised, steps = [], []
    try:
        listed = protected.load(posture)
        state = "unanswered" if listed is None else "answered"
    except LocalError as exc:
        listed, state = None, "unreadable"
        raised.append(output.warn(exc.code, f"{exc.message}; the list shows no device as "
                                            "protected, and tag writes are refused"))
        steps.extend(exc.next)
    me = selfnode.resolve_self(posture, found, listed)
    if not me.known:
        raised.append(output.warn(me.refusal, f"self is unknown: {me.reason}; every --apply is "
                                              "refused until it is known"))
    marked = [annotate(d, is_self=(d.node_id == me.device.node_id) if me.known else None,
                       protected=listed.protects(d) if listed is not None else None)
              for d in found]
    return marked, me, state, raised, steps


def fetch(session):
    """Every device, normalised, and the response they came in: the listing and every pre-read.

    A device the CLI cannot act on safely fails the whole read, named by the call it came
    from, so nothing is planned or listed from a partial inventory.
    """
    reply = api.list_devices(session)
    response = reply.response
    try:
        found = [normalise(raw) for raw in reply.data]
    except ApiError as exc:
        raise ApiError(exc.code, f"{response.where} → {response.status}: {exc.message}",
                       http_status=response.status, request_id=response.request_id) from None
    return found, response


def run_list(posture, args):
    """`tailnet device list`: every device with all fields, self and protection, warnings, the table."""
    found, response = fetch(api.session(posture))
    now = datetime.now(timezone.utc)
    found, me, state, raised, steps = _marked(posture, found)
    raised += [output.warn(code, message, source)
               for device in found for code, message, source in warnings(device, now)]
    count = len(found)
    headline = f"OK: {count} devices" + (f", {len(raised)} warnings" if raised else "")
    return Envelope(
        "device list", posture.kind,
        data={"devices": [device.to_dict(now) for device in found], "count": count,
              "self_node_id": me.device.node_id if me.known else None, "self": me.to_dict(),
              "protected_file": state},
        warnings=raised, next=steps,
        request_ids=[response.request_id] if response.request_id else [],
        measured_at=format_utc(now), headline=headline, lines=render_table(found, now))
