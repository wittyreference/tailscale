# ABOUTME: `tailnet diagnose`, the reachability ladder of DESIGN.md §15: why a port on a device cannot be
# ABOUTME: reached. The verdict, identities and ssh candidate are pure; the probes are real and read-only.

import copy
import errno
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from tailnet import api, devices, localts, output, policy, protected, selfnode
from tailnet.errors import ApiError, LocalError, Negative, Refused, UsageError
from tailnet.output import Envelope, format_utc

# §15.2 step 4: each local probe waits this long. A policy-dropped SYN is never answered,
# so the TCP probe's timeout is also how long a drop takes to show.
PROBE_TIMEOUT = 5
# An open port's first bytes are read for this long: sshd greets at once, so a banner that
# has not arrived by then is not coming [unverified for a Tailscale SSH host].
BANNER_TIMEOUT = 3
BANNER_BYTES = 255
# Tailscale SSH claims this port on the host's Tailscale address [tsssh L40, L410]; on any
# other port the host's own service answers, so the ssh section has no say there.
SSH_PORT = 22
# The host alias the ssh candidate adds: sshTests.dst takes host aliases, not raw IPs [pol (c)].
ALIAS = "tailnet-diag-dst"
SSH_MODES = ("accept", "check")

# A source is a device's identity, never its address [spec 2533-2540]: a tag, or the login
# of the user who owns an untagged device. A login is name@domain, and the domain need not
# hold a dot (Tailscale's GitHub logins end in @github), so only the @ is required.
# Anything else, an address or a wildcard included, is refused.
_IDENTITY = re.compile(r"tag:[A-Za-z0-9][A-Za-z0-9-]*|[^\s@*]+@[^\s@*]+")

# The verdicts that mean the port is reachable (§15.2 step 7); every other one exits 8.
REACHABLE = frozenset({"OPEN", "ADMITTED_CHECK_MODE", "ALLOWED"})
# Verdicts decided before any probe or policy call: the rest of the ladder is not run for
# that destination, because its answer cannot change them (step 3, "first match is final").
EARLY = frozenset({"SOURCE_DOWN", "NOT_FOUND", "AMBIGUOUS", "SAME_DEVICE", "KEY_EXPIRED",
                   "DEST_OFFLINE", "SHIELDS_UP"})
# Verdicts whose cause sits on the destination host, which the source cannot see into: they
# get the on-host block for MC (step 8).
HOST_SIDE = frozenset({"REFUSED_BY_HOST", "HOST_SIDE_DROP", "TS_SSH_TIMEOUT_UNEXPLAINED"})


@dataclass(frozen=True)
class Facts:
    """What the ladder learned about one destination, as the verdict needs it.

    Every field that was not measured stays None, and None is never read as yes or no:
    an unknown sshEnabled, a ping that was not run, a policy test that failed to answer.
    `mode` is "self" (this host is the source and the local probes run) or "from" (an
    API-only source). `source_found` and `dest_found` are "ok" or the step-1 verdict that
    stops the ladder; `dest_found` may also be "SAME_DEVICE". `tcp` is the TCP probe's
    result ("open", "refused", "timeout", "error:<errno>"). `ssh_admitted` is "accept" or
    "check" when the ssh section admitted the source in that mode, "denied" when it
    admitted it in neither, and None when that was not tested or got no answer.
    """

    mode: str
    port: int = SSH_PORT
    source_up: bool | None = None
    source_found: str = "ok"
    source_reason: str | None = None
    source_tagged: bool | None = None
    dest_found: str = "ok"
    dest_reason: str | None = None
    key_expired: bool | None = None
    online: bool | None = None
    last_seen: str | None = None
    blocks_incoming: bool | None = None
    ssh_enabled: bool | None = None
    ssh_host_keys: bool | None = None
    path_ok: bool | None = None
    icmp_ok: bool | None = None
    tcp: str | None = None
    network_allowed: bool | None = None
    ssh_user: str | None = None
    ssh_admitted: str | None = None


@dataclass(frozen=True)
class Verdict:
    """One destination's verdict code (§15.2 step 7) and what it means, in words."""

    code: str
    explanation: str

    @property
    def reachable(self):
        """True for the three verdicts that exit 0."""
        return self.code in REACHABLE


def ts_ssh_layer(facts):
    """Whether Tailscale SSH stands between the source and the port: True, False, or None.

    Only on port 22, and only when sshEnabled says so; an absent sshEnabled leaves it
    unknown, never false (critic Q12).
    """
    if facts.port != SSH_PORT:
        return False
    return facts.ssh_enabled


def _offline(facts):
    """DEST_OFFLINE's words, with lastSeen exactly as the API gave it, or that it gave none."""
    seen = facts.last_seen or "not given"
    # lastSeen is omitted both while connected and when never seen [spec 4548], so its
    # absence is reported as absence, not read as either.
    return (f"the API says it is not connected to control (connectedToControl false; lastSeen: "
            f"{seen})")


def _inconclusive(facts, layer):
    """INCONCLUSIVE's words: what is unknown, and for an unknown sshEnabled both hypotheses."""
    unknown = []
    if facts.mode == "self" and facts.tcp not in ("open", "refused", "timeout"):
        unknown.append(f"the TCP probe gave {facts.tcp or 'no result'}")
    if facts.network_allowed is None:
        unknown.append("the network policy test gave no answer")
    if layer and facts.ssh_admitted is None:
        unknown.append("the ssh section's answer is unknown")
    words = "the facts do not settle it"
    if unknown:
        words += ": " + "; ".join(unknown)
    if layer is None:
        words += ("; sshEnabled is absent, so both hypotheses stand: if Tailscale SSH is on, "
                  "tailscaled answers :22 itself and the ssh section decides admission; if it is "
                  "off, the host's own sshd and firewall decide")
        if facts.ssh_host_keys is not None:
            hint = "lists" if facts.ssh_host_keys else "does not list"
            words += (f"; the local status {hint} SSH host keys for the peer, a weak hint only "
                      "[ipnstate:316]")
    return words


def _ts_ssh_timeout(facts):
    """TS_SSH_TIMEOUT_UNEXPLAINED's words: why the ssh section is not the cause, and what it said.

    tailscaled completes the TCP handshake on :22 itself and asks the ssh section only at SSH
    login [tsssh L61, L118], so the ssh section's answer is a second finding here, never the
    reason the connection timed out (A50).
    """
    admitted, user = facts.ssh_admitted, facts.ssh_user
    if admitted == "accept":
        said = f"the ssh section admits the source as {user}"
    elif admitted == "check" and facts.source_tagged:
        said = (f"once it connects, the ssh section admits this tagged source as {user} only in "
                "check mode, which a tagged source cannot use [tsssh L218]: an accept-mode rule "
                "is MC's decision (MC6)")
    elif admitted == "check":
        said = f"the ssh section admits the source as {user} in check mode only"
    elif admitted == "denied":
        said = (f"once it connects, the ssh section will also refuse it as {user}, in accept or "
                "check mode")
    elif not user:
        said = "the ssh section was not asked: re-run with --ssh-user to learn whether it admits"
    else:
        said = "the ssh section's answer is unknown"
    return ("the policy allows it, yet the connection timed out; tailscaled answers :22 itself "
            "and asks the ssh section only at SSH login, after the TCP handshake, so the ssh "
            "section cannot cause a timeout: the SYN was dropped before tailscaled took it (a "
            "policy change not yet propagated, or traffic the identity test does not represent), "
            "or Tailscale SSH is not running there; while it runs, a host firewall is probably "
            f"not in the path [inference]; separately, {said}; if the policy changed within the "
            "last minute, re-run once first (propagation timing is unverified)")


def verdict(facts):
    """The verdict for one destination: the first row of §15.2 step 7 whose condition holds.

    Pure, so every row is testable without a network. ICMP never enters it: ping passes
    whenever any port is open between the pair, so it says nothing about this one
    [pol TL;DR 1]. Two readings are the safer ones where the table is loose (A31): a
    Tailscale SSH condition applies only on port 22, and check-mode admission is reachable
    only when the network path is known to hold.
    """
    self_mode = facts.mode == "self"
    layer = ts_ssh_layer(facts)
    allowed, admitted, tcp = facts.network_allowed, facts.ssh_admitted, facts.tcp
    user = facts.ssh_user
    if self_mode and facts.source_up is False:
        return Verdict("SOURCE_DOWN", f"this host is not on the tailnet now: {facts.source_reason}")
    if facts.source_found != "ok":
        return Verdict(facts.source_found, f"the source is not exactly one device: "
                                           f"{facts.source_reason}")
    if facts.dest_found == "SAME_DEVICE":
        return Verdict("SAME_DEVICE", "the destination is the source itself; pick another source")
    if facts.dest_found != "ok":
        return Verdict(facts.dest_found, f"the destination is not exactly one device: "
                                         f"{facts.dest_reason}")
    if facts.key_expired:
        return Verdict("KEY_EXPIRED", "its node key expired with key expiry on, so it is off the "
                                      "tailnet until MC re-authenticates it at the host (P9); "
                                      "then disable key expiry so it cannot lapse again")
    if facts.online is False:
        return Verdict("DEST_OFFLINE", _offline(facts))
    if facts.blocks_incoming:
        return Verdict("SHIELDS_UP", "it refuses every incoming tailnet connection "
                                     "(blocksIncomingConnections) [spec 4594]")
    if self_mode and facts.path_ok is False:
        return Verdict("PATH_DOWN", "the TSMP ping failed, and TSMP stops before the policy "
                                    "check: this is connectivity, not policy")
    if self_mode and tcp == "open" and (layer is False or admitted == "accept"):
        said = (" and the ssh section admits the source in accept mode" if layer else "")
        return Verdict("OPEN", f"port {facts.port} accepted a TCP connection from this host{said}; "
                               "if ssh still fails it is the user or the key, which look alike")
    path_holds = (allowed is True) if not self_mode else (tcp == "open")
    if admitted == "check" and facts.source_tagged is False and path_holds:
        return Verdict("ADMITTED_CHECK_MODE", "reachable, but the ssh section admits this user "
                                              "only in check mode: each session needs a browser "
                                              "check every period (P7)")
    # In self mode the probe, not the ssh section, explains a port that did not open: the ssh
    # section is asked only after tailscaled has completed the handshake [tsssh L61], so it
    # can never cause a timeout or a reset (A50). Its answer stays in the explanation.
    probe_decides = self_mode and layer and allowed and tcp != "open"
    if probe_decides and tcp == "timeout":
        return Verdict("TS_SSH_TIMEOUT_UNEXPLAINED", _ts_ssh_timeout(facts))
    if admitted == "check" and facts.source_tagged and not probe_decides:
        dropped = "; the network policy drops it as well" if allowed is False else ""
        return Verdict("TS_SSH_CHECK_FOR_TAGGED",
                       "the ssh section admits this source only in check mode, and an SSH rule "
                       "from a tagged device cannot be in check mode [tsssh L218]: it can never "
                       f"connect this way; an accept-mode rule is MC's decision (MC6){dropped}")
    if layer and allowed and admitted == "denied" and not probe_decides:
        return Verdict("TS_SSH_POLICY", f"the network allows it, but the ssh section has no rule "
                                        f"admitting this source as {user}, in accept or check mode")
    if layer and allowed and not user and not probe_decides:
        return Verdict("TS_SSH_UNVERIFIED", "the network allows it, and on :22 Tailscale SSH "
                                            "decides admission by user: re-run with --ssh-user")
    if allowed is False:
        # Said only when the ssh section did not already admit the source: then both layers
        # need a rule, and fixing the grant alone would end in a TS_SSH verdict.
        also = ("; on this Tailscale SSH host the ssh section also needs an accept rule"
                if layer and admitted not in SSH_MODES else "")
        return Verdict("POLICY_DROP", "the policy drops it (want Accept, got Drop); a dropped "
                                      "SYN gets a TSMP reject and no RST, so it looks like a "
                                      f"timeout{also}")
    if not self_mode and allowed and (layer is False or admitted == "accept"):
        said = (" and the ssh section admits the source in accept mode" if layer else "")
        return Verdict("ALLOWED", f"the policy permits it{said}; no probe is possible from here")
    if self_mode and tcp == "refused" and allowed:
        return Verdict("REFUSED_BY_HOST", "the policy let the SYN through and the host reset it: "
                                          f"nothing listens on port {facts.port} at its Tailscale "
                                          "address (for :22, sshd)")
    if self_mode and tcp == "timeout" and allowed and layer is False:
        return Verdict("HOST_SIDE_DROP", "the policy allows it but the SYN went unanswered: a host "
                                         "firewall, or a service bound to another address; if the "
                                         "policy changed within the last minute, re-run once "
                                         "first (propagation timing is unverified)")
    return Verdict("INCONCLUSIVE", _inconclusive(facts, layer))


def _identity(text):
    """Whether text is a source identity a test may run as: a tag, or a user's email."""
    return isinstance(text, str) and _IDENTITY.fullmatch(text) is not None


def identities(device):
    """The identities a source device acts as (§15.2 step 2), never its address.

    A tagged device is the union of its tags [pol (b)], and the user who registered it no
    longer owns it [spec Device.tags]; an untagged device is its user. A user field that is
    not an email gives no identity, so no test runs as something the policy cannot name.
    """
    if device.tags:
        return tuple(tag for tag in device.tags if _identity(tag))
    return (device.user,) if _identity(device.user) else ()


def _address(text):
    """The text as an IP address, refusing anything else: a name would be looked up."""
    try:
        return ipaddress.ip_address(text)
    except (TypeError, ValueError):
        raise ValueError(f"{text!r} is not an IP address; destinations are addressed by their "
                         "Tailscale IP, never by name") from None


def network_tests(src, dst_ip, port):
    """The one-test array step 5 posts: can identity `src` reach `dst_ip:port` over TCP?

    A Tailscale IP is a documented accept host [pol (c)]; the source must be an identity,
    because the spec's only IP source is its own invalid example [spec 2606-2612].
    """
    if not _identity(src):
        raise ValueError(f"source {src!r} is not a tag or a user email; a test runs as an identity")
    address = _address(dst_ip)
    host = f"[{address}]" if address.version == 6 else str(address)
    return [{"src": src, "proto": "tcp", "accept": [f"{host}:{port}"]}]


def ssh_candidate(live_json, dst_ip, src, user, mode):
    """The candidate policy step 6 validates: the live policy, asking only whether `src` may
    Tailscale-SSH to `dst_ip` as `user` in `mode` (accept or check).

    Pure, and the live copy is never changed. The policy's own tests and sshTests are
    dropped, so only the probe runs; the destination gets a host alias, because sshTests.dst
    takes aliases rather than raw IPs [pol (c)], and the alias never replaces one of MC's
    hosts entries. The candidate lives only in memory and is never written as a draft.
    """
    if mode not in SSH_MODES:
        raise ValueError(f"an ssh probe runs in {' or '.join(SSH_MODES)} mode, not {mode!r}")
    if not _identity(src):
        raise ValueError(f"source {src!r} is not a tag or a user email; a test runs as an identity")
    if not (isinstance(user, str) and user):
        raise ValueError("an ssh probe needs the host username it asks about")
    address = str(_address(dst_ip))
    if not isinstance(live_json, dict):
        raise TypeError("the live policy in its JSON form is not an object")
    candidate = copy.deepcopy(live_json)
    candidate.pop("tests", None)
    candidate.pop("sshTests", None)
    hosts = candidate.get("hosts", {})
    if not isinstance(hosts, dict):
        raise TypeError("the live policy's hosts section is not a map of names to addresses")
    # Compared without case, so no spelling of the alias can shadow an entry of MC's.
    taken = {name.lower() for name in hosts}
    alias, number = ALIAS, 1
    while alias in taken:
        number += 1
        alias = f"{ALIAS}-{number}"
    candidate["hosts"] = {**hosts, alias: address}
    candidate["sshTests"] = [{"src": src, "dst": [alias], mode: [user]}]
    return candidate


@dataclass(frozen=True)
class TcpProbe:
    """The TCP probe's answer: `result` as §15.2 step 4 names it, and an open port's banner.

    The banner is the first bytes the port sent, raw, with any byte that is not UTF-8 shown
    as a backslash escape; None when nothing arrived.
    """

    result: str
    banner: str | None = None


def tcp_probe(ip, port, timeout=PROBE_TIMEOUT, *, banner_timeout=BANNER_TIMEOUT):
    """Try one TCP connection to `ip:port`: open, refused, timeout, or error:<errno>.

    "refused" means an RST came back from the host's own stack. A SYN the policy dropped
    gets a TSMP reject and no RST [pol (d); wrap.go:1234-1252], so it ends as "timeout",
    as does one a host firewall dropped. Only an address is accepted, never a name.
    """
    address = str(_address(ip))
    try:
        connection = socket.create_connection((address, port), timeout=timeout)
    except ConnectionRefusedError:
        return TcpProbe("refused")
    except TimeoutError:
        return TcpProbe("timeout")
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
        return TcpProbe(f"error:{name}")
    with connection:
        connection.settimeout(banner_timeout)
        try:
            banner = connection.recv(BANNER_BYTES)
        except OSError:
            banner = b""
    return TcpProbe("open", banner.decode("utf-8", "backslashreplace") or None)


# --- The command: `tailnet diagnose DEVICE... [--port N] [--ssh-user USER] [--from DEVICE]` ---

# Step 0 gives `tailscale status` as long as self detection does (§11.3).
STATUS_TIMEOUT = selfnode.STATUS_TIMEOUT
NOT_RUN = "not-run: test posture"
# A host username as the ssh test sends it: the portable POSIX set, never starting with a
# hyphen. Anything else, a pasted `<user>` placeholder included, is refused before a request.
_USER = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]{0,63}")
_HELP = {"who": "agent", "run": "tailnet diagnose --help",
         "why": "shows the forms each argument takes"}
_LIST = {"who": "agent", "run": "tailnet device list",
         "why": "lists every device's nodeId, hostname and address; name one exactly"}


def check_args(args):
    """Hold --port and --ssh-user to §5.2 before anything is read or sent; returns (port, user)."""
    if not 1 <= args.port <= 65535:
        raise UsageError("USAGE", f"--port {args.port}: a port is one number from 1 to 65535",
                         next=[dict(_HELP)])
    user = args.ssh_user
    if user is not None and not _USER.fullmatch(user):
        raise UsageError("USAGE", f"--ssh-user {user!r} is not a host username: letters, digits, "
                                  "dots, underscores and hyphens, at most 64, not starting with "
                                  "a hyphen", next=[dict(_HELP)])
    return args.port, user


def source_health(text):
    """Step 0: why this host cannot be a source now, or None when it can.

    The backend must be Running, Self online with Tailscale IPs, and the peer map non-empty:
    a host that sees no peer has nothing to probe, and a stopped backend's stale peer list
    is never trusted [mc §5].
    """
    local = selfnode.parse_status(text)
    if not local.usable:
        return local.reason
    peers = json.loads(text).get("Peer")
    if not (isinstance(peers, dict) and peers):
        return "the local status lists no peers: this host sees nothing else on the tailnet"
    return None


def _addresses(values):
    """The IP addresses among `values`, as address objects; anything else is skipped."""
    found = set()
    for value in values if isinstance(values, (list, tuple)) else ():
        try:
            found.add(ipaddress.ip_address(value))
        except (TypeError, ValueError):
            continue
    return found


def peer_has_host_keys(text, addresses):
    """Whether the local status lists SSH host keys for the peer holding `addresses`.

    A weak hint about Tailscale SSH only [ipnstate:316; pol unverified 13]: True or False
    for exactly one matching peer, None when there is none or the status cannot be read.
    """
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    peers = doc.get("Peer") if isinstance(doc, dict) else None
    if not isinstance(peers, dict):
        return None
    wanted = _addresses(addresses)
    matched = [peer for peer in peers.values()
               if isinstance(peer, dict) and wanted & _addresses(peer.get("TailscaleIPs"))]
    return bool(matched[0].get("sshHostKeys")) if len(matched) == 1 else None


def on_host_block(dest, port, source, source_ip, *, ts_ssh=False):
    """The paste block MC runs on the destination (§15.2 step 8); the CLI never runs it.

    The source cannot reach the destination, which is the problem, so these checks run from
    a session that can. Each line names what it tells apart [pol (d) steps 4-7]; tcpdump and
    ufw are general Linux, not Tailscale's, and how `metrics print` renders the label is
    unverified, hence the grep. With `ts_ssh` (a Tailscale SSH timeout) the capture and the
    firewall check are left out: while Tailscale SSH takes :22, tailscaled's netstack consumes
    the SYN after the filter, so tailscale0 and the host firewall never see it (A51).
    """
    lines = [
        f"# On {dest}, while the agent retries from {source}:",
        ("tailscale metrics print | grep -E 'inbound_dropped_packets_total'   "
         "# reason=\"acl\" rising → Tailscale policy drop (client ≥ 1.78)"),
        ("sudo journalctl -u tailscaled --since '-10min' | "
         f"grep -E 'Drop: TCP\\{{[^}}]*:{port}\\}}'   # \"no rules matched\""),
    ]
    if ts_ssh:
        return "\n".join([
            *lines,
            ("# No tcpdump on tailscale0 and no ufw here: while Tailscale SSH takes this port, "
             "tailscaled's netstack consumes the SYN after the filter, so neither ever sees it"),
            "tailscale get ssh ; tailscale get shields-up",
        ])
    capture = f"tcp port {port}" + (f" and src host {source_ip}" if source_ip else "")
    return "\n".join([
        *lines,
        (f"sudo timeout 20 tcpdump -ni tailscale0 -c 5 '{capture}'   "
         "# SYN seen → passed Tailscale's filter"),
        ("sudo ufw status verbose ; tailscale get ssh ; tailscale get shields-up ; "
         "tailscale get netfilter-mode"),
    ])


def _agent(run, why):
    """A next step the agent takes."""
    return {"who": "agent", "run": run, "why": why}


def _any_pass(answers):
    """Combine per-identity answers: any pass passes; False only when every one said no."""
    if True in answers:
        return True
    if answers and all(answer is False for answer in answers):
        return False
    return None


def _network_answer(found):
    """One network test's answer: True passes, False only for a drop the server named.

    A failure that is not `want: Accept, got: Drop` (a 400, an unknown shape, a line in
    another form) says nothing about the port, so it is no answer rather than a drop.
    """
    if found.passed:
        return True
    if found.reason == "errors" and any(f.get("want") == "Accept" and f.get("got") == "Drop"
                                        for f in found.failures):
        return False
    return None


def _resolved(device):
    """Step 1's record of a destination: the Device fields the ladder reads, named as the API
    names them."""
    return {"nodeId": device.node_id, "hostname": device.hostname, "ipv4": device.ipv4,
            "tags": list(device.tags), "user": device.user, "sshEnabled": device.ssh_enabled,
            "connectedToControl": device.connected, "lastSeen": device.last_seen,
            "keyExpiryDisabled": device.key_expiry_disabled, "expires": device.expires,
            "blocksIncomingConnections": device.blocks_incoming,
            "clientVersion": device.client_version}


@dataclass(frozen=True)
class Source:
    """The source as step 1 found it: its device, or the step-1 verdict and why there is none.

    `up` is step 0's answer (self mode in production only); `self_source` says how self was
    found, "live" or "line".
    """

    mode: str
    device: object = None
    found: str = "ok"
    reason: str | None = None
    self_source: str | None = None
    up: bool | None = None

    def name(self):
        """How the on-host block names the source."""
        return (self.device.hostname or self.device.node_id) if self.device else "this host"

    def to_dict(self, identities):
        """The envelope's `source`."""
        device = self.device
        return {"mode": self.mode, "nodeId": device.node_id if device else None,
                "hostname": device.hostname if device else None,
                "ipv4": device.ipv4 if device else None, "identities": list(identities),
                "self_source": self.self_source, "up": self.up, "found": self.found,
                "reason": self.reason}


def _from_source(arg, inventory):
    """The --from source: the device the argument names, exactly as any DEVICE resolves."""
    try:
        return Source("from", devices.resolve(arg, inventory))
    except Refused as exc:
        found = "AMBIGUOUS" if exc.code == "DEVICE_AMBIGUOUS" else "NOT_FOUND"
        return Source("from", None, found, f"--from {arg}: {exc.message}")


def _self_source(posture, inventory, status_text, raised, steps):
    """This host as the source, found as self detection finds it (§11.3), failing closed.

    In production the live status from step 0 is joined by Tailscale IP and must agree with
    MC's self line; in test posture the self line is the only source. An unknown self stops
    every destination at step 1, since no identity can be named for it.
    """
    try:
        listed = protected.load(posture)
    except LocalError as exc:
        listed = None
        raised.append(output.warn(exc.code, f"{exc.message}; diagnose goes on without the self "
                                            "line"))
        steps.extend(exc.next)
    up = True if posture.runs_tailscale else None
    if posture.runs_tailscale:
        me = selfnode.decide(selfnode.parse_status(status_text), inventory, listed)
    else:
        me = selfnode.from_line(inventory, listed)
    if me.known:
        return Source("self", me.device, self_source=me.source, up=up)
    return Source("self", None, "NOT_FOUND", f"this host's own device is unknown: {me.reason}",
                   me.source, up)


class _Ladder:
    """One run of the ladder: the session, the API calls it made, and the live policy, read once."""

    def __init__(self, posture, session, port, user, inventory, source, status_text):
        self.posture = posture
        self.session = session
        self.port = port
        self.user = user
        self.inventory = inventory
        self.source = source
        self.status_text = status_text
        self.identities = identities(source.device) if source.device else ()
        self.calls = []
        self._live = None

    def made(self, name, response):
        """Record a call that got an answer."""
        self.calls.append({"api": name, "where": response.where, "status": response.status,
                           "request_id": response.request_id, "error": None})

    def failed(self, name, exc):
        """Record a call that ended in an API error."""
        self.calls.append({"api": name, "where": getattr(exc, "where", None),
                           "status": exc.http_status, "request_id": exc.request_id,
                           "error": exc.code})

    def _ask(self, name, send):
        """Send one validate and read its verdict: (response, verdict, error dict or None).

        An API error here is a fact about this destination, reported and judged
        INCONCLUSIVE, never the end of the whole command (§15.2 step 7).
        """
        try:
            response = send()
        except ApiError as exc:
            self.failed(name, exc)
            return None, None, {"code": exc.code, "message": exc.message}
        self.made(name, response)
        try:
            return response, policy.parse_verdict(response.status, response.body), None
        except ApiError as exc:
            return response, None, {"code": exc.code, "message": exc.message}

    def diagnose(self, arg, now):
        """Run the ladder for one DEVICE argument and return its record (§15.2 "Output")."""
        entry = {"dest": arg, "resolved": None, "gates": None, "probes": None,
                 "network_test": [], "ssh_test": [], "policy_warnings": [], "error": None}
        source = self.source
        facts = Facts(mode=source.mode, port=self.port, source_up=source.up,
                      source_found=source.found, source_reason=source.reason,
                      source_tagged=bool(source.device.tags) if source.device else None,
                      ssh_user=self.user)
        dest = None
        try:
            dest = devices.resolve(arg, self.inventory)
        except Refused as exc:
            found = "AMBIGUOUS" if exc.code == "DEVICE_AMBIGUOUS" else "NOT_FOUND"
            facts = replace(facts, dest_found=found, dest_reason=exc.message)
        else:
            facts = self._gates(entry, facts, dest, now)
        if verdict(facts).code not in EARLY:
            facts = self._climb(entry, facts, dest)
        found = verdict(facts)
        entry.update(verdict=found.code, explanation=found.explanation,
                     next=next_steps(found.code, dest, port=self.port, user=self.user,
                                     source=self.source, ids=self.identities,
                                     inventory=self.inventory),
                     measured_at=output.now_utc())
        return entry

    def _gates(self, entry, facts, dest, now):
        """Steps 1 and 3: the destination's record, and the gates that end the ladder early."""
        same = self.source.device is not None and dest.node_id == self.source.device.node_id
        expired = dest.key_expiry(now)["expired"] is True
        hint = (peer_has_host_keys(self.status_text, dest.addresses)
                if self.status_text is not None else None)
        entry["resolved"] = _resolved(dest)
        entry["gates"] = {"same_device": same, "key_expired": expired,
                          "offline": dest.connected is False,
                          "shields_up": dest.blocks_incoming is True}
        return replace(facts, dest_found="SAME_DEVICE" if same else "ok", key_expired=expired,
                       online=dest.connected, last_seen=dest.last_seen,
                       blocks_incoming=dest.blocks_incoming, ssh_enabled=dest.ssh_enabled,
                       ssh_host_keys=hint)

    def _climb(self, entry, facts, dest):
        """Steps 4-6 for a destination the gates let through: probes, network test, ssh layer."""
        ip = dest.ipv4
        if ip is None:
            entry["error"] = ("it has no Tailscale IPv4 address, and destinations are addressed "
                              "by IPv4 (§15)")
            return facts
        if facts.mode == "self":
            facts = self._probe(entry, facts, ip)
        facts = replace(facts, network_allowed=self._network(entry, ip))
        if ts_ssh_layer(facts) and self.user and self.identities:
            facts = replace(facts, ssh_admitted=self._ssh(entry, ip))
        return facts

    def _ping(self, ip, kind):
        """One `tailscale ping`: its exit code is the answer, its output kept raw (step 4)."""
        at = output.now_utc()
        try:
            result = localts.ping(self.posture, ip, kind, PROBE_TIMEOUT)
        except localts.Failed as exc:
            return {"result": "no answer", "exit": None, "output": exc.reason,
                    "measured_at": at}, None
        ok = result.exit == 0
        return {"result": "pong" if ok else f"exit {result.exit}", "exit": result.exit,
                "output": result.output, "measured_at": at}, ok

    def _probe(self, entry, facts, ip):
        """Step 4, self mode: the two pings in production only, the TCP probe in both postures."""
        probes = {}
        if self.posture.runs_tailscale:
            answers = {}
            for kind in localts.PING_KINDS:
                probes[kind], answers[kind] = self._ping(ip, kind)
            path_ok, icmp_ok = answers["tsmp"], answers["icmp"]
        else:
            # Test posture never runs tailscale (D23), so the PATH_DOWN gate is skipped.
            for kind in localts.PING_KINDS:
                probes[kind] = {"result": NOT_RUN, "exit": None, "output": None,
                                "measured_at": output.now_utc()}
            path_ok = icmp_ok = None
        tcp = tcp_probe(ip, self.port)
        probes["tcp"] = {"result": tcp.result, "banner": tcp.banner,
                         "measured_at": output.now_utc()}
        probes["path_ok"], probes["icmp_ok"] = path_ok, icmp_ok
        entry["probes"] = probes
        return replace(facts, path_ok=path_ok, icmp_ok=icmp_ok, tcp=tcp.result)

    def _network(self, entry, ip):
        """Step 5: one array-mode test per source identity against the live policy."""
        answers = []
        for src in self.identities:
            tests = network_tests(src, ip, self.port)
            response, found, error = self._ask(
                "validate_tests", lambda tests=tests: api.validate_tests(self.session, tests))
            record = {"src": src, "accept": tests[0]["accept"][0],
                      "request_id": response.request_id if response else None, "error": error}
            if found is None:
                record.update(verdict=None, allowed=None)
                answers.append(None)
            else:
                allowed = _network_answer(found)
                record.update(found.to_dict(), allowed=allowed)
                answers.append(allowed)
            entry["network_test"].append(record)
        return _any_pass(answers)

    def _live_policy(self):
        """The live policy in its JSON form, read once per run: (object, None) or (None, error)."""
        if self._live is None:
            self._live = self._read_live()
        return self._live

    def _read_live(self):
        """Read the live policy as JSON (step 6.2); its comments are not needed to test it."""
        try:
            reply = api.get_policy(self.session, api.JSON)
        except ApiError as exc:
            self.failed("get_policy", exc)
            return None, {"code": exc.code, "message": exc.message}
        self.made("get_policy", reply.response)
        try:
            doc = reply.response.json()
        except ApiError as exc:
            return None, {"code": exc.code, "message": exc.message}
        if not isinstance(doc, dict):
            return None, {"code": "API_BAD_RESPONSE",
                          "message": "the live policy in its JSON form is not an object"}
        return doc, None

    def _ssh(self, entry, ip):
        """Step 6: accept mode for every identity, then check mode only if none passed.

        Returns "accept", "check", "denied", or None when an answer is missing: an unanswered
        accept test could have passed, so check mode is not asked about after one.
        """
        live, error = self._live_policy()
        if error is not None:
            entry["ssh_test"].append({"src": None, "mode": None, "user": self.user, "alias": None,
                                      "verdict": None, "request_id": None, "error": error})
            return None
        for mode in SSH_MODES:
            outcomes = [self._ssh_one(entry, live, ip, src, mode) for src in self.identities]
            if True in outcomes:
                return mode
            if None in outcomes:
                return None
        return "denied"

    def _ssh_one(self, entry, live, ip, src, mode):
        """Validate one in-memory candidate; True admits, False denies, None is no answer."""
        record = {"src": src, "mode": mode, "user": self.user, "alias": None, "verdict": None,
                  "request_id": None, "error": None}
        entry["ssh_test"].append(record)
        try:
            candidate = ssh_candidate(live, ip, src, self.user, mode)
        except (TypeError, ValueError) as exc:
            record["error"] = {"code": "API_BAD_RESPONSE", "message": str(exc)}
            return None
        record["alias"] = candidate["sshTests"][0]["dst"][0]
        body = json.dumps(candidate).encode("utf-8")
        response, found, error = self._ask(
            "validate_policy", lambda: api.validate_policy(self.session, body, api.JSON))
        record.update(request_id=response.request_id if response else None, error=error)
        if found is None:
            return None
        record.update(verdict=found.verdict, reason=found.reason, message=found.message,
                      errors=[item["line"] for item in found.errors])
        # Warnings come from the live policy itself, not from the probe, so they are
        # reported apart from its answer (§15.2 step 6.6).
        for item in found.warnings:
            said = f"{item['user']}: {item['line']}" if item["user"] else item["line"]
            if said not in entry["policy_warnings"]:
                entry["policy_warnings"].append(said)
        if found.passed:
            return True
        return False if found.reason == "errors" else None


def next_steps(code, dest, *, port, user, source, ids, inventory):
    """What happens next for one verdict, naming who acts (§15.2 step 7's last column).

    Pure: `dest` is the destination Device (None when it did not resolve), `source` the
    Source, `ids` its identities and `inventory` every device, from which the on-host steps
    pick MC's user-owned devices to ask about with --from.
    """
    if code == "SOURCE_DOWN":
        return [_agent("tailscale status", "this host is not on the tailnet now; its local "
                                           "status says why")]
    if code in ("NOT_FOUND", "AMBIGUOUS"):
        return [dict(_LIST)]
    if code == "SAME_DEVICE":
        return [_agent("tailnet device list", "the destination is the source: name another "
                                              "source with --from, or another destination")]
    name = dest.hostname or dest.node_id
    if code == "KEY_EXPIRED":
        return [{"who": "mc", "needs": "terminal",
                 "do": f"re-authenticate {name} at the host, so it rejoins the tailnet",
                 "why": "its key expired with key expiry on, so it is off the tailnet (P9)"},
                _agent(f"tailnet device disable-key-expiry {dest.node_id}",
                       "once it is back: plans turning key expiry off so it cannot lapse "
                       "again; MC approves the apply")]
    if code == "SHIELDS_UP":
        return [{"who": "mc", "needs": "terminal", "do": f"on {name}: tailscale get shields-up",
                 "why": "the API says it refuses every incoming tailnet connection"}]
    if code == "PATH_DOWN":
        return [_agent("tailscale netcheck", "connectivity, not policy: what this host's "
                                             "network allows (the official skill's "
                                             "connectivity.md)"),
                _agent("tailscale status", "whether this host sees the peer, and how")]
    if code == "OPEN" and port == SSH_PORT:
        target = f"{user}@{dest.ipv4}" if user else dest.ipv4
        return [_agent(f"ssh -v {target}", "the port is reachable; a failing ssh is the user "
                                           "or the key, which look alike")]
    sources = " or ".join(ids)
    if code == "TS_SSH_CHECK_FOR_TAGGED":
        keep = "Keep check mode only"
        return [{"who": "ask_mc", "question": {
            "id": "MC6",
            "text": f"Allow {sources} to Tailscale-SSH to {name} in accept mode? A tagged "
                    "source cannot use check mode [tsssh L218], and check mode stays for "
                    "people (P7).",
            "options": [{"label": "Allow accept mode",
                         "description": f"the agent drafts an ssh rule {sources} → {name}, "
                                        "action accept; you apply it in the console"},
                        {"label": keep, "description": f"{sources} cannot Tailscale-SSH to "
                                                       f"{name}; nothing changes"}],
            "safe_default": keep}}]
    if code == "TS_SSH_POLICY":
        return [_agent("tailnet policy draft --name ssh-rule",
                       f"add an ssh rule admitting {sources} to {name} as {user}, then "
                       "validate and diff; MC applies it in the console; re-run this")]
    if code == "TS_SSH_UNVERIFIED":
        via = f" --from {source.device.node_id}" if source.mode == "from" else ""
        return [_agent(f"tailnet diagnose {dest.node_id} --port 22 --ssh-user <user>{via}",
                       "with <user> replaced by the host's username: Tailscale SSH admits by "
                       "user, and usernames differ per host")]
    if code == "POLICY_DROP":
        return [_agent(f"tailnet policy draft --name allow-tcp-{port}",
                       f"add a grant from {sources} to {name} on tcp:{port}, then validate and "
                       "diff; MC applies it in the console; re-run this")]
    if code in HOST_SIDE:
        return _on_host(dest, name, port=port, user=user, source=source, inventory=inventory,
                        ts_ssh=code == "TS_SSH_TIMEOUT_UNEXPLAINED")
    return []


def _on_host(dest, name, *, port, user, source, inventory, ts_ssh=False):
    """Step 8: the block MC runs on the destination, the retry it watches, and the --from
    checks of which of MC's user-owned devices may reach it."""
    me = source.device
    block = on_host_block(name, port, source.name(), (me.ipv4 or me.ipv6) if me else None,
                          ts_ssh=ts_ssh)
    steps = [{"who": "mc", "needs": "terminal", "do": block,
              "why": f"{name} cannot be reached from here, which is the problem: run this on "
                     "it from a session that can reach it (Termius on your phone, or another "
                     "host on the bench) while the agent retries"},
             _agent(f"tailnet diagnose {dest.node_id} --port {port}",
                    f"retries from this host while MC watches on {name}, so the counters "
                    "and the capture see its SYN")]
    ssh = f" --ssh-user {user}" if user else ""
    for other in inventory:
        if other.tags or other.node_id in (dest.node_id, me.node_id if me else None):
            continue
        steps.append(_agent(
            f"tailnet diagnose {dest.node_id} --port {port} --from {other.node_id}{ssh}",
            f"asks the API whether {other.hostname or other.node_id}, a user-owned device, "
            f"may reach {name}"))
    return steps


def _local(posture):
    """Step 0 in production self mode: (status text, why it cannot be a source or None).

    A missing binary is exit 3 (TAILSCALE_CLI_MISSING); a status that gives no answer is a
    source that is down. Test posture runs nothing and reports nothing here.
    """
    if not posture.runs_tailscale:
        return None, None
    try:
        text = localts.status_json(posture, STATUS_TIMEOUT)
    except localts.Failed as exc:
        return None, exc.reason
    return text, source_health(text)


def _yes(value):
    """A boolean for the human view: yes, no, or ? when unknown."""
    return "?" if value is None else ("yes" if value else "no")


def _entry_lines(entry, port):
    """One destination in the human view: its verdict line with its time, then the evidence."""
    resolved = entry["resolved"]
    label = (f"{resolved['hostname'] or resolved['nodeId']} ({resolved['ipv4'] or 'no IPv4'})"
             if resolved else entry["dest"])
    lines = [(f"{label} port {port} → {entry['verdict']} (as of {entry['measured_at']}): "
              f"{entry['explanation']}")]
    if resolved:
        expiry = "off" if resolved["keyExpiryDisabled"] else f"on, expires {resolved['expires']}"
        online, shields = (_yes(resolved["connectedToControl"]),
                           _yes(resolved["blocksIncomingConnections"]))
        lines.append(f"  device: {resolved['nodeId']}; online {online}; key expiry {expiry}; "
                     f"shields-up {shields}; Tailscale SSH {_yes(resolved['sshEnabled'])}")
    if entry["error"]:
        lines.append(f"  not probed: {entry['error']}")
    probes = entry["probes"]
    if probes:
        tcp = probes["tcp"]
        banner = f", banner {json.dumps(tcp['banner'])}" if tcp["banner"] else ""
        lines.append(f"  probes: tsmp {probes['tsmp']['result']}; icmp {probes['icmp']['result']} "
                     f"(never port evidence); tcp {tcp['result']}{banner} "
                     f"(as of {tcp['measured_at']})")
    for test in entry["network_test"]:
        said = test["verdict"] or f"no answer ({test['error']['code']})"
        lines.append(f"  network: {test['src']} → {test['accept']}: {said}")
        lines += [f"    {f['target']}: want {f['want']}, got {f['got']}"
                  for f in test.get("failures", []) if "target" in f]
    for test in entry["ssh_test"]:
        said = test["verdict"] or f"no answer ({test['error']['code']})"
        lines.append(f"  ssh ({test['mode'] or 'live policy'}): {test['src'] or '-'} as "
                     f"{test['user']}: {said}")
        lines += [f"    {line}" for line in test.get("errors", [])]
    lines += [f"  policy warning: {said}" for said in entry["policy_warnings"]]
    return lines


def _source_line(source, ids):
    """The human view's first evidence line: who the source is, and as which identities."""
    if source.up is False:
        return f"source: this host, which is not on the tailnet now ({source.reason})"
    if source.device is None:
        return f"source: unknown ({source.reason})"
    how = {"live": ", self by its Tailscale addresses", "line": ", self from the self line"}
    return (f"source: {source.device.hostname or '?'} ({source.device.node_id}) as "
            f"{', '.join(ids) or 'no identity'}{how.get(source.self_source, '')}")


def _envelope(posture, port, user, source, ids, entries, calls, raised, steps, measured_at):
    """The command's envelope: exit 0 only when every destination is reachable, else exit 8."""
    for entry in entries:
        steps += [step for step in entry["next"] if step not in steps]
    request_ids = []
    for call in calls:
        if call["request_id"] and call["request_id"] not in request_ids:
            request_ids.append(call["request_id"])
    data = {"port": port, "ssh_user": user, "source": source.to_dict(ids),
            "destinations": entries, "calls": calls}
    lines = [_source_line(source, ids)]
    for entry in entries:
        lines += _entry_lines(entry, port)
    fields = {"data": data, "warnings": raised, "request_ids": request_ids,
              "measured_at": measured_at, "lines": lines}
    count = len(entries)
    blocked = [entry for entry in entries if entry["verdict"] not in REACHABLE]
    if not blocked:
        return Envelope("diagnose", posture.kind, next=steps,
                        headline=f"OK: {count} of {count} reachable on port {port}", **fields)
    named = "; ".join(f"{(e['resolved'] or {}).get('hostname') or e['dest']} {e['verdict']}"
                      for e in blocked)
    summary = f"{len(blocked)} of {count} not reachable on port {port}"
    error = Negative("DIAGNOSE_BLOCKED", f"{summary}: {named}", next=steps)
    return Envelope.from_error("diagnose", posture.kind, error, headline=f"BLOCKED: {summary}",
                               **fields)


def run(posture, args):
    """`tailnet diagnose`: why each destination's port is or is not reachable (§15).

    Everything is read-only. Self mode probes from this host; --from asks the API about
    another source and probes nothing. Exit 0 when every destination is OPEN,
    ADMITTED_CHECK_MODE or ALLOWED, 8 otherwise; 3 and 4 when the run itself cannot proceed.
    """
    port, user = check_args(args)
    now = datetime.now(timezone.utc)
    raised, steps = [], []
    if args.from_device is None:
        status_text, problem = _local(posture)
        if problem is not None:
            # Step 0 failed: every destination is SOURCE_DOWN, and no API call is made.
            source = Source("self", None, reason=problem, up=False)
            ladder = _Ladder(posture, None, port, user, [], source, None)
            entries = [ladder.diagnose(arg, now) for arg in args.devices]
            return _envelope(posture, port, user, source, (), entries, [], raised, steps,
                             format_utc(now))
    else:
        status_text = None
    session = api.session(posture)
    inventory, response = devices.fetch(session)
    if args.from_device is None:
        source = _self_source(posture, inventory, status_text, raised, steps)
    else:
        source = _from_source(args.from_device, inventory)
    ladder = _Ladder(posture, session, port, user, inventory, source, status_text)
    ladder.made("list_devices", response)
    entries = [ladder.diagnose(arg, now) for arg in args.devices]
    return _envelope(posture, port, user, source, ladder.identities, entries, ladder.calls,
                     raised, steps, format_utc(now))
