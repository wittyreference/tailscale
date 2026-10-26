# ABOUTME: `tailnet diagnose`, the reachability ladder of DESIGN.md §15: why a port on a device cannot be
# ABOUTME: reached. The verdict, the source identities and the ssh candidate are pure; the TCP probe is real.

import copy
import errno
import ipaddress
import re
import socket
from dataclasses import dataclass

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
    if admitted == "check" and facts.source_tagged:
        dropped = "; the network policy drops it as well" if allowed is False else ""
        return Verdict("TS_SSH_CHECK_FOR_TAGGED",
                       "the ssh section admits this source only in check mode, and an SSH rule "
                       "from a tagged device cannot be in check mode [tsssh L218]: it can never "
                       f"connect this way; an accept-mode rule is MC's decision (MC6){dropped}")
    if layer and allowed and admitted == "denied":
        return Verdict("TS_SSH_POLICY", f"the network allows it, but the ssh section has no rule "
                                        f"admitting this source as {user}, in accept or check mode")
    if layer and allowed and not user:
        return Verdict("TS_SSH_UNVERIFIED", "the network allows it, and on :22 Tailscale SSH "
                                            "decides admission by user: re-run with --ssh-user")
    if allowed is False:
        also = ("; on this Tailscale SSH host the ssh section also needs an accept rule"
                if layer else "")
        return Verdict("POLICY_DROP", "the policy drops it (want Accept, got Drop); a dropped SYN "
                                      f"gets a TSMP reject and no RST, so it looks like a timeout{also}")
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
    if self_mode and tcp == "timeout" and allowed and layer and admitted in SSH_MODES:
        return Verdict("TS_SSH_TIMEOUT_UNEXPLAINED",
                       "the policy and the ssh section admit the source, yet the connection timed "
                       "out; tailscaled claims :22 itself, so a host firewall is probably not in "
                       "the path [inference]")
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
