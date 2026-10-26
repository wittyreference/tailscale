# ABOUTME: `tailnet dns`: the tailnet's DNS settings from the four documented dns:read endpoints, the
# ABOUTME: combined configuration best-effort, and this host's own view: accept-dns and its MagicDNS name.

import socket
from datetime import datetime, timezone

from tailnet import api, localts, output, selfnode
from tailnet.errors import ApiError, LocalError
from tailnet.output import Envelope, format_utc

# Each local tailscale call answers at once on a healthy host; a stalled daemon must not
# hold the whole command for long.
LOCAL_TIMEOUT = 5
_NOT_RUN = "not run: test posture"


def _bad(reply, what):
    """A DNS reply whose shape the spec requires and the server did not send."""
    response = reply.response
    return ApiError("API_BAD_RESPONSE", f"{response.where} → {response.status}: {what}",
                    http_status=response.status, request_id=response.request_id)


def _strings(reply, key):
    """A required list of strings from a reply; null reads as empty, since Go encodes an empty
    slice that way [unverified for this API], but a missing key or another type is refused."""
    doc = reply.data
    if key not in doc:
        raise _bad(reply, f"no {key!r} in the body")
    value = doc[key]
    if value is None:
        return []
    if not (isinstance(value, list) and all(isinstance(item, str) for item in value)):
        raise _bad(reply, f"{key!r} is not a list of strings")
    return value


def settings(session):
    """The four documented dns:read reads [TC L65-75], combined; returns (fields, request IDs).

    Every one must answer: their refusal is an API error like any other read's (exit 4).
    """
    nameservers = api.dns_nameservers(session)
    preferences = api.dns_preferences(session)
    searchpaths = api.dns_searchpaths(session)
    split = api.dns_split(session)
    magic = preferences.data.get("magicDNS")
    if not isinstance(magic, bool):
        raise _bad(preferences, "'magicDNS' is not true or false")
    # A domain maps to its nameservers, or to null [spec 5637-5653].
    if not all(value is None or (isinstance(value, list) and all(isinstance(v, str) for v in value))
               for value in split.data.values()):
        raise _bad(split, "a split-DNS domain maps to something other than nameservers or null")
    fields = {"nameservers": _strings(nameservers, "dns"), "magicDNS": magic,
              "searchPaths": _strings(searchpaths, "searchPaths"), "splitDns": split.data}
    replies = (nameservers, preferences, searchpaths, split)
    return fields, [r.response.request_id for r in replies if r.response.request_id]


def configuration(session):
    """The combined configuration, best-effort: dns:read's documented list does not name this
    endpoint (critic Q23), so a refusal is reported as a warning and the command goes on.

    Returns (the §18 `configuration` field, its request ID, the warning or None).
    """
    try:
        reply = api.dns_configuration(session)
    except ApiError as exc:
        message = (f"{exc.message}; dns:read may not cover this endpoint (unverified); the "
                   "four documented reads are complete without it")
        warning = ("DNS_CONFIGURATION_REFUSED", message, "critic Q23")
        return {"status": exc.http_status, "body": None}, exc.request_id, warning
    response = reply.response
    return {"status": response.status, "body": reply.data}, response.request_id, None


def lookup(name):
    """Resolve a name the way any program on this host would: (resolves, addresses, error)."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError) as exc:
        return False, [], f"{type(exc).__name__}: {exc}"
    return True, sorted({info[4][0] for info in infos}), None


def local_view(posture):
    """This host's side of DNS: its accept-dns preference and whether its MagicDNS name resolves.

    Production only: test posture never runs tailscale, so it reports "not run". A failure
    of either local read is recorded in `error`, said once, and never fails the command.
    """
    view = {"accept_dns": None, "self_dnsname": None, "resolves": None, "addresses": [],
            "error": None}
    if not posture.runs_tailscale:
        return {**view, "error": _NOT_RUN}
    problems = []

    def note(problem):
        """Keep one problem, once: both reads fail alike when the binary is missing."""
        if problem not in problems:
            problems.append(problem)

    try:
        text = localts.get_pref(posture, "accept-dns", LOCAL_TIMEOUT)
        view["accept_dns"] = {"true": True, "false": False}.get(text)
        if view["accept_dns"] is None:
            note(f"`tailscale get accept-dns` printed {text[:40]!r}, not true or false")
    except LocalError as exc:
        note(f"{exc.code}: {exc.message}")
    except localts.Failed as exc:
        note(exc.reason)
    try:
        local = selfnode.parse_status(localts.status_json(posture, LOCAL_TIMEOUT))
        view["self_dnsname"] = local.dns_name
        if not local.dns_name:
            note(local.reason or "the local status has no Self.DNSName")
    except LocalError as exc:
        note(f"{exc.code}: {exc.message}")
    except localts.Failed as exc:
        note(exc.reason)
    if view["self_dnsname"]:
        view["resolves"], view["addresses"], error = lookup(view["self_dnsname"])
        if error:
            note(f"{view['self_dnsname']} did not resolve: {error}")
    view["error"] = "; ".join(problems) or None
    return view


def unresolved_warning(view):
    """The warning for a MagicDNS name that did not resolve, or None when it did or was not tried.

    MagicDNS failed on the droplet once already (critic F3.6). accept-dns=false is a
    documented reason a node ignores the tailnet's DNS, so it is named beside the failure,
    but as a lead, never as the established cause [inference].
    """
    if view["resolves"] is not False:
        return None
    message = f"this host's MagicDNS name {view['self_dnsname']} did not resolve ({view['error']})"
    if view["accept_dns"] is False:
        message += ("; accept-dns is false on this host, a documented reason a node ignores the "
                    "tailnet's DNS settings, though that it is the cause here is not established")
    return "MAGICDNS_UNRESOLVED", message, "critic F3.6"


def _listed(values):
    """A list for a labelled line, or (none)."""
    return ", ".join(values) if values else "(none)"


def _lines(data):
    """The labelled sections of the human view, one line each."""
    split = "; ".join(f"{domain} → {_listed(servers or [])}"
                      for domain, servers in data["splitDns"].items())
    config = data["configuration"]
    if config["body"] is not None:
        config_line = f"configuration: read (HTTP {config['status']})"
    else:
        config_line = (f"configuration: refused (HTTP {config['status']}); the reads above do not "
                       "depend on it")
    local = data["local"]
    if local["error"] == _NOT_RUN:
        local_line = "local view: not run (test posture)"
    else:
        accept = {True: "true", False: "false", None: "unknown"}[local["accept_dns"]]
        if local["resolves"]:
            seen = f"{local['self_dnsname']} resolves to {', '.join(local['addresses'])}"
        elif local["resolves"] is False:
            seen = f"{local['self_dnsname']} does not resolve"
        else:
            seen = "MagicDNS name unknown"
        local_line = f"local view: accept-dns={accept}; {seen}"
        if local["error"]:
            local_line += f" ({local['error']})"
    return [f"nameservers: {_listed(data['nameservers'])}",
            f"MagicDNS: {'on' if data['magicDNS'] else 'off'}",
            f"search paths: {_listed(data['searchPaths'])}",
            f"split DNS: {split or '(none)'}", config_line, local_line]


def run(posture, args):
    """`tailnet dns`: the tailnet's DNS settings and this host's view of them (§18)."""
    session = api.session(posture)
    data, request_ids = settings(session)
    data["configuration"], config_id, refused = configuration(session)
    if config_id:
        request_ids.append(config_id)
    data["local"] = local_view(posture)
    raised = [output.warn(*warning) for warning in (refused, unresolved_warning(data["local"]))
              if warning is not None]
    headline = "OK: DNS settings for the tailnet" + (f", {len(raised)} warnings" if raised else "")
    return Envelope("dns", posture.kind, data=data, warnings=raised, request_ids=request_ids,
                    measured_at=format_utc(datetime.now(timezone.utc)), headline=headline,
                    lines=_lines(data))
