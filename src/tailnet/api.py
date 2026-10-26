# ABOUTME: One function per Tailscale API endpoint the CLI uses. Exactly two of them write, each with one
# ABOUTME: fixed request shape; nothing here can delete, expire, rename or re-address a device (§12.3).

import json
import re
from dataclasses import dataclass
from urllib.parse import quote

from tailnet import http, tokens
from tailnet.errors import ApiError, LocalError

JSON = "application/json"
HUJSON = "application/hujson"
# The OAuth scope each call needs, quoted when it is refused with a 403 (§10.2). Whether a
# missing scope gets 403 or 404 is unverified (critic Q4), so messages say "possibly".
SCOPES = {
    "list_devices": "devices:core:read",
    "get_device": "devices:core:read",
    # Any scope may read the key in use; other keys need oauth_keys:read [TC L45; api §9.2].
    "get_key": "oauth_keys:read, though any scope may read its own key",
    "get_routes": "devices:routes:read",
    "get_policy": "policy_file:read",
    "validate_tests": "policy_file:read",
    "validate_policy": "policy_file:read",
    "dns_nameservers": "dns:read",
    "dns_preferences": "dns:read",
    "dns_searchpaths": "dns:read",
    "dns_split": "dns:read",
    # The documented dns:read list does not name this endpoint [TC L65-75; critic Q23].
    "dns_configuration": "dns:read, if it covers this endpoint (unverified)",
    "set_device_tags": "devices:core",
    "disable_key_expiry": "devices:core",
}
# IDs go into request paths only as plain letters and digits, the shape the API gives them
# (`n292kg92CNTRL`, `k123456CNTRL`), so no ID can add a path segment or a query (§5.1).
_ID = re.compile(r"[A-Za-z0-9]+")


@dataclass(frozen=True)
class Session:
    """What one command's API calls share: the transport, and the read token it mints lazily."""

    transport: http.Transport
    read_token: tokens.ReadToken


def session(posture, *, transport=None):
    """Open a Session for this posture; nothing is read or minted until the first call."""
    transport = http.Transport(posture) if transport is None else transport
    return Session(transport, tokens.ReadToken(posture, transport))


@dataclass(frozen=True)
class Reply:
    """A read's answer: the value callers use, and the response it came from (request ID, ETag)."""

    data: object
    response: http.Response


def _node(node_id):
    """A device ID fit for a path; it always comes from the API, so a bad one is a bad response."""
    if not isinstance(node_id, str) or not _ID.fullmatch(node_id):
        raise ApiError("API_BAD_RESPONSE", f"device ID {node_id!r} is not plain letters and "
                                           "digits; it is never put in a request path")
    return quote(node_id, safe="")


def _key(key_id):
    """A key ID fit for a path; it comes from a credential file, so a bad one is a local fault."""
    if not isinstance(key_id, str) or not _ID.fullmatch(key_id):
        raise LocalError("CREDENTIAL_MALFORMED", f"client ID {key_id!r} is not plain letters and "
                                                 "digits; it is never put in a request path")
    return quote(key_id, safe="")


def _get(session, name, path, *, query=None, accept=None):
    """GET with the read token; a read, so the transport may retry it once on a 429."""
    return session.transport.request("GET", path, token=session.read_token, accept=accept,
                                     query=query, idempotent=True, needs_scope=SCOPES[name])


def _object(response):
    """The body as a JSON object, or a bad response: every read here answers with one."""
    doc = response.json()
    if not isinstance(doc, dict):
        raise ApiError("API_BAD_RESPONSE", f"{response.where} → {response.status}: the body is "
                                           "not a JSON object", http_status=response.status,
                       request_id=response.request_id)
    return doc


def _write_token(write_token):
    """Refuse anything but a token minted from the write client: a bug, never a user error."""
    if not (isinstance(write_token, tokens.Token) and write_token.role == "write"):
        raise ValueError("the two writes take the write token minted from write.secret (C10), "
                         "never the read token or a bare string")
    return write_token.access_token


def list_devices(session):
    """Every device in the tailnet, with all fields; the API does not paginate [spec 47-49].

    fields=all is what carries sshEnabled and multipleConnections [api §5.1; spec 4753].
    """
    response = _get(session, "list_devices", "/tailnet/-/devices", query={"fields": "all"})
    devices = _object(response).get("devices")
    if not (isinstance(devices, list) and all(isinstance(d, dict) for d in devices)):
        raise ApiError("API_BAD_RESPONSE", f"{response.where} → {response.status}: no devices "
                                           "array of objects", http_status=response.status,
                       request_id=response.request_id)
    return Reply(devices, response)


def get_device(session, node_id):
    """One device with all fields: the write flow's post-read (§12.6 step 8) [spec 303-325]."""
    response = _get(session, "get_device", f"/device/{_node(node_id)}",
                    query={"fields": "all"})
    return Reply(_object(response), response)


def get_key(session, key_id):
    """A key's record by ID: the self-lookup that reports a client's scopes and tags [api §9.2]."""
    response = _get(session, "get_key", f"/tailnet/-/keys/{_key(key_id)}")
    return Reply(_object(response), response)


def get_routes(session, node_id):
    """A device's routes; the read client lacks devices:routes:read, so doctor expects a refusal."""
    response = _get(session, "get_routes", f"/device/{_node(node_id)}/routes")
    return Reply(_object(response), response)


def get_policy(session, accept):
    """The live policy file as the bytes served, never parsed, with its raw ETag (§14.1).

    HuJSON keeps MC's comments [pol (f)]; JSON is for reading fields such as tagOwners.
    """
    if accept not in (HUJSON, JSON):
        raise ValueError(f"the policy is served as {HUJSON} or {JSON}, not {accept!r}")
    response = _get(session, "get_policy", "/tailnet/-/acl", accept=accept)
    return Reply(response.body, response)


def validate_tests(session, tests):
    """Run a list of tests against the live policy (§14.6); returns the 200 or 400 response.

    A JSON array is "tests against the current policy" [spec 2508-2516]; the endpoint
    changes nothing [spec 2518]. Its verdict is in the body, even on a 200 (critic R2).
    """
    if not isinstance(tests, list):
        raise TypeError("validate_tests sends a JSON array of tests")
    return session.transport.request(
        "POST", "/tailnet/-/acl/validate", token=session.read_token, content_type=JSON,
        body=json.dumps(tests).encode("utf-8"), idempotent=True,
        needs_scope=SCOPES["validate_tests"], expect=(400,))


def validate_policy(session, body, content_type):
    """Validate a whole candidate policy and run its own tests (§14.3); returns the 200 or 400.

    The bytes go as they are: the server is the only parser [critic R1]. A 400 means the
    candidate did not parse, which is a verdict, not an API failure.
    """
    if content_type not in (HUJSON, JSON):
        raise ValueError(f"a policy is sent as {HUJSON} or {JSON}, not {content_type!r}")
    return session.transport.request(
        "POST", "/tailnet/-/acl/validate", token=session.read_token, content_type=content_type,
        body=bytes(body), idempotent=True, needs_scope=SCOPES["validate_policy"], expect=(400,))


def dns_nameservers(session):
    """The tailnet's global nameservers [spec 1546]."""
    response = _get(session, "dns_nameservers", "/tailnet/-/dns/nameservers")
    return Reply(_object(response), response)


def dns_preferences(session):
    """Whether MagicDNS is on [spec 5613-5622]."""
    response = _get(session, "dns_preferences", "/tailnet/-/dns/preferences")
    return Reply(_object(response), response)


def dns_searchpaths(session):
    """The tailnet's DNS search paths [spec 5623-5636]."""
    response = _get(session, "dns_searchpaths", "/tailnet/-/dns/searchpaths")
    return Reply(_object(response), response)


def dns_split(session):
    """The split-DNS map, domain to resolvers [spec 5637-5653]."""
    response = _get(session, "dns_split", "/tailnet/-/dns/split-dns")
    return Reply(_object(response), response)


def dns_configuration(session):
    """The combined DNS configuration; best-effort, since dns:read may not cover it (§18)."""
    response = _get(session, "dns_configuration", "/tailnet/-/dns/configuration")
    return Reply(_object(response), response)


def get_openapi(session):
    """The API's own OpenAPI document as served, for doctor's drift check (§16.1 L11).

    No token goes with it: the document is public [api §12.19], so no credential is loaded
    for a question about the spec. It was served as YAML on 2026-10-26; Accept asks for
    whatever the server's own form is, since a JSON rendering would never match the pin.
    """
    response = session.transport.request("GET", "", query={"outputOpenapiSchema": "true"},
                                         accept="*/*", idempotent=True)
    return Reply(response.body, response)


def set_device_tags(session, node_id, tags, write_token):
    """Write one: replace a device's tags with `tags`, the full new set (§12.4) [spec 541-582].

    Sent exactly once, never retried; every status comes back for the write flow to judge
    against its re-read. The list replaces the old one [api §5.7], so an empty list would
    strip every tag: it is refused here as well as by the guard (TAG_SET_EMPTY).
    """
    bearer = _write_token(write_token)
    if not (isinstance(tags, list) and tags and all(isinstance(t, str) for t in tags)):
        raise ValueError("set_device_tags sends a non-empty list of tag strings")
    return session.transport.request(
        "POST", f"/device/{_node(node_id)}/tags", token=bearer, content_type=JSON,
        body=json.dumps({"tags": tags}).encode("utf-8"), idempotent=False)


def disable_key_expiry(session, node_id, write_token):
    """Write two: turn key expiry off for a device, so it cannot drop off the tailnet (P9).

    The body is the constant {"keyExpiryDisabled": true} [spec 592-609]: no argument can make
    it false, because re-enabling expiry can take a device off the tailnet (R4, §12.3).
    Sent exactly once, never retried.
    """
    bearer = _write_token(write_token)
    return session.transport.request(
        "POST", f"/device/{_node(node_id)}/key", token=bearer, content_type=JSON,
        body=json.dumps({"keyExpiryDisabled": True}).encode("utf-8"), idempotent=False)
