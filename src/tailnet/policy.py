# ABOUTME: The policy flows of DESIGN.md §14, pure half: the /acl/validate verdict, want/got lines, the
# ABOUTME: array-body scan, the raw ETag, draft readiness and `policy test`'s arguments. Never parses HuJSON.

import ipaddress
import json
import re
from dataclasses import dataclass

from tailnet.errors import ApiError, UsageError
from tailnet.http import body_says

PASS = "pass"
PASS_WITH_WARNINGS = "pass-with-warnings"
FAIL = "fail"
PASSING = frozenset({PASS, PASS_WITH_WARNINGS})

# How a failing test names an address in a validate answer [spec 2660-2667]. Anything else is
# kept verbatim: a line the parser half-understood would be worse than one shown as it came.
_WANT_GOT = re.compile(r'address "([^"]+)": want: (\w+), got: (\w+)')
# The keys a validate answer documents [spec 2640-2675]. A key outside these could carry a
# failure in a form this parser cannot read, so such a body is never read as a pass.
_ANSWER_KEYS = frozenset({"message", "data"})
_ENTRY_KEYS = frozenset({"user", "errors", "warnings"})

# Readiness reasons (§14.4). The first four are the spec's words; the last three name drift
# the spec's two checks would otherwise report as something it is not.
NOT_VALIDATED = "not validated"
CHANGED = "candidate changed since validate: re-run `policy validate`"
FAILED = "validation failed"
MOVED = "MC's console changed the policy since this draft (ETag moved): re-draft"
BYTES_MOVED = "the live policy's bytes changed since this draft, though its ETag did not: re-draft"
NO_ETAG = ("the live policy came without an ETag, so a console change since this draft cannot be "
           "ruled out")
BASE_CHANGED = "base.hujson no longer holds the bytes this draft was made from: re-draft"

# §5.2's policy test rules. A source is one of the documented identities [spec 2533-2540];
# a raw IP is refused because the spec's only IP source is its own invalid example
# [spec 2606-2612], and `autogroup:` is none of the four forms.
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+")
_GROUP = re.compile(r"group:\S+")
_TAG = re.compile(r"tag:[A-Za-z0-9][A-Za-z0-9-]*")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
# Digits and dots, or hex and colons: an address, however short, never a host alias.
_ADDRESS_LIKE = re.compile(r"[0-9.]+|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
_PORT = re.compile(r"[0-9]{1,5}")
_PROTO = re.compile(r"[a-z0-9-]{1,32}")
# ICMP has no ports, so its tests use port 0 [pol (c)]: by name or by IANA number (1, and 58
# for IPv6).
_ICMP = frozenset({"icmp", "1", "ipv6-icmp", "58"})
_TEST_HELP = {"who": "agent", "run": "tailnet policy test --help",
              "why": "shows the forms SRC and HOST:PORT take"}


@dataclass(frozen=True)
class Verdict:
    """What /acl/validate said about a candidate or a set of tests, read from its body.

    The status says little: a failed test is HTTP 200 (critic R2), so the body decides.
    `reason` names what the verdict rests on: None for an empty pass, "errors",
    "warnings", "message without data", "unknown shape", or "HTTP 400" (the candidate did
    not parse). `errors` and `warnings` keep each line verbatim with the user whose test
    produced it.
    """

    verdict: str
    status: int
    reason: str | None = None
    message: str | None = None
    errors: tuple = ()
    warnings: tuple = ()

    @property
    def passed(self):
        """True for a pass, with or without warnings: both exit 0 (§14.3)."""
        return self.verdict in PASSING

    @property
    def failures(self):
        """Each error line as {user, target, want, got}, or {user, raw} when it names no address."""
        return [{"user": entry["user"], **parsed} for entry in self.errors
                for parsed in parse_want_got([entry["line"]])]

    def messages(self):
        """The server's words in the order it gave them, for a draft's meta.json (§14.3)."""
        said = [self.message] if self.message else []
        return said + [_attributed(entry) for entry in (*self.errors, *self.warnings)]

    def to_dict(self):
        """The verdict as the envelope's data carries it."""
        return {"verdict": self.verdict, "status": self.status, "reason": self.reason,
                "message": self.message, "failures": self.failures,
                "warnings": [dict(entry) for entry in self.warnings]}


def _attributed(entry):
    """A line with the user it came from, as one string."""
    return f"{entry['user']}: {entry['line']}" if entry["user"] else entry["line"]


def parse_want_got(lines):
    """Split failure lines into {target, want, got}; a line in any other form is kept as {raw}.

    `address "2.2.2.2:22": want: Drop, got: Accept` is the documented form [spec 2660-2667].
    """
    parsed = []
    for line in lines:
        match = _WANT_GOT.fullmatch(line.strip())
        parsed.append({"target": match[1], "want": match[2], "got": match[3]} if match
                      else {"raw": line})
    return parsed


def _lines(doc):
    """The (errors, warnings) of a validate answer, or None when its shape is not the documented one."""
    if not isinstance(doc, dict) or not set(doc) <= _ANSWER_KEYS:
        return None
    if doc.get("message") is not None and not isinstance(doc["message"], str):
        return None
    data = doc.get("data")
    if data is None:
        return (), ()
    if not isinstance(data, list):
        return None
    errors, warnings = [], []
    for entry in data:
        if not isinstance(entry, dict) or not set(entry) <= _ENTRY_KEYS:
            return None
        user = entry.get("user")
        if user is not None and not isinstance(user, str):
            return None
        for key, found in (("errors", errors), ("warnings", warnings)):
            # Go encodes an empty list as null, so null is read as none.
            items = entry.get(key)
            items = [] if items is None else items
            if not (isinstance(items, list) and all(isinstance(item, str) for item in items)):
                return None
            found.extend({"user": user, "line": item} for item in items)
    return tuple(errors), tuple(warnings)


def parse_verdict(status, body):
    """Read /acl/validate's answer as pass, pass-with-warnings or fail (§14.3; critic R2).

    200 and an empty body or {} passes; errors fail; warnings alone pass with warnings; a
    message without data fails; any other 200 fails as an unknown shape, so nothing the
    parser does not recognise can read as a pass. A 400 is the server failing to parse the
    candidate, which is a verdict on it. Any other status, or a 200 body that is neither
    empty nor JSON, is a malformed answer (exit 4).
    """
    if status == 400:
        return Verdict(FAIL, status, "HTTP 400", body_says(body))
    if status != 200:
        raise ApiError("API_BAD_RESPONSE", f"/acl/validate answered HTTP {status}, which is "
                                           "neither a verdict (200) nor a parse failure (400)",
                       http_status=status)
    if not body.strip():
        return Verdict(PASS, status)
    try:
        doc = json.loads(body)
    except ValueError:
        raise ApiError("API_BAD_RESPONSE", "/acl/validate → 200: the body is neither empty nor "
                                           f"JSON: {body_says(body)}", http_status=status) from None
    if doc == {}:
        return Verdict(PASS, status)
    lines = _lines(doc)
    if lines is None:
        return Verdict(FAIL, status, "unknown shape", body_says(body))
    errors, warnings = lines
    message = doc.get("message")
    if errors:
        return Verdict(FAIL, status, "errors", message, errors, warnings)
    if warnings:
        return Verdict(PASS_WITH_WARNINGS, status, "warnings", message, errors, warnings)
    if message is not None and doc.get("data") is None:
        return Verdict(FAIL, status, "message without data", message)
    return Verdict(FAIL, status, "unknown shape", body_says(body))


_BOM = b"\xef\xbb\xbf"
_SPACE = b" \t\r\n"


def is_array_body(data):
    """Whether a body starts with `[` once leading whitespace and comments are skipped.

    A scan of the start only, not a parser (§5.2): the server picks its mode from the
    body's shape [api §6.3], and an array would run tests against the live policy instead of
    validating the candidate. An unterminated comment hides everything after it.
    """
    data = bytes(data)
    at = len(_BOM) if data.startswith(_BOM) else 0
    while at < len(data):
        if data[at] in _SPACE:
            at += 1
        elif data.startswith(b"//", at):
            end = data.find(b"\n", at)
            if end < 0:
                return False
            at = end + 1
        elif data.startswith(b"/*", at):
            end = data.find(b"*/", at + 2)
            if end < 0:
                return False
            at = end + 2
        else:
            return data[at:at + 1] == b"["
    return False


def check_validate_body(data):
    """Refuse an array-shaped body before anything is sent (VALIDATE_ARRAY_BODY, exit 2)."""
    if is_array_body(data):
        raise UsageError("VALIDATE_ARRAY_BODY",
                         "a tests array runs against the live policy: use `tailnet policy test`",
                         next=[{"who": "agent", "run": "tailnet policy test --help",
                                "why": "tests the live policy; validate is for a whole candidate"}])


def display_etag(raw):
    """The ETag for display: one surrounding pair of double quotes stripped (critic R3).

    The raw header is what is stored, because If-Match wants it back quoted.
    """
    if raw is not None and len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1]
    return raw


def new_meta(name, etag_raw, sha256, fetched_at, request_id):
    """A new draft's meta.json (§14.2): where its base came from, and no verdict yet."""
    return {"v": 1, "name": name, "base_etag_raw": etag_raw, "base_sha256": sha256,
            "fetched_at": fetched_at, "request_id": request_id, "validated": None}


@dataclass(frozen=True)
class Readiness:
    """Whether a draft is ready for MC to apply, and every reason it is not (§14.4)."""

    ready: bool
    reasons: tuple


def readiness(meta, *, base_sha256, candidate_sha256, live_etag_raw, live_sha256):
    """READY only when the candidate as it stands passed validate and the live policy has not
    moved since the draft (§14.4).

    Drift is checked first: a policy MC changed in the console would show up in the diff as
    a reversal of MC's own edit, and validating again would not fix that. A missing ETag
    cannot vouch for an unmoved policy, so it is never READY.
    """
    reasons = []
    if base_sha256 != meta["base_sha256"]:
        reasons.append(BASE_CHANGED)
    if live_etag_raw is None:
        reasons.append(NO_ETAG)
    elif live_etag_raw != meta["base_etag_raw"]:
        reasons.append(MOVED)
    elif live_sha256 != meta["base_sha256"]:
        reasons.append(BYTES_MOVED)
    validated = meta.get("validated")
    if not validated:
        reasons.append(NOT_VALIDATED)
    elif validated.get("sha256") != candidate_sha256:
        reasons.append(CHANGED)
    elif validated.get("verdict") not in PASSING:
        reasons.append(FAILED)
    return Readiness(not reasons, tuple(reasons))


def _address_like(text):
    """Whether text is an IP address or network, bracketed or not, or shaped like one."""
    bare = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ipaddress.ip_network(bare, strict=False)
        return True
    except ValueError:
        return bool(_ADDRESS_LIKE.fullmatch(bare))


def _is_ipv6(text):
    """Whether text is a bare IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except ValueError:
        return False


def _usage(code, message):
    """A policy test argument refused before any request (exit 2)."""
    return UsageError(code, message, next=[dict(_TEST_HELP)])


def _source(src):
    """Hold SRC to the identities a test may run as (§5.2)."""
    if _address_like(src):
        raise _usage("TEST_SRC_IS_IP", f"--src {src} is an IP address; a test runs as an "
                                       "identity: a user email, group:…, tag:… or a host alias")
    if not any(form.fullmatch(src) for form in (_EMAIL, _GROUP, _TAG, _ALIAS)):
        raise _usage("USAGE", f"--src {src!r} is not a user email, group:…, tag:… or a bare "
                              "host alias")


def _destination(entry, icmp):
    """Hold one HOST:PORT to §5.2: a single port, IPv6 in brackets, no CIDR, port 0 for ICMP."""
    host, colon, port = entry.rpartition(":")
    if not colon or not host:
        raise _usage("USAGE", f"{entry!r} is not HOST:PORT")
    if not _PORT.fullmatch(port) or int(port) > 65535:
        raise _usage("TEST_PORT", f"{entry!r}: the port must be one number from 0 to 65535, "
                                  "never a range or a list")
    if host.startswith("["):
        if not (host.endswith("]") and _is_ipv6(host[1:-1])):
            raise _usage("USAGE", f"{entry!r}: brackets hold an IPv6 address")
    elif _is_ipv6(host):
        raise _usage("USAGE", f"{entry!r}: write an IPv6 destination as [address]:port")
    if "/" in host:
        raise _usage("USAGE", f"{entry!r}: a test destination cannot be a CIDR range")
    if (int(port) == 0) != icmp:
        raise _usage("TEST_PORT", f"{entry!r}: port 0 is for --proto icmp, and an ICMP test "
                                  "takes port 0 [pol (c)]")


def build_tests(src, accept, deny, proto):
    """The one-test array `policy test` sends, after §5.2's checks (each failure exits 2).

    No `*` anywhere [spec 2574, 2585]; SRC an identity, never an IP; each destination a
    single port. At least one --accept or --deny, since a test that asserts nothing passes
    and says nothing. `proto` is sent only when given, lowercased.
    """
    accept, deny = list(accept), list(deny)
    if any("*" in text for text in (src, proto or "", *accept, *deny)):
        raise _usage("TEST_WILDCARD", "a test cannot use `*`: name a specific user, group, tag, "
                                      "host and port")
    _source(src)
    if not (accept or deny):
        raise _usage("USAGE", "policy test needs at least one --accept HOST:PORT or "
                              "--deny HOST:PORT")
    if proto is not None:
        proto = proto.lower()
        if not _PROTO.fullmatch(proto):
            raise _usage("USAGE", f"--proto {proto!r} is not a protocol name or number")
    for entry in (*accept, *deny):
        _destination(entry, proto in _ICMP)
    test = {"src": src}
    if proto is not None:
        test["proto"] = proto
    if accept:
        test["accept"] = accept
    if deny:
        test["deny"] = deny
    return [test]
