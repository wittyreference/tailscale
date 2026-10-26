# ABOUTME: The policy flows of DESIGN.md §14: the pure verdict, want/got, array-scan and readiness rules,
# ABOUTME: then `policy get|draft|validate|diff|test`. The CLI never parses HuJSON: the server does.

import hashlib
import ipaddress
import json
import os
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from tailnet import api, audit, output, secure_files
from tailnet.errors import ApiError, LocalError, UsageError
from tailnet.http import body_says
from tailnet.output import Envelope, format_utc
from tailnet.redact import redact

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


# --- Drafts and `policy get` (§14.1, §14.2) -------------------------------------------------

_NAME = re.compile(r"[a-z0-9-]{1,40}")
DEFAULT_NAME = "draft"
BASE, CANDIDATE, META = "base.hujson", "candidate.hujson", "meta.json"
_FORMATS = {"hujson": api.HUJSON, "json": api.JSON}
_LABELS = {"hujson": "HuJSON", "json": "JSON"}
# The parts §14.1 counts: rule lists, then name-to-value maps.
_LISTS = ("acls", "grants", "ssh", "tests", "sshTests")
_MAPS = ("hosts", "groups", "tagOwners")
# Drafts sit in the state directory beside the audit log, so a state directory that cannot
# hold them is reported as one that cannot hold the log, as the apply lock is (A26).
_STATE_CODE = "AUDIT_UNWRITABLE"


def check_name(name):
    """A draft's --name, held to §5.2 before any request; a draft without one is "draft"."""
    if name is None:
        return DEFAULT_NAME
    if not _NAME.fullmatch(name):
        raise UsageError("USAGE", f"--name {name!r} must be 1-40 lowercase letters, digits and "
                                  "hyphens")
    return name


def draft_dir_name(moment, name):
    """A draft directory's name: the UTC time of its fetch, then its name (§14)."""
    return f"{moment.astimezone(timezone.utc):%Y%m%dT%H%M%SZ}-{name}"


def sections(doc):
    """How many of each part a policy in its JSON form holds (§14.1); None for a part whose
    shape no policy file has."""
    counts = {}
    for key, kind in [*((k, list) for k in _LISTS), *((k, dict) for k in _MAPS)]:
        value = doc.get(key, kind())
        counts[key] = len(value) if isinstance(value, kind) else None
    return counts


def _sha256(data):
    """The hex sha256 the draft records and readiness compares."""
    return hashlib.sha256(data).hexdigest()


def _line_count(data):
    """Lines in a body, a last line without its newline included."""
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def _plural(count, word):
    """`1 line`, `2 lines`."""
    return f"{count} {word}{'' if count == 1 else 's'}"


def _inside(path, directory):
    """Whether `path` is `directory` or below it, both already resolved."""
    return path == directory or directory in path.parents


def _out_path(posture, out):
    """Where --out may write, resolved and checked before anything is fetched.

    Never into the CLI's own directories, where the file could replace a credential or
    rewrite the audit log (invariant 6); never into a directory others can write, where the
    0600 file could be swapped after it lands (§8.2 item 6).
    """
    real = Path(os.path.realpath(out))
    for own in (posture.config_dir, posture.state_dir):
        if _inside(real, Path(os.path.realpath(own))):
            raise UsageError("USAGE", f"--out {out} is inside {own}, which holds the CLI's own "
                                      "files; write the policy somewhere else")
    try:
        problems = secure_files.check_parent(real, os.geteuid())
    except OSError as exc:
        raise UsageError("USAGE", f"--out {out}: its directory cannot be used: "
                                  f"{exc.strerror}") from None
    if problems:
        raise UsageError("USAGE", f"--out {out}: " + "; ".join(problems))
    return real


def _write_out(real, out, data):
    """Write --out's bytes 0600 and atomically; a refusal is the argument's fault (exit 2)."""
    try:
        secure_files.write_private_atomic(real, data)
    except LocalError as exc:
        raise UsageError("USAGE", f"--out {out}: {exc.message}") from None
    except OSError as exc:
        raise UsageError("USAGE", f"--out {out}: cannot write it: {exc.strerror}") from None


def _etag_line(etag_raw):
    """The ETag as shown, with the raw header beside it."""
    if etag_raw is None:
        return "etag: none (the response carried no ETag header)"
    return f"etag: {display_etag(etag_raw)} (raw header: {etag_raw})"


def run_get(posture, args):
    """`tailnet policy get`: the live policy exactly as served, its metadata beside it (§14.1).

    The bytes go to stdout (or --out, 0600) and the ETag, hash and line count to stderr.
    The JSON form is parsed only to count its sections; HuJSON is never parsed.
    """
    out = None if args.out is None else _out_path(posture, args.out)
    reply = api.get_policy(api.session(posture), _FORMATS[args.format])
    response, raw = reply.response, reply.data
    measured_at = output.now_utc()
    counted, raised = None, []
    if args.format == "json":
        doc = response.json()
        if not isinstance(doc, dict):
            raise ApiError("API_BAD_RESPONSE", f"{response.where} → {response.status}: the "
                                               "policy is not a JSON object",
                           http_status=response.status, request_id=response.request_id)
        counted = sections(doc)
        raised.append(output.warn(
            "POLICY_JSON_NO_COMMENTS", "comments are not in this form: the JSON form leaves out "
            "MC's comments; read or draft the default HuJSON form to keep them",
            "pol (f), inference"))
    # Decoded with surrogateescape so even a byte that is not UTF-8 is written back unchanged.
    text = raw.decode("utf-8", "surrogateescape")
    if out is not None:
        _write_out(out, args.out, redact(text).encode("utf-8", "surrogateescape"))
    count, digest = _line_count(raw), _sha256(raw)
    headline = (f"OK: the live policy as {_LABELS[args.format]}, {_plural(count, 'line')}"
                + (f", written to {args.out}" if out is not None else ""))
    lines = [_etag_line(response.etag_raw), f"sha256: {digest}"]
    if counted is not None:
        lines.append("sections: " + ", ".join(f"{key} {value}" for key, value in counted.items()))
    data = {"text": None if out is not None else raw.decode("utf-8", "replace"),
            "etag_raw": response.etag_raw, "etag": display_etag(response.etag_raw),
            "sha256": digest, "format": args.format, "sections": counted, "lines": count,
            "out": None if out is None else args.out}
    return Envelope("policy get", posture.kind, data=data, warnings=raised,
                    request_ids=[response.request_id] if response.request_id else [],
                    measured_at=measured_at, headline=headline, lines=lines,
                    stdout_text=None if out is not None else text)


def _new_draft(posture, dirname):
    """Create a draft's directory, 0700, under the state directory's drafts/ (§14)."""
    audit.state_dir(posture)
    try:
        posture.drafts_dir.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise LocalError(_STATE_CODE, f"cannot create {posture.drafts_dir}: "
                                      f"{exc.strerror}") from None
    path = posture.drafts_dir / dirname
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise UsageError("USAGE", f"a draft {dirname} was made this second already; pass another "
                                  "--name or run it again") from None
    except OSError as exc:
        raise LocalError(_STATE_CODE, f"cannot create {path}: {exc.strerror}") from None
    return path


def _write_draft_file(path, data):
    """Write one draft file 0600 and atomically, so a reader never sees half of it."""
    try:
        secure_files.write_private_atomic(path, data, code=_STATE_CODE)
    except OSError as exc:
        raise LocalError(_STATE_CODE, f"cannot write {path}: {exc.strerror}") from None


def _meta_bytes(meta):
    """meta.json's bytes; redacted like any record the CLI writes, though it holds no secret."""
    return (redact(json.dumps(meta, indent=2)) + "\n").encode("utf-8")


def run_draft(posture, args):
    """`tailnet policy draft`: the live HuJSON as a new draft the agent edits as text (§14.2).

    base.hujson and candidate.hujson are the bytes as served; meta.json records where they
    came from, so diff can tell a console change from the agent's own edit.
    """
    name = check_name(args.name)
    reply = api.get_policy(api.session(posture), api.HUJSON)
    response, raw = reply.response, reply.data
    fetched = datetime.now(timezone.utc)
    digest = _sha256(raw)
    meta = new_meta(name, response.etag_raw, digest, format_utc(fetched), response.request_id)
    path = _new_draft(posture, draft_dir_name(fetched, name))
    for filename, data in ((BASE, raw), (CANDIDATE, raw), (META, _meta_bytes(meta))):
        _write_draft_file(path / filename, data)
    quoted = shlex.quote(str(path))
    lines = [f"path: {path}",
             f"{BASE} and {CANDIDATE} are the live bytes, sha256 {digest}; "
             + _etag_line(response.etag_raw),
             ("Edit candidate.hujson as text (the Edit tool); keep MC's comments; add tests (and "
              "sshTests for a Tailscale SSH host) asserting the intended access"),
             "then validate until it exits 0, diff until READY, and MC applies it in the console"]
    steps = [{"who": "agent", "run": f"tailnet policy validate {quoted}",
              "why": "after editing: the server parses the candidate and runs its own tests"},
             {"who": "agent", "run": f"tailnet policy diff {quoted}",
              "why": "READY only after a passing validate, with the live policy unchanged"}]
    data = {"path": str(path), "name": name, "files": [BASE, CANDIDATE, META],
            "base_etag_raw": response.etag_raw, "base_etag": display_etag(response.etag_raw),
            "base_sha256": digest, "fetched_at": meta["fetched_at"],
            "request_id": response.request_id}
    return Envelope("policy draft", posture.kind, data=data, next=steps,
                    request_ids=[response.request_id] if response.request_id else [],
                    measured_at=meta["fetched_at"], headline=f"OK: draft {path.name} of the live "
                                                             "policy", lines=lines)
