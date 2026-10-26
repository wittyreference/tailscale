# ABOUTME: The read and write OAuth clients in MC's 0600 files: loaded and checked, stored for `credentials
# ABOUTME: set`, the mode they make, and `credentials forget`. No secret comes from argv or the environment.

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from tailnet import audit, output, secure_files
from tailnet.errors import LocalError, Refused, TailnetError
from tailnet.output import Envelope
from tailnet.redact import REDACTOR

# §8.2 item 7: a credential file and a secret file are a few hundred bytes at most.
CREDENTIAL_MAX = 4 * 1024
TOKEN_CACHE = "read-token.json"

# The read client's whole grant, as MC chose it on 2026-10-26 (amendment A1). Single-client
# mode asks for exactly these when it mints a read token (§8.3).
READ_SCOPES = ("devices:core:read", "policy_file:read", "devices:posture_attributes:read",
               "dns:read")

# §7.1. Production takes only an OAuth client secret. Test posture refuses anything that
# looks like a real key, so a real secret copied into a test home is never sent to loopback.
_CLIENT_SECRET = re.compile(r"tskey-client-[A-Za-z0-9_-]+")
_FIXTURE_SECRET = re.compile(r"[A-Za-z0-9_-]{8,256}")
# No valid secret in either posture is shorter: a fixture is at least 8 characters and an
# OAuth client secret at least 14.
_MIN_SECRET = 8
# A client ID is not secret (Tailscale logs it as the actor [TC L392]), but it is sent in a
# form body and printed, so anything with spaces or control characters is a typo.
_CLIENT_ID = re.compile(r"[!-~]{1,256}")

# §8.6: each role's files, secret first, so an interrupted forget leaves metadata without a
# secret (visible, harmless) rather than a secret nothing refers to any more.
_FORGET = {
    "write": ("write.secret", "write.json"),
    "read": ("read.secret", "read.json", TOKEN_CACHE),
    "token": (TOKEN_CACHE,),
}

# §8.6: what `forget` must say every time. Removing a file disarms this host only; the client
# and its live tokens die only when MC revokes it in the console [TC L380-388; cred §6].
NOT_REVOCATION = ("this is not revocation. The client still exists in Tailscale; MC revokes it in "
                  "the console: Trust credentials → Revoke → Revoke")
_REVOKE = {"who": "mc", "needs": "console",
           "do": "Only if the client is no longer wanted or its secret may have been exposed: in "
                 "the admin console open Settings → Trust credentials, select it, then Revoke → "
                 "Revoke",
           "why": "removing files disarms this host only; revoking kills the client and every "
                  "token it has issued, and a new client then needs `credentials set`"}

# Where MC creates the client before `credentials set` can store it [cred §12; OC L34-42].
_CONSOLE_STEPS = (
    "In the admin console open Settings → Trust credentials "
    "(https://console.tailscale.com/admin/settings/trust-credentials), select Credential → OAuth, "
    "choose Read for Devices Core, Policy file, Device posture attributes and DNS and nothing "
    "else, select Generate credential, and copy the client ID and secret into your password "
    "manager: the secret is shown once"
)


def cacheable(scope):
    """Say whether a token with this granted scope holds read power only, so may be cached.

    §9.2: split on whitespace and commas (the multi-scope format is unverified [critic Q5]);
    cacheable only if non-empty and every item ends in `:read`. A missing scope, a legacy
    name such as `devices`, or `all` counts as write power. It lives here because mode()
    needs it and §6 orders credentials before tokens; tokens re-exports it.
    """
    if not isinstance(scope, str):
        return False
    items = [item for item in re.split(r"[\s,]+", scope) if item]
    return bool(items) and all(item.endswith(":read") for item in items)


@dataclass(frozen=True)
class Credential:
    """One OAuth client, secret included, loaded for the length of one command.

    The secret is kept out of repr so a stray print or traceback cannot show it; it is
    registered with the redactor the moment it is read, before any use.
    """

    role: str
    client_id: str
    secret: str = field(repr=False)
    granted_scope: str | None
    set_at: str | None


@dataclass(frozen=True)
class ReadMeta:
    """What read.json records about the read client: everything but its secret.

    `secret_path` is None when the secret is inline in read.json. Status shows only this,
    so it never opens read.secret.
    """

    client_id: str
    secret_path: Path | None
    granted_scope: str | None
    set_at: str | None


@dataclass(frozen=True)
class WriteMeta:
    """What write.json records about the write client: everything but its secret.

    Status, doctor and the guard work from this alone, so the write secret is opened only
    by an --apply that has passed every check (invariant 4, D20).
    """

    client_id: str
    secret_path: Path
    tags: tuple | None
    tags_source: str | None
    granted_scope: str | None
    set_at: str | None


@dataclass(frozen=True)
class Forgotten:
    """What `credentials forget` removed, and whether the audit line could be written."""

    role: str
    removed: tuple
    client_id: str | None
    audit_error: str | None


def _register(secret):
    """Register a secret with the redactor as soon as it is in memory, before any use.

    A value too short to be a secret is refused as malformed anyway, and registering it
    would blank that string out of every later line of ordinary output.
    """
    if len(secret) >= _MIN_SECRET:
        REDACTOR.add_secret(secret)


def _malformed(path, why):
    """A refusal for a file whose contents are wrong; it names the problem, never the contents."""
    return LocalError("CREDENTIAL_MALFORMED", f"{path} is not a valid credential: {why}")


def _missing_read(path):
    """The refusal for mode `none`: what MC does in the console, then the one command to run."""
    return LocalError(
        "CREDENTIAL_MISSING",
        f"no read credential: {path} is missing; MC creates an OAuth client in the console, "
        "then runs `tailnet credentials set read` over SSH",
        next=[
            {"who": "mc", "do": _CONSOLE_STEPS, "needs": "console",
             "why": "the read client does every read; it cannot change the tailnet"},
            {"who": "mc", "do": "tailnet credentials set read", "needs": "terminal",
             "why": "it prompts for the client ID and secret, so neither passes through chat"},
        ])


def _load_doc(posture, role):
    """Read and validate <role>.json (§8.2 item 8); FileNotFoundError when it is absent.

    An inline secret is registered with the redactor here, whatever happens next, because
    it is in memory from this point on.
    """
    path = posture.config_dir / f"{role}.json"
    raw = secure_files.read_private(path, CREDENTIAL_MAX)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _malformed(path, "it is not JSON") from None
    if not isinstance(doc, dict):
        raise _malformed(path, "it is not a JSON object")
    secret = doc.get("client_secret")
    if isinstance(secret, str) and not secret.startswith("file:"):
        _register(secret)
    missing = [key for key in ("v", "role", "client_id", "client_secret") if key not in doc]
    if missing:
        raise _malformed(path, f"missing {', '.join(missing)}")
    # `True == 1` in Python, so the type is checked too.
    if type(doc["v"]) is not int or doc["v"] != 1:
        raise _malformed(path, "only version 1 is understood")
    if doc["role"] != role:
        raise _malformed(path, f"its role is not {role!r}, the role its file name says")
    if not isinstance(doc["client_id"], str) or not _CLIENT_ID.fullmatch(doc["client_id"]):
        raise _malformed(path, "client_id must be the client ID as the console shows it")
    if not isinstance(doc["client_secret"], str):
        raise _malformed(path, "client_secret must be a string")
    for key in ("granted_scope", "set_at", "tags_source"):
        if doc.get(key) is not None and not isinstance(doc[key], str):
            raise _malformed(path, f"{key} must be a string")
    tags = doc.get("tags")
    if tags is not None and not (isinstance(tags, list) and all(isinstance(t, str) for t in tags)):
        raise _malformed(path, "tags must be a list of strings")
    return doc


def _secret_target(posture, role, value, path):
    """Resolve a `file:` client_secret, which must name exactly <config dir>/<role>.secret.

    The Terraform provider's `file:` form [critic R12] could otherwise point anywhere: out of
    the directory the deny rules cover, or, for read.json, at write.secret, which would let
    every read open the write secret (invariant 4).
    """
    expected = posture.config_dir / f"{role}.secret"
    target = value[len("file:"):]
    if not os.path.isabs(target) or Path(os.path.normpath(target)) != expected:
        raise LocalError("CREDENTIAL_UNSAFE",
                         f"refusing {path}: its client_secret must be file:{expected}")
    return expected


def _check_secret(posture, secret, origin):
    """Hold a loaded secret to the posture's format (§7.1); messages never include it."""
    if posture.kind == "test":
        if secret.startswith("tskey-"):
            raise LocalError("TEST_POSTURE_REAL_SECRET",
                             f"{origin} holds a tskey- secret, and this is a test run: a real "
                             "secret is never sent to a loopback API; remove it from the test home")
        if not _FIXTURE_SECRET.fullmatch(secret):
            raise _malformed(origin, "a test secret is 8 to 256 letters, digits, - or _")
        return
    if secret.startswith("tskey-api-"):
        raise _malformed(origin, "it holds an API access token (tskey-api-), refused by name: "
                                 "the CLI takes only an OAuth client secret (tskey-client-), "
                                 "whose scopes MC chose [cred §7]")
    if not _CLIENT_SECRET.fullmatch(secret):
        raise _malformed(origin, "the secret is not an OAuth client secret (tskey-client-…)")


def _load_secret(posture, role, doc, *, missing):
    """Load and check the secret <role>.json names, inline or `file:`.

    `missing(path)` builds the error for a `file:` target that does not exist, because what
    that means differs by role: no read credential (exit 3), or a write refused (exit 5).
    """
    path = posture.config_dir / f"{role}.json"
    value = doc["client_secret"]
    if value.startswith("file:"):
        target = _secret_target(posture, role, value, path)
        try:
            raw = secure_files.read_private(target, CREDENTIAL_MAX)
        except FileNotFoundError:
            raise missing(target) from None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _malformed(target, "it is not text") from None
        # The file holds the secret and one newline, nothing else (§8.1).
        secret = text.removesuffix("\n")
        origin = target
    else:
        secret, origin = value, path
    if not secret:
        raise _malformed(origin, "the secret is empty")
    _register(secret)
    _check_secret(posture, secret, origin)
    return secret


def load_read(posture):
    """Load the read client, secret and all, for a command that is about to mint a read token.

    Every failure exits 3; a missing credential carries the console steps and the one
    command MC runs (§8.3, mode `none`).
    """
    try:
        doc = _load_doc(posture, "read")
    except FileNotFoundError:
        raise _missing_read(posture.config_dir / "read.json") from None
    secret = _load_secret(posture, "read", doc, missing=_missing_read)
    return Credential("read", doc["client_id"], secret, doc.get("granted_scope"),
                      doc.get("set_at"))


def load_read_meta(posture):
    """Load read.json without opening read.secret; None when there is no read client.

    An inline secret is in read.json itself, so it is registered for redaction as the file
    is read, like any secret in memory; a `file:` target is checked but never opened.
    """
    path = posture.config_dir / "read.json"
    try:
        doc = _load_doc(posture, "read")
    except FileNotFoundError:
        return None
    value = doc["client_secret"]
    target = _secret_target(posture, "read", value, path) if value.startswith("file:") else None
    return ReadMeta(doc["client_id"], target, doc.get("granted_scope"), doc.get("set_at"))


def load_write_meta(posture):
    """Load write.json without opening write.secret; None when there is no write client.

    write.json must name its secret with `file:` (§8.1): an inline secret would put the
    write secret in every process that only wanted the metadata (D20).
    """
    path = posture.config_dir / "write.json"
    try:
        doc = _load_doc(posture, "write")
    except FileNotFoundError:
        return None
    if not doc["client_secret"].startswith("file:"):
        raise LocalError("WRITE_SECRET_INLINE",
                         f"{path} holds the write secret inline; it must say file:"
                         f"{posture.config_dir / 'write.secret'}; MC re-runs "
                         "`tailnet credentials set write`")
    target = _secret_target(posture, "write", doc["client_secret"], path)
    tags = doc.get("tags")
    return WriteMeta(doc["client_id"], target, None if tags is None else tuple(tags),
                     doc.get("tags_source"), doc.get("granted_scope"), doc.get("set_at"))


def load_write_secret(posture, meta):
    """Open write.secret: only an --apply that has passed every guard check calls this (C10).

    A secret that has gone missing since write.json was read refuses the write before
    anything is sent (exit 5).
    """
    def missing(path):
        """A vanished write secret refuses the write: nothing has been sent yet."""
        return Refused("WRITE_CREDENTIAL_MISSING",
                       f"{path} is missing; nothing was sent; MC runs "
                       "`tailnet credentials set write` to arm writes again")

    secret = _load_secret(posture, "write", {"client_secret": f"file:{meta.secret_path}"},
                          missing=missing)
    return Credential("write", meta.client_id, secret, meta.granted_scope, meta.set_at)


def mode(posture):
    """Name the configured mode (§8.3): "none", "read-only", "two-client" or "single-client".

    Opens no secret file. A read client whose granted scope is not read-only makes this
    single-client with or without write.json: its read tokens could write, so reads must be
    minted narrowed and the separate-secret lever (L2) is absent.
    """
    try:
        read_doc = _load_doc(posture, "read")
    except FileNotFoundError:
        return "none"
    if not cacheable(read_doc.get("granted_scope")):
        return "single-client"
    meta = load_write_meta(posture)
    if meta is None:
        return "read-only"
    if meta.client_id == read_doc["client_id"]:
        return "single-client"
    return "two-client"


def typed(posture, role, client_id, secret):
    """The client MC typed at the terminal for `credentials set`, held to the rules a loaded one is.

    The secret is registered with the redactor before any check, so no refusal, warning or
    traceback after this point can show it; a message names the problem, never the value.
    """
    _register(secret)
    origin = f"the {role} client typed at the terminal"
    if not _CLIENT_ID.fullmatch(client_id):
        raise _malformed(origin, "the client ID must be the ID as the console shows it, with no "
                                 "spaces")
    if not secret:
        raise _malformed(origin, "the secret is empty")
    _check_secret(posture, secret, origin)
    return Credential(role, client_id, secret, None, None)


def ensure_config_dir(posture):
    """Create the config directory 0700, or tighten it to 0700, and return it (§8.4 step 3).

    A directory that is a symlink or belongs to someone else is refused: whoever controls it
    could swap the files written into it.
    """
    path = posture.config_dir
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(path)
    except OSError as exc:
        raise LocalError("CREDENTIAL_UNSAFE", f"cannot create {path}: {exc.strerror}") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise LocalError("CREDENTIAL_UNSAFE", f"refusing {path}: it is not a directory you own")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def store(posture, cred, *, granted_scope, set_at, tags=None, tags_source=None):
    """Write <role>.secret, then <role>.json naming it with `file:`, each 0600 and atomic (§8.5).

    The secret goes first, so an interruption leaves a secret nothing names yet rather than
    metadata pointing at a secret that is not there. Both roles name their secret with `file:`
    (§8.1), so status, doctor and the guard read the metadata without opening it. Returns the
    two paths written.
    """
    config = ensure_config_dir(posture)
    role = cred.role
    secret_path, doc_path = config / f"{role}.secret", config / f"{role}.json"
    doc = {"v": 1, "role": role, "client_id": cred.client_id,
           "client_secret": f"file:{secret_path}", "set_at": set_at,
           "granted_scope": granted_scope}
    if role == "write":
        doc.update(tags=list(tags or ()), tags_source=tags_source)
    try:
        secure_files.write_private_atomic(secret_path, (cred.secret + "\n").encode("utf-8"))
        secure_files.write_private_atomic(doc_path, json.dumps(doc).encode("utf-8"))
    except OSError as exc:
        raise LocalError("CREDENTIAL_UNSAFE", f"cannot write the {role} client into {config}: "
                                              f"{exc.strerror}") from None
    return secret_path, doc_path


def _metadata_for_log(posture, role):
    """The non-secret facts a forget line records, read best-effort: a broken file must not
    stop MC removing it."""
    try:
        doc = _load_doc(posture, "write" if role == "write" else "read")
    except (FileNotFoundError, TailnetError):
        return {"client_id": None, "granted_scope": None, "tags": None, "tags_source": None}
    return {"client_id": doc["client_id"], "granted_scope": doc.get("granted_scope"),
            "tags": doc.get("tags"), "tags_source": doc.get("tags_source")}


def forget(posture, role):
    """Remove a role's files (`write` disarms writes), then log `credential.forget` (§8.6).

    It only removes power, so it never prompts and any agent may run it. It does not revoke
    anything: the client still exists in Tailscale until MC revokes it in the console. The
    files go first and the log line after, so the disarm never waits on the log; a log that
    cannot be written comes back in `audit_error`. A file that cannot be removed raises,
    because reporting a disarm that did not happen would be worse than failing.
    """
    if role not in _FORGET:
        raise ValueError(f"forget takes read, write or token, not {role!r}")
    facts = _metadata_for_log(posture, role)
    removed = []
    for name in _FORGET[role]:
        path = posture.config_dir / name
        try:
            os.unlink(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise LocalError("CREDENTIAL_UNSAFE",
                             f"could not remove {path}: {exc.strerror}; the {role} credential "
                             "is still in place") from None
        removed.append(name)
    try:
        audit.append(posture, {"event": "credential.forget", "role": role, **facts,
                               "removed": removed})
        audit_error = None
    except LocalError as exc:
        audit_error = f"{exc.code}: {exc.message}"
    return Forgotten(role, tuple(removed), facts["client_id"], audit_error)


def run_forget(posture, args):
    """`tailnet credentials forget {read|write|token}`: remove the files, say it is not revocation.

    Exit 0 whatever was there: removing power never prompts and never waits on the log, and
    a log line that could not be written is a warning, since the disarm itself happened
    (A13). Only a file that cannot be removed fails (CREDENTIAL_UNSAFE, exit 3).
    """
    done = forget(posture, args.role)
    raised = []
    if done.audit_error is not None:
        code, _, message = done.audit_error.partition(": ")
        raised.append(output.warn(code, f"{message}; the files are gone, but this forget is not "
                                        "in the local audit log"))
    who = {"write": "the write client", "read": "the read client",
           "token": "the cached read token"}[args.role]
    named = f" {done.client_id}" if done.client_id and args.role != "token" else ""
    if done.removed:
        headline = f"OK: forgot {who}{named}: removed {', '.join(done.removed)}"
    else:
        headline = f"OK: nothing to forget: {who} has no files on this host"
    lines = [NOT_REVOCATION]
    if args.role == "token":
        lines.append("a removed token stays valid until it expires, at most an hour; revoking "
                     "the read client ends it now")
    return Envelope("credentials forget", posture.kind,
                    data={"role": args.role, "removed": list(done.removed),
                          "client_id": done.client_id, "audit_error": done.audit_error,
                          "not_revocation": NOT_REVOCATION},
                    warnings=raised, next=[dict(_REVOKE)], measured_at=output.now_utc(),
                    headline=headline, lines=lines)
