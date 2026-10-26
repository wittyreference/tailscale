# ABOUTME: OAuth access tokens: minting one from a client at the token endpoint, and the 0600 cache that
# ABOUTME: lets a read token serve its whole hour. Only read tokens are ever cached; write tokens never are.

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from tailnet import audit, credentials, secure_files
from tailnet.credentials import READ_SCOPES, cacheable
from tailnet.errors import ApiError, LocalError, TailnetError
from tailnet.output import format_utc, warn
from tailnet.redact import REDACTOR

__all__ = ["READ_SCOPES", "ReadToken", "Token", "cache_expiry", "cache_usable", "cacheable",
           "mint"]

TOKEN_PATH = "/oauth/token"
FORM = "application/x-www-form-urlencoded"
CACHE_NAME = "read-token.json"
# §8.2 item 7: a token cache is small; anything larger is not one.
CACHE_MAX = 16 * 1024
# A cached token is dropped this long before it expires, so a long doctor or diagnose run
# never watches its token die mid-command (OC L20: renew "shortly before" expiry).
RENEW_MARGIN = timedelta(seconds=300)
# Every access token lives exactly this long and it cannot be changed [OC L20, L272]; used
# only to say when an unread, unsafe cache stops being dangerous.
TOKEN_LIFE = timedelta(seconds=3600)
_TIME = "%Y-%m-%dT%H:%M:%SZ"
# Shorter than any real token; registering one this short would blank it out of all output.
_MIN_TOKEN = 8


@dataclass(frozen=True)
class Token:
    """An access token minted for one client, and what the token endpoint said about it.

    The token itself is kept out of repr and is registered with the redactor the moment it
    is parsed, so no later output, log line or traceback can show it.
    """

    role: str
    client_id: str
    access_token: str = field(repr=False)
    scope: str | None
    minted_at: datetime
    expires_at: datetime
    request_id: str | None

    @property
    def cacheable(self):
        """Whether this token holds read power only, so may sit on disk for its hour (§9.2)."""
        return cacheable(self.scope)


def _register(value):
    """Register a token for redaction; refuse one too short to be a token at all."""
    if not isinstance(value, str) or len(value) < _MIN_TOKEN:
        return False
    REDACTOR.add_secret(value)
    return True


def _bad_reply(response, why):
    """The token endpoint answered 2xx with something that is not a token response.

    The body is never quoted: it may hold the token itself.
    """
    return ApiError("API_BAD_RESPONSE",
                    f"{response.where} → {response.status}: not an OAuth token response: {why}",
                    http_status=response.status, request_id=response.request_id)


def _parse(response, cred, now):
    """Build the Token from a 2xx token response [OC L132], checking every field it relies on."""
    try:
        doc = json.loads(response.body)
    except ValueError:
        raise _bad_reply(response, "the body is not JSON") from None
    if not isinstance(doc, dict):
        raise _bad_reply(response, "the body is not a JSON object")
    access = doc.get("access_token")
    if not _register(access):
        raise _bad_reply(response, "access_token is missing or too short")
    token_type = doc.get("token_type")
    # RFC 6749 §5.1 token types are case-insensitive.
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise _bad_reply(response, "token_type is not Bearer")
    expires_in = doc.get("expires_in")
    # `True` is an int in Python, so the type is checked exactly.
    if type(expires_in) is not int or expires_in <= 0:
        raise _bad_reply(response, "expires_in is not a positive whole number of seconds")
    scope = doc.get("scope")
    if scope is not None and not isinstance(scope, str):
        raise _bad_reply(response, "scope is not a string")
    # Local time plus the server's lifetime: the server's clock is never trusted for this.
    return Token(role=cred.role, client_id=cred.client_id, access_token=access, scope=scope,
                 minted_at=now, expires_at=now + timedelta(seconds=expires_in),
                 request_id=response.request_id)


def _rejected(cred, response):
    """A 401 from the token endpoint: the client is revoked, or its ID or secret is wrong (§9.1)."""
    return LocalError(
        "TOKEN_REJECTED",
        f"{response.where} → 401: the token endpoint refused the {cred.role} client "
        f"{cred.client_id}: the client may be revoked or mistyped: Trust credentials",
        http_status=401, request_id=response.request_id,
        next=[{"who": "mc", "needs": "console",
               "do": "In the admin console open Settings → Trust credentials, check the "
                     f"{cred.role} client {cred.client_id} exists and is not revoked, then run "
                     f"`tailnet credentials set {cred.role}` over SSH",
               "why": "the client may be revoked or mistyped"}])


def _log(posture, record, *, strict):
    """Append the token.mint line; with `strict`, a line that cannot be written is fatal.

    A write's token is minted only after every guard check, and a write that cannot be
    recorded is not sent (C9), so for the write role the failure stops the command. A read
    changes nothing and the console keeps its own record of the mint (L5), so for a read,
    and for an attempt that is failing anyway, it is a loud warning instead.
    """
    try:
        audit.append(posture, record)
    except LocalError as exc:
        if strict:
            raise
        warn(exc.code, f"{exc.message}; this token mint is not in the local audit log, only "
                       "in the console's")


def _mint_once(posture, transport, cred, scope):
    """One POST to the token endpoint, and the audit line it leaves whatever the outcome."""
    record = {"event": "token.mint", "role": cred.role, "client_id": cred.client_id,
              "scope_requested": scope, "scope_granted": None, "cacheable": False,
              "expires_at": None, "http_status": None, "request_id": None}
    form = [("client_id", cred.client_id), ("client_secret", cred.secret),
            ("grant_type", "client_credentials")]
    if scope is not None:
        form.append(("scope", scope))
    try:
        # A read in the 429 sense: nothing changes on a refused mint, so one retry is safe.
        # A 400 is an answer only when a narrowed scope was asked for (§9.1).
        response = transport.request("POST", TOKEN_PATH, content_type=FORM,
                                     body=urlencode(form).encode("ascii"), idempotent=True,
                                     expect=(400, 401) if scope is not None else (401,))
        record.update(http_status=response.status, request_id=response.request_id)
        if response.status == 401:
            raise _rejected(cred, response)
        if response.status == 400:
            # The narrowed request was refused; mint() asks again without a scope.
            _log(posture, record, strict=False)
            return None
        token = _parse(response, cred, datetime.now(timezone.utc))
    except TailnetError as exc:
        if record["http_status"] is None:
            record.update(http_status=exc.http_status, request_id=exc.request_id)
        _log(posture, record, strict=False)
        raise
    record.update(scope_granted=token.scope, cacheable=token.cacheable,
                  expires_at=format_utc(token.expires_at))
    _log(posture, record, strict=cred.role == "write")
    return token


def mint(posture, transport, cred, *, scope=None):
    """Mint an access token for a client (§9.1) and log it; the caller decides what to keep.

    A form POST of client_id, client_secret and grant_type, plus `scope` only when the
    caller narrows the grant (a single-client read). If the server refuses that narrowed
    request with a 400, it is asked once more with no scope, and whatever it grants is
    classified by cacheable(). A 401 is never retried: it exits 3 with the console steps.
    Every attempt leaves one token.mint line, so MC can match each to the console's
    "Create OAuth access token" event [AUDIT L329].
    """
    token = _mint_once(posture, transport, cred, scope)
    if token is None:
        token = _mint_once(posture, transport, cred, None)
    return token


def _parse_time(text):
    """Read a cache timestamp; None when it is not one."""
    try:
        return datetime.strptime(text, _TIME).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def cache_expiry(doc):
    """When a parsed cache document says its token expires, or None when it does not say."""
    return _parse_time(doc.get("expires_at"))


def cache_usable(doc, client_id, now):
    """Whether a parsed cache document may serve this read client's requests at `now` (§9.3).

    It must be version 1, for this client, hold a scope that is still read-only, and not be
    within RENEW_MARGIN of expiry. Pure, so status reports the cache by the same rule the
    reads use.
    """
    expires_at = cache_expiry(doc)
    return (type(doc.get("v")) is int and doc["v"] == 1
            and doc.get("client_id") == client_id
            and cacheable(doc.get("scope"))
            and expires_at is not None
            and now < expires_at - RENEW_MARGIN)


def _discard(path):
    """Remove a cache file if it is there; True when nothing is left behind."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def _drop_unsafe_cache(path):
    """Unlink a cache that failed the §8.2 checks, unread, and say how long it stays dangerous.

    Its contents are never read, so its expiry comes from when it was written: a token
    lives an hour from its mint, and the cache is written straight after.
    """
    try:
        expires_by = format_utc(datetime.fromtimestamp(os.lstat(path).st_mtime, timezone.utc)
                                + TOKEN_LIFE)
    except OSError:
        expires_by = "an hour after it was written"
    removed = _discard(path)
    warn("TOKEN_CACHE_UNSAFE",
         f"token cache {path} had unsafe permissions and may have been exposed; it expires by "
         f"{expires_by}; " + ("it was removed and a new token is minted" if removed else
                              "it could not be removed; MC removes it by hand"))


class ReadToken:
    """The read token for one command (§9): the cached one while it is good, else a fresh mint.

    The transport calls bearer() for every request and, on a 401, renew() once. A cached
    token may have died before its hour was up (the client was revoked or replaced), so
    renew() drops the cache and mints once; a token minted in this command is never
    renewed, because the same client would get the same answer. Nothing is minted until a
    request needs it.
    """

    def __init__(self, posture, transport):
        self._posture = posture
        self._transport = transport
        self._path = posture.config_dir / CACHE_NAME
        self._cred = None
        self._token = None
        self._from_cache = False
        # Tokens this source minted: each is one "Create OAuth access token" event in MC's
        # console [AUDIT L329], which doctor counts for MC (§16.4).
        self.mints = 0

    @property
    def token(self):
        """The Token in use, or None before any request has needed one."""
        return self._token

    @property
    def from_cache(self):
        """Whether the token in use came from the cache, so cost no mint in this command."""
        return self._from_cache

    def bearer(self):
        """The access token to send, loading or minting it on first use."""
        if self._token is None:
            self._cred = credentials.load_read(self._posture)
            self._token = self._cached()
            self._from_cache = self._token is not None
            if self._token is None:
                self._token = self._mint()
        return self._token.access_token

    def renew(self):
        """After a 401: a fresh token if the rejected one came from the cache, else None."""
        if not self._from_cache:
            return None
        self._from_cache = False
        _discard(self._path)
        self._token = self._mint()
        return self._token.access_token

    def _cached(self):
        """The cached token if §9.3 allows its use now, else None."""
        try:
            raw = secure_files.read_private(self._path, CACHE_MAX)
        except FileNotFoundError:
            return None
        except LocalError:
            _drop_unsafe_cache(self._path)
            return None
        try:
            doc = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(doc, dict) or not _register(doc.get("access_token")):
            return None
        if not cache_usable(doc, self._cred.client_id, datetime.now(timezone.utc)):
            return None
        expires_at = cache_expiry(doc)
        minted_at = _parse_time(doc.get("minted_at")) or expires_at - TOKEN_LIFE
        return Token(role="read", client_id=doc["client_id"], access_token=doc["access_token"],
                     scope=doc["scope"], minted_at=minted_at, expires_at=expires_at,
                     request_id=None)

    def _mint(self):
        """Mint a read token, narrowed in single-client mode, and cache it if it may be cached."""
        # In single-client mode the read client can write, so its reads ask for the four read
        # scopes only (§8.3); otherwise the client's own grant is already read-only.
        single = credentials.mode(self._posture) == "single-client"
        scope = " ".join(READ_SCOPES) if single else None
        token = mint(self._posture, self._transport, self._cred, scope=scope)
        self.mints += 1
        if token.cacheable:
            self._store(token)
        else:
            # This grant can write, so it lives in memory only; an older cache would be a
            # token on disk that nothing uses any more.
            _discard(self._path)
        return token

    def _store(self, token):
        """Write the cache atomically, 0600; a cache that cannot be written only costs a mint."""
        doc = {"v": 1, "client_id": token.client_id, "access_token": token.access_token,
               "scope": token.scope, "minted_at": format_utc(token.minted_at),
               "expires_at": format_utc(token.expires_at)}
        try:
            secure_files.write_private_atomic(self._path, json.dumps(doc).encode("utf-8"))
        except (LocalError, OSError) as exc:
            reason = exc.message if isinstance(exc, LocalError) else exc.strerror
            warn("TOKEN_CACHE_UNWRITABLE",
                 f"could not cache the read token at {self._path}: {reason}; the next command "
                 "mints again")
