# ABOUTME: The transport: the only code that sends HTTP to the Tailscale API. No redirects, proxies per
# ABOUTME: posture, full TLS in production, the 429 rule for reads, and writes sent exactly once (§10).

import email.utils
import http.client
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlencode

from tailnet import __version__
from tailnet.errors import ApiError, LocalError
from tailnet.redact import redact

USER_AGENT = f"tailnet/{__version__} (+wittyreference/tailscale)"
JSON = "application/json"
# Per request, not per command: a long doctor run makes many requests (§10.1).
TIMEOUT = 20
# Nothing this CLI reads comes near this; a larger body is a fault, not data (§10.1).
MAX_BODY = 8 * 1024 * 1024
# §10.2's 429 rule for reads: one retry, after Retry-After, never longer than this.
RETRY_AFTER_CAP = 30
# Retry-After is undocumented for this API [api §3.5]; when it is absent, wait this long.
RETRY_AFTER_DEFAULT = 5
# The error text quotes at most this much of a body that is not the API's {"message": …} shape.
EXCERPT = 200

_CONSOLE_FIX = {
    "who": "mc", "needs": "console",
    "do": "In the admin console open Settings → Trust credentials and check the read client "
          "exists and is not revoked; if it is gone, create one and run "
          "`tailnet credentials set read` over SSH",
    "why": "the API refused the token: the client may be revoked, or its ID or secret mistyped",
}


class NoResponse(ApiError):
    """A request that got no usable response (exit 4), and whether it may have reached the API.

    Reads only need the exit code. A write needs `sent` (§10.2, §12.6): False means the API
    cannot have acted, so the write is reported rejected and not sent; True means it may
    have landed, so its outcome comes from the re-read and it is never re-applied. `where`
    is the method and path, as a Response gives them, for the write's audit line.
    """

    def __init__(self, code, message, *, sent, where=None, **details):
        super().__init__(code, message, **details)
        self.sent = sent
        self.where = where


@dataclass(frozen=True)
class Response:
    """One HTTP response, kept for the caller to read: the status, the body as bytes, and the
    request ID, raw ETag and Date that errors, the audit log and doctor's clock check need.
    """

    method: str
    where: str
    status: int
    headers: dict = field(repr=False)
    body: bytes = field(repr=False)
    request_id: str | None
    etag_raw: str | None
    date: str | None

    def json(self):
        """Parse the body as JSON; a body that is not JSON is a bad response (exit 4, §10.3)."""
        try:
            return json.loads(self.body)
        except ValueError:
            raise ApiError("API_BAD_RESPONSE",
                           f"{self.where} → {self.status}: the body is not JSON: "
                           f"{_excerpt(self.body)}{_rid(self.request_id)}",
                           http_status=self.status, request_id=self.request_id) from None


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Follows no redirect: a 3xx comes back as its own status (§10.1).

    A redirect could carry the bearer token to whatever host it names, so none is ever
    followed; the Authorization header is also unredirected, as a second layer.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Decline every redirect: returning nothing makes urllib report the 3xx as a status."""


def _opener(posture):
    """Build the urllib opener for this posture: its proxies, no redirects, verified TLS.

    Production honours the environment's proxies (posture.proxies is None) and verifies
    certificates and host names with the system trust store; nothing turns that off. Test
    posture passes {} so no proxy is used, whatever the environment says.
    """
    return urllib.request.build_opener(
        urllib.request.ProxyHandler(posture.proxies),
        _RefuseRedirects(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def _display(method, path, query):
    """Method and path for messages, with every query value replaced: values are never shown."""
    where = f"{method} {path}"
    if query:
        pairs = query.items() if isinstance(query, dict) else query
        where += "?" + "&".join(f"{name}=…" for name, _ in pairs)
    return where


def _rid(request_id):
    """The request ID clause support will ask for (`x-tailscale-request-id`, api §3.3)."""
    return f" (request {request_id})" if request_id else ""


def _excerpt(body):
    """At most the first EXCERPT characters of a body, redacted before it is cut, so a secret
    split by the cut is still caught whole."""
    return redact(body.decode("utf-8", "replace"))[:EXCERPT]


def server_says(response):
    """The server's own explanation, redacted: its `message`, or an excerpt of a body without one.

    The write flow quotes it too, when it reports what the API said to a write.
    """
    return body_says(response.body)


def body_says(body):
    """What a response body says, redacted: the API's `{"message": …}` [spec 4823-4829], or an
    excerpt of a body in any other shape. The policy verdict quotes a validate 400 this way.
    """
    try:
        doc = json.loads(body)
    except ValueError:
        doc = None
    if isinstance(doc, dict) and isinstance(doc.get("message"), str):
        return redact(doc["message"])
    return _excerpt(body) if body else "(empty body)"


def _read_capped(reply, where):
    """Read a response body, refusing one larger than MAX_BODY or shorter than it declared.

    The response has arrived, so the request was sent: a refusal here says so, and a write
    takes its outcome from the re-read like any other unanswered write.
    """
    chunks, total = [], 0
    while True:
        chunk = reply.read(MAX_BODY + 1 - total)
        if not chunk:
            # A sized read() returns what came when the connection closes early, where a bare
            # read() raises IncompleteRead, so the cap dropped the stdlib's only length
            # check. `length` is http.client's count of the bytes still owed: None without a
            # Content-Length, and a chunked body that breaks off raises on its own.
            short = getattr(reply, "length", None)
            if isinstance(short, int) and short > 0:
                raise NoResponse("API_BAD_RESPONSE",
                                 f"{where}: the body ended {short} bytes short of its "
                                 "Content-Length; refused, not read as whole",
                                 sent=True, where=where)
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_BODY:
            raise NoResponse("API_BAD_RESPONSE",
                             f"{where}: the response is over {MAX_BODY} bytes; refused unread",
                             sent=True, where=where)


def _response(method, where, status, headers, body):
    """Wrap what urllib returned; the named headers come from the first occurrence of each."""
    return Response(method=method, where=where, status=status,
                    headers={name.lower(): value for name, value in headers.items()},
                    body=body, request_id=headers.get("x-tailscale-request-id"),
                    etag_raw=headers.get("ETag"), date=headers.get("Date"))


def retry_delay(value, now=None):
    """Seconds to wait before the one retry of a read that got a 429 (§10.2, critic X7).

    Retry-After is delay-seconds or an HTTP-date (RFC 9110 §10.2.3); the wait is capped at
    RETRY_AFTER_CAP, a past date waits not at all, and a missing or unreadable value waits
    RETRY_AFTER_DEFAULT.
    """
    if value is None:
        return RETRY_AFTER_DEFAULT
    value = value.strip()
    if re.fullmatch(r"[0-9]+", value):
        return min(int(value), RETRY_AFTER_CAP)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return RETRY_AFTER_DEFAULT
    if when.tzinfo is None:
        # RFC 9110 dates are GMT; "-0000" parses as naive, meaning the same thing.
        when = when.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc) if now is None else now
    return min(max(0, int((when - now).total_seconds())), RETRY_AFTER_CAP)


def _status_error(response, needs_scope):
    """Turn a read's non-2xx status into its stable error (§10.2)."""
    status, where = response.status, response.where
    scope = f" ({needs_scope})" if needs_scope else ""
    if status == 401:
        return LocalError("TOKEN_REJECTED",
                          f"{where} → 401: token rejected: the client may be revoked; console → "
                          f"Trust credentials{_rid(response.request_id)}",
                          http_status=401, request_id=response.request_id,
                          next=[dict(_CONSOLE_FIX)])
    if 300 <= status < 400:
        code, summary = "API_REDIRECT", "redirect refused (would carry the token)"
    elif status == 400:
        code, summary = "API_BAD_REQUEST", "bad request"
    elif status == 402:
        code, summary = "API_PAYMENT", "plan or billing refuses this"
    elif status == 403:
        # Which status a missing scope gets is unverified (critic Q4), so it is "possibly".
        code = "API_FORBIDDEN"
        summary = (f"forbidden: possibly a missing scope{scope} (unconfirmed, critic Q4); "
                   "refused calls show in the console as 'Failed request' [AUDIT L316]")
    elif status == 404:
        code = "API_NOT_FOUND"
        summary = f"not found: wrong ID, or possibly a missing scope{scope} (unconfirmed)"
    elif status == 429:
        code, summary = "API_RATE_LIMITED", "rate limited, and again after the one retry"
    elif 400 <= status < 500:
        code, summary = "API_BAD_REQUEST", f"refused with HTTP {status}"
    elif 500 <= status < 600:
        # A 504 is "took too long, please try again" [spec 172-174]; the CLI leaves that to
        # whoever reads this, rather than retrying unseen.
        code, summary = "API_SERVER", "server error; not retried"
    else:
        code, summary = "API_BAD_RESPONSE", f"unexpected HTTP {status}"
    return ApiError(code, f"{where} → {status}: {summary}; server said: {server_says(response)}"
                          f"{_rid(response.request_id)}",
                    http_status=status, request_id=response.request_id)


class Transport:
    """Sends requests to this posture's API and maps their outcomes (§10.1, §10.2).

    Reads (`idempotent=True`) raise a stable error for every status that is not 2xx and not
    in `expect`, retrying once only on a 429. Writes (`idempotent=False`) are sent exactly
    once and every status comes back as a Response, because a write's outcome is decided by
    the re-read that follows it (§12.6), not by this layer; that path has no retry at all.
    `sleep` and `timeout` are parameters so tests can observe the 429 wait and cause a
    timeout without waiting for real.
    """

    def __init__(self, posture, *, sleep=time.sleep, timeout=TIMEOUT):
        self.base = posture.api_base
        self.opener = _opener(posture)
        self._sleep = sleep
        self._timeout = timeout

    def request(self, method, path, *, token=None, accept=None, content_type=None, body=None,
                query=None, idempotent, needs_scope=None, expect=()):
        """Send one request (plus, for a read, at most one retry) and return its Response.

        `idempotent` has no default: every caller says whether this is a read, which may be
        retried, or a write, which never is. `token` is a bearer string, or a source with
        bearer() and renew() whose token may be renewed once after a 401 on a read.
        `needs_scope` names the OAuth scope the call needs, for a 403's message. `expect`
        lists statuses the caller treats as an answer rather than an error, such as a 400
        from /acl/validate.
        """
        where = _display(method, path, query)
        url = self.base + path + (f"?{urlencode(query, doseq=True)}" if query else "")
        # A token source (tokens.ReadToken) is asked for its value only now, so nothing is
        # minted for a request that is never made.
        renewable = token is not None and not isinstance(token, str)
        bearer = token.bearer() if renewable else token
        send = (method, url, where, accept, content_type, body)
        response = self._send(*send, bearer)
        if not idempotent:
            return response
        if response.status == 429:
            self._sleep(retry_delay(response.headers.get("retry-after")))
            response = self._send(*send, bearer)
        if response.status == 401 and renewable:
            # §9.3: a cached token may be dead before its hour is up. Its source re-mints at
            # most once, and only for a cached token; the read is retried once with it.
            fresh = token.renew()
            if fresh is not None:
                response = self._send(*send, fresh)
        if 200 <= response.status < 300 or response.status in expect:
            return response
        raise _status_error(response, needs_scope)

    def _send(self, method, url, where, accept, content_type, body, token):
        """Make exactly one HTTP exchange; return its Response whatever the status."""
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("Accept", accept or JSON)
        if content_type is not None:
            request.add_header("Content-Type", content_type)
        if token is not None:
            # Unredirected: even if a redirect were followed, the token would not go with it.
            request.add_unredirected_header("Authorization", f"Bearer {token}")
        try:
            with self.opener.open(request, timeout=self._timeout) as reply:
                return _response(method, where, reply.status, reply.headers,
                                 _read_capped(reply, where))
        except urllib.error.HTTPError as exc:
            # urllib raises every non-2xx status, refused redirects included. It is still the
            # API's answer, and the caller decides what it means. Its body is read below,
            # outside this clause: an exception raised inside an except clause skips the
            # clauses after it, so a reset mid-body would escape raw (exit 1, no audit line).
            reply = exc
        except urllib.error.URLError as exc:
            # urllib wraps exactly the failures of connecting and of sending the request, so
            # the API never received a whole request and cannot have acted on it.
            raise NoResponse("NETWORK", f"{where}: could not reach the API: {exc.reason}",
                             sent=False, where=where) from None
        except (OSError, http.client.HTTPException) as exc:
            # Raised while waiting for or reading the response: the request had gone out.
            raise NoResponse("NETWORK", f"{where}: no response after the request was sent "
                                        f"({type(exc).__name__}: {exc}); it may have reached "
                                        "the API", sent=True, where=where) from None
        request_id = reply.headers.get("x-tailscale-request-id")
        with reply:
            try:
                body = _read_capped(reply, where)
            except (OSError, http.client.HTTPException) as exc:
                # The status line arrived, so the request had gone out; the body broke off.
                # Mapped as any failure after sending is, with what did arrive kept.
                raise NoResponse("NETWORK", f"{where} → {reply.code}: the response broke off "
                                            f"before its body was read ({type(exc).__name__}: "
                                            f"{exc}); it may have reached the API"
                                            f"{_rid(request_id)}",
                                 sent=True, where=where, http_status=reply.code,
                                 request_id=request_id) from None
        return _response(method, where, reply.code, reply.headers, body)
