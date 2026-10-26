# ABOUTME: Tests for tailnet.http, the only code that talks to the API (DESIGN.md §10): headers, the refused
# ABOUTME: redirect, the 429 rule, status mapping, and writes sent exactly once. Every call is real loopback HTTP.

import email.utils
import socket
import ssl
import threading
import time
import urllib.request

import pytest
from credfiles import access_token, token_reply, write_cache, write_role
from loopback import Cut

import tailnet
from tailnet import errors, http, tokens
from tailnet.output import Envelope
from tailnet.posture import Posture

API = "/api/v2"
JSON = "application/json"


def bearer():
    """A token-shaped value assembled at runtime (CLAUDE.md invariant 14)."""
    return "test-token-" + "http0001"


def posture_for(base, tmp_path):
    """A test posture whose API is `base`."""
    environ = {"TAILNET_API_BASE": base, "TAILNET_HOME": str(tmp_path / "tn")}
    return Posture.from_env(environ, real_home=tmp_path / "real")


@pytest.fixture
def sleeps():
    """The delays the transport asked for, recorded instead of slept (§21.2)."""
    return []


@pytest.fixture
def transport(loopback, tmp_path, sleeps):
    """A transport pointed at the loopback seam, with an injected sleep."""
    return http.Transport(posture_for(loopback.base_url, tmp_path), sleep=sleeps.append)


def failure(call, *args, **kwargs):
    """Call expecting a TailnetError; return it."""
    with pytest.raises(errors.TailnetError) as caught:
        call(*args, **kwargs)
    return caught.value


def get(transport, path="/tailnet/-/devices", **kwargs):
    """A read with the test bearer token."""
    kwargs.setdefault("token", bearer())
    return transport.request("GET", path, idempotent=True, **kwargs)


def post_write(transport, path="/device/n1/key"):
    """A write: one POST that is never retried."""
    return transport.request("POST", path, token=bearer(), content_type=JSON,
                             body=b'{"keyExpiryDisabled": true}', idempotent=False)


def test_every_request_carries_bearer_and_user_agent(loopback, transport):
    loopback.route("GET", API + "/tailnet/-/devices",
                   (200, {"X-Tailscale-Request-Id": "REQ-1", "ETag": '"e1"'}, {"devices": []}))
    loopback.route("GET", API + "/tailnet/-/acl", (200, {}, "// hujson\n{}\n"))
    loopback.route("POST", API + "/oauth/token", (200, {}, {"ok": True}))
    reply = get(transport, query={"fields": "all"})
    # The ETag is kept raw, quotes and all: whether the API quotes it is unverified (critic R3).
    assert (reply.status, reply.request_id, reply.etag_raw) == (200, "REQ-1", '"e1"')
    # The server's Date header is kept as sent, for doctor's clock-skew check.
    served_at = email.utils.parsedate_to_datetime(reply.date).timestamp()
    assert abs(served_at - time.time()) < 60
    assert reply.json() == {"devices": []}
    get(transport, "/tailnet/-/acl", accept="application/hujson")
    transport.request("POST", "/oauth/token", content_type="application/x-www-form-urlencoded",
                      body=b"grant_type=client_credentials", idempotent=True)
    listing, policy, mint = loopback.requests
    assert listing.query == "fields=all"
    for seen in (listing, policy):
        assert seen.header("authorization") == f"Bearer {bearer()}"
        assert seen.header("user-agent") == f"tailnet/{tailnet.__version__} (+wittyreference/tailscale)"
    assert listing.header("accept") == JSON
    assert policy.header("accept") == "application/hujson"
    # The token endpoint takes its credential in the form body, never a bearer header.
    assert mint.header("authorization") is None
    assert mint.header("content-type") == "application/x-www-form-urlencoded"
    assert mint.body == b"grant_type=client_credentials"


def test_a_redirect_is_refused_and_the_token_never_reaches_the_target(loopback, transport):
    with type(loopback)() as elsewhere:
        elsewhere.route("GET", API + "/tailnet/-/devices", (200, {}, {"devices": []}))
        loopback.route("GET", API + "/tailnet/-/devices",
                       (302, {"Location": elsewhere.base_url + API + "/tailnet/-/devices"}, b""))
        loopback.route("POST", API + "/device/n1/key",
                       (307, {"Location": elsewhere.base_url + API + "/device/n1/key"}, b""))
        exc = failure(get, transport)
        assert (exc.exit, exc.code, exc.http_status) == (4, "API_REDIRECT", 302)
        assert "redirect refused" in exc.message
        # A write gets the status back, for the write flow to call rejected (§12.6).
        assert post_write(transport).status == 307
    assert elsewhere.requests == []
    assert len(loopback.requests) == 2


def test_a_read_retries_once_on_429_honouring_retry_after(loopback, transport, sleeps):
    loopback.route("GET", API + "/tailnet/-/devices",
                   (429, {"Retry-After": "7"}, {"message": "too many requests"}),
                   (200, {}, {"devices": []}))
    assert get(transport).status == 200
    assert sleeps == [7]
    assert len(loopback.requests) == 2
    # Retry-After may also be an HTTP-date; the wait is the time until it.
    soon = email.utils.formatdate(time.time() + 10, usegmt=True)
    loopback.route("GET", API + "/tailnet/-/acl", (429, {"Retry-After": soon}, b""),
                   (200, {}, "{}"))
    assert get(transport, "/tailnet/-/acl").status == 200
    assert 8 <= sleeps[1] <= 10


@pytest.mark.parametrize("retry_after,expected", [
    ("120", 30), ("30", 30), ("0", 0), (None, 5), ("soon", 5), ("-3", 5),
    ("date+3600", 30), ("date-60", 0),
])
def test_retry_after_is_capped_at_thirty_seconds(loopback, transport, sleeps, retry_after,
                                                 expected):
    if retry_after and retry_after.startswith("date"):
        retry_after = email.utils.formatdate(time.time() + int(retry_after[4:]), usegmt=True)
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    loopback.route("GET", API + "/tailnet/-/devices", (429, headers, b""), (200, {}, "{}"))
    get(transport)
    assert sleeps == [expected]


def test_a_second_429_on_a_read_is_an_error(loopback, transport, sleeps):
    loopback.route("GET", API + "/tailnet/-/devices", (429, {"Retry-After": "1"}, b""),
                   (429, {"Retry-After": "1"}, b""))
    exc = failure(get, transport)
    assert (exc.exit, exc.code, exc.http_status) == (4, "API_RATE_LIMITED", 429)
    assert sleeps == [1]
    assert len(loopback.requests) == 2


@pytest.mark.parametrize("status", [400, 429, 500, 504, "read timeout"])
def test_a_write_makes_exactly_one_request_whatever_the_status(loopback, tmp_path, sleeps,
                                                               status):
    release = threading.Event()
    if status == "read timeout":
        def stall(request):
            """Answer only after the client has given up waiting."""
            release.wait(5)
            return 200, {}, {}
        loopback.route("POST", API + "/device/n1/key", stall)
    else:
        loopback.route("POST", API + "/device/n1/key",
                       (status, {"Retry-After": "1"}, {"message": "no"}), (200, {}, {}))
    transport = http.Transport(posture_for(loopback.base_url, tmp_path), sleep=sleeps.append,
                               timeout=0.3)
    try:
        if status == "read timeout":
            exc = failure(post_write, transport)
            # The request went out and no answer came: it may have landed (§10.2).
            assert (exc.exit, exc.code, exc.sent) == (4, "NETWORK", True)
        else:
            assert post_write(transport).status == status
    finally:
        release.set()
    assert [r.method for r in loopback.requests] == ["POST"]
    assert sleeps == []


@pytest.mark.parametrize("call", [get, post_write], ids=["read", "write"])
def test_an_error_body_cut_by_a_reset_is_no_response_that_may_have_landed(loopback, transport,
                                                                          call):
    # A proxy that gives up mid-answer, say: the status line came, so the request had gone
    # out, and the body never did. A read is NETWORK (exit 4); a write takes its outcome from
    # the re-read, as after any reset once sent (§10.2), never a raw exception (exit 1).
    reply = (502, {"X-Tailscale-Request-Id": "REQ-c1"},
             Cut({"message": "bad gateway"}, 5, end="reset"))
    loopback.route("GET", API + "/tailnet/-/devices", reply)
    loopback.route("POST", API + "/device/n1/key", reply)
    exc = failure(call, transport)
    assert (exc.exit, exc.code, exc.sent) == (4, "NETWORK", True)
    assert exc.where.endswith(("/tailnet/-/devices", "/device/n1/key"))
    # The status and request ID it did send are kept: support asks for the ID.
    assert (exc.http_status, exc.request_id) == (502, "REQ-c1")
    assert "→ 502" in exc.message and "REQ-c1" in exc.message
    assert len(loopback.requests) == 1


def test_a_connect_failure_before_send_is_reported_as_not_sent(tmp_path):
    # A port nothing listens on: the connection is refused before any byte is sent.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    transport = http.Transport(posture_for(f"http://127.0.0.1:{port}", tmp_path))
    for call in (get, post_write):
        exc = failure(call, transport)
        assert (exc.exit, exc.code, exc.sent) == (4, "NETWORK", False)


def test_request_id_is_surfaced_in_errors(loopback, transport):
    loopback.route("GET", API + "/tailnet/-/devices",
                   (500, {"X-Tailscale-Request-Id": "REQ-77"}, {"message": "internal error"}))
    exc = failure(get, transport)
    assert (exc.code, exc.http_status, exc.request_id) == ("API_SERVER", 500, "REQ-77")
    assert "REQ-77" in exc.message and "internal error" in exc.message
    assert Envelope.from_error("device list", "test", exc).request_ids == ["REQ-77"]


def test_a_403_names_the_needed_scope_and_says_possibly(loopback, transport):
    loopback.route("GET", API + "/device/n1/routes", (403, {}, {"message": "forbidden"}))
    exc = failure(get, transport, "/device/n1/routes", needs_scope="devices:routes:read")
    assert (exc.exit, exc.code, exc.http_status) == (4, "API_FORBIDDEN", 403)
    assert "devices:routes:read" in exc.message
    # Which status a missing scope gets is unverified (critic Q4), so it is never asserted.
    assert "possibly" in exc.message
    assert "Failed request" in exc.message


def test_a_non_json_error_body_is_excerpted_and_redacted(loopback, transport):
    key = "tskey-" + "client-" + "kHttp1CNTRL-" + "q" * 24
    # Dots: no fixture secret can contain one, and the redactor is process-wide, so a filler a
    # secret could match would be collapsed by another test's registration.
    page = f"<html>proxy error near {key} " + "." * 300 + "TAIL-MARKER</html>"
    loopback.route("GET", API + "/tailnet/-/devices", (502, {"Content-Type": "text/html"}, page))
    exc = failure(get, transport)
    assert exc.code == "API_SERVER"
    assert key not in exc.message
    assert "tskey-…[REDACTED]" in exc.message
    # The first 200 characters only: the tail of a long page never reaches the transcript.
    assert "TAIL-MARKER" not in exc.message
    assert "." * 100 in exc.message


@pytest.mark.parametrize("status,code", [
    (301, "API_REDIRECT"), (400, "API_BAD_REQUEST"), (402, "API_PAYMENT"),
    (404, "API_NOT_FOUND"), (409, "API_BAD_REQUEST"), (500, "API_SERVER"), (502, "API_SERVER"),
    (503, "API_SERVER"), (504, "API_SERVER"),
])
def test_each_error_status_maps_to_its_stable_code_and_is_not_retried(loopback, transport, sleeps,
                                                                      status, code):
    loopback.route("GET", API + "/tailnet/-/devices", (status, {}, {"message": "nope"}))
    exc = failure(get, transport)
    assert (exc.exit, exc.code, exc.http_status) == (4, code, status)
    assert len(loopback.requests) == 1
    assert sleeps == []


def test_a_401_on_a_read_with_a_plain_token_is_token_rejected_once(loopback, transport):
    loopback.route("GET", API + "/tailnet/-/devices", (401, {}, {"message": "API token invalid"}))
    exc = failure(get, transport)
    assert (exc.exit, exc.code, exc.http_status) == (3, "TOKEN_REJECTED", 401)
    [step] = exc.next
    assert (step["who"], step["needs"]) == ("mc", "console")
    assert "Trust credentials" in step["do"]
    assert len(loopback.requests) == 1


def test_an_expected_status_comes_back_as_an_answer(loopback, transport):
    # /acl/validate answers a draft that does not parse with a 400: a verdict, not an error.
    loopback.route("POST", API + "/tailnet/-/acl/validate", (400, {}, {"message": "parse error"}))
    reply = transport.request("POST", "/tailnet/-/acl/validate", token=bearer(),
                              content_type="application/hujson", body=b"{", idempotent=True,
                              expect=(400,))
    assert (reply.status, reply.json()) == (400, {"message": "parse error"})


def test_oversized_responses_are_refused(loopback, transport):
    loopback.route("GET", API + "/tailnet/-/devices", (200, {}, b"x" * (http.MAX_BODY + 1)))
    loopback.route("GET", API + "/tailnet/-/acl", (200, {}, b"y" * http.MAX_BODY))
    exc = failure(get, transport)
    assert (exc.exit, exc.code) == (4, "API_BAD_RESPONSE")
    assert len(get(transport, "/tailnet/-/acl").body) == http.MAX_BODY


def test_a_body_that_is_not_json_is_a_bad_response_with_a_redacted_excerpt(loopback, transport):
    key = "tskey-" + "auth-" + "kHttp2CNTRL-" + "r" * 24
    loopback.route("GET", API + "/tailnet/-/devices", (200, {}, f"not json {key}"))
    exc = failure(get(transport).json)
    assert (exc.exit, exc.code) == (4, "API_BAD_RESPONSE")
    assert key not in exc.message and "not json" in exc.message


def test_query_values_never_appear_in_error_messages(loopback, transport):
    loopback.route("GET", API + "/tailnet/-/devices", (404, {}, {"message": "no tailnet"}))
    exc = failure(get, transport, query={"fields": "all", "hostname": "secret-host"})
    assert "/tailnet/-/devices?fields=…&hostname=…" in exc.message
    assert "secret-host" not in exc.message


def test_test_posture_ignores_environment_proxies(loopback, tmp_path, monkeypatch):
    # A proxy on loopback would carry fixture traffic off the box; netguard refuses its port,
    # so a transport that used it would fail here rather than reach the seam. no_proxy is
    # cleared so the proxy is not skipped for 127.0.0.1 by that route instead.
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:3128")
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    transport = http.Transport(posture_for(loopback.base_url, tmp_path))
    loopback.route("GET", API + "/tailnet/-/devices", (200, {}, {"devices": []}))
    assert get(transport).status == 200
    assert len(loopback.requests) == 1


def test_production_verifies_tls_and_honours_environment_proxies(tmp_path, monkeypatch):
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:3128")
    transport = http.Transport(Posture.from_env({}, real_home=tmp_path))
    handlers = transport.opener.handlers
    [tls] = [h for h in handlers if isinstance(h, urllib.request.HTTPSHandler)]
    assert tls._context.verify_mode == ssl.CERT_REQUIRED
    assert tls._context.check_hostname is True
    [proxy] = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy.proxies["https"] == "http://proxy.invalid:3128"


def test_a_401_on_a_cached_token_remints_once_and_retries_once(loopback, transport, tmp_path):
    posture = posture_for(loopback.base_url, tmp_path)
    write_role(posture, "read")
    write_cache(posture, access_token("cached01"), expires_in=3000)
    # A cached token can be dead before its hour is up: the client was revoked or replaced.
    loopback.route("GET", API + "/tailnet/-/devices", (401, {}, {"message": "API token invalid"}),
                   (200, {}, {"devices": []}))
    loopback.route("POST", API + "/oauth/token", token_reply(access_token("fresh002")))
    assert get(transport, token=tokens.ReadToken(posture, transport)).status == 200
    first, mint, retry = loopback.requests
    assert first.header("authorization") == f"Bearer {access_token('cached01')}"
    assert (mint.method, mint.path) == ("POST", API + "/oauth/token")
    assert retry.header("authorization") == f"Bearer {access_token('fresh002')}"
    cache = (posture.config_dir / "read-token.json").read_text()
    assert access_token("fresh002") in cache and access_token("cached01") not in cache


def test_a_second_401_after_reminting_is_token_rejected_without_looping(loopback, transport,
                                                                        tmp_path):
    posture = posture_for(loopback.base_url, tmp_path)
    write_role(posture, "read")
    write_cache(posture, access_token("cached03"), expires_in=3000)
    loopback.route("GET", API + "/tailnet/-/devices", (401, {}, {"message": "API token invalid"}),
                   (401, {}, {"message": "API token invalid"}))
    loopback.route("POST", API + "/oauth/token", token_reply(access_token("fresh004")))
    exc = failure(get, transport, token=tokens.ReadToken(posture, transport))
    assert (exc.exit, exc.code) == (3, "TOKEN_REJECTED")
    assert [r.method for r in loopback.requests] == ["GET", "POST", "GET"]


def test_a_401_on_a_token_minted_in_this_command_is_not_reminted(loopback, transport, tmp_path):
    posture = posture_for(loopback.base_url, tmp_path)
    write_role(posture, "read")
    loopback.route("GET", API + "/tailnet/-/devices", (401, {}, {"message": "API token invalid"}))
    loopback.route("POST", API + "/oauth/token", token_reply(access_token("fresh005")))
    exc = failure(get, transport, token=tokens.ReadToken(posture, transport))
    assert (exc.exit, exc.code) == (3, "TOKEN_REJECTED")
    # Minting again would get the same answer from the same client: no loop.
    assert [r.method for r in loopback.requests] == ["POST", "GET"]
