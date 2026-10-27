# ABOUTME: Tests for tests/loopback.py, the one seam that stands in for api.tailscale.com.
# ABOUTME: A real HTTP client talks to the real server over 127.0.0.1; nothing is stubbed.

import http.client
import json

import pytest
from loopback import Cut, Loopback


def call(server, method, path, body=None, headers=None):
    """Send one real HTTP request to the seam and return (status, headers, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


def test_the_seam_listens_on_loopback_with_an_ephemeral_port():
    with Loopback() as server:
        assert server.base_url == f"http://127.0.0.1:{server.port}"
        assert server.port > 0


def test_a_routed_request_gets_its_reply_and_is_recorded(loopback):
    loopback.route("GET", "/api/v2/tailnet/-/devices", (200, {"X-Tailscale-Request-Id": "REQ-1"},
                                                         {"devices": []}))
    status, headers, body = call(loopback, "GET", "/api/v2/tailnet/-/devices?fields=all",
                                 headers={"Authorization": "Bearer t0k"})
    assert status == 200
    assert headers["X-Tailscale-Request-Id"] == "REQ-1"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"devices": []}
    [seen] = loopback.requests
    assert (seen.method, seen.path, seen.query) == ("GET", "/api/v2/tailnet/-/devices", "fields=all")
    assert seen.header("authorization") == "Bearer t0k"
    assert seen.body == b""


def test_a_request_body_is_recorded_byte_for_byte(loopback):
    loopback.route("POST", "/api/v2/oauth/token", (200, {}, {"access_token": "a"}))
    form = b"client_id=k1&client_secret=s%2F1&grant_type=client_credentials"
    call(loopback, "POST", "/api/v2/oauth/token", body=form,
         headers={"Content-Type": "application/x-www-form-urlencoded"})
    [seen] = loopback.requests
    assert seen.body == form
    assert seen.form() == {"client_id": ["k1"], "client_secret": ["s/1"],
                           "grant_type": ["client_credentials"]}


def test_a_sequence_is_served_in_order_for_retry_cases(loopback):
    loopback.route("GET", "/api/v2/x", (429, {"Retry-After": "1"}, {"message": "slow down"}),
                   (200, {}, {"ok": True}))
    assert call(loopback, "GET", "/api/v2/x")[0] == 429
    assert call(loopback, "GET", "/api/v2/x")[0] == 200
    assert [r.path for r in loopback.requests] == ["/api/v2/x", "/api/v2/x"]


def test_a_single_reply_is_served_every_time(loopback):
    loopback.route("GET", "/api/v2/x", (200, {}, b"same"))
    assert [call(loopback, "GET", "/api/v2/x")[2] for _ in range(3)] == [b"same"] * 3


def test_an_exhausted_sequence_is_an_error_and_is_reported():
    with Loopback() as server:
        server.route("POST", "/api/v2/device/n1/tags", (500, {}, {"message": "boom"}),
                     (200, {}, {}))
        call(server, "POST", "/api/v2/device/n1/tags", body=b"{}")
        call(server, "POST", "/api/v2/device/n1/tags", body=b"{}")
        status, _, _ = call(server, "POST", "/api/v2/device/n1/tags", body=b"{}")
    assert status == 500
    assert server.unexpected == ["POST /api/v2/device/n1/tags: all 2 replies already served"]


def test_an_unrouted_request_is_a_404_and_is_reported():
    with Loopback() as server:
        status, _, body = call(server, "DELETE", "/api/v2/device/n1")
    assert status == 404
    assert "no route" in json.loads(body)["message"]
    assert server.unexpected == ["DELETE /api/v2/device/n1: no route"]


def test_a_handler_computes_its_reply_from_the_request(loopback):
    loopback.route("POST", "/api/v2/echo", lambda request: (201, {}, {"got": request.json()}))
    status, _, body = call(loopback, "POST", "/api/v2/echo", body=b'{"a": 1}')
    assert status == 201
    assert json.loads(body) == {"got": {"a": 1}}


def test_a_handler_that_raises_is_an_error_and_is_reported():
    def broken(request):
        raise ValueError("handler bug")

    with Loopback() as server:
        server.route("GET", "/api/v2/x", broken)
        status, _, _ = call(server, "GET", "/api/v2/x")
    assert status == 500
    assert server.unexpected == ["GET /api/v2/x: handler raised ValueError: handler bug"]


def test_a_fixture_source_key_is_stripped_before_serving(loopback):
    fixture = {"_source": "spec 4461-4822", "id": "n1", "hostname": "pi5"}
    loopback.route("GET", "/api/v2/device/n1", (200, {}, fixture))
    _, _, body = call(loopback, "GET", "/api/v2/device/n1")
    assert json.loads(body) == {"id": "n1", "hostname": "pi5"}
    assert "_source" in fixture


def test_text_bodies_keep_the_content_type_the_route_gives(loopback):
    hujson = "// MC's policy\n{\"grants\": []}\n"
    loopback.route("GET", "/api/v2/tailnet/-/acl",
                   (200, {"Content-Type": "application/hujson", "ETag": '"abc"'}, hujson))
    status, headers, body = call(loopback, "GET", "/api/v2/tailnet/-/acl")
    assert status == 200
    assert headers["Content-Type"] == "application/hujson"
    assert headers["ETag"] == '"abc"'
    assert body == hujson.encode()


def test_a_cut_body_declares_its_whole_length_and_closes_after_its_start(loopback):
    loopback.route("GET", "/api/v2/tailnet/-/acl", (200, {"ETag": '"abc"'}, Cut(b"0123456789", 4)))
    conn = http.client.HTTPConnection("127.0.0.1", loopback.port, timeout=5)
    try:
        conn.request("GET", "/api/v2/tailnet/-/acl")
        response = conn.getresponse()
        assert (response.status, response.getheader("Content-Length")) == (200, "10")
        # The whole-body read is the stdlib's one check of the length, and it trips.
        with pytest.raises(http.client.IncompleteRead) as caught:
            response.read()
        assert caught.value.partial == b"0123"
    finally:
        conn.close()


def test_a_cut_body_can_end_in_a_reset_after_the_status_line(loopback):
    loopback.route("POST", "/api/v2/device/n1/key",
                   (502, {}, Cut({"message": "bad gateway"}, 5, end="reset")))
    conn = http.client.HTTPConnection("127.0.0.1", loopback.port, timeout=5)
    try:
        conn.request("POST", "/api/v2/device/n1/key", body=b"{}")
        response = conn.getresponse()
        assert response.status == 502
        with pytest.raises(ConnectionResetError):
            response.read()
    finally:
        conn.close()
    with pytest.raises(ValueError):
        Cut(b"", 0, end="stall")
