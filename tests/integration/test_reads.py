# ABOUTME: Integration tests for the read commands as real CLI processes against the loopback seam: the
# ABOUTME: device inventory, the token rules across processes, the 401/429/3xx handling and the secret sweep.

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from credfiles import access_token, fixture_secret, token_reply, write_cache, write_role
from fixturefiles import body

API = "/api/v2"
TOKEN = API + "/oauth/token"
DEVICES = API + "/tailnet/-/devices"
TIME = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
READ_TOKEN = access_token("read0001")


def tskey():
    """A key-shaped OAuth client secret, assembled at runtime (CLAUDE.md invariant 14)."""
    return "tskey-" + "client-" + "kReal1tCNTRL-" + "R" * 30


def stamp(days):
    """An API time `days` from now."""
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def configured(home):
    """A test home with the read client configured, as `credentials set read` leaves it."""
    write_role(home, "read")
    return home


def serve_devices(loopback, devices_body=None, *replies, mint=READ_TOKEN):
    """Route the token endpoint and the device list; return the body the list serves."""
    devices_body = body("scenario", "devices") if devices_body is None else devices_body
    loopback.route("POST", TOKEN, token_reply(mint))
    loopback.route("GET", DEVICES, *(replies or [
        (200, {"X-Tailscale-Request-Id": "REQ-list"}, devices_body)]))
    return devices_body


def requests_to(loopback, path):
    """The recorded requests to one path, in order."""
    return [request for request in loopback.requests if request.path == path]


def envelope(result):
    """The one tailnet.v1 object stdout holds; json.loads refuses anything after it."""
    return json.loads(result.stdout)


def audit_records(posture, event):
    """Every audit record of one event in the test home, oldest first."""
    log = posture.state_dir / "audit.jsonl"
    if not log.exists():
        return []
    return [r for r in map(json.loads, log.read_text().splitlines()) if r["event"] == event]


def test_device_list_prints_every_device_and_n_of_n(cli, loopback, configured):
    served = serve_devices(loopback)
    result = cli("device", "list")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert re.fullmatch(rf"OK: 6 devices.* \(as of {TIME}\)", lines[0])
    for device in served["devices"]:
        assert device["hostname"] in result.stdout and device["nodeId"] in result.stdout
    assert re.fullmatch(rf"6 of 6 devices \(the API does not paginate\) \(as of {TIME}\)",
                        lines[-1])
    [listing] = requests_to(loopback, DEVICES)
    # fields=all is what carries sshEnabled and multipleConnections [api §5.1].
    assert listing.query == "fields=all"
    assert listing.header("authorization") == f"Bearer {READ_TOKEN}"


def test_device_list_json_is_one_envelope_with_measured_at_and_request_ids(cli, loopback,
                                                                          configured):
    served = serve_devices(loopback)
    result = cli("device", "list", "--json")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["schema"], env["command"], env["posture"]) == ("tailnet.v1", "device list", "test")
    assert (env["ok"], env["exit"], env["outcome"], env["error"]) == (True, 0, "ok", None)
    assert re.fullmatch(TIME, env["measured_at"])
    assert env["request_ids"] == ["REQ-list"]
    data = env["data"]
    assert data["count"] == len(data["devices"]) == 6
    assert "self_node_id" in data
    # Every device keeps the untouched API object beside the normalised fields.
    assert [d["raw"] for d in data["devices"]] == served["devices"]
    spec5 = next(d for d in data["devices"] if d["hostname"] == "spec5")
    assert (spec5["nodeId"], spec5["ipv4"], spec5["owner"]) == (
        "nSpec5x1CNTRL", "100.64.0.11", {"kind": "tag", "value": "tag:fleet"})
    assert spec5["tailscale_ssh"] is True
    pi5 = next(d for d in data["devices"] if d["hostname"] == "pi5")
    assert pi5["tailscale_ssh"] is None


def test_device_list_warns_about_tagged_devices_with_expiry_on(cli, loopback, configured):
    served = body("scenario", "devices")
    by_name = {device["hostname"]: device for device in served["devices"]}
    by_name["spec5"]["expires"] = stamp(12.5)
    by_name["pi5"]["expires"] = stamp(40.5)
    serve_devices(loopback, served)
    result = cli("--json", "device", "list")
    assert result.returncode == 0, result.stderr
    warnings = envelope(result)["warnings"]
    tagged = [w for w in warnings if w["code"] == "TAGGED_KEY_EXPIRY_ON"]
    # The three fleet boxes still carry expiry; the droplet's is off; user devices are not
    # flagged, because a user device's expiry is its owner's re-login cycle.
    assert [w["message"].split()[0] for w in tagged] == ["spec5", "nomad-b", "pi5"]
    assert {w["source"] for w in tagged} == {"TAGS L84"}
    assert "12 days" in tagged[0]["message"] and "40 days" in tagged[2]["message"]
    [soon] = [w for w in warnings if w["code"] == "KEY_EXPIRES_SOON"]
    assert soon["message"].startswith("spec5")
    # Warnings go to stderr as well, prefixed, so the human view shows them too.
    assert result.stderr.count("tailnet: TAGGED_KEY_EXPIRY_ON: ") == 3


def test_reads_never_send_the_write_secret(cli, loopback, configured):
    sentinel = fixture_secret("sentinel77")
    write_role(configured, "write", sentinel)
    serve_devices(loopback)
    result = cli("--json", "device", "list")
    assert result.returncode == 0, result.stderr
    assert loopback.requests
    for request in loopback.requests:
        seen = (request.path + request.query + json.dumps(request.headers)
                + request.body.decode("utf-8", "replace"))
        assert sentinel not in seen
    assert sentinel not in result.stdout + result.stderr


def test_one_mint_serves_two_processes(cli, loopback, configured):
    serve_devices(loopback)
    first, second = cli("device", "list"), cli("device", "list", "--json")
    assert (first.returncode, second.returncode) == (0, 0), first.stderr + second.stderr
    assert len(requests_to(loopback, TOKEN)) == 1
    assert len(audit_records(configured, "token.mint")) == 1
    bearers = {r.header("authorization") for r in requests_to(loopback, DEVICES)}
    assert bearers == {f"Bearer {READ_TOKEN}"}


def test_a_401_on_a_cached_token_remints_once_and_retries_once(cli, loopback, configured):
    stale, fresh = access_token("stale001"), access_token("fresh001")
    write_cache(configured, stale, expires_in=3600)
    serve_devices(loopback, None, (401, {}, {"message": "token expired"}),
                  (200, {}, body("scenario", "devices")), mint=fresh)
    result = cli("device", "list")
    assert result.returncode == 0, result.stderr
    assert [(r.method, r.header("authorization")) for r in loopback.requests] == [
        ("GET", f"Bearer {stale}"), ("POST", None), ("GET", f"Bearer {fresh}")]
    cached = json.loads((configured.config_dir / "read-token.json").read_text())
    assert cached["access_token"] == fresh


def test_a_second_401_exits_3_without_looping(cli, loopback, configured):
    write_cache(configured, access_token("stale001"), expires_in=3600)
    serve_devices(loopback, None, (401, {}, {"message": "revoked"}),
                  mint=access_token("fresh001"))
    result = cli("--json", "device", "list")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (3, "TOKEN_REJECTED")
    assert [r.method for r in loopback.requests] == ["GET", "POST", "GET"]
    assert env["next"] and env["next"][0]["who"] == "mc"


def test_a_429_on_a_read_waits_and_retries_once(cli, loopback, configured):
    arrivals = []

    def arrive(reply):
        """Note when the request arrived, then answer with `reply`."""
        def handler(request):
            arrivals.append(time.monotonic())
            return reply
        return handler

    serve_devices(loopback, None, arrive((429, {"Retry-After": "1"}, {"message": "slow down"})),
                  arrive((200, {}, body("scenario", "devices"))))
    result = cli("device", "list")
    assert result.returncode == 0, result.stderr
    assert len(requests_to(loopback, DEVICES)) == 2
    # The retry came after the Retry-After the server asked for, not before.
    assert arrivals[1] - arrivals[0] >= 1.0
    # A second 429 is the answer: one retry, then exit 4.
    loopback.route("GET", DEVICES, (429, {"Retry-After": "0"}, {"message": "slow down"}))
    result = cli("--json", "device", "list")
    assert (result.returncode, envelope(result)["error"]["code"]) == (4, "API_RATE_LIMITED")
    assert len(requests_to(loopback, DEVICES)) == 4


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_3xx_is_never_followed(cli, loopback, configured, status):
    elsewhere = "/api/v2/elsewhere"
    serve_devices(loopback, None, (status, {"Location": loopback.base_url + elsewhere}, ""))
    loopback.route("GET", elsewhere, (200, {}, {"devices": []}))
    result = cli("--json", "device", "list")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (4, "API_REDIRECT")
    # The redirect target never saw a request, so the bearer token never went there.
    assert requests_to(loopback, elsewhere) == []


def test_no_secret_or_token_reaches_stdout_stderr_audit_or_any_file_outside_config(
        cli, loopback, configured):
    read_secret = fixture_secret("read0001")
    write_secret = fixture_secret("write001")
    write_role(configured, "write", write_secret)
    stale, fresh = access_token("stale001"), access_token("fresh001")
    serve_devices(loopback)
    outputs = []

    def run(*args):
        """Run one command of the battery and keep everything it printed."""
        result = cli(*args)
        outputs.append(result.stdout + result.stderr)
        return result

    # Passing commands: a mint, then a cached read, in both output forms.
    assert run("device", "list").returncode == 0
    assert run("--json", "device", "list").returncode == 0
    # A server error that quotes the token and the secret back: the message is shown redacted.
    echo = f"internal: saw Bearer {READ_TOKEN} with client_secret={read_secret}"
    loopback.route("GET", DEVICES, (500, {}, {"message": echo}))
    assert run("--json", "device", "list").returncode == 4
    assert run("device", "list").returncode == 4
    # A rejected cached token and a rejected fresh one.
    write_cache(configured, stale, expires_in=3600)
    loopback.route("POST", TOKEN, token_reply(fresh))
    loopback.route("GET", DEVICES, (401, {}, {"message": f"revoked: {fresh}"}))
    assert run("--json", "device", "list").returncode == 3
    # Grammar errors and commands not built yet, with a reason that quotes a secret.
    assert run("--json", "device", "tag", "pi5", "--appl").returncode == 2
    assert run("device", "tag", "pi5", "--add", "tag:fleet", "--apply", "--reason",
               f"rotate {read_secret}").returncode == 1
    assert run("--json", "doctor").returncode == 1

    secrets = [read_secret, write_secret, READ_TOKEN, stale, fresh]
    for printed in outputs:
        for secret in secrets:
            assert secret not in printed
    tn = configured.config_dir.parent
    scanned = []
    for directory, _, names in os.walk(tn):
        if os.path.commonpath([directory, configured.config_dir]) == str(configured.config_dir):
            continue
        for name in names:
            path = os.path.join(directory, name)
            content = Path(path).read_bytes().decode("utf-8", "replace")
            scanned.append(name)
            for secret in secrets:
                assert secret not in content, path
    # The sweep really covered the audit log, where every mint left a line.
    assert "audit.jsonl" in scanned


@pytest.mark.parametrize("form", ["file", "inline"])
def test_a_tskey_secret_in_test_posture_sends_zero_requests(cli, loopback, home, form):
    secret = tskey()
    if form == "file":
        write_role(home, "read", secret)
    else:
        write_role(home, "read", client_secret=secret)
    serve_devices(loopback)
    result = cli("--json", "device", "list")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (3, "TEST_POSTURE_REAL_SECRET")
    assert loopback.requests == []
    assert secret not in result.stdout + result.stderr


def test_an_unsafe_override_exits_3_and_contacts_nothing(cli, loopback, configured):
    serve_devices(loopback)
    port = loopback.port
    cases = [
        ({"TAILNET_API_BASE": loopback.base_url + "/api"}, (), "ENV_UNSAFE_OVERRIDE"),
        ({"TAILNET_API_BASE": f"https://127.0.0.1:{port}"}, (), "ENV_UNSAFE_OVERRIDE"),
        ({"TAILNET_API_BASE": f"http://user@127.0.0.1:{port}"}, (), "ENV_UNSAFE_OVERRIDE"),
        ({"TAILNET_API_BASE": f"http://127.0.0.1.example.com:{port}"}, (), "ENV_UNSAFE_OVERRIDE"),
        ({"TAILNET_HOME": "tn"}, (), "ENV_UNSAFE_OVERRIDE"),
        ({"TAILNET_API_BASE": ""}, (), "ENV_UNSAFE_OVERRIDE"),
        ({}, ("TAILNET_HOME",), "ENV_UNSAFE_OVERRIDE"),
        ({}, ("TAILNET_API_BASE",), "HOME_WITHOUT_BASE"),
    ]
    for env, unset, code in cases:
        result = cli("--json", "device", "list", env=env, unset=unset)
        refused = envelope(result)
        assert (result.returncode, refused["error"]["code"]) == (3, code), (env, unset)
        # Neither posture holds, and nothing falls back to production.
        assert refused["posture"] == "unknown"
    assert loopback.requests == []
    assert not configured.state_dir.exists()
