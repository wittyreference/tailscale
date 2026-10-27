# ABOUTME: Tests for tailnet.writes.send, one target's POST and re-read, on the rows of DESIGN.md §12.6's
# ABOUTME: outcome table the integration seam cannot produce: a refused connect, and a timeout after sending.

import socket
import threading
from datetime import datetime, timedelta, timezone

import pytest
from credfiles import access_token, token_reply, write_role
from fixturefiles import body

from tailnet import (
    api,
    devices,
    errors,
    guard,
    http,
    protected,
    selfnode,
    tokens,
    writes,
)
from tailnet.posture import Posture

API = "/api/v2"
NOW = datetime(2026, 10, 27, 1, 2, 3, tzinfo=timezone.utc)
PI5 = "nPi5x001CNTRL"


def posture_for(base, tmp_path):
    """A test posture whose API is `base`, with the read client configured."""
    environ = {"TAILNET_API_BASE": base, "TAILNET_HOME": str(tmp_path / "tn")}
    posture = Posture.from_env(environ, real_home=tmp_path / "real")
    write_role(posture, "read")
    return posture


def pi5(**fields):
    """The scenario's pi5 as the API sends it: tagged, key expiry still on."""
    raw = next(d for d in body("scenario", "devices")["devices"] if d["nodeId"] == PI5)
    raw.update(fields)
    return raw


def plan():
    """A planned key-expiry disable on pi5, every check passing."""
    found = [devices.normalise(pi5())]
    ctx = guard.Context(me=selfnode.SelfNode(True, found[0], "line", None, None, None),
                        protected=protected.parse(f"self {PI5}\n"), gate_present=True,
                        settings_path="/s", write=None, now=NOW)
    [planned] = guard.plan_disable_key_expiry(found, ctx)
    return planned


def write_token():
    """A token as minted from the write client, held in memory only."""
    return tokens.Token(role="write", client_id="kWrite0001CNTRL",
                        access_token=access_token("write001"), scope="devices:core",
                        minted_at=NOW, expires_at=NOW + timedelta(hours=1), request_id=None)


def test_a_write_that_never_reached_the_api_is_rejected_as_not_sent(tmp_path):
    # A port nothing listens on: the connection is refused before a byte of the write is sent.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    session = api.session(posture_for(f"http://127.0.0.1:{port}", tmp_path))
    result = writes.send(session, plan(), write_token())
    assert (result.outcome, result.exit, result.audit_outcome) == ("rejected", errors.REJECTED,
                                                                   "failed")
    # Nothing can have changed, so the outcome is certain and there is nothing to re-read.
    assert (result.sent, result.confirmed, result.failure) == (False, True, "rejected")
    assert [entry["method"] for entry in result.http] == ["POST"]
    assert "nothing was sent" in result.message


@pytest.mark.parametrize("lands", [True, False])
def test_a_timeout_after_sending_is_decided_by_the_reread(loopback, tmp_path, lands):
    release = threading.Event()
    record = pi5()

    def stall(request):
        """Take the write (or not), then answer only after the client has given up."""
        if lands:
            record["keyExpiryDisabled"] = True
        release.wait(5)
        return 200, {}, {}

    loopback.route("POST", API + "/oauth/token", token_reply(access_token("read0001")))
    loopback.route("POST", f"{API}/device/{PI5}/key", stall)
    loopback.route("GET", f"{API}/device/{PI5}", lambda request: (200, {}, record))
    posture = posture_for(loopback.base_url, tmp_path)
    transport = http.Transport(posture, timeout=0.3)
    session = api.Session(transport, tokens.ReadToken(posture, transport))
    try:
        result = writes.send(session, plan(), write_token())
    finally:
        release.set()
    assert result.sent is True
    assert [r.method for r in loopback.requests if r.path.endswith("/key")] == ["POST"]
    if lands:
        # The answer never came, but the re-read shows the change: applied, confirmed.
        assert (result.outcome, result.exit, result.confirmed) == ("applied", errors.OK, True)
        assert result.observed == {"keyExpiryDisabled": True}
    else:
        # It may still land: never re-applied, and the agent is told so.
        assert (result.outcome, result.exit, result.failure) == ("unconfirmed",
                                                                 errors.UNCONFIRMED,
                                                                 "unconfirmed")
        assert "do not re-apply" in result.message
