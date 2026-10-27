# ABOUTME: Tests for tailnet.tokens: minting at the OAuth endpoint, what may be cached, and the 0600
# ABOUTME: read-token cache that keeps an hour of reads to one console event (DESIGN.md §9), over loopback.

import json
import stat
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from credfiles import (
    READ_SCOPES,
    WRITE_SCOPE,
    access_token,
    fixture_secret,
    token_reply,
    write_cache,
    write_role,
)

from tailnet import credentials, errors, http, tokens
from tailnet.posture import Posture
from tailnet.redact import redact

TOKEN = "/api/v2/oauth/token"
FORM = "application/x-www-form-urlencoded"


@pytest.fixture
def posture(loopback, tmp_path):
    """A test posture pointed at the loopback seam, with a read client configured."""
    environ = {"TAILNET_API_BASE": loopback.base_url, "TAILNET_HOME": str(tmp_path / "tn")}
    posture = Posture.from_env(environ, real_home=tmp_path / "real")
    write_role(posture, "read")
    return posture


@pytest.fixture
def transport(posture):
    """A transport to the seam; no test here should ever need to wait."""
    return http.Transport(posture, sleep=lambda seconds: None)


def cache_path(posture):
    """Where the read-token cache lives (§9.3)."""
    return posture.config_dir / "read-token.json"


def audit_lines(posture, event="token.mint"):
    """Every audit record of one event, oldest first."""
    log = posture.state_dir / "audit.jsonl"
    records = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return [record for record in records if record["event"] == event]


def failure(call, *args, **kwargs):
    """Call expecting a TailnetError; return it."""
    with pytest.raises(errors.TailnetError) as caught:
        call(*args, **kwargs)
    return caught.value


def test_only_scopes_that_all_end_in_read_are_cacheable():
    # One rule, kept in credentials because mode() needs it, re-exported here (A13).
    assert tokens.cacheable is credentials.cacheable
    assert tokens.cacheable(READ_SCOPES)
    assert tokens.cacheable("devices:core:read")
    assert not tokens.cacheable("devices:core:read devices:core")
    assert not tokens.cacheable("policy_file dns:read")


@pytest.mark.parametrize("scope", [None, "", "   ", ",", " , ", 5, ["devices:core:read"]])
def test_a_missing_or_empty_scope_is_not_cacheable(scope):
    assert not tokens.cacheable(scope)


@pytest.mark.parametrize("scope", ["devices", "all", "devices dns:read", "dns:read,all"])
def test_legacy_devices_and_all_count_as_write_power(scope):
    # OC L132's own example grant is the legacy "devices"; it can write.
    assert not tokens.cacheable(scope)


def test_scope_is_split_on_spaces_and_commas():
    # The multi-scope format is unverified (critic Q5), so both separators are read.
    assert tokens.cacheable("devices:core:read,dns:read")
    assert tokens.cacheable("devices:core:read, dns:read")
    assert tokens.cacheable("devices:core:read\tdns:read\n")
    assert not tokens.cacheable("devices:core:read,devices:core")


def test_a_cached_token_is_reused_until_five_minutes_before_expiry(loopback, posture, transport):
    write_cache(posture, access_token("cached01"), expires_in=400)
    assert tokens.ReadToken(posture, transport).bearer() == access_token("cached01")
    assert loopback.requests == []
    # Inside the five-minute margin a long command could watch it expire: mint instead.
    write_cache(posture, access_token("cached02"), expires_in=200)
    loopback.route("POST", TOKEN, token_reply(access_token("fresh003")))
    source = tokens.ReadToken(posture, transport)
    assert source.bearer() == access_token("fresh003")
    assert source.bearer() == access_token("fresh003")
    assert len(loopback.requests) == 1
    cache = json.loads(cache_path(posture).read_text())
    assert (cache["v"], cache["client_id"], cache["access_token"], cache["scope"]) == (
        1, "kRead0001CNTRL", access_token("fresh003"), READ_SCOPES)
    expires = datetime.strptime(cache["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
    left = expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
    assert timedelta(seconds=3500) < left <= timedelta(seconds=3600)
    assert stat.S_IMODE(cache_path(posture).stat().st_mode) == 0o600
    # The next command, in another process in real use, reuses it: one mint an hour.
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh003")
    assert len(loopback.requests) == 1


def test_the_read_token_says_where_it_came_from_and_counts_its_mints(loopback, posture,
                                                                       transport):
    # Doctor reports "reused cache: no audit event" or "minted: 1 event" from these (§16.2 S1).
    source = tokens.ReadToken(posture, transport)
    assert (source.token, source.from_cache, source.mints) == (None, False, 0)
    write_cache(posture, access_token("cached09"), expires_in=3000)
    source.bearer()
    assert (source.token.access_token, source.from_cache, source.mints) == (
        access_token("cached09"), True, 0)
    assert source.token.scope == READ_SCOPES
    loopback.route("POST", TOKEN, token_reply(access_token("renewed9")))
    assert source.renew() == access_token("renewed9")
    assert (source.from_cache, source.mints) == (False, 1)
    fresh = tokens.ReadToken(posture, transport)
    cache_path(posture).unlink()
    fresh.bearer()
    assert (fresh.from_cache, fresh.mints) == (False, 1)


def test_a_cache_for_another_client_id_is_ignored(loopback, posture, transport):
    write_cache(posture, access_token("other001"), expires_in=3000, client_id="kOther0001CNTRL")
    loopback.route("POST", TOKEN, token_reply(access_token("fresh004")))
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh004")
    assert json.loads(cache_path(posture).read_text())["client_id"] == "kRead0001CNTRL"


def test_a_cached_scope_that_can_write_is_ignored(loopback, posture, transport):
    write_cache(posture, access_token("wide0001"), expires_in=3000, scope="devices:core")
    loopback.route("POST", TOKEN, token_reply(access_token("fresh005")))
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh005")


def test_an_insecure_cache_is_unlinked_with_a_warning(loopback, posture, transport, capsys,
                                                      syscalls):
    write_cache(posture, access_token("exposed1"), expires_in=3000, mode=0o644)
    loopback.route("POST", TOKEN, token_reply(access_token("fresh006")))
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh006")
    err = capsys.readouterr().err
    assert "tailnet: TOKEN_CACHE_UNSAFE:" in err
    assert "may have been exposed" in err and "expires by" in err
    assert access_token("exposed1") not in err
    assert [event for event, _ in syscalls.named("read-token.json")].count("os.remove") == 1
    # Replaced by a private cache holding the new token.
    assert stat.S_IMODE(cache_path(posture).stat().st_mode) == 0o600
    assert json.loads(cache_path(posture).read_text())["access_token"] == access_token("fresh006")


@pytest.mark.parametrize("with_write_client", [False, True])
def test_the_mint_is_a_form_post_with_grant_type_and_no_scope_in_two_client_mode(
        loopback, posture, transport, with_write_client):
    if with_write_client:
        write_role(posture, "write")
    assert credentials.mode(posture) == ("two-client" if with_write_client else "read-only")
    loopback.route("POST", TOKEN, token_reply(access_token("fresh007")))
    tokens.ReadToken(posture, transport).bearer()
    [seen] = loopback.requests
    assert (seen.method, seen.path) == ("POST", TOKEN)
    assert seen.header("content-type") == FORM
    # No scope, no tags [critic Q2], and no Authorization header: the credential is the form.
    assert seen.form() == {"client_id": ["kRead0001CNTRL"],
                           "client_secret": [fixture_secret("read0001")],
                           "grant_type": ["client_credentials"]}
    assert seen.header("authorization") is None


def test_single_client_read_mints_send_the_four_read_scopes(loopback, posture, transport):
    write_role(posture, "write", client_id="kRead0001CNTRL", granted_scope="all")
    assert credentials.mode(posture) == "single-client"
    loopback.route("POST", TOKEN, token_reply(access_token("fresh008")))
    tokens.ReadToken(posture, transport).bearer()
    [seen] = loopback.requests
    assert seen.form()["scope"] == [READ_SCOPES]
    # The narrowed grant holds read power only, so it may be cached like any read token.
    assert json.loads(cache_path(posture).read_text())["access_token"] == access_token("fresh008")


def test_a_400_on_a_scoped_mint_retries_once_without_scope(loopback, posture, transport):
    write_role(posture, "write", client_id="kRead0001CNTRL")
    write_cache(posture, access_token("stale001"), expires_in=3000, client_id="kOld0001CNTRL")
    loopback.route("POST", TOKEN,
                   (400, {"X-Tailscale-Request-Id": "REQ-400"}, {"message": "invalid scope"}),
                   token_reply(access_token("fresh009"), scope="all", request_id="REQ-200"))
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh009")
    narrowed, unscoped = loopback.requests
    assert narrowed.form()["scope"] == [READ_SCOPES]
    assert "scope" not in unscoped.form()
    # "all" can write: held in memory for this command only, and the stale cache is gone.
    assert not cache_path(posture).exists()
    first, second = audit_lines(posture)
    assert (first["http_status"], first["scope_requested"], first["scope_granted"]) == (
        400, READ_SCOPES, None)
    assert (second["http_status"], second["scope_requested"], second["scope_granted"]) == (
        200, None, "all")
    assert (first["request_id"], second["request_id"], second["cacheable"]) == (
        "REQ-400", "REQ-200", False)


def test_a_401_on_mint_is_not_retried(loopback, posture, transport):
    loopback.route("POST", TOKEN,
                   (401, {"X-Tailscale-Request-Id": "REQ-401"}, {"message": "API token invalid"}),
                   token_reply(access_token("never010")))
    exc = failure(tokens.ReadToken(posture, transport).bearer)
    assert (exc.exit, exc.code, exc.http_status) == (3, "TOKEN_REJECTED", 401)
    assert "revoked or mistyped" in exc.message
    [step] = exc.next
    assert (step["who"], step["needs"]) == ("mc", "console")
    assert "Trust credentials" in step["do"]
    assert len(loopback.requests) == 1
    [line] = audit_lines(posture)
    assert (line["http_status"], line["request_id"], line["scope_granted"]) == (401, "REQ-401", None)


def test_every_mint_appends_a_token_mint_line(loopback, posture, transport):
    loopback.route("POST", TOKEN, token_reply(access_token("fresh011"), request_id="REQ-r"))
    source = tokens.ReadToken(posture, transport)
    source.bearer()
    write_role(posture, "write")
    write_cred = credentials.load_write_secret(posture, credentials.load_write_meta(posture))
    loopback.route("POST", TOKEN, token_reply(access_token("write012"), scope=WRITE_SCOPE,
                                              request_id="REQ-w"))
    write_token = tokens.mint(posture, transport, write_cred)
    read_line, write_line = audit_lines(posture)
    assert read_line == {**read_line, "role": "read", "client_id": "kRead0001CNTRL",
                         "scope_requested": None, "scope_granted": READ_SCOPES, "cacheable": True,
                         "http_status": 200, "request_id": "REQ-r"}
    assert write_line == {**write_line, "role": "write", "client_id": "kWrite0001CNTRL",
                          "scope_requested": None, "scope_granted": WRITE_SCOPE,
                          "cacheable": False, "http_status": 200, "request_id": "REQ-w"}
    # The line's expiry is the token's, so MC can match it to the console event [AUDIT L329].
    assert write_line["expires_at"] == write_token.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert access_token("fresh011") not in json.dumps(read_line)


def test_write_tokens_are_never_cached(loopback, posture, transport, syscalls):
    write_role(posture, "write")
    write_cred = credentials.load_write_secret(posture, credentials.load_write_meta(posture))
    # Even a grant that looks read-only is never written to disk for the write role.
    loopback.route("POST", TOKEN, token_reply(access_token("write013"), scope="devices:core:read"))
    token = tokens.mint(posture, transport, write_cred)
    assert (token.role, token.client_id, token.access_token) == (
        "write", "kWrite0001CNTRL", access_token("write013"))
    assert not cache_path(posture).exists()
    assert syscalls.named("read-token.json") == []


def test_only_a_read_only_read_token_is_ever_stored(loopback, posture, transport):
    # `credentials set read` caches its verification token by the same rule the reads use.
    loopback.route("POST", TOKEN, token_reply(access_token("store001")))
    token = tokens.mint(posture, transport, credentials.load_read(posture))
    tokens.store_cache(posture, token)
    cache = json.loads(cache_path(posture).read_text())
    assert (cache["client_id"], cache["access_token"], cache["scope"]) == (
        "kRead0001CNTRL", access_token("store001"), READ_SCOPES)
    assert stat.S_IMODE(cache_path(posture).stat().st_mode) == 0o600
    for unsafe in (replace(token, scope="devices:core"), replace(token, role="write")):
        with pytest.raises(ValueError):
            tokens.store_cache(posture, unsafe)
    tokens.discard_cache(posture)
    assert not cache_path(posture).exists()
    tokens.discard_cache(posture)


def test_a_write_mint_that_cannot_be_logged_stops_the_write(loopback, posture, transport):
    # A write whose token mint cannot be recorded is not sent (C9, invariant 6).
    write_role(posture, "write")
    write_cred = credentials.load_write_secret(posture, credentials.load_write_meta(posture))
    posture.state_dir.parent.mkdir(parents=True, exist_ok=True)
    posture.state_dir.write_bytes(b"")
    loopback.route("POST", TOKEN, token_reply(access_token("write014"), scope=WRITE_SCOPE))
    exc = failure(tokens.mint, posture, transport, write_cred)
    assert (exc.exit, exc.code) == (3, "AUDIT_UNWRITABLE")


def test_a_read_mint_that_cannot_be_logged_warns_and_continues(loopback, posture, transport,
                                                               capsys):
    posture.state_dir.parent.mkdir(parents=True, exist_ok=True)
    posture.state_dir.write_bytes(b"")
    loopback.route("POST", TOKEN, token_reply(access_token("fresh015")))
    assert tokens.ReadToken(posture, transport).bearer() == access_token("fresh015")
    assert "tailnet: AUDIT_UNWRITABLE:" in capsys.readouterr().err


def test_a_minted_token_is_registered_for_redaction_and_kept_out_of_repr(loopback, posture,
                                                                        transport):
    loopback.route("POST", TOKEN, token_reply(access_token("secret16")))
    token = tokens.mint(posture, transport, credentials.load_read(posture))
    assert redact(f"Bearer-less {access_token('secret16')} text") == "Bearer-less [REDACTED] text"
    assert access_token("secret16") not in repr(token)


@pytest.mark.parametrize("body", [
    {"token_type": "Bearer", "expires_in": 3600, "scope": READ_SCOPES},
    {"access_token": "test-access-" + "shape017", "token_type": "mac", "expires_in": 3600},
    {"access_token": "test-access-" + "shape018", "token_type": "Bearer", "expires_in": "3600"},
    {"access_token": "test-access-" + "shape019", "token_type": "Bearer", "expires_in": True},
    {"access_token": "test-access-" + "shape020", "token_type": "Bearer", "expires_in": 0},
    {"access_token": "test-access-" + "shape021", "token_type": "Bearer", "expires_in": 3600,
     "scope": 5},
    {"access_token": "short", "token_type": "Bearer", "expires_in": 3600},
    ["test-access-" + "shape022"],
    "test-access-" + "shape023 is not JSON",
])
def test_a_malformed_token_response_is_a_bad_response_that_never_shows_the_body(
        loopback, posture, transport, body):
    loopback.route("POST", TOKEN, (200, {}, body))
    exc = failure(tokens.mint, posture, transport, credentials.load_read(posture))
    assert (exc.exit, exc.code) == (4, "API_BAD_RESPONSE")
    assert "test-access-" not in exc.message
    assert not cache_path(posture).exists()
