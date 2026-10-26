# ABOUTME: Tests for tailnet.api, one wrapper per endpoint (DESIGN.md §6, §12.3): each read goes where the
# ABOUTME: spec says with the read token, and the two writes go once, with the write token, over loopback.

import json

import pytest
from credfiles import READ_SCOPES, WRITE_SCOPE, access_token, token_reply, write_role

from tailnet import api, credentials, errors, http, tokens
from tailnet.posture import Posture

API = "/api/v2"
TOKEN = API + "/oauth/token"
READ_BEARER = f"Bearer {access_token('read0001')}"
WRITE_BEARER = f"Bearer {access_token('write001')}"


@pytest.fixture
def posture(loopback, tmp_path):
    """A test posture at the seam, with read and write clients configured."""
    environ = {"TAILNET_API_BASE": loopback.base_url, "TAILNET_HOME": str(tmp_path / "tn")}
    posture = Posture.from_env(environ, real_home=tmp_path / "real")
    write_role(posture, "read")
    write_role(posture, "write")
    return posture


@pytest.fixture
def transport(posture):
    """A transport to the seam that never really sleeps."""
    return http.Transport(posture, sleep=lambda seconds: None)


@pytest.fixture
def write_token(loopback, posture, transport):
    """A real write token, minted from the write client at the seam."""
    cred = credentials.load_write_secret(posture, credentials.load_write_meta(posture))
    loopback.route("POST", TOKEN, token_reply(access_token("write001"), scope=WRITE_SCOPE))
    return tokens.mint(posture, transport, cred)


@pytest.fixture
def session(loopback, posture, transport, write_token):
    """An API session whose read token the seam mints on first use."""
    loopback.route("POST", TOKEN, token_reply(access_token("read0001"), scope=READ_SCOPES))
    return api.Session(transport, tokens.ReadToken(posture, transport))


def sent(loopback):
    """The requests after the token mints: the API calls under test."""
    return [r for r in loopback.requests if r.path != TOKEN]


def failure(call, *args):
    """Call expecting a TailnetError; return it."""
    with pytest.raises(errors.TailnetError) as caught:
        call(*args)
    return caught.value


def test_session_builds_a_transport_and_a_lazy_read_token(loopback, posture):
    session = api.session(posture)
    assert isinstance(session.transport, http.Transport)
    assert session.transport.base == loopback.base_url + API
    # Nothing is minted until a request needs the token.
    assert loopback.requests == []


def test_list_devices_reads_every_field_with_the_read_token(loopback, session):
    devices = [{"nodeId": "n1", "hostname": "pi5"}, {"nodeId": "n2", "hostname": "spec5"}]
    loopback.route("GET", API + "/tailnet/-/devices",
                   (200, {"X-Tailscale-Request-Id": "REQ-d"}, {"devices": devices}))
    reply = api.list_devices(session)
    assert reply.data == devices
    assert reply.response.request_id == "REQ-d"
    [listing] = sent(loopback)
    # fields=all carries sshEnabled and multipleConnections [api §5.1; spec 4753].
    assert listing.query == "fields=all"
    assert listing.header("authorization") == READ_BEARER


@pytest.mark.parametrize("call,path,query", [
    (lambda s: api.get_device(s, "nAbc456CNTRL"), "/device/nAbc456CNTRL", "fields=all"),
    (lambda s: api.get_key(s, "kRead0001CNTRL"), "/tailnet/-/keys/kRead0001CNTRL", ""),
    (lambda s: api.get_routes(s, "nAbc456CNTRL"), "/device/nAbc456CNTRL/routes", ""),
    (api.dns_nameservers, "/tailnet/-/dns/nameservers", ""),
    (api.dns_preferences, "/tailnet/-/dns/preferences", ""),
    (api.dns_searchpaths, "/tailnet/-/dns/searchpaths", ""),
    (api.dns_split, "/tailnet/-/dns/split-dns", ""),
    (api.dns_configuration, "/tailnet/-/dns/configuration", ""),
])
def test_each_read_goes_to_its_documented_endpoint(loopback, session, call, path, query):
    loopback.route("GET", API + path, (200, {}, {"answer": path}))
    assert call(session).data == {"answer": path}
    [seen] = sent(loopback)
    assert (seen.method, seen.query) == ("GET", query)
    assert seen.header("authorization") == READ_BEARER


@pytest.mark.parametrize("call,path,scope", [
    (api.list_devices, "/tailnet/-/devices", "devices:core:read"),
    (lambda s: api.get_routes(s, "n1"), "/device/n1/routes", "devices:routes:read"),
    (lambda s: api.get_policy(s, "application/json"), "/tailnet/-/acl", "policy_file:read"),
    (api.dns_configuration, "/tailnet/-/dns/configuration", "dns:read"),
])
def test_a_403_names_the_scope_the_call_needs(loopback, session, call, path, scope):
    loopback.route("GET", API + path, (403, {}, {"message": "forbidden"}))
    exc = failure(call, session)
    assert (exc.exit, exc.code) == (4, "API_FORBIDDEN")
    assert scope in exc.message and "possibly" in exc.message


def test_get_policy_returns_the_served_bytes_and_the_raw_etag(loopback, session):
    hujson = b'// MC\'s policy, comments kept\n{"grants": [], /* trailing */}\n'
    loopback.route("GET", API + "/tailnet/-/acl",
                   (200, {"Content-Type": "application/hujson", "ETag": '"e0b2816b418"'}, hujson))
    reply = api.get_policy(session, "application/hujson")
    # Never parsed and never re-serialised, so the comments survive [pol (f)].
    assert reply.data == hujson
    assert reply.response.etag_raw == '"e0b2816b418"'
    [seen] = sent(loopback)
    assert seen.header("accept") == "application/hujson"
    with pytest.raises(ValueError):
        api.get_policy(session, "text/plain")


def test_validate_tests_posts_a_json_array_and_takes_a_400_as_an_answer(loopback, session):
    tests = [{"src": "tag:dev", "proto": "tcp", "accept": ["100.64.0.5:22"]}]
    loopback.route("POST", API + "/tailnet/-/acl/validate", (200, {}, b""),
                   (400, {}, {"message": "parse error"}))
    assert api.validate_tests(session, tests).status == 200
    assert api.validate_tests(session, tests).status == 400
    first, _ = sent(loopback)
    # An array is "tests against the current policy" [spec 2508-2516].
    assert first.json() == tests
    assert first.header("content-type") == "application/json"
    assert first.header("authorization") == READ_BEARER
    with pytest.raises(TypeError):
        api.validate_tests(session, {"tests": tests})


def test_validate_policy_posts_the_bytes_with_their_content_type(loopback, session):
    draft = b"// candidate\n{\"tests\": []}\n"
    loopback.route("POST", API + "/tailnet/-/acl/validate", (200, {}, {}))
    assert api.validate_policy(session, draft, "application/hujson").status == 200
    [seen] = sent(loopback)
    assert seen.body == draft
    assert seen.header("content-type") == "application/hujson"
    with pytest.raises(ValueError):
        api.validate_policy(session, draft, "text/plain")


@pytest.mark.parametrize("status", [200, 500])
def test_set_device_tags_posts_the_full_set_once_with_the_write_token(loopback, session,
                                                                     write_token, status):
    loopback.route("POST", API + "/device/nAbc456CNTRL/tags", (status, {}, {}), (200, {}, {}))
    reply = api.set_device_tags(session, "nAbc456CNTRL", ["tag:fleet", "tag:lab"], write_token)
    assert reply.status == status
    [seen] = sent(loopback)
    # The list replaces the device's tags, so the whole new set is sent [api §5.7].
    assert seen.json() == {"tags": ["tag:fleet", "tag:lab"]}
    assert seen.header("authorization") == WRITE_BEARER
    assert seen.header("content-type") == "application/json"


@pytest.mark.parametrize("status", [200, 504])
def test_disable_key_expiry_posts_true_once_with_the_write_token(loopback, session, write_token,
                                                                status):
    loopback.route("POST", API + "/device/nAbc456CNTRL/key", (status, {}, {}), (200, {}, {}))
    assert api.disable_key_expiry(session, "nAbc456CNTRL", write_token).status == status
    [seen] = sent(loopback)
    assert seen.json() == {"keyExpiryDisabled": True}
    assert seen.header("authorization") == WRITE_BEARER


def test_writes_refuse_any_token_but_the_write_token(loopback, posture, session, transport):
    read_token = tokens.mint(posture, transport, credentials.load_read(posture))
    for wrong in (read_token, read_token.access_token, None):
        with pytest.raises(ValueError, match="write token"):
            api.disable_key_expiry(session, "n1", wrong)
        with pytest.raises(ValueError, match="write token"):
            api.set_device_tags(session, "n1", ["tag:fleet"], wrong)
    assert sent(loopback) == []


@pytest.mark.parametrize("node_id", ["n1/../acl", "n1?x=1", "", "n 1", "n1%2F", "ñ1", None])
def test_a_device_id_that_is_not_plain_letters_and_digits_is_never_sent(loopback, session,
                                                                        write_token, node_id):
    for call in (lambda: api.get_device(session, node_id),
                 lambda: api.get_routes(session, node_id),
                 lambda: api.disable_key_expiry(session, node_id, write_token),
                 lambda: api.set_device_tags(session, node_id, ["tag:fleet"], write_token)):
        exc = failure(call)
        assert (exc.exit, exc.code) == (4, "API_BAD_RESPONSE")
    assert sent(loopback) == []


def test_a_key_id_that_is_not_plain_letters_and_digits_is_refused_locally(loopback, session):
    exc = failure(api.get_key, session, "k1/../../devices")
    assert (exc.exit, exc.code) == (3, "CREDENTIAL_MALFORMED")
    assert sent(loopback) == []


@pytest.mark.parametrize("tags", [[], (), ["tag:fleet", 5], "tag:fleet"])
def test_a_tag_set_that_is_empty_or_not_a_list_of_strings_is_never_sent(loopback, session,
                                                                        write_token, tags):
    # The guard refuses an empty set first (TAG_SET_EMPTY); this is the backstop under it.
    with pytest.raises(ValueError):
        api.set_device_tags(session, "n1", tags, write_token)
    assert sent(loopback) == []


@pytest.mark.parametrize("call,path,body", [
    (api.list_devices, "/tailnet/-/devices", {"devices": "n1"}),
    (api.list_devices, "/tailnet/-/devices", {}),
    (api.list_devices, "/tailnet/-/devices", {"devices": ["n1"]}),
    (api.dns_nameservers, "/tailnet/-/dns/nameservers", ["8.8.8.8"]),
])
def test_a_body_of_the_wrong_shape_is_a_bad_response(loopback, session, call, path, body):
    loopback.route("GET", API + path, (200, {}, json.dumps(body)))
    exc = failure(call, session)
    assert (exc.exit, exc.code) == (4, "API_BAD_RESPONSE")


def test_the_openapi_document_is_read_without_a_token(loopback, posture, transport):
    # Doctor's drift check (§16.1 L11) needs no credential, so none is loaded or sent.
    loopback.route("GET", API, (200, {"Content-Type": "application/yaml"}, "openapi: 3.1.0\n"))
    reply = api.get_openapi(api.Session(transport, tokens.ReadToken(posture, transport)))
    assert reply.data == b"openapi: 3.1.0\n"
    [request] = loopback.requests
    assert (request.method, request.path, request.query) == ("GET", API, "outputOpenapiSchema=true")
    assert request.header("authorization") is None
    assert request.header("accept") == "*/*"
