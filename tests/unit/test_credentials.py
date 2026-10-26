# ABOUTME: Tests for tailnet.credentials: loading the read and write clients, the four modes, and forget
# ABOUTME: (DESIGN.md §8). Every secret here is assembled at runtime; none is a staged literal.

import ast
import json
from pathlib import Path

import pytest

from tailnet import audit, credentials, errors
from tailnet.posture import Posture
from tailnet.redact import redact

READ_SCOPES = "devices:core:read policy_file:read devices:posture_attributes:read dns:read"
WRITE_SCOPE = "devices:core"


def fixture_secret(tag):
    """A test-posture secret: no tskey- prefix, so test posture accepts it (§7.1)."""
    return "test-client-" + tag


def client_key(tag="c"):
    """A key-shaped OAuth client secret, built from parts (CLAUDE.md invariant 14)."""
    return "tskey-" + "client-" + "kCred1tCNTRL-" + tag * 24


def api_key():
    """A key-shaped API access token, built from parts."""
    return "tskey-" + "api-" + "kCred1tCNTRL-" + "a" * 24


def make_posture(tmp_path, kind="test"):
    """A posture of the given kind rooted in tmp_path, with its config directory made 0700."""
    if kind == "test":
        environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    else:
        environ = {}
    posture = Posture.from_env(environ, real_home=tmp_path / "home")
    posture.config_dir.mkdir(mode=0o700, parents=True)
    return posture


@pytest.fixture
def posture(tmp_path):
    """A test posture with an empty, private config directory."""
    return make_posture(tmp_path)


def put(path, text, mode=0o600):
    """Write a file with an exact mode and return its path."""
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def write_role(posture, role, secret=None, /, *, inline=False, **fields):
    """Write <role>.json (and <role>.secret unless inline), as `credentials set` would.

    `fields` override the JSON document, including its own `role`, which is why `role`
    here is positional-only.
    """
    secret = fixture_secret(role + "0001") if secret is None else secret
    config = posture.config_dir
    doc = {"v": 1, "role": role, "client_id": f"k{role.title()}0001CNTRL",
           "client_secret": secret if inline else f"file:{config / (role + '.secret')}",
           "set_at": "2026-10-26T20:00:00Z",
           "granted_scope": READ_SCOPES if role == "read" else WRITE_SCOPE}
    if role == "write":
        doc.update(tags=["tag:fleet"], tags_source="self-lookup")
    doc.update(fields)
    if not inline:
        put(config / f"{role}.secret", secret + "\n")
    return put(config / f"{role}.json", json.dumps(doc))


def refusal(call, *args):
    """Call expecting a TailnetError; return it."""
    with pytest.raises(errors.TailnetError) as caught:
        call(*args)
    return caught.value


def test_missing_read_credential_names_the_set_command(posture):
    exc = refusal(credentials.load_read, posture)
    assert (exc.exit, exc.code) == (3, "CREDENTIAL_MISSING")
    assert "tailnet credentials set read" in exc.message
    steps = {step["needs"]: step for step in exc.next}
    assert steps["terminal"]["who"] == "mc"
    assert steps["terminal"]["do"] == "tailnet credentials set read"
    # The client has to exist before it can be set: the console steps come first.
    assert steps["console"]["who"] == "mc"
    assert "Trust credentials" in steps["console"]["do"]
    assert credentials.mode(posture) == "none"


def test_a_file_secret_is_loaded_and_its_target_checked(posture):
    secret = fixture_secret("file0002")
    write_role(posture, "read", secret)
    cred = credentials.load_read(posture)
    assert (cred.role, cred.client_id, cred.secret) == ("read", "kRead0001CNTRL", secret)
    assert cred.granted_scope == READ_SCOPES
    # Registered for redaction the moment it is loaded, and kept out of the repr.
    assert redact(f"x {secret} y") == "x [REDACTED] y"
    assert secret not in repr(cred)
    # The target gets the same checks as the file that names it.
    (posture.config_dir / "read.secret").chmod(0o644)
    exc = refusal(credentials.load_read, posture)
    assert exc.code == "CREDENTIAL_UNSAFE"
    assert "read.secret" in exc.message
    (posture.config_dir / "read.secret").unlink()
    exc = refusal(credentials.load_read, posture)
    assert exc.code == "CREDENTIAL_MISSING"
    assert str(posture.config_dir / "read.secret") in exc.message


def test_an_inline_read_secret_is_allowed(posture):
    secret = fixture_secret("inline0003")
    write_role(posture, "read", secret, inline=True)
    assert credentials.load_read(posture).secret == secret


def test_a_file_target_outside_the_config_dir_is_refused(posture, tmp_path, syscalls):
    config = posture.config_dir
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    put(elsewhere / "read.secret", fixture_secret("outside04") + "\n")
    (config / "sub").mkdir(mode=0o700)
    put(config / "sub" / "read.secret", fixture_secret("subdir05") + "\n")
    write_role(posture, "write")
    targets = [
        elsewhere / "read.secret",
        "read.secret",
        f"{config}/../config/../../elsewhere/read.secret",
        config / "sub" / "read.secret",
        # The other role's secret: a read must never be able to open write.secret.
        config / "write.secret",
        "",
    ]
    syscalls.events.clear()
    for target in targets:
        # inline=True writes no read.secret of its own; the field still names the target.
        write_role(posture, "read", inline=True, client_secret=f"file:{target}")
        exc = refusal(credentials.load_read, posture)
        assert exc.code == "CREDENTIAL_UNSAFE", target
    assert syscalls.named("write.secret") == []
    assert [args for event, args in syscalls.named("read.secret") if event == "open"] == []


def test_a_value_too_short_to_be_a_secret_is_refused_without_blanking_output(posture):
    write_role(posture, "read", "ab", inline=True)
    assert refusal(credentials.load_read, posture).code == "CREDENTIAL_MALFORMED"
    # Registering "ab" would have redacted it out of every later line.
    assert redact("tabs and labs") == "tabs and labs"


def test_an_inline_write_secret_is_refused(posture):
    secret = fixture_secret("wrinline6")
    write_role(posture, "write", secret, inline=True)
    exc = refusal(credentials.load_write_meta, posture)
    assert (exc.exit, exc.code) == (3, "WRITE_SECRET_INLINE")
    assert secret not in str(exc)
    # It was in memory, so it is redacted from anything printed later.
    assert redact(secret) == "[REDACTED]"


def test_write_metadata_loads_without_opening_the_write_secret(posture, syscalls):
    write_role(posture, "write", fixture_secret("write0007"))
    # A mode that would be refused if the secret were opened: metadata must not care.
    (posture.config_dir / "write.secret").chmod(0o644)
    syscalls.events.clear()
    meta = credentials.load_write_meta(posture)
    assert meta.client_id == "kWrite0001CNTRL"
    assert meta.tags == ("tag:fleet",)
    assert (meta.tags_source, meta.granted_scope) == ("self-lookup", WRITE_SCOPE)
    assert meta.secret_path == posture.config_dir / "write.secret"
    assert syscalls.named("write.secret") == []
    # Opening it is a separate, deliberate step, held to the full checks.
    assert refusal(credentials.load_write_secret, posture, meta).code == "CREDENTIAL_UNSAFE"
    (posture.config_dir / "write.secret").chmod(0o600)
    cred = credentials.load_write_secret(posture, meta)
    assert (cred.role, cred.client_id, cred.secret) == (
        "write", "kWrite0001CNTRL", fixture_secret("write0007"))


def test_read_metadata_loads_without_opening_the_read_secret(posture, syscalls):
    # status shows the read client without ever holding its secret (§17).
    assert credentials.load_read_meta(posture) is None
    write_role(posture, "read", fixture_secret("read0007"))
    (posture.config_dir / "read.secret").chmod(0o644)
    syscalls.events.clear()
    meta = credentials.load_read_meta(posture)
    assert (meta.client_id, meta.granted_scope) == ("kRead0001CNTRL", READ_SCOPES)
    assert meta.secret_path == posture.config_dir / "read.secret"
    assert meta.set_at == "2026-10-26T20:00:00Z"
    assert syscalls.named("read.secret") == []
    # An inline secret has no file; it is registered for redaction all the same.
    inline = fixture_secret("inline07")
    write_role(posture, "read", inline, inline=True)
    meta = credentials.load_read_meta(posture)
    assert meta.secret_path is None
    assert redact(f"x {inline} y") == "x [REDACTED] y"
    # A file: target outside the config directory is refused here too.
    write_role(posture, "read", client_secret="file:/etc/passwd")
    assert refusal(credentials.load_read_meta, posture).code == "CREDENTIAL_UNSAFE"


def test_write_metadata_is_none_without_write_json_and_unrecorded_tags_are_none(posture):
    assert credentials.load_write_meta(posture) is None
    write_role(posture, "write", tags=None, tags_source=None)
    assert credentials.load_write_meta(posture).tags is None


def test_a_missing_write_secret_is_refused_before_any_send(posture):
    write_role(posture, "write")
    meta = credentials.load_write_meta(posture)
    (posture.config_dir / "write.secret").unlink()
    exc = refusal(credentials.load_write_secret, posture, meta)
    assert (exc.exit, exc.code) == (5, "WRITE_CREDENTIAL_MISSING")


def test_an_api_access_token_is_refused_by_name(tmp_path):
    production = make_posture(tmp_path, "production")
    write_role(production, "read", api_key(), inline=True)
    exc = refusal(credentials.load_read, production)
    assert (exc.exit, exc.code) == (3, "CREDENTIAL_MALFORMED")
    assert "tskey-api-" in exc.message and "API access token" in exc.message
    assert api_key() not in str(exc)
    # The shape production does accept: an OAuth client secret.
    write_role(production, "read", client_key())
    assert credentials.load_read(production).secret == client_key()
    write_role(production, "read", fixture_secret("noprefix08"))
    assert refusal(credentials.load_read, production).code == "CREDENTIAL_MALFORMED"


def test_a_tskey_secret_is_refused_in_test_posture(posture):
    for role in ("read", "write"):
        write_role(posture, role, client_key("t"))
    exc = refusal(credentials.load_read, posture)
    assert (exc.exit, exc.code) == (3, "TEST_POSTURE_REAL_SECRET")
    assert client_key("t") not in str(exc)
    meta = credentials.load_write_meta(posture)
    assert refusal(credentials.load_write_secret, posture, meta).code == "TEST_POSTURE_REAL_SECRET"
    # Fixture secrets must still look like secrets.
    for bad in ("short", "has a space in it", "x" * 257):
        write_role(posture, "read", bad, inline=True)
        assert refusal(credentials.load_read, posture).code == "CREDENTIAL_MALFORMED", bad


@pytest.mark.parametrize("change", [
    {"role": "write"}, {"v": 2}, {"v": True}, {"v": "1"}, {"client_id": None}, {"client_id": ""},
    {"client_id": "k with spaces"}, {"client_secret": None}, {"granted_scope": ["devices:core:read"]},
])
def test_a_role_mismatching_its_file_name_is_refused(posture, change):
    # Named for the role check; every other malformed field is refused the same way.
    secret = fixture_secret("malformed9")
    write_role(posture, "read", secret, inline=True, **change)
    exc = refusal(credentials.load_read, posture)
    assert exc.code == "CREDENTIAL_MALFORMED"
    assert secret not in str(exc)


@pytest.mark.parametrize("text", ["not json", "[1, 2]", "", '{"v": 1}', "invalid-utf-8"])
def test_a_file_that_is_not_a_credential_object_is_malformed(posture, text):
    path = posture.config_dir / "read.json"
    if text == "invalid-utf-8":
        path.write_bytes(b'{"v": 1, "role": "\xff"}')
        path.chmod(0o600)
    else:
        put(path, text)
    assert refusal(credentials.load_read, posture).code == "CREDENTIAL_MALFORMED"


def test_no_secret_is_read_from_the_environment(posture, monkeypatch):
    for name in ("TAILNET_CLIENT_SECRET", "TS_API_CLIENT_SECRET", "TAILSCALE_CLIENT_SECRET",
                 "OAUTH_CLIENT_SECRET", "TS_CLIENT_SECRET", "CLIENT_SECRET"):
        monkeypatch.setenv(name, fixture_secret("environ10"))
    assert refusal(credentials.load_read, posture).code == "CREDENTIAL_MISSING"
    # And by construction: the module never touches the environment at all.
    source = Path(credentials.__file__).read_text(encoding="utf-8")
    names = {node.attr for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Attribute)}
    names |= {node.id for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Name)}
    assert not names & {"environ", "getenv", "environb", "getenvb"}


def test_modes_none_read_only_two_client_single_client(posture):
    assert credentials.mode(posture) == "none"
    write_role(posture, "read")
    assert credentials.mode(posture) == "read-only"
    write_role(posture, "write")
    assert credentials.mode(posture) == "two-client"
    # One client recorded under both roles: its read token could write.
    write_role(posture, "write", client_id="kRead0001CNTRL")
    assert credentials.mode(posture) == "single-client"
    # Without read.json nothing works, whatever else is there.
    (posture.config_dir / "read.json").unlink()
    assert credentials.mode(posture) == "none"


@pytest.mark.parametrize("granted", [
    "devices:core:read policy_file:read devices:core", "all", "devices", "", None,
    "devices:core:read,policy_file:write",
])
def test_a_read_client_granted_write_scope_means_single_client(posture, granted):
    write_role(posture, "read", granted_scope=granted)
    assert credentials.mode(posture) == "single-client"
    write_role(posture, "write")
    assert credentials.mode(posture) == "single-client"


def test_forget_write_removes_secret_then_metadata_and_logs(posture, syscalls):
    write_role(posture, "read")
    write_role(posture, "write")
    result = credentials.forget(posture, "write")
    removals = [Path(args[0]).name for event, args in syscalls.events if event == "os.remove"]
    assert removals == ["write.secret", "write.json"]
    assert sorted(p.name for p in posture.config_dir.iterdir()) == ["read.json", "read.secret"]
    assert result.removed == ("write.secret", "write.json")
    assert result.audit_error is None
    record = audit.last(posture, "credential.forget")
    assert (record["role"], record["client_id"]) == ("write", "kWrite0001CNTRL")
    assert (record["tags"], record["tags_source"]) == (["tag:fleet"], "self-lookup")
    assert record["removed"] == ["write.secret", "write.json"]
    # Disarming twice is not an error: there is just nothing left to remove.
    again = credentials.forget(posture, "write")
    assert again.removed == ()
    assert audit.count_lines(posture) == 2


def test_forget_read_removes_its_token_cache_and_forget_token_only_the_cache(posture):
    write_role(posture, "read")
    write_role(posture, "write")
    put(posture.config_dir / "read-token.json", "{}")
    assert credentials.forget(posture, "token").removed == ("read-token.json",)
    put(posture.config_dir / "read-token.json", "{}")
    assert credentials.forget(posture, "read").removed == (
        "read.secret", "read.json", "read-token.json")
    assert sorted(p.name for p in posture.config_dir.iterdir()) == ["write.json", "write.secret"]
    with pytest.raises(ValueError):
        credentials.forget(posture, "everything")


def test_forget_never_waits_on_the_audit_log(posture):
    # Removing power must not depend on recording it: a log that cannot be written is
    # reported, and the files are gone anyway.
    write_role(posture, "write")
    posture.state_dir.parent.mkdir(parents=True, exist_ok=True)
    posture.state_dir.write_bytes(b"")
    result = credentials.forget(posture, "write")
    assert result.removed == ("write.secret", "write.json")
    assert "AUDIT_UNWRITABLE" in result.audit_error
    assert not (posture.config_dir / "write.secret").exists()


def test_a_typed_client_is_checked_as_a_loaded_one_is_and_its_secret_registered_first(posture):
    secret = fixture_secret("typed0042")
    cred = credentials.typed(posture, "read", "kTyped01CNTRL", secret)
    assert (cred.role, cred.client_id, cred.secret) == ("read", "kTyped01CNTRL", secret)
    assert secret not in repr(cred)
    assert redact(f"echo {secret}") == "echo [REDACTED]"
    # A real key typed into a test home is refused, and never shown, like one in a file.
    with pytest.raises(errors.LocalError) as caught:
        credentials.typed(posture, "read", "kTyped01CNTRL", client_key("t"))
    assert caught.value.code == "TEST_POSTURE_REAL_SECRET"
    assert client_key("t") not in str(caught.value)
    for client_id, typed_secret in (("k with spaces", secret), ("", secret),
                                    ("kTyped01CNTRL", "")):
        with pytest.raises(errors.LocalError) as caught:
            credentials.typed(posture, "read", client_id, typed_secret)
        assert caught.value.code == "CREDENTIAL_MALFORMED"


def test_store_writes_the_secret_then_its_metadata_0600_in_a_tightened_directory(tmp_path,
                                                                                 syscalls):
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    posture = Posture.from_env(environ, real_home=tmp_path / "home")
    posture.config_dir.mkdir(parents=True)
    posture.config_dir.chmod(0o755)
    cred = credentials.typed(posture, "write", "kTyped02CNTRL", fixture_secret("typed0043"))
    written = credentials.store(posture, cred, granted_scope=WRITE_SCOPE,
                                set_at="2026-10-26T20:00:00Z", tags=("tag:fleet",),
                                tags_source="typed")
    config = posture.config_dir
    assert written == (config / "write.secret", config / "write.json")
    assert config.stat().st_mode & 0o777 == 0o700
    renames = [Path(args[1]).name for event, args in syscalls.events if event == "os.rename"]
    assert renames == ["write.secret", "write.json"]
    assert (config / "write.secret").read_text() == fixture_secret("typed0043") + "\n"
    meta = credentials.load_write_meta(posture)
    assert (meta.client_id, meta.tags, meta.tags_source, meta.granted_scope) == (
        "kTyped02CNTRL", ("tag:fleet",), "typed", WRITE_SCOPE)
    for name in ("write.secret", "write.json"):
        assert (config / name).stat().st_mode & 0o777 == 0o600
    cred = credentials.typed(posture, "read", "kTyped03CNTRL", fixture_secret("typed0044"))
    credentials.store(posture, cred, granted_scope=READ_SCOPES, set_at="2026-10-26T20:00:00Z")
    loaded = credentials.load_read(posture)
    assert (loaded.client_id, loaded.secret, loaded.granted_scope) == (
        "kTyped03CNTRL", fixture_secret("typed0044"), READ_SCOPES)
    assert "tags" not in json.loads((config / "read.json").read_text())
