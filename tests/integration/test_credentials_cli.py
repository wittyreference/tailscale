# ABOUTME: Integration tests for `tailnet credentials set` on a real terminal (pty.fork, so getpass reads a
# ABOUTME: terminal) and for `forget`: files 0600, one verifying mint, the write client's tags, no stray secret.

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from credfiles import (
    READ_SCOPES,
    WRITE_SCOPE,
    access_token,
    fixture_secret,
    token_reply,
    write_role,
)

API = "/api/v2"
TOKEN = API + "/oauth/token"
KEYS = API + "/tailnet/-/keys/"
PTY_CLI = Path(__file__).resolve().parents[1] / "pty_cli.py"
READ_ID, WRITE_ID = "kRead0002CNTRL", "kWrite0002CNTRL"
REMINDER = "each mint is one 'Create OAuth access token' event in your Tailscale audit log"
TAGS_PROMPT = "Tags on this write client, comma-separated, as the console shows them:"


def on_terminal(cli, script, *args):
    """Run `tailnet ARGS` on a real terminal, answering each prompt from `script`.

    Returns (exit code, everything the terminal showed). The CLI process is the same one
    the other integration tests run, with the same environment, only on a pty.
    """
    result = subprocess.run([sys.executable, "-I", str(PTY_CLI), json.dumps(script), *args],
                            env=cli.env, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    run = json.loads(result.stdout)
    return run["exit"], run["transcript"]


def audit_records(posture, event):
    """Every audit record of one event in the test home, oldest first."""
    log = posture.state_dir / "audit.jsonl"
    if not log.exists():
        return []
    return [r for r in map(json.loads, log.read_text().splitlines()) if r["event"] == event]


def mode_of(path):
    """A file's permission bits."""
    return stat.S_IMODE(path.stat().st_mode)


def every_file(posture):
    """The text of every file under the test home, for sweeping it for a value."""
    root = posture.config_dir.parent
    return {path: path.read_bytes().decode("utf-8", "replace")
            for path in root.rglob("*") if path.is_file()}


def test_set_refuses_without_a_terminal(cli, loopback, home):
    result = cli("--json", "credentials", "set", "read")
    assert result.returncode == 3
    env = json.loads(result.stdout)
    assert env["error"]["code"] == "NOT_A_TTY"
    # The agent's Bash tool has no terminal, so this is MC's command: it says so and how.
    assert any(step["who"] == "mc" and step.get("needs") == "terminal" for step in env["next"])
    assert loopback.requests == []
    assert not (home.config_dir / "read.json").exists()


def test_set_read_over_a_pty_writes_0600_files_and_mints_once(cli, loopback, home):
    secret = fixture_secret("typed0001")
    loopback.route("POST", TOKEN, token_reply(access_token("verify01")))
    code, shown = on_terminal(cli, [["Client ID:", READ_ID], ["Client secret:", secret]],
                              "credentials", "set", "read")
    assert code == 0, shown
    config = home.config_dir
    assert mode_of(config) == 0o700
    assert (mode_of(config / "read.json"), mode_of(config / "read.secret")) == (0o600, 0o600)
    assert (config / "read.secret").read_text() == secret + "\n"
    doc = json.loads((config / "read.json").read_text())
    assert (doc["v"], doc["role"], doc["client_id"]) == (1, "read", READ_ID)
    assert doc["client_secret"] == f"file:{config / 'read.secret'}"
    assert doc["granted_scope"] == READ_SCOPES and doc["set_at"]
    [mint] = loopback.requests
    assert (mint.method, mint.path) == ("POST", TOKEN)
    assert mint.form()["client_id"] == [READ_ID] and mint.form()["client_secret"] == [secret]
    # Two-client and read-only mode mint with no scope (§9.1).
    assert "scope" not in mint.form()
    # The read token's grant is read-only, so it is cached for its hour.
    cache = json.loads((config / "read-token.json").read_text())
    assert (cache["client_id"], cache["access_token"]) == (READ_ID, access_token("verify01"))
    # The ID was typed with echo on; the secret never appeared on the terminal.
    assert READ_ID in shown and secret not in shown
    assert REMINDER in shown
    [line] = audit_records(home, "credential.set")
    assert (line["role"], line["client_id"], line["granted_scope"]) == ("read", READ_ID,
                                                                      READ_SCOPES)
    assert len(audit_records(home, "token.mint")) == 1
    assert all(secret not in text for path, text in every_file(home).items()
               if path.name != "read.secret")


def test_set_write_over_a_pty_records_tags_from_the_self_lookup(cli, loopback, home):
    write_role(home, "read")
    secret = fixture_secret("typedw001")
    write_token = access_token("writev01")
    loopback.route("POST", TOKEN, token_reply(write_token, scope=WRITE_SCOPE))
    loopback.route("GET", KEYS + WRITE_ID, (200, {"X-Tailscale-Request-Id": "REQ-key"}, {
        "id": WRITE_ID, "keyType": "client", "scopes": [WRITE_SCOPE], "tags": ["tag:fleet"],
        "invalid": False}))
    code, shown = on_terminal(cli, [["Client ID:", WRITE_ID], ["Client secret:", secret]],
                              "credentials", "set", "write")
    assert code == 0, shown
    doc = json.loads((home.config_dir / "write.json").read_text())
    assert (doc["client_id"], doc["tags"], doc["tags_source"]) == (WRITE_ID, ["tag:fleet"],
                                                                   "self-lookup")
    assert doc["client_secret"] == f"file:{home.config_dir / 'write.secret'}"
    assert doc["granted_scope"] == WRITE_SCOPE
    assert mode_of(home.config_dir / "write.secret") == 0o600
    mint, lookup = loopback.requests
    assert "scope" not in mint.form()
    # The self-lookup goes with the write token: any scope may read its own key [TC L45].
    assert lookup.header("authorization") == f"Bearer {write_token}"
    # The write token is held for this one command and never touches disk (invariant 3).
    assert not (home.config_dir / "read-token.json").exists()
    assert all(write_token not in text for text in every_file(home).values())
    [line] = audit_records(home, "credential.set")
    assert (line["tags"], line["tags_source"]) == (["tag:fleet"], "self-lookup")
    assert line["self_lookup"]["status"] == 200
    assert TAGS_PROMPT not in shown and secret not in shown


def test_set_write_falls_back_to_typed_tags(cli, loopback, home):
    secret = fixture_secret("typedw002")
    loopback.route("POST", TOKEN, token_reply(access_token("writev02"), scope=WRITE_SCOPE))
    loopback.route("GET", KEYS + WRITE_ID, (404, {}, {"message": "Tailnet or key not found."}))
    code, shown = on_terminal(cli, [["Client ID:", WRITE_ID], ["Client secret:", secret],
                                    [TAGS_PROMPT, "tag:fleet, TAG:CI"]],
                              "credentials", "set", "write")
    assert code == 0, shown
    doc = json.loads((home.config_dir / "write.json").read_text())
    # Tailscale reads every tag as lowercase [pol (f)].
    assert (doc["tags"], doc["tags_source"]) == (["tag:fleet", "tag:ci"], "typed")
    [line] = audit_records(home, "credential.set")
    # The lookup's outcome is recorded either way: it settles Q3 for the write client.
    assert line["self_lookup"]["status"] == 404
    assert line["tags_source"] == "typed"


def test_set_write_refuses_a_client_that_cannot_write(cli, loopback, home):
    loopback.route("POST", TOKEN, token_reply(access_token("writev03"), scope="devices:core:read"))
    code, shown = on_terminal(cli, [["Client ID:", WRITE_ID],
                                    ["Client secret:", fixture_secret("typedw003")]],
                              "--json", "credentials", "set", "write")
    assert code == 3, shown
    assert "CREDENTIAL_MALFORMED" in shown
    assert not (home.config_dir / "write.json").exists()
    assert not (home.config_dir / "write.secret").exists()


def test_a_client_the_token_endpoint_refuses_is_never_stored(cli, loopback, home):
    write_role(home, "read")
    before = (home.config_dir / "read.json").read_text()
    loopback.route("POST", TOKEN, (401, {}, {"message": "API token invalid"}))
    code, shown = on_terminal(cli, [["replace the existing read client? [y/N]", "y"],
                                    ["Client ID:", READ_ID],
                                    ["Client secret:", fixture_secret("typed0004")]],
                              "credentials", "set", "read")
    assert code == 3, shown
    assert "TOKEN_REJECTED" in shown
    # Verified before stored: the client that worked is still in place.
    assert (home.config_dir / "read.json").read_text() == before
    assert audit_records(home, "credential.set") == []


def test_set_asks_before_replacing_and_keeps_the_old_client_on_no(cli, loopback, home):
    write_role(home, "read")
    before = (home.config_dir / "read.json").read_text()
    code, shown = on_terminal(cli, [["replace the existing read client? [y/N]", "n"]],
                              "credentials", "set", "read")
    assert code == 0, shown
    assert "Client ID:" not in shown
    assert (home.config_dir / "read.json").read_text() == before
    assert loopback.requests == []


@pytest.mark.parametrize("typed", ["tag:fleet,,", "fleet", ""])
def test_typed_tags_that_are_not_tags_store_nothing(cli, loopback, home, typed):
    loopback.route("POST", TOKEN, token_reply(access_token("writev05"), scope=WRITE_SCOPE))
    loopback.route("GET", KEYS + WRITE_ID, (404, {}, {"message": "Tailnet or key not found."}))
    code, shown = on_terminal(cli, [["Client ID:", WRITE_ID],
                                    ["Client secret:", fixture_secret("typedw005")],
                                    [TAGS_PROMPT, typed]],
                              "credentials", "set", "write")
    assert code == 2, shown
    assert "TAG_MALFORMED" in shown
    assert not (home.config_dir / "write.json").exists()


NOT_REVOCATION = ("this is not revocation. The client still exists in Tailscale; MC revokes it in "
                  "the console: Trust credentials → Revoke → Revoke")


def test_forget_write_disarms_without_a_prompt(cli, loopback, home):
    write_role(home, "read")
    write_role(home, "write")
    # No terminal and no input: any agent may disarm, and nothing waits for an answer.
    result = cli("credentials", "forget", "write")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in home.config_dir.iterdir()) == ["read.json", "read.secret"]
    assert NOT_REVOCATION in result.stdout
    assert result.stdout.startswith("OK: forgot the write client kWrite0001CNTRL")
    [line] = audit_records(home, "credential.forget")
    assert (line["role"], line["client_id"], line["removed"]) == (
        "write", "kWrite0001CNTRL", ["write.secret", "write.json"])
    # Disarming again is not an error: there is nothing left to remove, and it says so.
    again = json.loads(cli("--json", "credentials", "forget", "write").stdout)
    assert (again["exit"], again["outcome"]) == (0, "ok")
    assert again["data"]["removed"] == [] and again["data"]["not_revocation"] == NOT_REVOCATION
    assert any(step["who"] == "mc" and step.get("needs") == "console" for step in again["next"])
    assert loopback.requests == []


def test_forget_token_removes_only_the_cache(cli, home):
    write_role(home, "read")
    (home.config_dir / "read-token.json").write_text("{}")
    (home.config_dir / "read-token.json").chmod(0o600)
    env = json.loads(cli("--json", "credentials", "forget", "token").stdout)
    assert env["data"]["removed"] == ["read-token.json"]
    assert sorted(p.name for p in home.config_dir.iterdir()) == ["read.json", "read.secret"]


def test_forget_reports_a_log_it_cannot_write_and_disarms_anyway(cli, home):
    write_role(home, "write")
    home.state_dir.parent.mkdir(parents=True, exist_ok=True)
    home.state_dir.write_bytes(b"")
    result = cli("--json", "credentials", "forget", "write")
    assert result.returncode == 0, result.stderr
    env = json.loads(result.stdout)
    assert env["data"]["removed"] == ["write.secret", "write.json"]
    assert [w["code"] for w in env["warnings"]] == ["AUDIT_UNWRITABLE"]
    assert "the files are gone" in env["warnings"][0]["message"]
    assert "tailnet: AUDIT_UNWRITABLE:" in result.stderr
    assert not (home.config_dir / "write.secret").exists()
