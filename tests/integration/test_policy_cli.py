# ABOUTME: Integration tests for the policy commands as real CLI processes against the loopback seam: get
# ABOUTME: byte for byte, drafts under the state directory, validate's verdict, diff's readiness, live tests.

import hashlib
import json
import re
import stat
from pathlib import Path

import pytest
from credfiles import access_token, token_reply, write_role
from fixturefiles import body, raw_bytes

API = "/api/v2"
TOKEN = API + "/oauth/token"
ACL = API + "/tailnet/-/acl"
VALIDATE = ACL + "/validate"
READ_TOKEN = access_token("read0001")
ETAG = '"e0b2816b418"'
TIME = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"


class LivePolicy:
    """The tailnet's live policy behind the seam, as GET /acl serves it, and validate's answer.

    It serves HuJSON or JSON by the request's Accept header [spec 2244-2265] with one ETag,
    and both can be changed mid-test, which is how MC saving in the console looks.
    """

    def __init__(self, loopback):
        self.loopback = loopback
        self.hujson = raw_bytes("api", "policy.hujson")
        self.json = body("api", "policy")
        self.etag = ETAG
        self.answer = (200, {"X-Tailscale-Request-Id": "REQ-validate"}, {})
        loopback.route("POST", TOKEN, token_reply(READ_TOKEN))
        loopback.route("GET", ACL, self._get)
        loopback.route("POST", VALIDATE, lambda request: self.answer)

    def _get(self, request):
        """The policy in the form the request asked for, with the ETag header."""
        headers = {"X-Tailscale-Request-Id": "REQ-acl", "ETag": self.etag}
        if request.header("accept") == "application/json":
            return 200, {**headers, "Content-Type": "application/json"}, self.json
        return 200, {**headers, "Content-Type": "application/hujson"}, self.hujson

    def requests(self, method, path):
        """The recorded requests to one path with one method, in order."""
        return [r for r in self.loopback.requests if (r.method, r.path) == (method, path)]


@pytest.fixture
def live(loopback):
    """The live policy behind this test's seam."""
    return LivePolicy(loopback)


@pytest.fixture
def configured(home):
    """A test home with the read client configured, as `credentials set read` leaves it."""
    write_role(home, "read")
    return home


def envelope(result):
    """The one tailnet.v1 object stdout holds."""
    return json.loads(result.stdout)


def sha256(data):
    """The hex sha256 of some bytes."""
    return hashlib.sha256(data).hexdigest()


def mode(path):
    """A path's permission bits."""
    return stat.S_IMODE(path.stat().st_mode)


def test_policy_get_prints_hujson_byte_for_byte_and_the_raw_etag_on_stderr(cli, live, configured):
    # MC's own comments, a carriage return, a tab and a non-ASCII character must all survive:
    # the bytes are never parsed or re-serialised [pol (f)].
    live.hujson += "// MC’s note on the fleet\t\r\n".encode()
    result = cli("policy", "get", text=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == live.hujson
    [request] = live.requests("GET", ACL)
    assert request.header("accept") == "application/hujson"
    assert request.header("authorization") == f"Bearer {READ_TOKEN}"
    # The metadata goes to stderr: the raw ETag, quotes included, then the same shown without
    # one pair [critic R3], the body's hash and its line count, with the time it was read.
    err = result.stderr.decode("utf-8")
    lines = live.hujson.count(b"\n")
    assert re.search(rf"^OK: the live policy as HuJSON, {lines} lines \(as of {TIME}\)$", err,
                     re.MULTILINE)
    assert f'etag: e0b2816b418 (raw header: {ETAG})' in err
    assert f"sha256: {sha256(live.hujson)}" in err


def test_policy_get_json_envelope_carries_the_text_and_both_etag_forms(cli, live, configured):
    result = cli("--json", "policy", "get")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["command"], env["outcome"], env["request_ids"]) == ("policy get", "ok", ["REQ-acl"])
    data = env["data"]
    assert data["text"].encode() == live.hujson
    assert (data["etag_raw"], data["etag"], data["format"]) == (ETAG, "e0b2816b418", "hujson")
    assert (data["sha256"], data["lines"]) == (sha256(live.hujson), live.hujson.count(b"\n"))
    # HuJSON is never parsed, so its sections are not counted.
    assert data["sections"] is None


def test_policy_get_json_format_counts_sections_and_says_comments_are_not_in_it(cli, live,
                                                                               configured):
    result = cli("--json", "policy", "get", "--format", "json")
    assert result.returncode == 0, result.stderr
    [request] = live.requests("GET", ACL)
    assert request.header("accept") == "application/json"
    data = envelope(result)["data"]
    assert json.loads(data["text"]) == live.json
    assert data["format"] == "json"
    assert data["sections"] == {"acls": 1, "grants": 0, "ssh": 0, "tests": 0, "sshTests": 0,
                                "hosts": 1, "groups": 1, "tagOwners": 0}
    [warning] = envelope(result)["warnings"]
    assert warning["code"] == "POLICY_JSON_NO_COMMENTS"
    assert "comments" in warning["message"]
    assert "tailnet: POLICY_JSON_NO_COMMENTS: " in result.stderr


def test_policy_get_out_writes_the_bytes_0600_and_says_where(cli, live, configured, tmp_path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    out = work / "policy.hujson"
    result = cli("policy", "get", "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert out.read_bytes() == live.hujson
    assert mode(out) == 0o600
    # The body went to the file, so stdout holds the verdict instead.
    assert re.match(rf"OK: the live policy as HuJSON, \d+ lines, written to {re.escape(str(out))}"
                    rf" \(as of {TIME}\)\n", result.stdout)
    assert f"sha256: {sha256(live.hujson)}" in result.stdout
    data = envelope(cli("--json", "policy", "get", "--out", str(out)))["data"]
    assert (data["out"], data["text"]) == (str(out), None)


def test_policy_get_out_refuses_the_cli_s_own_directories_before_any_request(cli, live, loopback,
                                                                              configured,
                                                                              tmp_path):
    # An --out there could replace a credential or rewrite the audit log (invariant 6).
    read_json = configured.config_dir / "read.json"
    before = read_json.read_bytes()
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    for target in (read_json, configured.state_dir / "audit.jsonl", shared / "policy.hujson",
                   tmp_path / "missing" / "policy.hujson"):
        result = cli("--json", "policy", "get", "--out", str(target))
        assert (result.returncode, envelope(result)["error"]["code"]) == (2, "USAGE"), target
    assert read_json.read_bytes() == before
    assert not (configured.state_dir / "audit.jsonl").exists()
    assert not (shared / "policy.hujson").exists()
    # Every refusal comes before the fetch, so a refused --out costs no request.
    assert loopback.requests == []


def test_draft_files_are_byte_identical_to_the_served_policy(cli, live, configured):
    live.hujson += b"// kept exactly\r\n"
    result = cli("--json", "policy", "draft", "--name", "fix-ssh")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    path = Path(env["data"]["path"])
    # Drafts live under the state directory, never in a repository [mc P13].
    assert path.parent == configured.drafts_dir == configured.state_dir / "drafts"
    assert re.fullmatch(r"\d{8}T\d{6}Z-fix-ssh", path.name)
    assert (path / "base.hujson").read_bytes() == live.hujson
    assert (path / "candidate.hujson").read_bytes() == live.hujson
    assert mode(path) == 0o700
    for name in ("base.hujson", "candidate.hujson", "meta.json"):
        assert mode(path / name) == 0o600, name
    meta = json.loads((path / "meta.json").read_text())
    assert meta == {"v": 1, "name": "fix-ssh", "base_etag_raw": ETAG,
                    "base_sha256": sha256(live.hujson), "fetched_at": env["measured_at"],
                    "request_id": "REQ-acl", "validated": None}
    [request] = live.requests("GET", ACL)
    assert request.header("accept") == "application/hujson"
    # The loop that follows is the agent's next steps.
    assert [step["run"] for step in env["next"]] == [f"tailnet policy validate {path}",
                                                      f"tailnet policy diff {path}"]
    human = cli("policy", "draft", "--name", "second")
    assert human.returncode == 0, human.stderr
    assert "Edit candidate.hujson as text" in human.stdout
    assert "keep MC's comments" in human.stdout


def test_a_draft_s_name_is_checked_before_any_request_and_defaults_to_draft(cli, live, loopback,
                                                                             configured):
    for name in ("Fix", "a" * 41, "", "fix_ssh", "../up"):
        result = cli("--json", "policy", "draft", "--name", name)
        assert (result.returncode, envelope(result)["error"]["code"]) == (2, "USAGE"), name
    assert loopback.requests == []
    result = cli("--json", "policy", "draft")
    assert result.returncode == 0, result.stderr
    data = envelope(result)["data"]
    assert data["name"] == "draft" and data["path"].endswith("Z-draft")


def test_policy_reads_without_a_read_credential_exit_3_and_send_nothing(cli, live, loopback, home):
    for args in (("policy", "get"), ("policy", "draft")):
        result = cli("--json", *args)
        assert (result.returncode, envelope(result)["error"]["code"]) == (3, "CREDENTIAL_MISSING")
    assert loopback.requests == []
