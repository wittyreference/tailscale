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
from loopback import Cut

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


def test_a_policy_cut_short_is_never_served_as_the_live_policy(cli, live, loopback, configured):
    # The connection closes cleanly partway through: what arrived is not the live policy, so
    # nothing is printed as it, and no hash or ETag vouches for it.
    loopback.route("GET", ACL, (200, {"ETag": ETAG, "Content-Type": "application/hujson"},
                                Cut(live.hujson, 110)))
    result = cli("policy", "get", text=False)
    assert result.returncode == 4, result.stderr
    assert result.stdout.startswith(b"API: API_BAD_RESPONSE: GET /tailnet/-/acl: the body ended ")
    assert live.hujson[:110] not in result.stdout
    assert b"sha256" not in result.stdout + result.stderr


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
    second = work / "policy-2.hujson"
    data = envelope(cli("--json", "policy", "get", "--out", str(second)))["data"]
    assert (data["out"], data["text"]) == (str(second), None)


def test_policy_get_out_never_replaces_a_file_nor_writes_into_a_hidden_path(cli, live, loopback,
                                                                            configured, tmp_path):
    # The skill pre-approves `tailnet policy *` (§19.2), so an --out of an existing file, such
    # as ~/.ssh/authorized_keys, or a new one in a dot-directory, such as ~/.bash_profile,
    # would land without a prompt; both are refused before the fetch (A68).
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    keys = work / "authorized_keys"
    keys.write_text("ssh-ed25519 AAAA mc\n")
    hidden = work / ".ssh"
    hidden.mkdir(mode=0o700)
    linked = work / "link.hujson"
    linked.symlink_to(keys)
    for target, words in ((keys, "already exists"), (linked, "already exists"),
                          (hidden / "rc", "hidden"), (work / ".bash_profile", "hidden")):
        result = cli("--json", "policy", "get", "--out", str(target))
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (2, "USAGE"), target
        assert words in env["error"]["message"], env["error"]["message"]
    assert keys.read_text() == "ssh-ed25519 AAAA mc\n"
    assert sorted(p.name for p in work.iterdir()) == [".ssh", "authorized_keys", "link.hujson"]
    assert list(hidden.iterdir()) == []
    assert loopback.requests == []


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


# The edit an agent makes with its Edit tool: a test asserting the intended access, added as
# text before the closing brace, so MC's comments and trailing commas stay as they were.
ADDED_TEST = '  "tests": [{"src": "user1@example.com", "accept": ["example-host-1:22"]}],\n'


def draft(cli, name="fix-ssh"):
    """Make a draft through the CLI and return its directory."""
    result = cli("--json", "policy", "draft", "--name", name)
    assert result.returncode == 0, result.stderr
    return Path(envelope(result)["data"]["path"])


def edit(path, text=ADDED_TEST):
    """Insert text before candidate.hujson's last closing brace, the way an editor would."""
    candidate = path / "candidate.hujson"
    data = candidate.read_bytes()
    at = data.rindex(b"}")
    candidate.write_bytes(data[:at] + text.encode() + data[at:])
    return candidate.read_bytes()


def meta_of(path):
    """A draft's meta.json."""
    return json.loads((path / "meta.json").read_text())


def test_validate_posts_candidate_bytes_as_hujson_and_records_the_verdict(cli, live, configured,
                                                                          tmp_path):
    path = draft(cli)
    candidate = edit(path)
    result = cli("--json", "policy", "validate", str(path))
    assert result.returncode == 0, result.stderr
    [post] = live.requests("POST", VALIDATE)
    # The bytes as edited, comments and all: the server is the only parser [critic R1].
    assert post.body == candidate
    assert post.header("content-type") == "application/hujson"
    assert post.header("authorization") == f"Bearer {READ_TOKEN}"
    env = envelope(result)
    assert (env["outcome"], env["data"]["verdict"], env["data"]["recorded"]) == ("ok", "pass", True)
    assert env["request_ids"] == ["REQ-validate"]
    validated = meta_of(path)["validated"]
    assert re.fullmatch(TIME, validated.pop("at"))
    assert validated == {"sha256": sha256(candidate), "verdict": "pass",
                         "request_id": "REQ-validate", "messages": []}
    assert [step["run"] for step in env["next"]] == [f"tailnet policy diff {path}"]
    # A file is validated the same way, and has no meta.json to record anything in. Its
    # mode is the agent's business: it holds no secret.
    loose = tmp_path / "policy.hujson"
    loose.write_bytes(candidate)
    loose.chmod(0o644)
    env = envelope(cli("--json", "policy", "validate", str(loose)))
    assert (env["exit"], env["data"]["kind"], env["data"]["recorded"]) == (0, "file", False)
    assert live.requests("POST", VALIDATE)[-1].body == candidate


def test_validate_failure_exits_8_with_want_got(cli, live, configured):
    path = draft(cli)
    edit(path)
    live.answer = (200, {"X-Tailscale-Request-Id": "REQ-validate"},
                   body("api", "validate-tests-failed"))
    result = cli("--json", "policy", "validate", str(path))
    assert result.returncode == 8, result.stderr
    env = envelope(result)
    assert (env["outcome"], env["error"]["code"], env["error"]["kind"]) == (
        "negative", "POLICY_INVALID", "negative")
    assert env["data"]["failures"] == [{"user": "user1@example.com", "target": "2.2.2.2:22",
                                        "want": "Drop", "got": "Accept"}]
    validated = meta_of(path)["validated"]
    assert validated["verdict"] == "fail"
    assert validated["messages"] == [
        "test(s) failed", 'user1@example.com: address "2.2.2.2:22": want: Drop, got: Accept']
    human = cli("policy", "validate", str(path))
    assert human.returncode == 8
    assert human.stdout.startswith("NEGATIVE: POLICY_INVALID: ")
    assert "user1@example.com: 2.2.2.2:22  want Drop, got Accept" in human.stdout
    # A candidate the server cannot parse is a 400, and a verdict on the draft too.
    live.answer = (400, {"X-Tailscale-Request-Id": "REQ-validate"},
                   {"message": "line 22, column 1: unexpected end of input"})
    env = envelope(cli("--json", "policy", "validate", str(path)))
    assert (env["exit"], env["error"]["code"], env["data"]["reason"]) == (8, "POLICY_INVALID",
                                                                         "HTTP 400")
    assert "line 22, column 1: unexpected end of input" in env["error"]["message"]
    assert meta_of(path)["validated"]["messages"] == ["line 22, column 1: unexpected end of input"]


def test_validate_warnings_exit_0_and_are_printed(cli, live, configured):
    path = draft(cli)
    edit(path)
    live.answer = (200, {}, body("api", "validate-scim-warnings"))
    result = cli("policy", "validate", str(path))
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("OK: PASS WITH WARNINGS: 1 warning")
    assert ("tailnet: POLICY_WARNING: group:unknown@example.com: group is not syncing from SCIM "
            "and will be ignored by rules in the policy file") in result.stderr
    assert meta_of(path)["validated"]["verdict"] == "pass-with-warnings"
    env = envelope(cli("--json", "policy", "validate", str(path)))
    assert (env["exit"], env["data"]["verdict"]) == (0, "pass-with-warnings")
    assert [w["code"] for w in env["warnings"]] == ["POLICY_WARNING"]


def test_validate_refuses_an_array_file_without_any_request(cli, live, loopback, configured,
                                                            tmp_path):
    tests = tmp_path / "tests.hujson"
    tests.write_text('// the tests I meant\n[{"src": "user1@example.com", '
                     '"accept": ["example-host-1:22"]}]\n')
    result = cli("--json", "policy", "validate", str(tests))
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (2, "VALIDATE_ARRAY_BODY")
    assert "tailnet policy test" in env["error"]["message"]
    assert loopback.requests == []
    # The same for a draft whose candidate became an array; its record is left alone.
    path = draft(cli)
    (path / "candidate.hujson").write_bytes(tests.read_bytes())
    before = len(loopback.requests)
    result = cli("--json", "policy", "validate", str(path))
    assert (result.returncode, envelope(result)["error"]["code"]) == (2, "VALIDATE_ARRAY_BODY")
    assert len(loopback.requests) == before
    assert meta_of(path)["validated"] is None


def test_validate_and_diff_refuse_what_is_not_theirs_to_send_or_record(cli, live, loopback,
                                                                      configured, tmp_path):
    # A directory outside the drafts would get a meta.json written into it, perhaps in a
    # repository; a file in the config directory would be sent to the API.
    elsewhere = tmp_path / "repo" / "draft"
    elsewhere.mkdir(parents=True)
    for name in ("base.hujson", "candidate.hujson"):
        (elsewhere / name).write_bytes(live.hujson)
    (elsewhere / "meta.json").write_text(json.dumps({"v": 1}))
    secret = configured.config_dir / "read.secret"
    real = draft(cli)
    (real / "meta.json").write_text("{}")
    linked = draft(cli, "linked")
    (linked / "candidate.hujson").unlink()
    (linked / "candidate.hujson").symlink_to(secret)
    before = len(loopback.requests)
    cases = [("validate", elsewhere), ("diff", elsewhere), ("validate", secret),
             ("validate", tmp_path / "missing.hujson"), ("diff", tmp_path / "missing"),
             ("diff", real / "candidate.hujson"), ("validate", real), ("diff", real),
             ("validate", linked), ("validate", configured.drafts_dir)]
    for command, target in cases:
        result = cli("--json", "policy", command, str(target))
        assert (result.returncode, envelope(result)["error"]["code"]) == (2, "USAGE"), target
        assert secret.read_text().strip() not in result.stdout + result.stderr
    assert len(loopback.requests) == before
    assert not (elsewhere / "meta.json").read_text().count("validated")


def test_validate_sends_a_file_only_when_it_is_a_policy_file_outside_hidden_paths(cli, live,
                                                                                loopback,
                                                                                configured,
                                                                                tmp_path):
    # validate is pre-approved with the rest of `tailnet policy *` (§19.2), so a file TARGET
    # is an upload no prompt stands in front of; a key or a dot-directory's file never goes
    # (A68). A draft goes by its directory.
    plain = tmp_path / "plain"
    plain.mkdir()
    key = plain / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    hidden = tmp_path / ".aws"
    hidden.mkdir()
    (hidden / "credentials.json").write_bytes(live.hujson)
    (plain / ".env.json").write_bytes(live.hujson)
    path = draft(cli)
    before = len(loopback.requests)
    for target, words in ((key, ".hujson or .json"), (hidden / "credentials.json", "hidden"),
                          (plain / ".env.json", "hidden"),
                          (path / "candidate.hujson", "by its directory")):
        result = cli("--json", "policy", "validate", str(target))
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (2, "USAGE"), target
        assert words in env["error"]["message"], env["error"]["message"]
        assert "BEGIN OPENSSH" not in result.stdout + result.stderr
    assert len(loopback.requests) == before
    assert "policy validate" in envelope(
        cli("--json", "policy", "validate", str(path / "candidate.hujson")))["error"]["message"]


def test_diff_is_ready_only_after_validate_and_with_an_unmoved_live_policy(cli, live, configured):
    from tailnet import policy

    path = draft(cli)
    candidate = edit(path)
    result = cli("--json", "policy", "diff", str(path))
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (8, "DRAFT_NOT_READY")
    assert env["data"]["reasons"] == [policy.NOT_VALIDATED]
    assert env["next"][0]["run"] == f"tailnet policy validate {path}"
    assert cli("policy", "validate", str(path)).returncode == 0
    result = cli("policy", "diff", str(path))
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert re.fullmatch(rf'READY: candidate sha256:{sha256(candidate)[:12]} validated PASS at '
                        rf'{TIME}; live unchanged since draft \(ETag "e0b2816b418"\) '
                        rf'\(as of {TIME}\)', lines[0])
    assert "--- base.hujson" in lines and "+++ candidate.hujson" in lines
    added = [line for line in lines if line.endswith(ADDED_TEST.rstrip("\n"))]
    assert len(added) == 1 and re.match(r" {6}\s*\d+ \+ ", added[0])
    assert ("MC applies it: https://console.tailscale.com/admin/acls/file → make the edits shown "
            "above → Save.") in lines
    assert "Saving re-runs the policy's tests; a failing test blocks the save." in lines
    # Each diff fetched the live policy for the drift check, as HuJSON.
    gets = live.requests("GET", ACL)
    assert len(gets) == 3 and {g.header("accept") for g in gets} == {"application/hujson"}
    env = envelope(cli("--json", "policy", "diff", str(path)))
    data = env["data"]
    assert (env["exit"], data["ready"], data["reasons"], data["changed"]) == (0, True, [], True)
    assert data["candidate_sha256"] == sha256(candidate)
    [step] = env["next"]
    assert (step["who"], step["needs"]) == ("mc", "console")
    # An edit after validate is not what was validated.
    edit(path, "  // one more thought\n")
    env = envelope(cli("--json", "policy", "diff", str(path)))
    assert (env["exit"], env["data"]["reasons"]) == (8, [policy.CHANGED])


def test_diff_reports_a_moved_etag_as_not_ready(cli, live, configured):
    from tailnet import policy

    path = draft(cli)
    edit(path)
    assert cli("policy", "validate", str(path)).returncode == 0
    # MC saved in the console meanwhile: a new ETag and new bytes. Applying the draft now
    # would undo MC's change, which the diff would show as the agent's own edit.
    live.etag = '"f00d5eed"'
    live.hujson += b"// MC's console edit\n"
    result = cli("--json", "policy", "diff", str(path))
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (8, "DRAFT_NOT_READY")
    assert env["data"]["reasons"] == [policy.MOVED]
    assert env["error"]["message"] == policy.MOVED
    assert (env["data"]["live_etag_raw"], env["data"]["base_etag_raw"]) == ('"f00d5eed"', ETAG)
    assert env["next"][0]["run"] == "tailnet policy draft --name fix-ssh"
    human = cli("policy", "diff", str(path))
    assert human.stdout.startswith(f"NOT READY: {policy.MOVED} (as of ")


def test_a_fresh_draft_is_ready_after_validate_with_nothing_for_mc_to_apply(cli, live, configured):
    path = draft(cli)
    assert cli("policy", "validate", str(path)).returncode == 0
    result = cli("--json", "policy", "diff", str(path))
    env = envelope(result)
    assert (result.returncode, env["data"]["ready"], env["data"]["changed"]) == (0, True, False)
    assert env["data"]["diff"] == "" and env["next"] == []


SSH_QUESTION = ("policy", "test", "--src", "tag:dev", "--accept", "tag:fleet:22", "--deny",
                "tag:fleet:443", "--proto", "tcp")


def test_policy_test_posts_one_array_against_live_and_exits_8_on_a_drop(cli, live, configured):
    live.answer = (200, {"X-Tailscale-Request-Id": "REQ-test"}, {})
    result = cli("--json", *SSH_QUESTION)
    assert result.returncode == 0, result.stderr
    [post] = live.requests("POST", VALIDATE)
    # An array is "tests against the current policy" [spec 2508-2516]: no policy is sent.
    assert post.header("content-type") == "application/json"
    assert post.header("authorization") == f"Bearer {READ_TOKEN}"
    assert post.json() == [{"src": "tag:dev", "proto": "tcp", "accept": ["tag:fleet:22"],
                            "deny": ["tag:fleet:443"]}]
    env = envelope(result)
    assert (env["outcome"], env["request_ids"]) == ("ok", ["REQ-test"])
    data = env["data"]
    assert (data["verdict"], data["src"], data["proto"]) == ("pass", "tag:dev", "tcp")
    assert data["asserted"] == [{"target": "tag:fleet:22", "want": "Accept"},
                                {"target": "tag:fleet:443", "want": "Drop"}]
    assert (data["failures"], data["raw_errors"]) == ([], [])
    human = cli(*SSH_QUESTION)
    assert human.returncode == 0
    assert human.stdout.startswith("OK: PASS: every assertion holds for tag:dev (as of ")
    assert "ACCEPT tag:fleet:22  as asserted" in human.stdout
    assert "DROP tag:fleet:443  as asserted" in human.stdout
    # The live policy drops port 22: one line per address the server names, and any line
    # it cannot parse kept as it came.
    live.answer = (200, {"X-Tailscale-Request-Id": "REQ-test"}, {
        "message": "test(s) failed", "data": [{"user": "tag:dev", "errors": [
            'address "tag:fleet:22": want: Accept, got: Drop', "tag:fleet: no devices match"]}]})
    result = cli("--json", *SSH_QUESTION)
    assert result.returncode == 8
    env = envelope(result)
    assert (env["outcome"], env["error"]["code"]) == ("negative", "POLICY_TEST_FAILED")
    assert env["data"]["failures"] == [{"user": "tag:dev", "target": "tag:fleet:22",
                                        "want": "Accept", "got": "Drop"}]
    assert env["data"]["raw_errors"] == ["tag:fleet: no devices match"]
    human = cli(*SSH_QUESTION)
    assert human.returncode == 8
    assert human.stdout.startswith("NEGATIVE: POLICY_TEST_FAILED: ")
    assert "DROP tag:fleet:22  want Accept, got Drop" in human.stdout
    assert "raw: tag:fleet: no devices match" in human.stdout
    # A 400 means the server could not run the tests at all, and says so: it is not a drop.
    live.answer = (400, {}, {"message": "invalid test: unknown host"})
    env = envelope(cli("--json", *SSH_QUESTION))
    assert (env["exit"], env["data"]["reason"]) == (8, "HTTP 400")
    assert "could not parse the tests (HTTP 400): invalid test: unknown host" in \
        env["error"]["message"]


def test_a_test_answer_cut_before_its_body_is_no_pass(cli, live, configured):
    # A failed test comes back as a 200 with a body [critic R2]; a pass is an empty 200. A
    # body that never arrived must not read as the empty one.
    live.answer = (200, {}, Cut({"message": "test(s) failed", "data": []}, 0))
    result = cli("--json", *SSH_QUESTION)
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (4, "error",
                                                                         "API_BAD_RESPONSE")
    assert "PASS" not in cli(*SSH_QUESTION).stdout


def test_policy_test_arguments_are_refused_before_any_request(cli, live, loopback, configured):
    cases = [
        (("--src", "*", "--accept", "tag:fleet:22"), "TEST_WILDCARD"),
        (("--src", "tag:dev", "--accept", "tag:fleet:*"), "TEST_WILDCARD"),
        (("--src", "100.64.0.1", "--accept", "tag:fleet:22"), "TEST_SRC_IS_IP"),
        (("--src", "tag:dev", "--accept", "tag:fleet:22-23"), "TEST_PORT"),
        (("--src", "tag:dev"), "USAGE"),
        (("--accept", "tag:fleet:22"), "USAGE"),
    ]
    for args, code in cases:
        result = cli("--json", "policy", "test", *args)
        assert (result.returncode, envelope(result)["error"]["code"]) == (2, code), args
    assert loopback.requests == []
