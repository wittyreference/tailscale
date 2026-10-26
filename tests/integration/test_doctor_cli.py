# ABOUTME: Integration tests for `tailnet doctor` as a real CLI process against the loopback seam: every
# ABOUTME: check timed, reads only, the write secret never opened, settling, questions and accounting.

import json
import re
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest
from credfiles import (
    READ_SCOPES,
    access_token,
    fixture_secret,
    token_reply,
    write_cache,
    write_role,
)
from fixturefiles import body, raw_bytes

from tailnet import audit, cli, gate, secure_files
from tailnet.output import format_utc

API = "/api/v2"
TOKEN = API + "/oauth/token"
DEVICES = API + "/tailnet/-/devices"
KEY = API + "/tailnet/-/keys/kRead0001CNTRL"
ROUTES = API + "/device/nFactory1CNTRL/routes"
ACL = API + "/tailnet/-/acl"
VALIDATE = ACL + "/validate"
DNS_CONFIG = API + "/tailnet/-/dns/configuration"
NAMESERVERS = API + "/tailnet/-/dns/nameservers"
READ_TOKEN = access_token("read0001")
TIME = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
SELF_LINE = "self nFactory1CNTRL     # claude-factory\n"
CHECKS = ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10", "L11",
          "S1", "S2", "S3", "S4", "S5", "S6", "S7a", "S7b", "S8"]
# The calls only the settle-gated steps make (§16.3): S3, S5, S8's configuration read.
GATED_CALLS = {("GET", KEY), ("GET", ROUTES), ("GET", DNS_CONFIG)}


def drop(src, targets):
    """A validate answer in the documented failure shape [spec 2660-2667]: each target dropped."""
    return {"message": "test(s) failed",
            "data": [{"user": src, "errors": [f'address "{t}": want: Accept, got: Drop'
                                              for t in targets]}]}


class Tailnet:
    """The tailnet behind the seam for doctor: every endpoint its steps read.

    A test changes the attributes before running doctor: the scope the token endpoint
    grants, the answer each network test gets by its source, the answer the S7b candidate
    gets, and the statuses of the reads doctor expects may be refused.
    """

    def __init__(self, loopback):
        self.loopback = loopback
        self.scope = READ_SCOPES
        self.network = {}
        self.member = {}
        self.routes_status = 403
        self.config_status = 200
        self.devices = body("scenario", "devices")["devices"]
        self.policy = body("scenario", "policy")
        loopback.route("POST", TOKEN, lambda request: token_reply(READ_TOKEN, scope=self.scope))
        loopback.route("GET", DEVICES, lambda request: (
            200, {"X-Tailscale-Request-Id": "REQ-list"}, {"devices": self.devices}))
        loopback.route("GET", KEY, (200, {"X-Tailscale-Request-Id": "REQ-key"}, {
            "id": "kRead0001CNTRL", "keyType": "client", "scopes": READ_SCOPES.split(),
            "tags": [], "invalid": False}))
        loopback.route("GET", ROUTES, lambda request: (
            self.routes_status, {"X-Tailscale-Request-Id": "REQ-routes"},
            {"message": "API call attempted with insufficient permission"}))
        loopback.route("GET", ACL, self._policy)
        loopback.route("POST", VALIDATE, self._validate)
        loopback.route("GET", DNS_CONFIG, lambda request: (
            self.config_status, {"X-Tailscale-Request-Id": "REQ-dnsconfig"},
            body("api", "dns-configuration") if self.config_status == 200
            else {"message": "API call attempted with insufficient permission"}))
        loopback.route("GET", NAMESERVERS, (200, {}, body("api", "dns-nameservers")))

    def _policy(self, request):
        """The live policy in the form the Accept header asks for, with its quoted ETag."""
        headers = {"ETag": '"etag-live-1"', "X-Tailscale-Request-Id": "REQ-acl"}
        if request.header("accept") == "application/hujson":
            return 200, headers, raw_bytes("api", "policy.hujson")
        return 200, headers, self.policy

    def _validate(self, request):
        """A network test answers by its source; the S7b candidate gets `member`."""
        doc = request.json()
        if isinstance(doc, list):
            return 200, {}, self.network.get(doc[0]["src"], {})
        return 200, {}, self.member

    def calls(self, since=0):
        """Every request from the `since`-th on, as (method, path)."""
        return [(r.method, r.path) for r in self.loopback.requests[since:]]

    def validates(self):
        """Every validate body posted, parsed, in order."""
        return [r.json() for r in self.loopback.requests if (r.method, r.path) == ("POST", VALIDATE)]


@pytest.fixture
def tailnet(loopback):
    """The tailnet behind this test's seam."""
    return Tailnet(loopback)


def install_rules(posture):
    """The settings file a full install leaves, so the gate rules are all present (L8)."""
    expected = gate.rules_for(gate.claude_dir(posture, {}))
    path = posture.claude_settings
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": expected}))


def write_protected(posture, text=SELF_LINE):
    """MC's protected file: test posture takes self from its self line (§11.3)."""
    path = posture.config_dir / "protected"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


@pytest.fixture
def ready(home):
    """A test home as MC leaves it after setup: the read client, the list and the rules."""
    write_role(home, "read")
    write_protected(home)
    install_rules(home)
    return home


def envelope(result):
    """The one tailnet.v1 object stdout holds."""
    return json.loads(result.stdout)


def checks_of(env):
    """The envelope's checks by id."""
    return {check["id"]: check for check in env["data"]["checks"]}


def audit_records(posture, event):
    """Every audit record of one event in the test home, oldest first."""
    log = posture.state_dir / "audit.jsonl"
    if not log.exists():
        return []
    return [r for r in map(json.loads, log.read_text().splitlines()) if r["event"] == event]


def test_doctor_reports_every_check_with_a_time(cli, tailnet, ready):
    result = cli("--json", "doctor")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["command"], env["outcome"], env["posture"]) == ("doctor", "ok", "test")
    assert [check["id"] for check in env["data"]["checks"]] == CHECKS
    for check in env["data"]["checks"]:
        assert check["status"] in ("PASS", "WARN", "FAIL", "INFO", "SKIP"), check
        assert re.fullmatch(TIME, check["measured_at"]), check
        assert check["finding"], check
    found = checks_of(env)
    # Test posture never runs tailscale or the network extras, and says so (§7.1).
    assert found["L2"]["status"] == "WARN"
    assert found["L3"]["status"] == "SKIP" and "test posture" in found["L3"]["finding"]
    assert found["L11"]["status"] == "SKIP"
    assert found["L4"]["status"] == "PASS" and "read-only" in found["L4"]["finding"]
    assert found["L8"]["status"] == "PASS"
    assert found["S4"]["evidence"]["count"] == 6
    assert found["S4"]["evidence"]["self"]["nodeId"] == "nFactory1CNTRL"
    assert found["S6"]["evidence"]["etag_raw"] == {"hujson": '"etag-live-1"',
                                                   "json": '"etag-live-1"'}
    # The human view: the verdict, then one line per check with its time.
    human = cli("doctor")
    assert human.returncode == 0, human.stderr
    lines = human.stdout.splitlines()
    assert re.fullmatch(rf"OK: doctor: .* \(as of {TIME}\)", lines[0])
    for check_id in CHECKS:
        [line] = [line for line in lines if re.match(rf"(PASS|WARN|FAIL|INFO|SKIP) +{check_id} ",
                                                     line)]
        assert re.search(rf"\(as of {TIME}\)", line), line


def test_doctor_reuses_the_cached_token_and_mints_nothing_new(cli, tailnet, ready):
    write_cache(ready, READ_TOKEN, expires_in=3600)
    env = envelope(cli("--json", "doctor"))
    assert env["exit"] == 0, env
    assert ("POST", TOKEN) not in tailnet.calls()
    assert env["data"]["mints_this_run"] == 0
    assert "reused" in checks_of(env)["S1"]["finding"]
    assert not [e for e in env["data"]["audit_events_caused"] if "OAuth" in e]
    assert audit_records(ready, "token.mint") == []


def test_doctor_never_sends_a_write_request(cli, tailnet, ready):
    result = cli("--json", "doctor", "--settle")
    assert result.returncode == 0, result.stderr
    calls = set(tailnet.calls())
    assert calls
    assert {(method, path) for method, path in calls if method != "GET"} <= {
        ("POST", TOKEN), ("POST", VALIDATE)}
    # Every validate is a question about the policy, as an identity, never an address.
    for doc in tailnet.validates():
        tests = doc if isinstance(doc, list) else doc["tests"]
        for test in tests:
            assert re.fullmatch(r"tag:[a-z0-9-]+|[^@\s]+@[^@\s]+", test["src"]), test


def test_doctor_never_opens_the_write_secret(cli, tailnet, ready, loopback, monkeypatch,
                                             capsys, syscalls):
    sentinel = fixture_secret("sentinel88")
    write_role(ready, "write", sentinel)
    result = cli("--json", "doctor", "--settle")
    assert result.returncode == 0, result.stderr
    for request in loopback.requests:
        seen = request.body.decode("utf-8", "replace") + json.dumps(request.headers)
        assert sentinel not in seen
    assert sentinel not in result.stdout + result.stderr
    assert "two-client" in checks_of(envelope(result))["L4"]["finding"]
    # The same run in this process, where every open is recorded: write.secret is only
    # stat'ed, never opened (D20).
    for name in ("TAILNET_API_BASE", "TAILNET_HOME"):
        monkeypatch.setenv(name, cli.env[name])
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    syscalls.events.clear()
    assert cli_main(capsys, "--json", "doctor", "--settle") == 0
    assert [event for event, _ in syscalls.named("write.secret") if event == "open"] == []
    assert syscalls.named("read.secret")


def cli_main(capsys, *argv):
    """Run the CLI in this process and return its exit code, discarding its output."""
    code = cli.main(list(argv))
    capsys.readouterr()
    return code


def test_doctor_settles_once_then_reuses_answers(cli, tailnet, ready):
    first = envelope(cli("--json", "doctor"))
    assert first["exit"] == 0, first
    assert GATED_CALLS <= set(tailnet.calls())
    settled = first["data"]["settled"]
    # Q1 is moot without a single client; the other four were measured now.
    assert set(settled) == {"Q3", "Q4", "Q20", "Q23"}
    assert not any(entry["reused"] for entry in settled.values())
    assert "HTTP 403" in settled["Q4"]["answer"]
    [line] = audit_records(ready, "doctor.run")
    assert set(line["settled"]) == {"Q3", "Q4", "Q20", "Q23"}
    member_tests = [doc for doc in tailnet.validates() if isinstance(doc, dict)]
    assert len(member_tests) == 1

    before = len(tailnet.loopback.requests)
    second = envelope(cli("--json", "doctor"))
    assert second["exit"] == 0, second
    assert not GATED_CALLS & set(tailnet.calls(before))
    assert len([doc for doc in tailnet.validates() if isinstance(doc, dict)]) == 1
    found = checks_of(second)
    for step in ("S3", "S5", "S7b", "S8"):
        assert re.search(r"settled \d{4}-\d\d-\d\dT\d\d:\d\dZ \(0 days ago\)",
                         found[step]["finding"]), step
    assert all(entry["reused"] for entry in second["data"]["settled"].values())
    # A run records only what it measured, so the answers stay with the run that found them.
    assert audit_records(ready, "doctor.run")[-1]["settled"] == {}
    assert "Failed request" not in json.dumps(second["data"]["audit_events_caused"])

    before = len(tailnet.loopback.requests)
    third = envelope(cli("--json", "doctor", "--settle"))
    assert GATED_CALLS <= set(tailnet.calls(before))
    assert not any(entry["reused"] for entry in third["data"]["settled"].values())


def test_an_answer_older_than_30_days_is_measured_again(cli, tailnet, ready):
    old = format_utc(datetime.now(timezone.utc) - timedelta(days=31))
    young = format_utc(datetime.now(timezone.utc) - timedelta(days=2))
    audit.append(ready, {"event": "doctor.run", "settled": {
        "Q4": {"answer": "a call outside the read scopes is refused with HTTP 404",
               "evidence": {}, "status": "INFO", "measured_at": old},
        "Q3": {"answer": "the read client's ID works as a key ID", "evidence": {},
               "status": "PASS", "measured_at": young, "client_id": "kRead0001CNTRL"}}})
    env = envelope(cli("--json", "doctor"))
    calls = set(tailnet.calls())
    assert ("GET", ROUTES) in calls and ("GET", KEY) not in calls
    found = checks_of(env)
    assert "(2 days ago)" in found["S3"]["finding"]
    assert "HTTP 403" in found["S5"]["finding"]
    assert "over 30" in found["S5"]["evidence"]["measured_because"]


def test_an_answer_recorded_under_another_posture_is_never_reused(cli, tailnet, ready):
    # A production line in a test home's log (or a test line that reached the real log)
    # answered against another API: it must never stop this run measuring for 30 days.
    young = format_utc(datetime.now(timezone.utc) - timedelta(days=2))
    line = {"v": 1, "ts": young, "event": "doctor.run", "cli_version": "0.1.0",
            "posture": "production", "host": "h", "user": "u", "pid": 1, "argv": [],
            "settled": {"Q3": {"answer": "the read client's ID works as a key ID",
                               "evidence": {}, "status": "PASS", "measured_at": young,
                               "client_id": "kRead0001CNTRL"}}}
    ready.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secure_files.append_locked(ready.state_dir / "audit.jsonl", (json.dumps(line) + "\n").encode())
    env = envelope(cli("--json", "doctor"))
    assert ("GET", KEY) in set(tailnet.calls())
    assert "days ago" not in checks_of(env)["S3"]["finding"]


def test_a_rotated_read_client_has_its_own_key_looked_up(cli, tailnet, ready, loopback):
    # `credentials set read` tells the agent to run doctor next to check the new client, so
    # S3 must not report the old client's key record as the new one's (A55).
    assert envelope(cli("--json", "doctor"))["exit"] == 0
    write_role(ready, "read", client_id="kRead0002CNTRL")
    rotated = API + "/tailnet/-/keys/kRead0002CNTRL"
    loopback.route("GET", rotated, (200, {"X-Tailscale-Request-Id": "REQ-key-2"}, {
        "id": "kRead0002CNTRL", "keyType": "client", "scopes": ["all"], "tags": ["tag:fleet"],
        "invalid": False}))
    before = len(tailnet.loopback.requests)
    env = envelope(cli("--json", "doctor"))
    calls = set(tailnet.calls(before))
    assert ("GET", rotated) in calls and ("GET", KEY) not in calls
    s3 = checks_of(env)["S3"]
    assert "days ago" not in s3["finding"] and "scopes all, tags tag:fleet" in s3["finding"]
    assert "kRead0001CNTRL, not kRead0002CNTRL" in s3["evidence"]["measured_because"]
    # The answers that are about the API, not the client, are still reused.
    assert ("GET", ROUTES) not in calls
    [_, line] = audit_records(ready, "doctor.run")
    assert line["settled"]["Q3"]["client_id"] == "kRead0002CNTRL"
    # Reused, the answer names the client it belongs to.
    again = checks_of(envelope(cli("--json", "doctor")))["S3"]
    assert "(0 days ago) for read client kRead0002CNTRL:" in again["finding"]


def test_doctor_emits_questions_in_priority_order(cli, tailnet, home):
    write_role(home, "read")
    install_rules(home)
    tailnet.scope = "devices:core:read policy_file:read"
    env = envelope(cli("--json", "doctor"))
    ids = [q["id"] for q in env["data"]["questions"]]
    # No write client exists here, and still the consent question is never asked (A1).
    assert ids == ["scope-set", "protected-list", "fleet-key-expiry"]
    for question in env["data"]["questions"]:
        assert question["safe_default"] == question["options"][0]["label"]
    asks = [step["question"]["id"] for step in env["next"] if step["who"] == "ask_mc"]
    assert asks == ids
    # status reads the open questions from this run's audit line (A24).
    assert audit_records(home, "doctor.run")[-1]["questions"] == ids
    status = envelope(cli("--json", "status"))
    assert status["data"]["open_questions"] == ids

    write_protected(home)
    tailnet.network["tag:dev"] = drop("tag:dev", ["100.64.0.11:22"])
    env = envelope(cli("--json", "doctor"))
    ids = [q["id"] for q in env["data"]["questions"]]
    assert ids == ["scope-set", "fleet-key-expiry", "policy-fix"]
    found = checks_of(env)
    assert found["S7a"]["status"] == "WARN"
    assert any(step.get("run", "").startswith("tailnet diagnose nSpec5x1CNTRL")
               for step in found["S7a"]["next"])
    assert audit_records(home, "doctor.run")[-1]["questions"] == ids


def test_single_client_mode_raises_the_scope_question_although_narrowing_works(cli, tailnet,
                                                                              ready):
    # The read client's grant is "all": its read tokens are minted narrowed to the four and
    # granted them, so comparing the token's scope would never ask MC (A56).
    write_role(ready, "read", granted_scope="all")
    env = envelope(cli("--json", "doctor"))
    found = checks_of(env)
    assert "single-client" in found["L4"]["finding"]
    assert found["S1"]["evidence"]["scope"] == READ_SCOPES
    [question] = [q for q in env["data"]["questions"] if q["id"] == "scope-set"]
    assert "holds all" in question["text"]
    assert "scope-set" in audit_records(ready, "doctor.run")[-1]["questions"]
    # The same client named in both files: read.json may hold the four it was narrowed to at
    # `credentials set`, so the grant named is the write metadata's.
    write_role(ready, "read")
    write_role(ready, "write", client_id="kRead0001CNTRL", granted_scope="devices:core")
    env = envelope(cli("--json", "doctor"))
    [question] = [q for q in env["data"]["questions"] if q["id"] == "scope-set"]
    assert "holds devices:core" in question["text"]


def test_doctor_reports_mints_and_audit_events_caused(cli, tailnet, ready):
    env = envelope(cli("--json", "doctor"))
    assert env["exit"] == 0, env
    assert env["data"]["mints_this_run"] == 1
    assert env["data"]["audit_events_caused"] == ["Create OAuth access token ×1",
                                                  "Failed request ×1 (S5)"]
    assert len(audit_records(ready, "token.mint")) == 1
    [line] = audit_records(ready, "doctor.run")
    assert line["mints_this_run"] == 1
    assert line["audit_events_caused"] == env["data"]["audit_events_caused"]
    assert line["counts"] == env["data"]["counts"]
    assert sum(line["counts"].values()) == len(CHECKS)
    # The human view says the same; a fresh mint and --settle make this run cause both again.
    (ready.config_dir / "read-token.json").unlink()
    human = cli("doctor", "--settle").stdout
    assert "mints this run: 1 · audit events caused: Create OAuth access token ×1, " \
           "Failed request ×1 (S5)" in human


def test_doctor_without_a_read_credential_exits_3_with_console_steps(cli, tailnet, home):
    install_rules(home)
    result = cli("--json", "doctor")
    assert result.returncode == 3
    env = envelope(result)
    assert (env["error"]["code"], env["outcome"]) == ("CREDENTIAL_MISSING", "error")
    assert any(step["who"] == "mc" and step.get("needs") == "console" for step in env["next"])
    assert any(step.get("do") == "tailnet credentials set read" for step in env["next"])
    found = checks_of(env)
    assert found["L4"]["status"] == "FAIL"
    assert all(found[step]["status"] == "SKIP" for step in CHECKS if step.startswith("S"))
    assert tailnet.loopback.requests == []
    [line] = audit_records(home, "doctor.run")
    assert line["counts"]["fail"] >= 1


def test_a_missing_gate_rule_fails_doctor(cli, tailnet, home):
    write_role(home, "read")
    write_protected(home)
    result = cli("--json", "doctor")
    assert result.returncode == 8
    env = envelope(result)
    assert (env["error"]["code"], env["outcome"]) == ("DOCTOR_FAIL", "negative")
    assert checks_of(env)["L8"]["status"] == "FAIL"
    assert "L8" in env["error"]["message"]


def test_a_rejected_token_fails_s1_and_skips_the_api_steps(cli, tailnet, ready, loopback):
    loopback.route("POST", TOKEN, (401, {}, {"message": "API token invalid"}))
    env = envelope(cli("--json", "doctor"))
    assert (env["exit"], env["error"]["code"]) == (8, "DOCTOR_FAIL")
    found = checks_of(env)
    assert found["S1"]["status"] == "FAIL" and "TOKEN_REJECTED" in found["S1"]["finding"]
    assert all(found[step]["status"] == "SKIP" for step in CHECKS[12:])
    assert any(step.get("needs") == "console" for step in env["next"])
    assert set(tailnet.calls()) == {("POST", TOKEN)}


def test_an_unsafe_audit_log_trusts_no_settled_answer(cli, tailnet, ready):
    assert envelope(cli("--json", "doctor"))["exit"] == 0
    log = audit.log_path(ready)
    log.chmod(0o620)
    before = len(tailnet.loopback.requests)
    result = cli("--json", "doctor")
    env = envelope(result)
    assert (env["exit"], env["error"]["code"]) == (8, "DOCTOR_FAIL")
    assert checks_of(env)["L7"]["status"] == "FAIL"
    # Answers from a log that fails the private-file checks may have been planted, so every
    # settle-gated step measures again.
    assert GATED_CALLS <= set(tailnet.calls(before))
    assert not any(entry["reused"] for entry in env["data"]["settled"].values())
    assert any(w["code"] == "AUDIT_UNWRITABLE" for w in env["warnings"])
    assert env["data"]["audit_line"]["written"] is False


def test_an_unanswered_protected_list_warns_and_explains_the_missing_proposal(cli, tailnet,
                                                                              home):
    write_role(home, "read")
    install_rules(home)
    env = envelope(cli("--json", "doctor"))
    found = checks_of(env)
    assert found["L6"]["status"] == "WARN"
    assert "tag writes are refused until MC writes it" in found["L6"]["finding"]
    # In test posture self comes only from the file that is missing, so no self line can be
    # proposed; the reason is given instead of a block that would not parse.
    assert env["data"]["protected_proposal"] is None
    assert "self is unknown" in found["L6"]["finding"]


def test_a_key_shaped_environment_value_is_named_not_shown(cli, tailnet, ready):
    value = "tskey-" + "client-" + "kEnv01CNTRL-" + "Q" * 26
    result = cli("--json", "doctor", env={"STRAY_TAILSCALE_KEY": value})
    assert value not in result.stdout + result.stderr
    env = envelope(result)
    [warning] = [w for w in env["warnings"] if w["code"] == "SECRET_IN_ENVIRONMENT"]
    assert "STRAY_TAILSCALE_KEY" in warning["message"]
    assert checks_of(env)["L4"]["status"] == "WARN"


def test_a_write_secret_left_by_an_interrupted_set_is_reported_and_l2_never_claimed(cli, tailnet,
                                                                                   ready):
    # No write.json: the set died before it got that far, so only the temp copy is on disk.
    left = ready.config_dir / ".write.secret.4242.0a1b2c3d.tmp"
    left.write_text(fixture_secret("left0003") + "\n")
    left.chmod(0o600)
    env = envelope(cli("--json", "doctor"))
    found = checks_of(env)
    assert found["L4"]["status"] == "WARN"
    assert left.name in found["L4"]["finding"]
    assert "tailnet credentials forget write" in found["L4"]["finding"]
    assert "L2 holds" not in found["L9"]["finding"]
    assert "L2 does not hold" in found["L9"]["finding"]
