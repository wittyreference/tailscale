# ABOUTME: Integration tests for the two writes as real CLI processes against the loopback seam: dry runs,
# ABOUTME: the guard under --apply, one POST per target, the re-read that decides it, the lock and the audit.

import fcntl
import json
import os
import re

import pytest
from credfiles import access_token, fixture_secret, token_reply, write_role
from fixturefiles import body
from loopback import Cut

from tailnet import gate

API = "/api/v2"
TOKEN = API + "/oauth/token"
DEVICES = API + "/tailnet/-/devices"
ACL = API + "/tailnet/-/acl"
READ_TOKEN = access_token("read0001")
WRITE_TOKEN = access_token("write001")
READ_CLIENT, WRITE_CLIENT = "kRead0001CNTRL", "kWrite0001CNTRL"
TIME = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
REASON = "keep the fleet on the tailnet past its old expiry"
# MC's protected list: self is the droplet, spec5 is protected. Test posture takes self from
# this line and never runs tailscale (§11.3).
PROTECTED = """\
self nFactory1CNTRL     # claude-factory
spec5                   # Elmer console
"""
IDS = {"claude-factory": "nFactory1CNTRL", "spec5": "nSpec5x1CNTRL", "nomad-b": "nNomadB1CNTRL",
       "pi5": "nPi5x001CNTRL", "albini": "nAlbini1CNTRL", "Michaels-iPhone": "nPhone01CNTRL"}


class Tailnet:
    """A stateful stand-in for the tailnet's device records behind the loopback seam.

    It serves the device list and each device from one table and applies the two writes to
    that table, so the CLI's re-read sees what a write did. `outcome(name, status, lands)`
    makes the next writes to a device answer `status`, and `lands` says whether the change
    is made anyway, which is how a 504 that landed differs from one that did not.
    """

    def __init__(self, loopback):
        self.loopback = loopback
        self.devices = {d["nodeId"]: d for d in body("scenario", "devices")["devices"]}
        self._outcomes = {}
        self.policy = body("scenario", "policy")
        loopback.route("POST", TOKEN, self._mint)
        loopback.route("GET", DEVICES, self._list)
        loopback.route("GET", ACL, lambda request: (
            200, {"X-Tailscale-Request-Id": "REQ-acl", "ETag": '"etag-1"'}, self.policy))
        for node_id in self.devices:
            loopback.route("GET", f"{API}/device/{node_id}", self._get(node_id))
            loopback.route("POST", f"{API}/device/{node_id}/key", self._write(node_id, "key"))
            loopback.route("POST", f"{API}/device/{node_id}/tags", self._write(node_id, "tags"))

    def device(self, name):
        """A device's record in the table, by hostname."""
        return self.devices[IDS[name]]

    def outcome(self, name, status, lands, headers=None, cut=None):
        """Answer writes to `name` with `status`; `lands` says whether the change happens.

        `cut` ("close" or "reset") breaks the answer's body off after its first bytes.
        """
        self._outcomes[IDS[name]] = (status, lands, headers or {}, cut)

    def _mint(self, request):
        """Hand each client its own token, so a test can tell which one a request carried."""
        client = request.form()["client_id"][0]
        if client == READ_CLIENT:
            return token_reply(READ_TOKEN, request_id="REQ-mint-read")
        if client == WRITE_CLIENT:
            return token_reply(WRITE_TOKEN, scope="devices:core", request_id="REQ-mint-write")
        return 401, {}, {"message": "unknown client"}

    def _list(self, request):
        """The whole list, as it stands now."""
        return 200, {"X-Tailscale-Request-Id": "REQ-list"}, {"devices": list(self.devices.values())}

    def _get(self, node_id):
        """One device, as it stands now: the re-read."""
        return lambda request: (200, {"X-Tailscale-Request-Id": f"REQ-get-{node_id}"},
                                self.devices[node_id])

    def _write(self, node_id, kind):
        """Apply a write to the table (unless told it does not land), then answer it."""
        def handler(request):
            if request.header("content-type") != "application/json":
                # The spec documents both write bodies as JSON only [spec 559-573, 596-609];
                # answering as a strict server would keeps a mislabelled body from landing.
                return 415, {}, {"message": "the test takes application/json only"}
            status, lands, headers, cut = self._outcomes.get(node_id, (200, True, {}, None))
            if lands:
                field = "keyExpiryDisabled" if kind == "key" else "tags"
                self.devices[node_id][field] = request.json()[field]
            reply = {} if status < 300 else {"message": f"the test answers HTTP {status}"}
            if cut is not None:
                reply = Cut(reply, 5, end=cut)
            return status, {"X-Tailscale-Request-Id": f"REQ-{kind}-{node_id}", **headers}, reply
        return handler

    def requests(self, method=None, suffix=""):
        """Recorded requests, optionally only one method and paths ending in `suffix`."""
        return [r for r in self.loopback.requests
                if (method is None or r.method == method) and r.path.endswith(suffix)]

    def writes(self):
        """Every request that would change the tailnet: a POST anywhere but the token endpoint."""
        return [r for r in self.requests("POST") if r.path != TOKEN]

    def mints(self):
        """The client ID of every token request, in order."""
        return [r.form()["client_id"][0] for r in self.requests("POST", "/oauth/token")]


def write_protected(posture, text=PROTECTED):
    """MC's protected file in the test home, 0600 as MC's here-document leaves it."""
    path = posture.config_dir / "protected"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def install_gate(posture, *, without=()):
    """Claude settings holding every rule the installer writes, minus `without`."""
    expected = gate.rules_for(gate.claude_dir(posture, {}))
    posture.claude_settings.parent.mkdir(parents=True, exist_ok=True)
    posture.claude_settings.write_text(json.dumps({"permissions": {
        "ask": [r for r in expected["ask"] if r not in without],
        "deny": expected["deny"]}}))


@pytest.fixture
def armed(home):
    """A test home ready for --apply: both clients, MC's protected list, and the ask gate."""
    write_role(home, "read")
    write_role(home, "write")
    write_protected(home)
    install_gate(home)
    return home


@pytest.fixture
def net(loopback):
    """The stateful tailnet behind this test's seam."""
    return Tailnet(loopback)


def envelope(result):
    """The one tailnet.v1 object stdout holds."""
    return json.loads(result.stdout)


def writes_logged(posture):
    """Every `write` audit record in the test home, oldest first."""
    log = posture.state_dir / "audit.jsonl"
    if not log.exists():
        return []
    return [r for r in map(json.loads, log.read_text().splitlines()) if r["event"] == "write"]


def disable(cli, *devices, apply=False, confirm=None, reason=REASON):
    """Run `device disable-key-expiry` with --json; --apply brings its --reason."""
    args = ["--json", "device", "disable-key-expiry", *devices]
    if confirm is not None:
        args += ["--confirm", confirm]
    if apply:
        args += ["--apply", "--reason", reason]
    return cli(*args)


def test_a_dry_run_sends_no_write_and_mints_no_write_token(cli, net, armed):
    result = disable(cli, "pi5")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["command"], env["outcome"], env["exit"]) == ("device disable-key-expiry",
                                                             "dry-run", 0)
    line = 'tailnet device disable-key-expiry nPi5x001CNTRL --apply --reason "<why>"'
    [plan] = env["data"]["plans"]
    assert (plan["class"], plan["apply_line"], plan["noop"]) == ("R1", line, False)
    assert env["next"][0] == {"who": "agent", "run": line, "why": env["next"][0]["why"]}
    assert net.writes() == []
    assert net.mints() == [READ_CLIENT]
    [logged] = writes_logged(armed)
    assert (logged["mode"], logged["outcome"], logged["sent"]) == ("dry-run", "dry-run", False)
    assert logged["target"]["nodeId"] == "nPi5x001CNTRL"
    human = cli("device", "disable-key-expiry", "pi5")
    lines = human.stdout.splitlines()
    assert re.fullmatch(rf"DRY RUN: nothing changed \(as of {TIME}\)", lines[0])
    assert any(line in text for text in lines)


def test_a_dry_run_works_without_a_write_client(cli, net, home):
    write_role(home, "read")
    write_protected(home)
    install_gate(home)
    result = disable(cli, "pi5")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert env["outcome"] == "dry-run"
    [missing] = [w for w in env["warnings"] if w["code"] == "WRITE_CREDENTIAL_MISSING"]
    assert missing["message"].startswith("apply would be refused: ")
    assert "credentials set write" in json.dumps(env["next"])
    assert net.writes() == [] and net.mints() == [READ_CLIENT]


def test_apply_without_a_write_client_is_refused_before_any_write_request(cli, net, armed):
    for name in ("write.secret", "write.json"):
        (armed.config_dir / name).unlink()
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (
        5, "refused", "WRITE_CREDENTIAL_MISSING")
    assert net.writes() == [] and net.mints() == [READ_CLIENT]
    [logged] = writes_logged(armed)
    assert (logged["mode"], logged["outcome"], logged["sent"]) == ("apply", "refused", False)
    assert logged["refusal"]["code"] == "WRITE_CREDENTIAL_MISSING"


def test_apply_without_the_gate_rule_is_refused(cli, net, armed):
    install_gate(armed, without=("Bash(*tailnet*--apply*)",))
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (5, "GATE_MISSING")
    assert str(armed.claude_settings) in env["error"]["message"]
    # No settings file at all is the same answer: nothing there can prompt MC.
    armed.claude_settings.unlink()
    result = disable(cli, "pi5", apply=True)
    assert (result.returncode, envelope(result)["error"]["code"]) == (5, "GATE_MISSING")
    assert net.writes() == []
    assert WRITE_CLIENT not in net.mints()


def test_an_unanswered_protected_list_does_not_hold_up_a_disable_plan(cli, net, armed):
    (armed.config_dir / "protected").unlink()
    result = disable(cli, "spec5", "nomad-b", "pi5")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    codes = [w["code"] for w in env["warnings"]]
    # D7: the list being unanswered is no reason to refuse this write...
    assert "PROTECTED_UNANSWERED" not in codes
    # ...but test posture takes self from the list's self line, so self is unknown and the
    # apply is refused for that (§11.3).
    assert "SELF_UNKNOWN" in codes
    result = disable(cli, "spec5", "nomad-b", "pi5", apply=True)
    assert (result.returncode, envelope(result)["error"]["code"]) == (5, "SELF_UNKNOWN")
    assert net.writes() == []


def test_disable_key_expiry_apply_posts_true_once_and_rereads(cli, net, armed):
    result = disable(cli, "pi5", apply=True)
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["outcome"], env["error"]) == ("applied", None)
    [posted] = net.writes()
    assert (posted.path, posted.json()) == (f"{API}/device/nPi5x001CNTRL/key",
                                           {"keyExpiryDisabled": True})
    assert posted.header("authorization") == f"Bearer {WRITE_TOKEN}"
    # The re-read is the last request, with the read token, and it decided the outcome.
    reread = net.loopback.requests[-1]
    assert (reread.method, reread.path, reread.query) == ("GET", f"{API}/device/nPi5x001CNTRL",
                                                          "fields=all")
    assert reread.header("authorization") == f"Bearer {READ_TOKEN}"
    assert net.device("pi5")["keyExpiryDisabled"] is True
    [outcome] = env["data"]["results"]
    assert (outcome["outcome"], outcome["sent"], outcome["confirmed"]) == ("applied", True, True)
    [logged] = writes_logged(armed)
    assert (logged["outcome"], logged["sent"], logged["confirmed"], logged["failure"]) == (
        "applied", True, True, None)
    assert logged["observed_after"] == {"keyExpiryDisabled": True}
    assert [(h["method"], h["status"]) for h in logged["http"]] == [("POST", 200), ("GET", 200)]
    assert logged["write_client"] == {"client_id": WRITE_CLIENT, "tags": ["tag:fleet"]}


def test_a_user_device_needs_the_no_expiry_confirm_and_a_wrong_one_sends_nothing(cli, net,
                                                                                armed):
    dry = envelope(disable(cli, "albini"))
    assert dry["data"]["plans"][0]["confirm_required"] == "no-expiry:albini"
    assert "--confirm no-expiry:albini" in dry["next"][0]["run"]
    for confirm, code in ((None, "CONFIRM_MISSING"), ("no-expiry:Albini", "CONFIRM_MISMATCH")):
        result = disable(cli, "albini", apply=True, confirm=confirm)
        assert (result.returncode, envelope(result)["error"]["code"]) == (5, code)
    assert net.writes() == []
    result = disable(cli, "albini", apply=True, confirm="no-expiry:albini")
    assert result.returncode == 0, result.stderr
    assert [r.path for r in net.writes()] == [f"{API}/device/nAlbini1CNTRL/key"]


def test_an_already_disabled_device_is_a_noop_that_sends_nothing(cli, net, armed):
    dry = disable(cli, "claude-factory")
    assert (dry.returncode, envelope(dry)["outcome"]) == (0, "noop")
    result = disable(cli, "claude-factory", apply=True)
    assert (result.returncode, envelope(result)["outcome"]) == (0, "noop")
    # Nothing to send, so no write token is minted; the test below holds that the write
    # secret stays shut as well.
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    applied = writes_logged(armed)[-1]
    assert (applied["outcome"], applied["sent"], applied["noop"]) == ("applied", False, True)


def test_write_commands_open_the_write_secret_only_to_send(cli, net, armed):
    # 0644 makes any load of write.secret a CREDENTIAL_UNSAFE refusal (§8.2), so a run that
    # exits as planned never opened it (invariant 4, D20); the last apply proves the sensor.
    (armed.config_dir / "write.secret").chmod(0o644)
    runs = [(disable(cli, "pi5"), 0), (tag(cli, "pi5", "--add", "tag:lab"), 0),
            (disable(cli, "albini", apply=True), 5),
            (tag(cli, "pi5", "--add", "tag:lab", apply=True), 5),
            (disable(cli, "claude-factory", apply=True), 0)]
    for result, code in runs:
        assert result.returncode == code, result.stdout + result.stderr
        assert "CREDENTIAL_UNSAFE" not in result.stdout + result.stderr
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    result = disable(cli, "pi5", apply=True)
    assert (result.returncode, envelope(result)["error"]["code"]) == (3, "CREDENTIAL_UNSAFE")
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()


def test_multi_target_disable_applies_in_order_and_stops_at_the_first_failure(cli, net, armed):
    net.outcome("nomad-b", 400, lands=False)
    result = disable(cli, "spec5", "nomad-b", "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (7, "rejected",
                                                                         "WRITE_REJECTED")
    assert [r.path for r in net.writes()] == [f"{API}/device/nSpec5x1CNTRL/key",
                                              f"{API}/device/nNomadB1CNTRL/key"]
    # One write token for the whole batch: one approval, one mint.
    assert net.mints().count(WRITE_CLIENT) == 1
    assert [r["outcome"] for r in env["data"]["results"]] == ["applied", "rejected",
                                                              "not-attempted"]
    logged = writes_logged(armed)
    assert [(r["target"]["nodeId"], r["outcome"], r["failure"]) for r in logged] == [
        ("nSpec5x1CNTRL", "applied", None), ("nNomadB1CNTRL", "failed", "rejected"),
        ("nPi5x001CNTRL", "failed", "not-attempted")]
    assert net.device("pi5")["keyExpiryDisabled"] is False


def test_a_device_named_twice_is_planned_and_sent_once(cli, net, armed):
    # One device needs one write (A26 (7)): two plans from one pre-read would both be non-noop
    # and POST twice in one approved command (invariant 5).
    dry = envelope(disable(cli, "pi5", "pi5"))
    [plan] = dry["data"]["plans"]
    assert plan["apply_line"].split().count("nPi5x001CNTRL") == 1
    result = disable(cli, "pi5", "nPi5x001CNTRL", apply=True)
    env = envelope(result)
    assert result.returncode == 0, result.stderr
    assert len(env["data"]["plans"]) == 1
    assert [r.path for r in net.writes()] == [f"{API}/device/nPi5x001CNTRL/key"]
    assert net.mints().count(WRITE_CLIENT) == 1
    applied = [r for r in writes_logged(armed) if r["mode"] == "apply"]
    assert [(r["target"]["nodeId"], r["outcome"]) for r in applied] == [
        ("nPi5x001CNTRL", "applied")]


def test_a_refused_target_sends_nothing_for_any_target(cli, net, armed):
    result = disable(cli, "pi5", "albini", apply=True)
    assert (result.returncode, envelope(result)["error"]["code"]) == (5, "MULTI_TARGET_NOT_R1")
    net.device("spec5")["isExternal"] = True
    result = disable(cli, "pi5", "spec5", apply=True)
    assert (result.returncode, envelope(result)["error"]["code"]) == (5, "SHARED_IN")
    # An operation refusal refuses the dry run too: no plan of it can ever be applied.
    result = disable(cli, "pi5", "spec5")
    assert (result.returncode, envelope(result)["outcome"]) == (5, "refused")
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    assert {r["outcome"] for r in writes_logged(armed)} == {"refused"}
    assert len(writes_logged(armed)) == 6


def test_a_504_with_the_change_visible_is_applied(cli, net, armed):
    net.outcome("pi5", 504, lands=True)
    result = disable(cli, "pi5", apply=True)
    assert result.returncode == 0, result.stderr
    assert envelope(result)["outcome"] == "applied"
    [logged] = writes_logged(armed)
    assert (logged["outcome"], logged["confirmed"]) == ("applied", True)
    assert logged["http"][0]["status"] == 504
    assert len(net.writes()) == 1


def test_a_504_with_the_change_absent_exits_6(cli, net, armed):
    net.outcome("pi5", 504, lands=False)
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (6, "unconfirmed",
                                                                         "WRITE_UNCONFIRMED")
    assert "do not re-apply" in env["error"]["message"]
    assert env["next"][0]["run"] == "tailnet device list --json"
    assert len(net.writes()) == 1
    [logged] = writes_logged(armed)
    assert (logged["outcome"], logged["confirmed"], logged["failure"]) == ("failed", False,
                                                                           "unconfirmed")


@pytest.mark.parametrize("lands", [True, False])
def test_a_500_whose_body_is_reset_is_decided_by_the_reread_with_one_audit_line(cli, net, armed,
                                                                               lands):
    # The status line came, then the connection reset mid-body: the write was sent, so the
    # re-read decides it (§10.2), never a crash that leaves no audit line (invariant 6).
    net.outcome("pi5", 500, lands=lands, cut="reset")
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert len(net.writes()) == 1
    [logged] = writes_logged(armed)
    assert logged["sent"] is True
    if lands:
        assert (result.returncode, env["outcome"]) == (0, "applied"), result.stderr
        assert (logged["outcome"], logged["confirmed"]) == ("applied", True)
    else:
        assert (result.returncode, env["outcome"], env["error"]["code"]) == (
            6, "unconfirmed", "WRITE_UNCONFIRMED")
        assert "do not re-apply" in env["error"]["message"]
        assert "→ 500" in env["error"]["message"]
        assert (logged["outcome"], logged["failure"]) == ("failed", "unconfirmed")


def test_a_2xx_whose_reread_differs_exits_6(cli, net, armed):
    net.outcome("pi5", 200, lands=False)
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (6, "WRITE_UNCONFIRMED")
    assert "not yet visible" in env["error"]["message"]
    assert "tailnet device list --json" in env["error"]["message"]
    [logged] = writes_logged(armed)
    assert (logged["outcome"], logged["sent"], logged["confirmed"]) == ("failed", True, False)
    assert logged["observed_after"] == {"keyExpiryDisabled": False}


def test_a_429_on_a_write_is_sent_exactly_once(cli, net, armed):
    net.outcome("pi5", 429, lands=False, headers={"Retry-After": "0"})
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (7, "rejected",
                                                                         "WRITE_REJECTED")
    assert env["error"]["http_status"] == 429
    assert "nothing was retried" in env["error"]["message"]
    assert len(net.writes()) == 1
    [logged] = writes_logged(armed)
    # The re-read shows no change, so the rejection itself is confirmed.
    assert (logged["outcome"], logged["confirmed"], logged["failure"]) == ("failed", True,
                                                                           "rejected")


def test_the_write_token_never_touches_disk_and_comes_from_the_write_client(cli, net, armed):
    result = disable(cli, "pi5", apply=True)
    assert result.returncode == 0, result.stderr
    assert net.mints() == [READ_CLIENT, WRITE_CLIENT]
    [write_mint] = [r for r in net.requests("POST", "/oauth/token")
                    if r.form()["client_id"] == [WRITE_CLIENT]]
    assert write_mint.form()["client_secret"] == [fixture_secret("write0001")]
    assert "scope" not in write_mint.form()
    assert net.writes()[0].header("authorization") == f"Bearer {WRITE_TOKEN}"
    for request in net.requests("GET"):
        assert request.header("authorization") == f"Bearer {READ_TOKEN}"
    for directory, _, names in os.walk(armed.config_dir.parent):
        for name in names:
            path = os.path.join(directory, name)
            with open(path, "rb") as handle:
                assert WRITE_TOKEN.encode() not in handle.read(), path
    cached = json.loads((armed.config_dir / "read-token.json").read_text())
    assert cached["access_token"] == READ_TOKEN
    assert WRITE_TOKEN not in result.stdout + result.stderr
    mints = [json.loads(line) for line in (armed.state_dir / "audit.jsonl").read_text().splitlines()]
    assert [(r["role"], r["cacheable"]) for r in mints if r["event"] == "token.mint"] == [
        ("read", True), ("write", False)]


def test_a_held_apply_lock_refuses_a_second_apply(cli, net, armed):
    armed.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(armed.state_dir / "apply.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        result = disable(cli, "pi5", apply=True)
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (5, "APPLY_IN_PROGRESS")
        # The lock comes before the pre-reads, so nothing at all was asked of the API.
        assert net.loopback.requests == []
        # A dry run takes no lock: it changes nothing.
        assert disable(cli, "pi5").returncode == 0
    finally:
        os.close(fd)
    first = writes_logged(armed)[0]
    assert (first["outcome"], first["target"], first["refusal"]["code"]) == (
        "refused", None, "APPLY_IN_PROGRESS")
    result = disable(cli, "pi5", apply=True)
    assert result.returncode == 0, result.stderr


def test_an_unwritable_audit_log_stops_the_write(cli, net, armed):
    armed.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = armed.state_dir / "audit.jsonl"
    log.write_text("")
    log.chmod(0o644)
    for apply in (True, False):
        result = disable(cli, "pi5", apply=apply)
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (3, "AUDIT_UNWRITABLE"), apply
    # A write that cannot be recorded is not sent (C9), and its token is never minted.
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    assert log.read_text() == ""


def test_a_batch_sends_no_further_write_once_the_audit_log_stops_taking_lines(cli, net, armed):
    # The log turns group-readable just after spec5's write lands, before its line is written,
    # so from then on no line can be recorded and no later write may be sent (C9, invariant 6).
    log = armed.state_dir / "audit.jsonl"
    landed = net._write(IDS["spec5"], "key")

    def land_then_break_the_log(request):
        reply = landed(request)
        log.chmod(0o644)
        return reply

    net.loopback.route("POST", f"{API}/device/{IDS['spec5']}/key", land_then_break_the_log)
    result = disable(cli, "spec5", "nomad-b", "pi5", apply=True)
    env = envelope(result)
    assert [r.path for r in net.writes()] == [f"{API}/device/nSpec5x1CNTRL/key"]
    assert [(r["outcome"], r["sent"]) for r in env["data"]["results"]] == [
        ("applied", True), ("not-attempted", False), ("not-attempted", False)]
    assert all("audit log" in r["message"] for r in env["data"]["results"][1:])
    # The write that went out keeps its own exit (A26 (5)); the stop is said, not hidden.
    assert (result.returncode, env["outcome"]) == (0, "applied"), result.stderr
    assert "AUDIT_UNWRITABLE" in [w["code"] for w in env["warnings"]]
    assert "nNomadB1CNTRL" in result.stderr and "nPi5x001CNTRL" in result.stderr
    assert net.device("nomad-b")["keyExpiryDisabled"] is False
    assert net.device("pi5")["keyExpiryDisabled"] is False
    # Exit 0 alone would read as the whole batch, so the human verdict names what was left.
    log.chmod(0o600)
    net.device("spec5")["keyExpiryDisabled"] = False
    human = cli("device", "disable-key-expiry", "spec5", "nomad-b", "pi5", "--apply", "--reason",
                REASON)
    assert human.stdout.startswith("APPLIED: 1 of 3 sent, each confirmed by a re-read; "
                                   "2 not attempted"), human.stdout
    assert len(net.writes()) == 2
    log.chmod(0o600)
    assert writes_logged(armed) == []


def test_every_attempt_leaves_one_audit_line_with_the_decided_outcome(cli, net, armed):
    net.outcome("nomad-b", 403, lands=False)
    attempts = [
        (disable(cli, "pi5"), "dry-run"),
        (disable(cli, "pi5", apply=True, confirm="no-expiry:pi5"), "refused"),
        (disable(cli, "nosuchbox", apply=True), "refused"),
        (disable(cli, "pi5", apply=True), "applied"),
        (disable(cli, "claude-factory", apply=True), "applied"),
        (disable(cli, "nomad-b", apply=True), "failed"),
    ]
    logged = writes_logged(armed)
    assert len(logged) == len(attempts)
    for (result, outcome), record in zip(attempts, logged):
        assert record["outcome"] == outcome, (result.stdout, record)
        assert record["op"] == "device.disable-key-expiry"
        assert record["outcome"] in {"dry-run", "refused", "applied", "failed"}
    # A refusal before any device was resolved has no target, and says why.
    assert (logged[2]["target"], logged[2]["refusal"]["code"]) == (None, "DEVICE_NOT_FOUND")
    assert [r["mode"] for r in logged] == ["dry-run"] + ["apply"] * 5


@pytest.mark.parametrize("apply", [True, False])
def test_a_failed_pre_read_still_leaves_its_write_line(cli, net, armed, apply):
    # A stop the guard did not cause still reaches the narrative: one line, no target since
    # nothing was resolved, failed / not-attempted with the stop's code (A26 (2), invariant 6).
    net.loopback.route("GET", DEVICES, lambda request: (
        500, {"X-Tailscale-Request-Id": "REQ-list"}, {"message": "the test answers HTTP 500"}))
    result = disable(cli, "pi5", apply=apply)
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (4, "API_SERVER"), result.stderr
    assert net.writes() == []
    [logged] = writes_logged(armed)
    assert (logged["mode"], logged["outcome"], logged["failure"], logged["sent"],
            logged["target"]) == ("apply" if apply else "dry-run", "failed", "not-attempted",
                                  False, None)
    assert logged["error"]["code"] == env["error"]["code"]


def test_a_refused_write_mint_still_leaves_its_write_line(cli, net, armed):
    def mint(request):
        """The read client gets its token; the write client is refused, as a revoked one is."""
        if request.form()["client_id"][0] == WRITE_CLIENT:
            return 401, {"X-Tailscale-Request-Id": "REQ-mint-write"}, {"message": "revoked"}
        return token_reply(READ_TOKEN, request_id="REQ-mint-read")

    net.loopback.route("POST", TOKEN, mint)
    result = disable(cli, "pi5", apply=True)
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (3, "TOKEN_REJECTED"), result.stderr
    assert net.writes() == [] and net.mints() == [READ_CLIENT, WRITE_CLIENT]
    [logged] = writes_logged(armed)
    assert (logged["target"]["nodeId"], logged["outcome"], logged["failure"], logged["sent"]) == (
        "nPi5x001CNTRL", "failed", "not-attempted", False)
    assert logged["error"]["code"] == "TOKEN_REJECTED"


def test_the_reason_is_recorded_in_the_audit_line(cli, net, armed):
    result = disable(cli, "pi5", apply=True)
    assert result.returncode == 0, result.stderr
    assert writes_logged(armed)[-1]["reason"] == REASON
    # A reason is redacted like everything else on its way into the log.
    secret = fixture_secret("read0001")
    result = disable(cli, "spec5", apply=True, reason=f"pasted {secret} by mistake")
    assert result.returncode == 0, result.stderr
    assert writes_logged(armed)[-1]["reason"] == "pasted [REDACTED] by mistake"
    assert secret not in (armed.state_dir / "audit.jsonl").read_text()


def tag(cli, device, *changes, apply=False, confirm=None, reason=REASON):
    """Run `device tag DEVICE CHANGES…` with --json; --apply brings its --reason."""
    args = ["--json", "device", "tag", device, *changes]
    if confirm is not None:
        args += ["--confirm", confirm]
    if apply:
        args += ["--apply", "--reason", reason]
    return cli(*args)


def test_an_unanswered_protected_list_refuses_tag_applies_and_dry_runs_warn(cli, net, armed):
    (armed.config_dir / "protected").unlink()
    result = tag(cli, "pi5", "--add", "tag:lab")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    [unanswered] = [w for w in env["warnings"] if w["code"] == "PROTECTED_UNANSWERED"]
    assert unanswered["message"].startswith("apply would be refused: ")
    result = tag(cli, "pi5", "--add", "tag:lab", apply=True, confirm="retag:pi5")
    env = envelope(result)
    assert result.returncode == 5
    # Test posture takes self from the list's self line too, so self is unknown as well and
    # is the first refusal (C3 before C4); the unanswered list is refused all the same.
    assert env["error"]["code"] == "SELF_UNKNOWN"
    assert "PROTECTED_UNANSWERED" in [r["code"] for r in env["data"]["refusals"]]
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()


def test_tag_apply_posts_the_full_new_set_once_and_rereads(cli, net, armed):
    result = tag(cli, "pi5", "--add", "tag:lab", apply=True, confirm="retag:pi5")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert env["outcome"] == "applied"
    [posted] = net.writes()
    # The API replaces the list, so the whole new set is sent [api §5.7].
    assert (posted.path, posted.json()) == (f"{API}/device/nPi5x001CNTRL/tags",
                                           {"tags": ["tag:fleet", "tag:lab"]})
    assert posted.header("authorization") == f"Bearer {WRITE_TOKEN}"
    # tagOwners came from the live policy, read as JSON with the read token.
    [policy] = net.requests("GET", "/tailnet/-/acl")
    assert policy.header("accept") == "application/json"
    assert policy.header("authorization") == f"Bearer {READ_TOKEN}"
    assert net.device("pi5")["tags"] == ["tag:fleet", "tag:lab"]
    [logged] = writes_logged(armed)
    assert (logged["op"], logged["outcome"], logged["class"]) == ("device.tag", "applied", "R2")
    assert logged["requested"] == logged["observed_after"] == {"tags": ["tag:fleet", "tag:lab"]}
    assert logged["confirm"] == {"required": "retag:pi5", "matched": True}
    # Retagging leaves key expiry on, so the next step offered is to turn it off [TAGS L84].
    assert {"who": "agent", "run": "tailnet device disable-key-expiry nPi5x001CNTRL"}.items() \
        <= env["next"][0].items()


def test_a_concurrent_console_change_is_kept_by_the_delta(cli, net, armed):
    dry = envelope(tag(cli, "pi5", "--add", "tag:lab"))
    assert dry["data"]["plans"][0]["after"] == {"tags": ["tag:fleet", "tag:lab"]}
    # MC adds tag:ci in the console between the dry run and the apply.
    net.device("pi5")["tags"] = ["tag:fleet", "tag:ci"]
    result = tag(cli, "pi5", "--add", "tag:lab", apply=True, confirm="retag:pi5")
    assert result.returncode == 0, result.stderr
    [posted] = net.writes()
    assert posted.json() == {"tags": ["tag:ci", "tag:fleet", "tag:lab"]}


def test_a_confirm_from_before_a_rename_is_refused(cli, net, armed):
    dry = envelope(tag(cli, "pi5", "--add", "tag:lab"))
    line = dry["data"]["plans"][0]["apply_line"]
    assert "--confirm retag:pi5 " in line
    net.device("pi5")["hostname"] = "pi5-lab"
    result = tag(cli, "nPi5x001CNTRL", "--add", "tag:lab", apply=True, confirm="retag:pi5")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (5, "CONFIRM_MISMATCH")
    assert "pi5-lab" in env["error"]["message"] and "renamed" in env["error"]["message"]
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()


def test_strip_owner_without_confirm_exits_5_and_sends_nothing(cli, net, armed):
    dry = envelope(tag(cli, "albini", "--add", "tag:fleet"))
    [plan] = dry["data"]["plans"]
    assert (plan["class"], plan["confirm_required"]) == ("R3", "strip-owner:albini")
    assert any("removes mc@example.com as owner" in line for line in plan["consequences"])
    for confirm, code in ((None, "CONFIRM_MISSING"), ("retag:albini", "CONFIRM_MISMATCH")):
        result = tag(cli, "albini", "--add", "tag:fleet", apply=True, confirm=confirm)
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (5, code), confirm
        assert "strip-owner:albini" in env["error"]["message"]
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    assert net.device("albini")["tags"] == []


def test_a_write_to_self_exits_5(cli, net, armed):
    for apply in (True, False):
        result = tag(cli, "claude-factory", "--add", "tag:fleet", apply=apply,
                     confirm="retag:claude-factory")
        env = envelope(result)
        # Refused even as a dry run: no plan to retag the host the agent runs on can be applied.
        assert (result.returncode, env["outcome"], env["error"]["code"]) == (5, "refused",
                                                                             "SELF_DEVICE")
    assert net.writes() == []


def test_a_tag_change_on_a_protected_device_exits_5(cli, net, armed):
    for apply in (True, False):
        result = tag(cli, "spec5", "--add", "tag:lab", "--remove", "tag:fleet", apply=apply,
                     confirm="retag:spec5")
        env = envelope(result)
        assert (result.returncode, env["error"]["code"]) == (5, "PROTECTED_DEVICE")
        # MC's own reason for protecting it is what the refusal shows.
        assert "Elmer console" in env["error"]["message"]
    assert net.writes() == []
    assert {r["outcome"] for r in writes_logged(armed)} == {"refused"}


def test_a_device_listed_by_any_form_a_device_argument_takes_is_protected(cli, net, armed):
    # MC may name a device in the protected file as the CLI's own resolver would: its MagicDNS
    # name, a Tailscale address or its legacy id. Each protects it (A59); a line that names
    # nothing is said in the plan, by number, since it protects nothing.
    write_protected(armed, "self nFactory1CNTRL\npi5.tail0000.ts.net\n100.64.0.12\n1002\n"
                           "oldbox    # sold\n")
    for name, confirm in (("pi5", "retag:pi5"), ("nomad-b", "retag:nomad-b"),
                          ("spec5", "retag:spec5")):
        for apply in (False, True):
            result = tag(cli, name, "--add", "tag:lab", apply=apply, confirm=confirm)
            env = envelope(result)
            assert (result.returncode, env["error"]["code"]) == (5, "PROTECTED_DEVICE"), name
    assert net.writes() == [] and WRITE_CLIENT not in net.mints()
    result = tag(cli, "albini", "--add", "tag:fleet")
    assert result.returncode == 0, result.stderr
    [unmatched] = [w for w in envelope(result)["warnings"]
                   if w["code"] == "PROTECTED_LINE_UNMATCHED"]
    assert "line 5 " in unmatched["message"] and "oldbox" not in result.stdout + result.stderr


def test_a_400_on_a_tag_write_exits_7_and_explains_the_client_tag_rule(cli, net, armed):
    net.outcome("pi5", 400, lands=False)
    result = tag(cli, "pi5", "--add", "tag:lab", apply=True, confirm="retag:pi5")
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (7, "rejected",
                                                                         "WRITE_REJECTED")
    message = env["error"]["message"]
    assert "the test answers HTTP 400" in message
    assert "TAGS L324" in message and "tagOwners" in message
    assert "[tag:fleet]" in message
    assert len(net.writes()) == 1
    [logged] = writes_logged(armed)
    assert (logged["outcome"], logged["failure"], logged["confirmed"]) == ("failed", "rejected",
                                                                           True)
