# ABOUTME: Integration tests for `tailnet diagnose` as a real CLI process against the loopback seam: the API
# ABOUTME: checks of --from mode, the ssh candidate, real TCP probes on 127.0.0.x, and the on-host block.

import contextlib
import copy
import ipaddress
import json
import re
import socket
import threading

import pytest
from credfiles import access_token, token_reply, write_role
from fixturefiles import body

API = "/api/v2"
TOKEN = API + "/oauth/token"
DEVICES = API + "/tailnet/-/devices"
ACL = API + "/tailnet/-/acl"
VALIDATE = ACL + "/validate"
READ_TOKEN = access_token("read0001")
TIME = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"
# Scenario devices are moved onto real loopback addresses so the TCP probe runs for real
# against a socket the test controls (§21.1); 127/8 is all loopback on Linux.
PI5_LOOPBACK = "127.0.0.13"
BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"
SELF_LINE = "self nFactory1CNTRL     # claude-factory\n"


def drop(src, target):
    """A validate answer in the documented failure shape [spec 2660-2667]: the policy drops it."""
    return {"message": "test(s) failed",
            "data": [{"user": src, "errors": [f'address "{target}": want: Accept, got: Drop']}]}


def ssh_refusal(src):
    """A failed sshTest answer. Synthetic: the spec documents the envelope, not this line."""
    return {"message": "test(s) failed",
            "data": [{"user": src, "errors": ["ssh test to tailnet-diag-dst as spec5 failed"]}]}


class Diag:
    """The tailnet behind the seam for diagnose: the device list, the live policy, and validate.

    Validate answers by the body's shape, as the server picks its mode [api §6.3]: an array
    is a network test, answered from `network` by its source; an object is an ssh
    candidate, answered from `ssh` by (source, mode). Both pass unless a test says otherwise.
    """

    def __init__(self, loopback):
        self.loopback = loopback
        self.devices = {d["hostname"]: d for d in body("scenario", "devices")["devices"]}
        self.policy = body("scenario", "policy")
        self.network = {}
        self.ssh = {}
        loopback.route("POST", TOKEN, token_reply(READ_TOKEN))
        loopback.route("GET", DEVICES, lambda request: (
            200, {"X-Tailscale-Request-Id": "REQ-list"},
            {"devices": list(self.devices.values())}))
        loopback.route("GET", ACL, lambda request: (
            200, {"X-Tailscale-Request-Id": "REQ-acl", "ETag": '"etag-1"'}, self.policy))
        loopback.route("POST", VALIDATE, self._validate)

    def device(self, name):
        """A device's record in the list, by hostname, for a test to change."""
        return self.devices[name]

    def address(self, name, ipv4):
        """Move a device onto another IPv4 address, keeping its IPv6."""
        record = self.devices[name]
        record["addresses"] = [ipv4, *record["addresses"][1:]]

    def _validate(self, request):
        """Answer a network test or an ssh candidate as the test has arranged."""
        doc = request.json()
        if isinstance(doc, list):
            answer = self.network.get(doc[0]["src"], {})
        else:
            [test] = doc["sshTests"]
            mode = "accept" if "accept" in test else "check"
            answer = self.ssh.get((test["src"], mode), {})
        # The seam records a request before answering it, so the nth validate is REQ-validate-n.
        return 200, {"X-Tailscale-Request-Id": f"REQ-validate-{len(self.validates())}"}, answer

    def validates(self):
        """Every validate body posted so far, parsed, in order."""
        return [r.json() for r in self.loopback.requests
                if (r.method, r.path) == ("POST", VALIDATE)]

    def calls(self):
        """Every request as (method, path), in order."""
        return [(r.method, r.path) for r in self.loopback.requests]


@pytest.fixture
def diag(loopback):
    """The tailnet behind this test's seam."""
    return Diag(loopback)


@pytest.fixture
def configured(home):
    """A test home with the read client configured, as `credentials set read` leaves it."""
    write_role(home, "read")
    return home


def write_protected(posture, text=SELF_LINE):
    """MC's protected file with its self line: test posture takes self from it (§11.3)."""
    path = posture.config_dir / "protected"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def envelope(result):
    """The one tailnet.v1 object stdout holds."""
    return json.loads(result.stdout)


@contextlib.contextmanager
def greeter(address):
    """A real listener on a loopback address that greets each connection like sshd.

    Yields its port and the list of peers it accepted, so a test can see whether the CLI
    really connected, or really did not.
    """
    listener = socket.create_server((address, 0))
    listener.settimeout(0.05)
    seen, stop = [], threading.Event()

    def serve():
        """Accept and greet until told to stop."""
        while not stop.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            with connection:
                seen.append(peer)
                connection.sendall(BANNER)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield listener.getsockname()[1], seen
    finally:
        stop.set()
        thread.join()
        listener.close()


@contextlib.contextmanager
def closed_port(address):
    """A port bound on a loopback address with nothing listening: a SYN to it is reset."""
    with socket.socket() as bound:
        bound.bind((address, 0))
        yield bound.getsockname()[1]


def is_identity(src):
    """Whether a test source is a tag or a user login, and in no way an address."""
    try:
        ipaddress.ip_address(src)
        return False
    except ValueError:
        pass
    return bool(re.fullmatch(r"tag:[a-z0-9-]+|[^\s@]+@[^\s@]+", src))


def test_from_mode_runs_api_checks_only_and_reports_allowed(cli, diag, configured):
    # pi5 runs plain OpenSSH [mc §2], and sits on a real loopback socket that would see a probe.
    diag.device("pi5")["sshEnabled"] = False
    diag.address("pi5", PI5_LOOPBACK)
    with greeter(PI5_LOOPBACK) as (port, seen):
        result = cli("--json", "diagnose", "pi5", "--from", "albini", "--port", str(port))
        human = cli("diagnose", "pi5", "--from", "albini", "--port", str(port))
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    assert (env["command"], env["outcome"], env["error"]) == ("diagnose", "ok", None)
    [dest] = env["data"]["destinations"]
    assert (dest["dest"], dest["verdict"], dest["resolved"]["nodeId"]) == (
        "pi5", "ALLOWED", "nPi5x001CNTRL")
    # API-only: no probe of any kind, and the socket never saw a connection.
    assert dest["probes"] is None
    assert seen == []
    source = env["data"]["source"]
    assert (source["mode"], source["nodeId"], source["identities"], source["self_source"]) == (
        "from", "nAlbini1CNTRL", ["mc@example.com"], None)
    # The device list, then one network test as the source's identity; nothing else.
    calls = diag.calls()
    assert calls[:3] == [("POST", TOKEN), ("GET", DEVICES), ("POST", VALIDATE)]
    assert set(calls) == {("POST", TOKEN), ("GET", DEVICES), ("POST", VALIDATE)}
    assert diag.validates()[0] == [{"src": "mc@example.com", "proto": "tcp",
                                    "accept": [f"{PI5_LOOPBACK}:{port}"]}]
    [test] = dest["network_test"]
    assert (test["src"], test["verdict"], test["allowed"]) == ("mc@example.com", "pass", True)
    assert "REQ-list" in env["request_ids"] and "REQ-validate-1" in env["request_ids"]
    assert human.returncode == 0, human.stderr
    assert re.match(rf"OK: 1 of 1 reachable on port {port} \(as of {TIME}\)\n", human.stdout)
    assert re.search(rf"^pi5 \({PI5_LOOPBACK}\) port {port} → ALLOWED \(as of {TIME}\): ",
                     human.stdout, re.MULTILINE)


def test_from_mode_reports_a_policy_drop(cli, diag, configured):
    diag.device("pi5")["sshEnabled"] = False
    diag.network["mc@example.com"] = drop("mc@example.com", "100.64.0.13:22")
    # The phone is offline, which does not matter: --from asks the policy, not the phone.
    result = cli("--json", "diagnose", "pi5", "--from", "iphone192")
    env = envelope(result)
    assert (result.returncode, env["outcome"], env["error"]["code"]) == (8, "negative",
                                                                         "DIAGNOSE_BLOCKED")
    [dest] = env["data"]["destinations"]
    assert dest["verdict"] == "POLICY_DROP"
    assert "TSMP reject and no RST" in dest["explanation"]
    [test] = dest["network_test"]
    assert test["allowed"] is False
    assert test["failures"] == [{"user": "mc@example.com", "target": "100.64.0.13:22",
                                 "want": "Accept", "got": "Drop"}]
    assert "pi5 POLICY_DROP" in env["error"]["message"]
    drafts = [step for step in env["next"]
              if step.get("run", "").startswith("tailnet policy draft")]
    assert drafts and "mc@example.com" in drafts[0]["why"]
    assert ("GET", ACL) not in diag.calls()


def test_a_tailscale_ssh_destination_posts_an_ssh_candidate_with_a_host_alias(cli, diag,
                                                                               configured,
                                                                               loopback):
    # The live policy carries tests of its own and a hosts entry of MC's: the candidate must
    # drop the first and keep the second.
    diag.policy["sshTests"] = [{"src": "mc@example.com", "dst": ["tag:fleet"], "accept": ["root"]}]
    diag.policy["hosts"] = {"lab-printer": "100.64.0.99"}
    live = copy.deepcopy(diag.policy)
    result = cli("--json", "diagnose", "spec5", "--from", "albini", "--ssh-user", "spec5")
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    [dest] = env["data"]["destinations"]
    assert dest["verdict"] == "ALLOWED"
    # The live policy is read once, in its JSON form, with the read token.
    [policy_read] = [r for r in loopback.requests if (r.method, r.path) == ("GET", ACL)]
    assert policy_read.header("accept") == "application/json"
    network, candidate = diag.validates()
    assert network == [{"src": "mc@example.com", "proto": "tcp", "accept": ["100.64.0.11:22"]}]
    expected = {key: value for key, value in live.items() if key not in ("tests", "sshTests")}
    expected["hosts"] = {"lab-printer": "100.64.0.99", "tailnet-diag-dst": "100.64.0.11"}
    expected["sshTests"] = [{"src": "mc@example.com", "dst": ["tailnet-diag-dst"],
                             "accept": ["spec5"]}]
    assert candidate == expected
    [posted] = [r for r in loopback.requests
                if (r.method, r.path) == ("POST", VALIDATE) and r.json() == candidate]
    assert posted.header("content-type") == "application/json"
    [ssh] = dest["ssh_test"]
    assert (ssh["src"], ssh["mode"], ssh["user"], ssh["alias"], ssh["verdict"]) == (
        "mc@example.com", "accept", "spec5", "tailnet-diag-dst", "pass")


def test_a_failed_accept_probe_is_followed_by_a_check_probe(cli, diag, configured):
    for src in ("mc@example.com", "tag:dev"):
        diag.ssh[(src, "accept")] = ssh_refusal(src)
    # MC's own laptop: a user source admitted in check mode is reachable, with a browser check.
    result = cli("--json", "diagnose", "spec5", "--from", "albini", "--ssh-user", "spec5")
    assert result.returncode == 0, result.stderr
    [dest] = envelope(result)["data"]["destinations"]
    assert dest["verdict"] == "ADMITTED_CHECK_MODE"
    modes = [(test["mode"], test["verdict"]) for test in dest["ssh_test"]]
    assert modes == [("accept", "fail"), ("check", "pass")]
    assert dest["ssh_test"][0]["errors"] == ["ssh test to tailnet-diag-dst as spec5 failed"]
    _, accept, check = diag.validates()
    assert accept["sshTests"] == [{"src": "mc@example.com", "dst": ["tailnet-diag-dst"],
                                   "accept": ["spec5"]}]
    assert check["sshTests"] == [{"src": "mc@example.com", "dst": ["tailnet-diag-dst"],
                                  "check": ["spec5"]}]
    # The droplet's own tag: check mode can never admit a tagged source [tsssh L218], and
    # whether to allow accept mode is MC's open question MC6.
    result = cli("--json", "diagnose", "spec5", "--from", "claude-factory", "--ssh-user", "spec5")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (8, "DIAGNOSE_BLOCKED")
    [dest] = env["data"]["destinations"]
    assert dest["verdict"] == "TS_SSH_CHECK_FOR_TAGGED"
    [question] = [step for step in dest["next"] if step["who"] == "ask_mc"]
    assert question["question"]["id"] == "MC6"
    assert question["question"]["safe_default"] in [o["label"] for o in
                                                    question["question"]["options"]]


def test_a_plain_ssh_destination_uses_array_mode_only(cli, diag, configured):
    diag.device("pi5")["sshEnabled"] = False
    result = cli("--json", "diagnose", "pi5", "--from", "albini", "--ssh-user", "mc")
    assert result.returncode == 0, result.stderr
    [dest] = envelope(result)["data"]["destinations"]
    assert (dest["verdict"], dest["ssh_test"]) == ("ALLOWED", [])
    # Tailscale SSH is off there, so the ssh section is never consulted.
    assert [type(doc) for doc in diag.validates()] == [list]
    assert ("GET", ACL) not in diag.calls()


def test_self_mode_in_test_posture_probes_tcp_for_real_and_records_pings_not_run(cli, diag,
                                                                                 configured):
    write_protected(configured)
    diag.device("pi5")["sshEnabled"] = False
    diag.address("pi5", PI5_LOOPBACK)
    with greeter(PI5_LOOPBACK) as (port, seen):
        result = cli("--json", "diagnose", "pi5", "--port", str(port))
    # Test posture never runs tailscale: netguard would have crashed the process.
    assert result.returncode == 0, result.stderr
    env = envelope(result)
    source = env["data"]["source"]
    assert (source["mode"], source["nodeId"], source["self_source"], source["identities"]) == (
        "self", "nFactory1CNTRL", "line", ["tag:dev"])
    [dest] = env["data"]["destinations"]
    assert dest["verdict"] == "OPEN"
    probes = dest["probes"]
    assert probes["tsmp"]["result"] == probes["icmp"]["result"] == "not-run: test posture"
    assert (probes["path_ok"], probes["icmp_ok"]) == (None, None)
    assert (probes["tcp"]["result"], probes["tcp"]["banner"]) == ("open", BANNER.decode())
    assert re.fullmatch(TIME, probes["tcp"]["measured_at"])
    assert len(seen) == 1
    [network] = diag.validates()
    assert network == [{"src": "tag:dev", "proto": "tcp", "accept": [f"{PI5_LOOPBACK}:{port}"]}]
    # An open port that is not SSH's leaves nothing to do; on :22 the next step is `ssh -v`,
    # which the unit tests of the steps cover, since a test cannot bind port 22.
    assert dest["next"] == []


def test_every_validate_request_uses_identities_as_src(cli, diag, configured):
    write_protected(configured)
    diag.device("pi5")["sshEnabled"] = False
    diag.address("pi5", PI5_LOOPBACK)
    with closed_port(PI5_LOOPBACK) as port:
        cli("diagnose", "pi5", "--port", str(port))
    for source in ("albini", "claude-factory", "iphone192", "nAlbini1CNTRL", "100.64.0.20"):
        cli("diagnose", "spec5", "pi5", "--from", source, "--ssh-user", "spec5")
    sources = []
    for doc in diag.validates():
        tests = doc if isinstance(doc, list) else doc["sshTests"]
        sources += [test["src"] for test in tests]
    # Every way of naming the source, its address included, ends as its identity.
    assert set(sources) == {"tag:dev", "mc@example.com"}
    assert all(is_identity(src) for src in sources)


def test_the_on_host_block_is_emitted_for_host_side_verdicts(cli, diag, configured):
    write_protected(configured)
    diag.device("pi5")["sshEnabled"] = False
    diag.address("pi5", PI5_LOOPBACK)
    with closed_port(PI5_LOOPBACK) as port:
        result = cli("--json", "diagnose", "pi5", "nomad-b", "--port", str(port))
        human = cli("diagnose", "pi5", "nomad-b", "--port", str(port))
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (8, "DIAGNOSE_BLOCKED")
    pi5, nomad = env["data"]["destinations"]
    assert (pi5["verdict"], nomad["verdict"]) == ("REFUSED_BY_HOST", "DEST_OFFLINE")
    # The destination is unreachable from here, which is the problem, so the checks on it
    # are handed to MC to run from a session that can reach it, never run by the CLI.
    [block] = [step for step in pi5["next"] if step["who"] == "mc"]
    assert block["needs"] == "terminal"
    lines = block["do"].splitlines()
    assert lines[0] == "# On pi5, while the agent retries from claude-factory:"
    assert "tailscale metrics print | grep -E 'inbound_dropped_packets_total'" in lines[1]
    assert f":{port}\\}}" in lines[2] and "journalctl -u tailscaled" in lines[2]
    assert f"'tcp port {port} and src host 100.64.0.10'" in lines[3]
    assert "tailscale get shields-up" in lines[4]
    runs = [step["run"] for step in pi5["next"] if step["who"] == "agent"]
    assert f"tailnet diagnose nPi5x001CNTRL --port {port}" in runs
    # Which of MC's own devices can reach it: the user-owned ones, asked of the API.
    for other in ("nAlbini1CNTRL", "nPhone01CNTRL"):
        assert f"tailnet diagnose nPi5x001CNTRL --port {port} --from {other}" in runs
    # An offline host gets no block: there is nothing on it to look at.
    assert not [step for step in nomad["next"] if step["who"] == "mc"]
    assert block in env["next"]
    assert "Next (MC, terminal): # On pi5, while the agent retries from claude-factory:" in (
        human.stdout)
    assert re.search(rf"^nomad-b \(100\.64\.0\.12\) port {port} → DEST_OFFLINE \(as of {TIME}\)",
                     human.stdout, re.MULTILINE)


def test_an_unknown_source_or_the_source_itself_stops_at_step_one(cli, diag, configured):
    # No protected file: test posture has no self line, so this host's device is unknown.
    result = cli("--json", "diagnose", "spec5", "pi5")
    env = envelope(result)
    assert (result.returncode, env["error"]["code"]) == (8, "DIAGNOSE_BLOCKED")
    assert [d["verdict"] for d in env["data"]["destinations"]] == ["NOT_FOUND", "NOT_FOUND"]
    assert env["data"]["source"]["nodeId"] is None
    result = cli("--json", "diagnose", "spec5", "--from", "no-such-device")
    assert [d["verdict"] for d in envelope(result)["data"]["destinations"]] == ["NOT_FOUND"]
    write_protected(configured)
    result = cli("--json", "diagnose", "claude-factory", "spec5x")
    verdicts = [d["verdict"] for d in envelope(result)["data"]["destinations"]]
    assert verdicts == ["SAME_DEVICE", "NOT_FOUND"]
    # None of these could be judged, so nothing was asked of the policy.
    assert diag.validates() == []


def test_a_bad_port_or_ssh_user_is_refused_before_any_request(cli, diag, loopback, configured):
    for args in (["--port", "0"], ["--port", "65536"], ["--ssh-user", "<user>"],
                 ["--ssh-user", ""], ["--ssh-user", "a b"], ["--ssh-user", "*"]):
        result = cli("--json", "diagnose", "pi5", "--from", "albini", *args)
        assert (result.returncode, envelope(result)["error"]["code"]) == (2, "USAGE"), args
    assert loopback.requests == []
