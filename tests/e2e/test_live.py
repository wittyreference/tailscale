# ABOUTME: The end-to-end tests E1-E17 (DESIGN.md §21.4): the repo CLI against MC's real tailnet, read-only,
# ABOUTME: on the droplet. Each settles a question no loopback test can; none writes, and run_live refuses --apply.

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from tailnet import audit, credentials
from tailnet.doctor import DOCS_MCP, DOCS_MCP_URL, MARKER, UPSTREAM_PIN
from tailnet.output import now_utc
from tailnet.posture import passwd_home

E2E = Path(__file__).resolve().parent
REPO = E2E.parents[1]
GATE = "Bash(*tailnet*--apply*)"
# §15.2 step 7's verdicts, from the design rather than the code, so E10 and E11 hold the code to it.
VERDICTS = frozenset({
    "SOURCE_DOWN", "NOT_FOUND", "AMBIGUOUS", "SAME_DEVICE", "KEY_EXPIRED", "DEST_OFFLINE",
    "SHIELDS_UP", "PATH_DOWN", "OPEN", "ADMITTED_CHECK_MODE", "TS_SSH_CHECK_FOR_TAGGED",
    "TS_SSH_POLICY", "TS_SSH_UNVERIFIED", "POLICY_DROP", "ALLOWED", "REFUSED_BY_HOST",
    "HOST_SIDE_DROP", "TS_SSH_TIMEOUT_UNEXPLAINED", "INCONCLUSIVE",
})
# The verdicts only self mode can reach: each rests on step 0 or a local probe, and --from runs
# neither (§15.1).
SELF_MODE_ONLY = frozenset({"SOURCE_DOWN", "PATH_DOWN", "OPEN", "REFUSED_BY_HOST",
                            "HOST_SIDE_DROP", "TS_SSH_TIMEOUT_UNEXPLAINED"})
# Tailscale assigns addresses from 100.64.0.0/10 [critic F3]. E9 aims at the top of the range,
# far from the low addresses a small tailnet is given and from 100.100.100.100, the address
# tailscaled answers itself.
UNASSIGNED_CANDIDATES = [ipaddress.ip_address("100.127.255.254") - n for n in range(64)]
# How many connected peers E9 tries before saying none answered: each silent one costs 5 s.
PEERS_TRIED = 5


def ok(run, *exits):
    """Hold a live run to the exit statuses its test expects (0 unless named), saying why not."""
    exits = exits or (0,)
    error = (run.envelope or {}).get("error")
    assert run.exit in exits, (f"`{run.label}` exited {run.exit}, expected {exits}: {error}; "
                               f"stderr ends: {run.stderr[-400:]!r}")


def inventory(live):
    """A live `device list`: every device, and self as the CLI found it."""
    listing = live("device", "list")
    ok(listing)
    return listing


def written_by(posture, event, runs):
    """The audit lines of `event` that these runs wrote, found by the pid every line carries.

    Other sessions may share MC's log while the suite runs; the pid keeps them out.
    """
    pids = {run.pid for run in runs}
    return [record for record in audit.records(posture, event) if record.get("pid") in pids]


def ping(ip):
    """One live TSMP ping through ping_live.py: {ip, exit, output, measured_at}."""
    done = subprocess.run([sys.executable, "-I", str(E2E / "ping_live.py"), ip],
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, f"ping_live {ip} failed: {done.stderr[-400:]}"
    return json.loads(done.stdout)


def digest(path):
    """A file's sha256, or None when it is absent: proof it was left exactly as it was."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def test_doctor_completes_against_the_real_api(doctor_report, record_run, measure):
    """E1: critic §6 steps 1-8 against the real API. A FAIL is an answer (exit 8); a crash, a
    local refusal or an API failure (1, 3, 4) is not."""
    run = doctor_report
    record_run(run)
    ok(run, 0, 8)
    assert run.envelope["posture"] == "production" and run.data["settle"] is True
    checks = run.data["checks"]
    assert [check["id"] for check in checks][-1] == "S8"
    missing = [check["id"] for check in checks if not check["measured_at"]]
    assert missing == [], f"checks without a measured_at: {missing}"
    measure("doctor counts", f"{run.data['counts']} · mints {run.data['mints_this_run']} · "
                             f"console events {run.data['audit_events_caused']}")


def test_this_droplet_is_self_by_tailscale_ip(live, measure):
    """E2: self is joined by Tailscale IP from the real `tailscale status --json` (§11.3), which
    also checks the parser against the real binary; whether nodeId equals Self.ID is recorded."""
    local = live("status")
    ok(local)
    view = local.data["self_local"]
    assert view["backend_state"] == "Running" and view["reason"] is None, view
    listing = inventory(live)
    me = listing.data["self"]
    assert me["known"] is True and me["source"] == "live", me
    [device] = [d for d in listing.data["devices"] if d["nodeId"] == me["nodeId"]]
    assert set(view["ips"]) & set(device["addresses"]), (view["ips"], device["addresses"])
    measure("self", f"{me['hostname']} {me['nodeId']} · id_agrees {me['id_agrees']} "
                    "(recorded, never required)")


def test_device_list_counts_every_device_and_names_self(live):
    """E3: the inventory is whole, counted, and names exactly one device as self."""
    listing = inventory(live)
    devices = listing.data["devices"]
    assert listing.data["count"] == len(devices) > 0
    selves = [device["nodeId"] for device in devices if device["self"] is True]
    assert selves == [listing.data["self_node_id"]] != [None]
    human = live("device", "list", json_mode=False)
    ok(human)
    counted = re.search(r"(\d+) of (\d+) devices \(the API does not paginate\)", human.stdout)
    assert counted and counted.group(1) == counted.group(2), human.stdout[-400:]


def test_the_read_token_is_reused_across_invocations(live, production):
    """E4: with the cache dropped first, three reads in three processes mint exactly once (§9;
    critic F6), so an hour of reads costs MC one console event."""
    mode = live("status").data["mode"]
    ok(live("credentials", "forget", "token"))
    reads = [live("device", "list"), live("policy", "get", "--format", "json"),
             live("device", "list")]
    for run in reads:
        ok(run)
    mints = written_by(production, "token.mint", reads)
    assert len(mints) == 1, f"{len(mints)} token.mint lines across three reads ({mode} mode)"
    [mint] = mints
    assert mint["pid"] == reads[0].pid and mint["role"] == "read" and mint["cacheable"] is True


def test_policy_get_hujson_and_json_return_raw_etags(live, measure):
    """E5: both forms carry an ETag, stored raw and shown with one pair of quotes stripped
    (critic R3); whether it is quoted, and whether the two forms share it, is recorded."""
    runs = [live("policy", "get"), live("policy", "get", "--format", "json")]
    for run in runs:
        ok(run)
        raw = run.data["etag_raw"]
        assert isinstance(raw, str) and raw, f"`{run.label}`: the response had no ETag"
        quoted = len(raw) >= 2 and raw[0] == raw[-1] == '"'
        assert run.data["etag"] == (raw[1:-1] if quoted else raw)
        measure(f"{run.data['format']} ETag", f"quoted {quoted} · {run.data['lines']} lines")
    measure("same ETag for both forms", str(runs[0].data["etag_raw"] == runs[1].data["etag_raw"]))


def test_the_live_policy_validates_as_hujson(live, tmp_path):
    """E6: the live policy, exactly as served, passes the server's validate (critic R1)."""
    path = tmp_path / "live.hujson"
    ok(live("policy", "get", "--out", str(path)))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    checked = live("policy", "validate", str(path))
    ok(checked)
    assert checked.data["verdict"] in ("pass", "pass-with-warnings"), checked.data


def test_the_live_policy_validates_as_json(live, tmp_path):
    """E7: the JSON form of the live policy is itself a policy validate accepts, the premise of
    diagnose's ssh candidate (§15.2 step 6). JSON is HuJSON, so validate parses it unchanged."""
    path = tmp_path / "live.json"
    ok(live("policy", "get", "--format", "json", "--out", str(path)))
    json.loads(path.read_text(encoding="utf-8"))
    checked = live("policy", "validate", str(path))
    ok(checked)
    assert checked.data["verdict"] in ("pass", "pass-with-warnings"), checked.data


def test_a_fresh_draft_of_the_live_policy_is_ready_after_validate(live, production):
    """E8: draft, validate, diff: an unedited draft is READY with nothing for MC to apply (§14)."""
    draft = live("policy", "draft", "--name", "e2e")
    ok(draft)
    path = Path(draft.data["path"])
    drafts = Path(os.path.realpath(production.drafts_dir))
    try:
        assert path.parent == drafts, path
        ok(live("policy", "validate", str(path)))
        diff = live("policy", "diff", str(path))
        ok(diff)
        assert diff.data["ready"] is True and diff.data["changed"] is False, diff.data["reasons"]
    finally:
        # The draft is the suite's own; MC's drafts beside it are never touched.
        if path.parent == drafts and path.name.endswith("-e2e"):
            shutil.rmtree(path)


def test_tailscale_ping_tsmp_exit_codes_on_pong_and_timeout(live, measure):
    """E9: what diagnose reads as path_ok (§15.2 step 4): a pong from a connected peer exits 0,
    and a ping to an address no listed device holds exits non-zero with no pong."""
    listing = inventory(live)
    devices = listing.data["devices"]
    peers = [d for d in devices if d["online"] is True and d["ipv4"]
             and d["nodeId"] != listing.data["self_node_id"]]
    assert peers, "no connected peer with an IPv4 address to ping"
    answered, silent = None, []
    for peer in peers[:PEERS_TRIED]:
        result = ping(peer["ipv4"])
        measure(f"tailscale ping --tsmp {peer['hostname']} {peer['ipv4']}",
                f"exit {result['exit']} · measured_at {result['measured_at']}")
        if "pong" in result["output"]:
            answered = result
            break
        silent.append(result)
    assert answered is not None, f"no connected peer answered a TSMP ping: {silent}"
    assert answered["exit"] == 0, answered
    held = {address for device in devices for address in device["addresses"]}
    nobody = next(str(ip) for ip in UNASSIGNED_CANDIDATES if str(ip) not in held)
    result = ping(nobody)
    measure(f"tailscale ping --tsmp {nobody} (no listed device)",
            f"exit {result['exit']} · measured_at {result['measured_at']} · {result['output']!r}")
    assert result["exit"] != 0 and "pong" not in result["output"], result


def test_diagnose_returns_a_known_verdict_for_every_tagged_device(live):
    """E10: the ladder against reality gives every tagged device one of §15's verdicts; which
    one is MC's tailnet's business, not the test's."""
    listing = inventory(live)
    tagged = [device["nodeId"] for device in listing.data["devices"] if device["tags"]]
    assert tagged, "no tagged device to diagnose"
    run = live("diagnose", *tagged)
    ok(run, 0, 8)
    entries = run.data["destinations"]
    assert [entry["dest"] for entry in entries] == tagged
    for entry in entries:
        assert entry["verdict"] in VERDICTS, entry
        assert entry["measured_at"], entry


def test_diagnose_from_a_user_owned_device_runs_api_checks_only(live):
    """E11: --from asks the API about another source and probes nothing (§15.1), with that
    source's identities, never an address, as the policy tests' src (invariant 11)."""
    listing = inventory(live)
    devices, me = listing.data["devices"], listing.data["self_node_id"]
    sources = [d for d in devices if not d["tags"] and d["nodeId"] != me]
    assert sources, "no user-owned device to diagnose from"
    source = sources[0]
    others = [d for d in devices if d["nodeId"] not in (me, source["nodeId"])]
    assert others, "no device to diagnose besides self and the source"
    dest = next((d for d in others if d["tags"]), others[0])
    run = live("diagnose", dest["nodeId"], "--from", source["nodeId"])
    ok(run, 0, 8)
    origin = run.data["source"]
    assert origin["mode"] == "from" and origin["nodeId"] == source["nodeId"], origin
    assert all("@" in name or name.startswith("tag:") for name in origin["identities"]), origin
    [entry] = run.data["destinations"]
    assert entry["probes"] is None, entry["probes"]
    assert entry["verdict"] in VERDICTS - SELF_MODE_ONLY, entry


def test_a_dry_run_tag_change_on_self_is_refused_without_sending(live, production):
    """E12: the guard, run on live state, refuses any tag change on self (exit 5) and leaves
    one refused line in the audit log, which is the evidence it ran. Adding a tag self
    already has asks for no change at all, so nothing could be sent even by mistake."""
    listing = inventory(live)
    me = listing.data["self"]
    assert me["known"], f"self is unknown ({me['reason']}); E2 says why"
    [device] = [d for d in listing.data["devices"] if d["nodeId"] == me["nodeId"]]
    tag = device["tags"][0] if device["tags"] else "tag:fleet"
    run = live("device", "tag", me["nodeId"], "--add", tag)
    ok(run, 5)
    assert run.envelope["error"]["code"] == "SELF_DEVICE", run.data["refusals"]
    assert run.data["mode"] == "dry-run" and run.data["results"] is None
    [line] = written_by(production, "write", [run])
    assert (line["mode"], line["outcome"], line["sent"]) == ("dry-run", "refused", False)
    assert line["refusal"]["code"] == "SELF_DEVICE" and line["http"] == []
    assert line["target"]["nodeId"] == me["nodeId"]


def test_a_dry_run_disable_key_expiry_plans_without_sending(live, production):
    """E13: one dry run plans key-expiry disabling for every tagged device of this tailnet, the
    write that keeps them on it (§12.6, D7), and sends nothing: one dry-run line each."""
    listing = inventory(live)
    targets = [d["nodeId"] for d in listing.data["devices"] if d["tags"] and d["external"] is False]
    assert targets, "no tagged device of this tailnet to plan for"
    run = live("device", "disable-key-expiry", *targets)
    ok(run)
    assert run.envelope["outcome"] in ("dry-run", "noop")
    assert run.data["mode"] == "dry-run" and run.data["results"] is None
    plans = run.data["plans"]
    assert [plan["target"]["nodeId"] for plan in plans] == targets
    assert {plan["class"] for plan in plans} == {"R1"}
    lines = written_by(production, "write", [run])
    assert sorted(line["target"]["nodeId"] for line in lines) == sorted(targets)
    for line in lines:
        assert (line["mode"], line["outcome"], line["sent"], line["http"]) == (
            "dry-run", "dry-run", False, [])


def test_the_live_openapi_matches_the_pinned_sha256(doctor_report, record_run):
    """E14: the live OpenAPI document still hashes to spec/SHA256SUMS (D19; api §12.19). Doctor's
    L11 fetched it in the suite's one doctor run; a drift fails here and is INFO there."""
    record_run(doctor_report)
    [drift] = [check for check in doctor_report.data["checks"] if check["id"] == "L11"]
    spec = drift["evidence"].get("spec")
    assert spec, drift
    pinned = (REPO / "spec" / "SHA256SUMS").read_text(encoding="utf-8").split()[0]
    live_sha = re.search(r"\b[0-9a-f]{64}\b", spec["detail"])
    assert live_sha, f"the live spec was not read: {spec['detail']}"
    assert live_sha.group(0) == pinned, ("the live spec drifted from the pin: re-check the "
                                         "fixtures and the upstream corrections")
    assert spec["ok"] is True


def test_dns_reads_succeed(live, measure):
    """E15: the four dns:read reads answer, and the configuration read is reported either way
    (critic Q23); this host's local view runs, as it does only in production."""
    run = live("dns")
    ok(run)
    data = run.data
    assert isinstance(data["nameservers"], list) and isinstance(data["searchPaths"], list)
    assert isinstance(data["magicDNS"], bool) and isinstance(data["splitDns"], dict)
    config, local = data["configuration"], data["local"]
    measure("/dns/configuration", f"HTTP {config['status']} · "
                                  f"{'read' if config['body'] is not None else 'refused'}")
    assert local["error"] != "not run: test posture", local
    measure("local view", f"accept-dns {local['accept_dns']} · {local['self_dnsname']} resolves "
                          f"{local['resolves']} · {local['error'] or 'no error'}")


def test_the_cached_token_is_0600_and_read_only(live, production):
    """E16: after a read, the token cache is a private regular file whose granted scope is
    read-only (§9.2-9.3); only a single-client grant that could not be narrowed caches none."""
    ok(live("device", "list"))
    status = live("status")
    ok(status)
    cache, mode = status.data["token_cache"], status.data["mode"]
    path = production.config_dir / "read-token.json"
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        assert mode == "single-client", f"no token cache after a read in {mode} mode"
        return
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    assert st.st_uid == os.geteuid() and st.st_nlink == 1
    assert cache["error"] is None and cache["usable"] is True, cache
    assert credentials.cacheable(cache["scope"]), cache["scope"]
    assert cache["client_id"] == status.data["credentials"][0]["client_id"]


def test_install_into_a_temporary_home_pins_upstream_and_registers_mcp(tmp_path, measure):
    """E17: the installer, run for real into a temporary HOME and Claude directory, clones
    upstream from GitHub at the pin and registers the docs MCP server through Claude Code's
    own CLI; uninstall then removes both. MC's real settings are left byte for byte."""
    home, claude_dir = tmp_path / "home", tmp_path / "home" / "claude-config"
    home.mkdir(mode=0o700)
    real_claude = Path(os.environ.get("CLAUDE_CONFIG_DIR") or passwd_home() / ".claude")
    real_settings = digest(real_claude / "settings.json")
    env = {name: value for name, value in os.environ.items()
           if name not in ("DRY_RUN", "CLAUDE_CONFIG_DIR") and not name.startswith("GIT_")}
    env.update(HOME=str(home), CLAUDE_CONFIG_DIR=str(claude_dir))

    def installer(*args):
        """Run install-tailnet.sh in the temporary home and record when."""
        done = subprocess.run([str(REPO / "install-tailnet.sh"), *args], env=env,
                              capture_output=True, text=True, timeout=900, check=False)
        measure(f"install-tailnet.sh {' '.join(args)}".strip(),
                f"exit {done.returncode} · measured_at {now_utc()}")
        assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-1500:]
        return done

    def mcp_get(environ):
        """`claude mcp get tailscale-docs`: its exit status and whether the URL is ours."""
        done = subprocess.run(["claude", "mcp", "get", DOCS_MCP], env=environ,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=120, check=False)
        return done.returncode, DOCS_MCP_URL in done.stdout

    assert shutil.which("claude", path=env.get("PATH")), "claude is not on PATH"
    real_mcp = mcp_get(os.environ)
    installer()
    share = home / ".local" / "share" / "tailnet"
    clone = share / "upstream" / "tailscale-skill"
    head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], env=env,
                          capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    assert head == UPSTREAM_PIN
    marker = json.loads((claude_dir / "skills" / "tailscale" / MARKER).read_text())
    assert marker["pin"] == UPSTREAM_PIN
    added = json.loads((share / "install.json").read_text())["added"]
    assert added["upstream_clone"] and added["upstream_copy"] and added["mcp"], added
    assert mcp_get(env) == (0, True)
    settings = json.loads((claude_dir / "settings.json").read_text())
    assert GATE in settings["permissions"]["ask"]
    # A temporary HOME must never send an install into MC's real Claude settings (A38).
    assert mcp_get(os.environ) == real_mcp
    assert digest(real_claude / "settings.json") == real_settings
    installer("--uninstall")
    assert mcp_get(env)[0] != 0
    for path in (home / ".local" / "bin" / "tailnet", clone, claude_dir / "skills" / "tailscale",
                 claude_dir / "skills" / "tailnet", share / "install.json"):
        assert not path.exists(), path
    assert digest(real_claude / "settings.json") == real_settings
