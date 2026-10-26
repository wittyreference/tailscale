# ABOUTME: `tailnet doctor` (DESIGN.md §16): local checks and the read-only API steps that settle the open
# ABOUTME: questions, the settled answers kept in its own audit lines, MC's questions, and the accounting.

import email.utils
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from tailnet import (
    api,
    audit,
    credentials,
    devices,
    diagnose,
    dns,
    gate,
    localts,
    output,
    policy,
    protected,
    secure_files,
    selfnode,
    tokens,
)
from tailnet.credentials import READ_SCOPES
from tailnet.devices import parse_time
from tailnet.errors import ApiError, LocalError, Negative, TailnetError
from tailnet.output import Envelope, format_utc
from tailnet.posture import API_PATH
from tailnet.redact import REDACTOR, redact

# The five outcomes a check can have (§16.4). WARN never fails the run; FAIL exits 8.
STATUSES = ("PASS", "WARN", "FAIL", "INFO", "SKIP")

# The steps whose call costs MC a console event or leaves a deliberate scope refusal, each
# with the critic question its answer settles (§16.2, §16.3). They re-run only when asked,
# never answered, or answered more than SETTLE_AFTER ago; every other step runs every time.
GATED = {"S2": "Q1", "S3": "Q3", "S5": "Q4", "S7b": "Q20", "S8": "Q23"}
# Verification-discipline's drift rule: an answer older than this is assumed stale.
SETTLE_AFTER = timedelta(days=30)

# Hostnames come from the API, which takes them from each device's own OS, so one is never
# trusted inside a shell block MC runs: anything but these characters becomes "?".
_SAFE_COMMENT = re.compile(r"[^A-Za-z0-9._-]")
_NODE_ID = re.compile(r"[A-Za-z0-9]+")
# The here-document's end marker. It is quoted, so the shell expands nothing inside, and a
# sanitised comment cannot spell it on a line of its own.
_END = "TAILNET_PROTECTED_END"


@dataclass(frozen=True)
class Check:
    """One line of doctor's report: a local check (L1-L11) or an API step (S1-S8).

    `settles` names the critic question or design section the result answers, `finding`
    is the value in words, `evidence` the facts behind it, and `next` who acts on it.
    """

    id: str
    title: str
    status: str
    settles: str | None
    finding: str
    evidence: dict
    measured_at: str
    next: list

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"a check's status is one of {STATUSES}, not {self.status!r}")

    def to_dict(self):
        """The check as the envelope's data carries it."""
        return {"id": self.id, "title": self.title, "status": self.status,
                "settles": self.settles, "finding": self.finding, "evidence": self.evidence,
                "measured_at": self.measured_at, "next": self.next}


def counts(checks):
    """How many checks ended in each status, as the doctor.run line records them (§13.3)."""
    tally = {status.lower(): 0 for status in STATUSES}
    for check in checks:
        tally[check.status.lower()] += 1
    return {key: tally[key] for key in ("pass", "warn", "fail", "info", "skip")}


# --- Settling (D3): the answers live in doctor.run lines, never in a second state file ---


def _valid_answer(entry):
    """Whether a stored entry is an answer doctor can report: words, and a time it can read."""
    return (isinstance(entry, dict) and isinstance(entry.get("answer"), str)
            and parse_time(entry.get("measured_at")) is not None)


def settled_answers(records):
    """The newest stored answer per question, from doctor.run records given newest first.

    A run records only the answers it measured itself, so an older line may hold the
    newest answer to a question a later run reused; scanning back finds it (§16.3). An
    entry whose answer or time cannot be read is skipped, so it can never count as settled.
    """
    found = {}
    for record in records:
        settled = record.get("settled") if isinstance(record, dict) else None
        if not isinstance(settled, dict):
            continue
        for question, entry in settled.items():
            if question not in found and _valid_answer(entry):
                found[question] = entry
    return found


def age_days(entry, now):
    """Whole days since a stored answer was measured."""
    return (now - parse_time(entry["measured_at"])) // timedelta(days=1)


def due(entry, now, *, settle):
    """Why a settle-gated step must re-measure now, or None when its stored answer stands.

    It re-runs on --settle, when the question was never answered, and when the newest
    answer is older than SETTLE_AFTER: live state drifts, and a month-old answer is a
    claim about the past (§16.3).
    """
    if settle:
        return "--settle"
    if not _valid_answer(entry):
        return "never settled"
    measured = parse_time(entry["measured_at"])
    if now - measured > SETTLE_AFTER:
        return f"last settled {age_days(entry, now)} days ago, over {SETTLE_AFTER.days}"
    return None


# --- Questions for MC (D4): generic, one per turn, safe default first ---


@dataclass(frozen=True)
class Question:
    """One question doctor leaves for MC: the skill asks it as given, one per turn (§16.4).

    The first option is always the safe default, so a dismissed picker or an unanswered
    question lands on it.
    """

    id: str
    priority: int
    text: str
    options: tuple
    safe_default: str

    def to_dict(self):
        """The question as data.questions carries it."""
        return {"id": self.id, "priority": self.priority, "text": self.text,
                "options": [dict(option) for option in self.options],
                "safe_default": self.safe_default}


@dataclass(frozen=True)
class QuestionState:
    """What this run measured that decides which questions apply.

    `scope_known` is False when no read token was obtained, so the grant was never seen;
    `fleet_expiry` holds (hostname, expires) for each tagged device with key expiry on,
    `drops` holds (identity, address, hostname) for each S7a drop. `write_client` is kept
    to show the write-client question is never asked, whatever it says (amendment A1).
    """

    granted_scope: str | None
    scope_known: bool
    protected_missing: bool
    fleet_expiry: tuple
    drops: tuple
    write_client: bool


def _scope_items(scope):
    """The items of a scope string, split on whitespace and commas as §9.2 does."""
    return {item for item in re.split(r"[\s,]+", scope) if item} if isinstance(scope, str) else set()


def _option(label, description):
    """One answer MC can pick."""
    return {"label": label, "description": description}


def _scope_question(state):
    """Priority 2: the read client's grant is not the four read scopes MC chose (A1, MC2)."""
    granted = state.granted_scope if state.granted_scope else "no scope at all"
    keep = "Keep exactly these"
    return Question(
        "scope-set", 2,
        "Confirm the read client's scopes: Devices Core Read, Policy file Read, Device posture "
        "attributes Read (required by Policy file Read, TC L94), DNS Read. Its token was granted "
        f"{granted}.",
        (_option(keep, "these four are the set you chose; adjust the client in the console "
                       "until it is granted exactly them"),
         _option("Change them in the console", "you want a different set; doctor and status "
                                               "keep reporting the difference")),
        keep)


def _protected_question():
    """Priority 3: MC has not written the protected list, so every tag write is refused."""
    protect = "Protect every device"
    return Question(
        "protected-list", 3,
        "Which devices must the CLI never retag? Proposed: every device (listed in doctor's "
        "block). Delete lines for any you want it able to tag.",
        (_option(protect, "run doctor's block as it is; tag writes stay refused on every "
                          "device until you delete a line"),
         _option("Use the list minus some (I'll say which)", "name the devices the CLI may "
                                                              "tag; you delete their lines "
                                                              "before running the block")),
        protect)


def _expiry_question(state):
    """Priority 4: tagged devices still carry key expiry and drop off when it lapses (P9)."""
    names = ", ".join(name for name, _ in state.fleet_expiry)
    dated = [parse_time(expires) for _, expires in state.fleet_expiry]
    dated = [when for when in dated if when is not None]
    earliest = f" (earliest {min(dated).strftime('%Y-%m-%d')})" if dated else ""
    leave = "Leave it for now"
    return Question(
        "fleet-key-expiry", 4,
        f"{names} still have key expiry ON{earliest}. Console tagging keeps it (TAGS L84). "
        "Disable it so they cannot drop off (P9)?",
        (_option(leave, "nothing changes; device list keeps flagging TAGGED_KEY_EXPIRY_ON"),
         _option("Disable on all of them", "the agent dry-runs disable-key-expiry for all of "
                                           "them; you approve the one apply prompt"),
         _option("Only those expiring within 30 days", "the same, for the devices whose key "
                                                       "lapses soonest")),
        leave)


def _policy_question(state):
    """Priority 5: S7a found the policy dropping this host's identity on port 22."""
    sources = ", ".join(sorted({src for src, _, _ in state.drops}))
    hosts = ", ".join(sorted({name for _, _, name in state.drops}))
    wait = "Not now"
    return Question(
        "policy-fix", 5,
        f"The policy drops {sources} → {hosts} on tcp:22. I can draft and validate the grant; "
        "you would apply it in the console. Go ahead?",
        (_option(wait, "nothing is drafted; diagnose still reports POLICY_DROP"),
         _option("Draft it", "the agent drafts and validates the grant and shows you the diff "
                             "to apply"),
         _option("Show me the rule first", "the agent shows the grant's text before drafting")),
        wait)


def questions(state):
    """The questions this run leaves for MC, only those that apply, in priority order (§16.4).

    Pure. Question 1, write-client consent, is never asked: MC answered it on 2026-10-26
    (amendment A1). The scope question compares the grant as a set, so order and
    separators do not matter, and asks nothing when the grant was never measured.
    """
    asked = []
    if state.scope_known and _scope_items(state.granted_scope) != set(READ_SCOPES):
        asked.append(_scope_question(state))
    if state.protected_missing:
        asked.append(_protected_question())
    if state.fleet_expiry:
        asked.append(_expiry_question(state))
    if state.drops:
        asked.append(_policy_question(state))
    return asked


# --- The protected-list proposal (§11.4): one block MC runs, never the agent ---


def _comment(device):
    """A device's hostname for a comment in MC's shell, reduced to characters that cannot
    end the here-document or start a command."""
    return _SAFE_COMMENT.sub("?", device.hostname or "?")


def protected_proposal(devices, self_device, path, now):
    """The shell block that writes MC's protected file: the self line, then every device.

    "Protect everything" is the safe default: MC deletes the lines of devices the CLI may
    tag. The block creates the file 0600 from its first byte (umask before the file
    exists) and its here-document is quoted, so the shell expands nothing in it; nodeIds are
    used only when they are plain letters and digits, the form the API gives and the
    parser accepts. The agent never runs it: a deny rule covers the directory it names.
    """
    if not _NODE_ID.fullmatch(self_device.node_id):
        raise ValueError("self's nodeId is not plain letters and digits")
    lines = [
        "# MC's protected list. Written by MC, never by an agent. One entry per line.",
        f"# Proposed by `tailnet doctor` at {format_utc(now)} from the live device list:",
        "# every device is protected. Delete a device's line to let the CLI retag it;",
        "# the self line must stay, and self is always protected.",
        f"self {self_device.node_id}    # {_comment(self_device)} (this host)",
    ]
    for device in devices:
        if _NODE_ID.fullmatch(device.node_id):
            lines.append(f"{device.node_id}    # {_comment(device)}")
        else:
            # Such a device can never be a write target either: no path takes its ID.
            lines.append(f"# skipped {_comment(device)}: its nodeId is not letters and digits")
    folder, target = shlex.quote(str(path.parent)), shlex.quote(str(path))
    return "\n".join([f"umask 077; mkdir -p {folder}; cat > {target} <<'{_END}'", *lines, _END])


# --- Accounting (§16.4): every console event this run caused, so MC can match each ---


def audit_events_caused(mints, refused):
    """The console audit events this run caused, in words MC can match to the log.

    `mints` is the number of tokens issued, each one "Create OAuth access token" event
    [AUDIT L329]. `refused` lists (step, certain) for each call refused for its scope: S5
    is refused on purpose and is certain; any other refusal is logged as a failed request
    only if a missing scope caused it, which the status alone cannot show (critic Q4).
    """
    events = []
    if mints:
        events.append(f"Create OAuth access token ×{mints}")
    certain = [step for step, sure in refused if sure]
    possible = [step for step, sure in refused if not sure]
    if certain:
        events.append(f"Failed request ×{len(certain)} ({', '.join(certain)})")
    if possible:
        events.append(f"Failed request ×{len(possible)}, possibly ({', '.join(possible)})")
    return events


# --- The S7b probe (§16.2): does a grant from autogroup:member admit a tagged source? ---


def member_candidate(live_json, dst_ip, src):
    """The synthetic policy S7b validates and never saves; pure, and the live copy is untouched.

    It keeps only what the probe needs from the live policy (tagOwners so the tag exists,
    groups and hosts so names still resolve), adds one alias for the destination that never
    shadows one of MC's hosts, one grant from autogroup:member to it on tcp:22, and one test
    asking whether `src`, a tag, gets in. A pass means autogroup:member covers tagged
    sources; a drop means it does not (critic Q20).
    """
    if not (isinstance(src, str) and src.startswith("tag:")):
        raise ValueError(f"the S7b probe runs as one of this host's tags, not {src!r}")
    hosts = live_json.get("hosts") or {}
    if not isinstance(hosts, dict):
        raise TypeError("the live policy's hosts section is not a map of names to addresses")
    taken = {name.lower() for name in hosts}
    alias, number = diagnose.ALIAS, 1
    while alias in taken:
        number += 1
        alias = f"{diagnose.ALIAS}-{number}"
    candidate = {"tagOwners": live_json.get("tagOwners", {}), "hosts": {**hosts, alias: dst_ip},
                 "grants": [{"src": ["autogroup:member"], "dst": [alias], "ip": ["tcp:22"]}],
                 "tests": [{"src": src, "proto": "tcp", "accept": [f"{dst_ip}:22"]}]}
    if "groups" in live_json:
        candidate["groups"] = live_json["groups"]
    return candidate


# --- Other programs: doctor's install and drift checks only (§16.1 L8, L11) ---

# The only programs doctor starts, each for one check: git (the upstream clone's HEAD, and
# upstream's HEAD on GitHub), claude (whether the docs MCP server is registered), bash (whether
# `tailnet` is on MC's login PATH). Never tailscale: only localts runs that.
PROGRAMS = frozenset({"git", "claude", "bash"})


class ProgramRefused(RuntimeError):
    """Raised when doctor is asked to start a program in test posture: a bug, never MC's error.

    Test posture checks nothing outside its own home and runs nothing (§7.1), so callers skip
    these checks there; this is the backstop that makes a missed skip fail loudly.
    """


class ProgramFailed(Exception):
    """A program doctor asked gave no answer: it is missing, timed out, or could not start."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def run_program(posture, argv, timeout):
    """Run one of PROGRAMS for an install or drift check; return (exit status, stdout redacted).

    Production posture only. A word naming tailscale is refused whatever program carries
    it, so no argument can turn this into a second way to run the binary.
    """
    if posture.kind == "test":
        raise ProgramRefused(f"refusing to run `{' '.join(argv)}` in test posture: test runs "
                             "check nothing outside the test home (DESIGN.md §7.1)")
    if not argv or argv[0] not in PROGRAMS or any(
            os.path.basename(str(word)) == "tailscale" for word in argv):
        raise ValueError(f"doctor runs only {sorted(PROGRAMS)}, never tailscale: {argv!r}")
    path = shutil.which(argv[0])
    if path is None:
        raise ProgramFailed(f"{argv[0]} is not on PATH")
    command = " ".join(argv)
    try:
        done = subprocess.run([path, *argv[1:]], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ProgramFailed(f"`{command}` gave no answer within {timeout} s") from None
    except OSError as exc:
        raise ProgramFailed(f"could not run {path}: {exc.strerror}") from None
    return done.returncode, redact(done.stdout.decode("utf-8", "replace"))


# --- The command: `tailnet doctor [--settle]` ---

# The report's order, which is also the order of data.checks: local checks, then API steps.
ORDER = ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10", "L11",
         "S1", "S2", "S3", "S4", "S5", "S6", "S7a", "S7b", "S8")
TITLES = {
    "L1": "Python", "L2": "Posture", "L3": "Local tailscale", "L4": "Credentials",
    "L5": "Token cache", "L6": "Protected file", "L7": "Audit log",
    "L8": "Claude Code integration", "L9": "Lever notes", "L10": "Clock skew", "L11": "Drift",
    "S1": "Read token", "S2": "Narrowed read mint", "S3": "Key self-lookup",
    "S4": "Device inventory", "S5": "Out-of-scope read", "S6": "Live policy",
    "S7a": "This host to the fleet on tcp:22", "S7b": "autogroup:member and tagged sources",
    "S8": "DNS configuration",
}
# What each check settles or protects (§16.1, §16.2's last columns).
SETTLES = {
    "L1": "critic Q26", "L3": "§11.3; critic F3.6", "L5": "§9", "L6": "critic Q14",
    "L7": "§13", "L8": "D21", "L9": "§2", "L10": "expiry maths", "L11": "D19",
    "S1": "critic Q5", "S2": "critic Q1", "S3": "critic Q3",
    "S4": "critic Q15, F3.5, Q12, F3.2", "S5": "critic Q4", "S6": "critic Q21, R3, X13",
    "S7a": "part of critic X13", "S7b": "critic Q20", "S8": "critic Q23",
}
# The oldest Python the CLI is written for (§3.1); the droplet's own is unknown (critic Q26).
PYTHON_FLOOR = (3, 10)
# Local reads of a healthy daemon answer at once; a stalled one must not hold doctor long.
LOCAL_TIMEOUT = 5
PROGRAM_TIMEOUT = 10
# git ls-remote crosses the network to GitHub.
REMOTE_TIMEOUT = 20
# Beyond this, token expiry and key-expiry arithmetic start to mislead (§16.1 L10).
CLOCK_SKEW = timedelta(seconds=60)
# The pins drift is measured against: the spec's sha256 (spec/SHA256SUMS) and the upstream
# skill's commit (§20.3). A unit test holds them to the repo's own pins.
PINNED_SPEC_SHA256 = "b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38"
UPSTREAM_PIN = "4f05d353efc56962546aa26ccc59bb08ca699ad1"
UPSTREAM_URL = "https://github.com/tailscale/tailscale-skill"
DOCS_MCP = "tailscale-docs"
DOCS_MCP_URL = "https://tailscale.mcp.kapa.ai/"
MARKER = ".tailnet-install"
MARKER_MAX = 64 * 1024
_INSTALL_PARTS = ("skill", "upstream_copy", "upstream_clone", "docs_mcp", "launcher")
_FAILED_REQUEST = "it leaves one 'Failed request' event in MC's console by design [AUDIT L316]"
_INSTALLER = {"who": "mc", "needs": "terminal", "do": "./install-tailnet.sh (from the tailnet checkout)",
              "why": "it puts back the missing rules and install pieces; the rules put each "
                     "--apply in front of MC and keep the secrets out of the agent's reach"}


def _exists(path):
    """Whether a file is there, by lstat alone: the write secret is never opened (D20)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def _read_json(path):
    """A small JSON object the installer wrote: (object, None) or (None, why it is unusable).

    Markers and the install record hold no secret, so they are read as plain files; a
    symlink is still never followed.
    """
    try:
        raw = secure_files.read_regular(path, MARKER_MAX)
    except FileNotFoundError:
        return None, f"{path} is missing"
    except secure_files.Unreadable as exc:
        return None, f"{path}: {exc}"
    except OSError as exc:
        return None, f"{path}: {exc.strerror}"
    try:
        doc = json.loads(raw)
    except ValueError:
        return None, f"{path} is not JSON"
    return (doc, None) if isinstance(doc, dict) else (None, f"{path} is not a JSON object")


def install_markers(claude_dir, share):
    """L8's file parts: our skill's marker names the installed commit, and the upstream copy's
    marker names the pin (§20.2, §20.3). Reads files only; nothing is run.
    """
    parts = {}
    marker, problem = _read_json(claude_dir / "skills" / "tailnet" / MARKER)
    record, record_problem = _read_json(share / "install.json")
    if marker is None or record is None:
        parts["skill"] = _part(False, problem or record_problem)
    else:
        same = isinstance(marker.get("commit"), str) and marker["commit"] == record.get("commit")
        parts["skill"] = _part(same, f"skill marker commit {marker.get('commit')}, install "
                                     f"record commit {record.get('commit')}")
    upstream, problem = _read_json(claude_dir / "skills" / "tailscale" / MARKER)
    if upstream is None:
        parts["upstream_copy"] = _part(False, problem)
    else:
        parts["upstream_copy"] = _part(upstream.get("pin") == UPSTREAM_PIN,
                                       f"upstream copy marker pin {upstream.get('pin')}")
    return parts


def _listed(values):
    """A list from the API for a finding: its items joined, `none` when empty, as sent otherwise."""
    if isinstance(values, list) and all(isinstance(value, str) for value in values):
        return ", ".join(values) or "none"
    return str(values)


def _part(ok, detail):
    """One piece of a composite check: True, False, or None when it could not be told."""
    return {"ok": ok, "detail": detail}


class _Run:
    """One doctor run: each check's result, and the facts later checks build on."""

    def __init__(self, posture, args, environ, now):
        self.posture = posture
        self.settle = bool(args.settle)
        self.environ = environ
        self.now = now
        self.checks = {}
        self.warnings = []
        self.request_ids = []
        self.refused = []
        self.extra_mints = 0
        self.settled_now = {}
        self.settled_view = {}
        self.stored, self.stored_error = self._stored()
        self.local = None
        self.local_reason = None
        self.cred = None
        self.cred_error = None
        self.mode = None
        self.write_meta = None
        self.write_secret = None
        self.write_leftovers = []
        self.listed = None
        self.protected_state = None
        self.protected_error = None
        self.session = None
        self.token = None
        self.token_from_cache = False
        self.inventory = None
        self.me = None
        self.policy_json = None
        self.fleet = []
        self.drops = []
        self.dates = []
        self.proposal = None

    # -- bookkeeping --

    def _stored(self):
        """The settled answers earlier runs left, or none when the log cannot be read safely.

        A log that fails the private-file checks could have been swapped or written by
        someone else, so nothing in it is trusted to stop a re-measure (amendment A33). Only
        lines of this run's posture count: an answer measured against a loopback stand-in
        says nothing about the real API, and the reverse.
        """
        try:
            records = audit.records(self.posture, "doctor.run")
        except LocalError as exc:
            return {}, exc
        return settled_answers([record for record in records
                                if record.get("posture") == self.posture.kind]), None

    def add(self, check_id, status, finding, evidence=None, next_steps=()):
        """Record one check's result at this moment."""
        self.checks[check_id] = Check(check_id, TITLES[check_id], status,
                                      SETTLES.get(check_id), finding, evidence or {},
                                      output.now_utc(), list(next_steps))

    def saw(self, response, step):
        """Keep a response's request ID for the envelope, and its Date for the clock check."""
        if response.request_id and response.request_id not in self.request_ids:
            self.request_ids.append(response.request_id)
        if response.date:
            self.dates.append((step, response.date, datetime.now(timezone.utc)))

    def failed(self, exc):
        """Keep an API error's request ID: support asks for it."""
        if exc.request_id and exc.request_id not in self.request_ids:
            self.request_ids.append(exc.request_id)

    def gated(self, step):
        """For a settle-gated step: (why it measures now, or None, and the stored answer)."""
        if self.stored_error is not None:
            return "the audit log failed its checks, so no stored answer is trusted", None
        entry = self.stored.get(GATED[step])
        return due(entry, self.now, settle=self.settle), entry

    def reuse(self, step, entry, *, extra="", status=None):
        """Report a stored answer with its original time and its age (§16.3)."""
        when = parse_time(entry["measured_at"]).strftime("%Y-%m-%dT%H:%MZ")
        days = age_days(entry, self.now)
        self.settled_view[GATED[step]] = {**entry, "step": step, "reused": True,
                                          "age_days": days}
        stored = entry.get("evidence")
        evidence = {**(stored if isinstance(stored, dict) else {}),
                    "settled_at": entry["measured_at"], "reused": True}
        kept = entry.get("status") if entry.get("status") in STATUSES else "INFO"
        self.add(step, status or kept, f"settled {when} ({days} days ago): {entry['answer']}{extra}",
                 evidence)

    def settled(self, step, status, answer, evidence, because, *, extra="", next_steps=()):
        """Record a settle-gated step's fresh answer, in this run's line and in the report."""
        entry = {"answer": answer, "evidence": evidence, "status": status,
                 "measured_at": output.now_utc()}
        self.settled_now[GATED[step]] = entry
        self.settled_view[GATED[step]] = {**entry, "step": step, "reused": False, "age_days": 0}
        self.add(step, status, answer + extra, {**evidence, "measured_because": because},
                 next_steps)

    def unsettled(self, step, because, why, next_steps=()):
        """A settle-gated step that got no answer: reported, and measured again next run."""
        self.add(step, "WARN", f"not settled: {why}; it is measured again next run",
                 {"measured_because": because}, next_steps)

    def known_self(self):
        """Whether S4 found exactly one device that is this host."""
        return self.me is not None and self.me.known

    # -- local checks (§16.1) --

    def python(self):
        """L1: the interpreter, held to the 3.10 floor the droplet's unknown Python needs."""
        version = ".".join(str(part) for part in sys.version_info[:3])
        evidence = {"version": version, "executable": sys.executable}
        if tuple(sys.version_info[:2]) >= PYTHON_FLOOR:
            self.add("L1", "PASS", f"{version} at {sys.executable}", evidence)
        else:
            self.add("L1", "FAIL", f"{version}, below the 3.10 floor", evidence)

    def posture_check(self):
        """L2: which posture this run is in. Test posture warns, so integration runs still pass."""
        p = self.posture
        if p.kind == "production":
            self.add("L2", "PASS", "production posture: the Tailscale API and MC's own files",
                     {"kind": p.kind, "api": p.api_base})
            return
        api_root = p.api_base.removesuffix(API_PATH)
        self.add("L2", "WARN", f"test posture: API {api_root}, home {p.config_dir.parent}; "
                               "nothing here touches the real tailnet",
                 {"kind": p.kind, "api": p.api_base, "home": str(p.config_dir.parent)})

    def local_tailscale(self):
        """L3: what the local tailscale says about this host, and whether its name resolves."""
        if not self.posture.runs_tailscale:
            self.local_reason = "not run: test posture"
            self.add("L3", "SKIP", "not run: test posture never runs tailscale; self comes from "
                                   "the protected file's self line", {"run": False})
            return
        problems = []

        def note(problem):
            """Keep a problem once: a missing binary fails every read alike."""
            if problem not in problems:
                problems.append(problem)

        def ask(read):
            """One local read; None, with the reason kept, when it gives no answer."""
            try:
                return read()
            except LocalError as exc:
                note(f"{exc.code}: {exc.message}")
            except localts.Failed as exc:
                note(exc.reason)
            return None

        evidence = {"binary": localts.binary(),
                    "version": ask(lambda: localts.version(self.posture, LOCAL_TIMEOUT))}
        text = ask(lambda: localts.status_json(self.posture, selfnode.STATUS_TIMEOUT))
        if text is not None:
            self.local = local = selfnode.parse_status(text)
            evidence.update(backend_state=local.backend_state, online=local.online,
                            ips=list(local.ips), id=local.id, tags=list(local.tags),
                            dns_name=local.dns_name)
            if local.reason:
                note(local.reason)
        accept = ask(lambda: localts.get_pref(self.posture, "accept-dns", LOCAL_TIMEOUT))
        evidence["accept_dns"] = accept
        if self.local is not None and self.local.dns_name:
            resolves, addresses, error = dns.lookup(self.local.dns_name)
            evidence.update(resolves=resolves, addresses=addresses)
            if not resolves:
                note(f"its MagicDNS name {self.local.dns_name} did not resolve ({error}) "
                     "[critic F3.6]")
        usable = self.local is not None and self.local.usable
        self.local_reason = None if usable else "; ".join(problems) or "no local status"
        facts = [f"binary {evidence['binary'] or 'missing'}",
                 f"version {evidence['version'] or 'unknown'}"]
        if self.local is not None:
            facts += [f"BackendState {self.local.backend_state}",
                      f"online {self.local.online}", f"IPs {', '.join(self.local.ips) or '-'}",
                      f"tags {', '.join(self.local.tags) or '-'}"]
        facts.append(f"accept-dns {accept or 'unknown'}")
        finding = "; ".join(facts)
        if problems:
            finding += "; " + "; ".join(problems)
        if not usable:
            finding += "; writes will be refused: self unknown"
        self.add("L3", "WARN" if problems else "PASS", finding, evidence)

    def _environment(self):
        """Name, never show, each environment variable whose value looks like a Tailscale key.

        The CLI never reads a secret from the environment (§8.2 item 10), but every program
        started from that shell can, so MC is told which variable holds it.
        """
        names = sorted(name for name, value in self.environ.items() if "tskey-" in value)
        for name in names:
            self.warnings.append(output.warn(
                "SECRET_IN_ENVIRONMENT",
                f"the environment variable {name} holds a value that starts like a Tailscale "
                "key; the CLI never reads one from there, but every program started from this "
                "shell can; MC removes it, and revokes the key if it is real", "§8.2"))
        return names

    def _leftover_problem(self):
        """Look for write-secret copies an interrupted `credentials set` left; word any found.

        A set killed between writing its temp file and renaming it (§8.5) leaves the secret
        under a name nothing reads, so it is found by name alone and never opened (D20).
        """
        try:
            self.write_leftovers = secure_files.temp_leftovers(
                self.posture.config_dir / "write.secret")
        except OSError as exc:
            self.write_leftovers = None
            return (f"could not list {self.posture.config_dir} for leftover write-secret "
                    f"copies: {exc.strerror}")
        if not self.write_leftovers:
            return None
        names = ", ".join(path.name for path in self.write_leftovers)
        return (f"a copy of a write secret that an interrupted `credentials set write` left is "
                f"on disk ({names}); `tailnet credentials forget write` or the next "
                "`tailnet credentials set write` removes it")

    def credentials_check(self):
        """L4: the read client loads under §8.2; the mode; write.json as metadata only (D20)."""
        stray = self._environment()
        leftover = self._leftover_problem()
        try:
            self.cred = credentials.load_read(self.posture)
        except LocalError as exc:
            self.cred_error = exc
            finding = f"{exc.code}: {exc.message}; the API steps are skipped"
            self.add("L4", "FAIL", finding + (f"; {leftover}" if leftover else ""),
                     {"read": exc.code, "environment": stray}, exc.next)
            return
        problems, steps = [], []
        if leftover:
            problems.append(leftover)
        try:
            self.write_meta = credentials.load_write_meta(self.posture)
        except LocalError as exc:
            problems.append(f"write.json: {exc.code}: {exc.message}")
            steps.extend(exc.next)
        try:
            self.mode = credentials.mode(self.posture)
        except LocalError:
            self.mode = "unknown"
        parts = [f"read client {self.cred.client_id} (granted {self.cred.granted_scope or '?'})",
                 f"mode {self.mode}"]
        if self.write_meta is not None:
            self.write_secret = _exists(self.write_meta.secret_path)
            secret = {True: "present", False: "absent", None: "unknown"}[self.write_secret]
            tags = ",".join(self.write_meta.tags or ()) or "unrecorded"
            parts.append(f"write client {self.write_meta.client_id} (tags {tags}), write.secret "
                         f"{secret} (stat only)")
            if self.write_secret is not True:
                problems.append("write.json names a write.secret that is not there: writes are "
                                "refused until MC re-runs `tailnet credentials set write`")
        elif not problems:
            parts.append("no write client")
        if self.mode == "single-client":
            problems.append("single-client: one client holds read and write power, so the "
                            "separate write secret (L2) is absent")
        if stray:
            problems.append(f"a key-shaped value in the environment: {', '.join(stray)}")
        finding = "; ".join(parts + problems)
        self.add("L4", "WARN" if problems else "PASS", finding,
                 {"read_client": self.cred.client_id, "mode": self.mode,
                  "write_client": self.write_meta.client_id if self.write_meta else None,
                  "write_secret_present": self.write_secret, "environment": stray}, steps)

    def token_cache(self):
        """L5: the read-token cache is absent, or private with an expiry and a read-only scope."""
        path = self.posture.config_dir / tokens.CACHE_NAME
        try:
            raw = secure_files.read_private(path, tokens.CACHE_MAX)
        except FileNotFoundError:
            self.add("L5", "PASS", "absent: the next read mints a token and caches it if its "
                                   "scope is read-only", {"present": False})
            return
        except LocalError as exc:
            self.add("L5", "WARN", f"{exc.message}; the next read removes it unread",
                     {"present": True, "error": exc.code}, exc.next)
            return
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            self.add("L5", "WARN", "it is not a JSON object; the next read replaces it",
                     {"present": True})
            return
        token = doc.get("access_token")
        if isinstance(token, str) and len(token) >= 8:
            REDACTOR.add_secret(token)
        expires, scope = tokens.cache_expiry(doc), doc.get("scope")
        evidence = {"present": True, "client_id": doc.get("client_id"), "scope": scope,
                    "expires_at": doc.get("expires_at")}
        if expires is None or not tokens.cacheable(scope):
            why = "no readable expires_at" if expires is None else f"a scope that can write ({scope})"
            self.add("L5", "WARN", f"it has {why}; the next read replaces it", evidence)
            return
        left = (expires - self.now) // timedelta(minutes=1)
        usable = self.cred is not None and tokens.cache_usable(doc, self.cred.client_id, self.now)
        finding = (f"0600, for {doc.get('client_id')}, scope {scope}, expires "
                   f"{doc.get('expires_at')} ({left} min left)")
        if self.cred is None:
            finding += "; no read client loaded to judge it against"
        elif not usable:
            finding += "; not usable now (near expiry, or another client's), so the next read mints"
        self.add("L5", "PASS", finding, {**evidence, "usable": usable, "minutes_left": left})

    def protected_load(self):
        """L6, first half: read MC's list before the inventory, which self detection needs."""
        try:
            self.listed = protected.load(self.posture)
            self.protected_state = "unanswered" if self.listed is None else "answered"
        except LocalError as exc:
            self.protected_state, self.protected_error = "unreadable", exc

    def protected_check(self):
        """L6, second half: judge the list against the live inventory, or propose one."""
        state = self.protected_state
        if state == "unreadable":
            exc = self.protected_error
            self.add("L6", "WARN", f"{exc.code}: {exc.message}; tag writes are refused until it "
                                   "parses", {"state": state}, exc.next)
            return
        if state == "unanswered":
            finding = ("missing: tag writes are refused until MC writes it (disable-key-expiry "
                       "is still allowed)")
            steps = []
            if self.known_self() and self.inventory:
                path = self.posture.config_dir / protected.FILE_NAME
                self.proposal = protected_proposal(self.inventory, self.me.device, path, self.now)
                finding += (f"; doctor's block proposes protecting all {len(self.inventory)} "
                            "devices")
                steps.append({"who": "mc", "needs": "terminal", "do": self.proposal,
                              "why": "it writes the protected list, every device protected; "
                                     "delete the lines of devices the CLI may retag first. "
                                     "The agent cannot run it: a deny rule covers the directory"})
            elif self.me is not None and not self.me.known:
                finding += f"; no proposal yet: self is unknown ({self.me.reason})"
            else:
                finding += "; no proposal yet: the device list was not read"
            self.add("L6", "WARN", finding, {"state": state, "proposed": self.proposal is not None},
                     steps)
            return
        listed = self.listed
        evidence = {"state": state, "self_node_id": listed.self_node_id,
                    "entries": len(listed.entries)}
        problems = []
        if listed.self_only:
            problems.append("nothing but self is protected: tag writes are open on every other "
                            "device")
        if self.inventory is not None:
            # Lines, never their text: the file sits behind a deny rule (amendment A19).
            unmatched = [entry.line for entry in listed.entries
                         if not any(entry.matches(device) for device in self.inventory)]
            evidence["unmatched_lines"] = unmatched
            if unmatched:
                lines = ", ".join(str(n) for n in unmatched)
                problems.append(f"line{'s' if len(unmatched) > 1 else ''} {lines} match no device")
            if self.me is not None and self.me.refusal == "SELF_LINE_DISAGREES":
                problems.append(self.me.reason)
            elif not any(d.node_id == listed.self_node_id for d in self.inventory):
                problems.append(f"its self line names {listed.self_node_id}, which is no device")
        count = len(listed.entries)
        finding = f"answered: self {listed.self_node_id}, {count} entr{'y' if count == 1 else 'ies'}"
        self.add("L6", "WARN" if problems else "PASS",
                 "; ".join([finding, *problems]), evidence)

    def audit_log(self):
        """L7: the audit log opens for append, writing nothing, and reads back safely."""
        path = audit.log_path(self.posture)
        try:
            audit.check_writable(self.posture)
        except LocalError as exc:
            self.add("L7", "FAIL", f"{exc.message}; writes will not be sent, and no settled "
                                   "answer is trusted", {"path": str(path)}, exc.next)
            return
        if self.stored_error is not None:
            exc = self.stored_error
            self.add("L7", "FAIL", f"{exc.message}; it cannot be read back safely, so no settled "
                                   "answer is trusted", {"path": str(path)}, exc.next)
            return
        self.add("L7", "PASS", f"{path} opens for append (nothing written)", {"path": str(path)})

    def integration(self):
        """L8: MC's settings hold every rule; in production, the install is whole (D21)."""
        settings = self.posture.claude_settings
        claude = gate.claude_dir(self.posture, self.environ)
        missing = gate.missing_rules(settings, claude)
        gate_ok = gate.gate_present(settings)
        total = sum(len(rules) for rules in gate.rules_for(claude).values())
        rules = (f"{total - len(missing)}/{total} rules present in {settings}"
                 + (f" (MISSING: {', '.join(missing)})" if missing else ""))
        parts = {"rules": _part(not missing, rules)}
        if self.posture.kind == "test":
            for name in _INSTALL_PARTS:
                parts[name] = {**_part(None, "not run: test posture (the install lives outside "
                                             "the test home)"), "skipped": True}
        else:
            parts.update(self._installation())
        problems = [f"{name}: {part['detail']}" for name, part in parts.items()
                    if name != "rules" and part["ok"] is not True and not part.get("skipped")]
        if not gate_ok:
            status = "FAIL"
            rules = "the gate rule Bash(*tailnet*--apply*) is missing: every --apply is refused; " + rules
        else:
            status = "WARN" if missing or problems else "PASS"
        finding = "; ".join([rules, *problems])
        steps = [dict(_INSTALLER)] if missing or problems else []
        self.add("L8", status, finding, {"gate_present": gate_ok, "missing": missing,
                                         "parts": parts}, steps)

    def _installation(self):
        """L8's production parts: the skill and upstream markers, the clone, the MCP server, PATH.

        Paths come from the posture, which owns them: the Claude directory holds the settings
        it checks, and the installer's share directory sits beside the config one (§20.2).
        """
        claude_dir = self.posture.claude_settings.parent
        share = self.posture.config_dir.parent.parent / ".local" / "share" / "tailnet"
        parts = install_markers(claude_dir, share)
        clone = share / "upstream" / "tailscale-skill"
        try:
            code, out = run_program(self.posture, ["git", "-C", str(clone), "rev-parse", "HEAD"],
                                    PROGRAM_TIMEOUT)
            head = out.strip() if code == 0 else ""
            parts["upstream_clone"] = _part(code == 0 and head == UPSTREAM_PIN,
                                            f"{clone} HEAD {head}" if head
                                            else f"{clone} HEAD unreadable (git exited {code})")
        except ProgramFailed as exc:
            parts["upstream_clone"] = _part(None, exc.reason)
        try:
            code, out = run_program(self.posture, ["claude", "mcp", "get", DOCS_MCP],
                                    PROGRAM_TIMEOUT)
            parts["docs_mcp"] = _part(code == 0 and DOCS_MCP_URL in out,
                                      f"{DOCS_MCP} {'registered' if code == 0 else 'not registered'}"
                                      + ("" if code != 0 or DOCS_MCP_URL in out
                                         else f", but not at {DOCS_MCP_URL}"))
        except ProgramFailed as exc:
            parts["docs_mcp"] = _part(None, exc.reason)
        try:
            code, out = run_program(self.posture, ["bash", "-lc", "command -v tailnet"],
                                    PROGRAM_TIMEOUT)
            found = out.strip()
            parts["launcher"] = _part(code == 0 and bool(found),
                                      f"login PATH finds {found}" if found
                                      else "`tailnet` is not on the login PATH")
        except ProgramFailed as exc:
            parts["launcher"] = _part(None, exc.reason)
        return parts

    def levers(self):
        """L9: what holds and what does not, stated on every run (§2)."""
        if self.mode == "single-client":
            standing = ("single-client: one client holds read and write power, so there is no "
                        "separate write secret (L2 absent)")
        elif self.write_meta is not None and self.write_secret:
            standing = ("standing posture: write.secret is on disk; `tailnet credentials forget "
                        "write` after a write session makes it session-scoped (L2)")
        elif self.write_leftovers is None or self.write_leftovers:
            # A copy left under a temp name is a write secret on disk all the same.
            standing = ("a write secret may be on disk in a temp copy an interrupted `credentials "
                        "set write` left (L4), so L2 does not hold until it is removed")
        else:
            standing = ("no write secret on disk: nothing on this host can write to the tailnet "
                        "(L2 holds)")
        notes = [
            ("ask rules prompt in every interactive mode, bypassPermissions and auto included; "
             "headless `claude -p` runs deny writes instead [PM L34-36, L56, L327]"),
            ("an installed mod that handles tool.check can approve --apply without prompting you "
             "when there are no managed settings and no Team or Enterprise login [PERM L641-643]"),
            standing,
        ]
        self.add("L9", "INFO", standing, {"notes": notes})

    def clock(self):
        """L10: the API's Date against this host's clock; skew misleads every expiry sum."""
        if not self.dates:
            self.add("L10", "SKIP", "no API response with a Date header to compare against", {})
            return
        step, text, local = self.dates[0]
        try:
            remote = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            self.add("L10", "SKIP", f"the Date header from {step} is unreadable", {"date": text})
            return
        if remote.tzinfo is None:
            remote = remote.replace(tzinfo=timezone.utc)
        skew = (local - remote).total_seconds()
        side = "ahead of" if skew > 0 else "behind"
        finding = f"this host's clock is {abs(skew):.0f} s {side} the API's (Date from {step})"
        status = "PASS" if abs(skew) <= CLOCK_SKEW.total_seconds() else "WARN"
        self.add("L10", status, finding, {"skew_seconds": round(skew, 1), "date": text})

    def drift(self):
        """L11: the live OpenAPI document and upstream's HEAD against the pins (D19); INFO only."""
        if self.posture.kind == "test":
            self.add("L11", "SKIP", "not run: test posture (the network extras: spec drift and "
                                    "upstream's HEAD)", {})
            return
        parts = {}
        session = self.session or api.session(self.posture)
        try:
            reply = api.get_openapi(session)
            self.saw(reply.response, "L11")
            digest = hashlib.sha256(reply.data).hexdigest()
            parts["spec"] = _part(digest == PINNED_SPEC_SHA256, f"live spec sha256 {digest}")
        except ApiError as exc:
            self.failed(exc)
            parts["spec"] = _part(None, f"{exc.code}: {exc.message}")
        try:
            code, out = run_program(self.posture, ["git", "ls-remote", UPSTREAM_URL, "HEAD"],
                                    REMOTE_TIMEOUT)
            words = out.split()
            head = words[0] if code == 0 and words else None
            parts["upstream"] = _part(head == UPSTREAM_PIN, f"upstream HEAD {head or 'unreadable'}")
        except ProgramFailed as exc:
            parts["upstream"] = _part(None, exc.reason)
        if all(part["ok"] for part in parts.values()):
            self.add("L11", "PASS", "the live spec and upstream's HEAD match the pins", parts)
            return
        drifted = [name for name, part in parts.items() if part["ok"] is False]
        unknown = [f"{name}: {part['detail']}" for name, part in parts.items() if part["ok"] is None]
        finding = []
        if drifted:
            finding.append(f"drifted ({', '.join(drifted)}): re-check fixtures / upstream "
                           "corrections")
        if unknown:
            finding.append("not checked: " + "; ".join(unknown))
        self.add("L11", "INFO", "; ".join(finding), parts)

    # -- API steps (§16.2), with the read client only --

    def skip_api(self, why):
        """Mark every API step not yet run as skipped, with the one reason."""
        for step in ORDER:
            if step.startswith("S") and step not in self.checks:
                self.add(step, "SKIP", why, {})

    def read_token(self):
        """S1: the cached read token, else one mint; records the grant exactly as given."""
        self.session = api.session(self.posture)
        source = self.session.read_token
        try:
            source.bearer()
        except TailnetError as exc:
            self.failed(exc)
            self.add("S1", "FAIL", f"{exc.code}: {exc.message}",
                     {"http_status": exc.http_status}, exc.next)
            return False
        token = self.token = source.token
        self.token_from_cache = source.from_cache
        if token.request_id and token.request_id not in self.request_ids:
            self.request_ids.append(token.request_id)
        left = int((token.expires_at - datetime.now(timezone.utc)).total_seconds())
        how = ("reused the cached read token: no audit event" if source.from_cache
               else "minted a read token: one 'Create OAuth access token' event")
        finding = (f"{how}; granted {token.scope or 'no scope field'}; expires "
                   f"{format_utc(token.expires_at)} ({left} s left)")
        if not token.cacheable:
            finding += "; the grant can write, so it is never cached"
        self.add("S1", "PASS" if token.cacheable else "WARN", finding,
                 {"scope": token.scope, "cacheable": token.cacheable, "reused": source.from_cache,
                  "expires_at": format_utc(token.expires_at), "seconds_left": left})
        return True

    def narrowing(self):
        """S2, single-client only: may a write-capable client mint a read-only token (Q1)?"""
        if self.mode != "single-client":
            self.add("S2", "INFO", f"moot: the read client holds only read scopes ({self.mode} "
                                   "mode), so no narrowed mint is needed", {"mode": self.mode})
            return
        because, entry = self.gated("S2")
        if because is None:
            self.reuse("S2", entry)
            return
        requested = " ".join(READ_SCOPES)
        if not self.token_from_cache:
            # In single-client mode S1's own mint already asked for exactly these scopes.
            token, how = self.token, "S1's mint asked for exactly the four read scopes"
        else:
            try:
                token = tokens.mint(self.posture, self.session.transport, self.cred,
                                    scope=requested)
            except TailnetError as exc:
                self.failed(exc)
                self.unsettled("S2", because, f"{exc.code}: {exc.message}", exc.next)
                return
            self.extra_mints += 1
            how = "one mint asked for exactly the four read scopes"
        narrowed = token.cacheable
        granted = token.scope or "no scope field"
        if narrowed:
            answer = f"narrowing works: {how} and was granted {granted}"
        else:
            answer = (f"narrowing does not work: {how} and was granted {granted}, which can "
                      "write, so read tokens are never cached")
        self.settled("S2", "PASS" if narrowed else "WARN", answer,
                     {"requested": requested, "granted": token.scope, "cacheable": narrowed},
                     because)

    def key_lookup(self):
        """S3: does the self-lookup take the client ID as its key ID (Q3)?"""
        because, entry = self.gated("S3")
        if because is None:
            self.reuse("S3", entry)
            return
        try:
            reply = api.get_key(self.session, self.cred.client_id)
        except ApiError as exc:
            self.failed(exc)
            if exc.http_status in (403, 404):
                if exc.http_status == 403:
                    self.refused.append(("S3", False))
                self.settled("S3", "INFO", "the read client's ID is not accepted as a key ID "
                                           f"(HTTP {exc.http_status}); `credentials set write` "
                                           "falls back to typed tags",
                             {"status": exc.http_status}, because)
                return
            self.unsettled("S3", because, f"{exc.code}: {exc.message}")
            return
        except LocalError as exc:
            self.unsettled("S3", because, exc.message)
            return
        self.saw(reply.response, "S3")
        key = reply.data
        facts = {name: key.get(name) for name in ("keyType", "scopes", "tags", "invalid")}
        answer = ("the read client's ID works as a key ID: keyType "
                  f"{facts['keyType']}, scopes {_listed(facts['scopes'])}, tags "
                  f"{_listed(facts['tags'])}, invalid {facts['invalid']}")
        self.settled("S3", "WARN" if facts["invalid"] is True else "PASS", answer,
                     {"status": 200, **facts}, because)

    def _self_from(self, found):
        """Self as §11.3 finds it: the live join in production, the self line in test posture."""
        if not self.posture.runs_tailscale:
            return selfnode.from_line(found, self.listed)
        if self.local is None:
            return selfnode.SelfNode(False, None, None, None,
                                     f"the local status gave no answer ({self.local_reason})",
                                     "SELF_UNKNOWN")
        return selfnode.decide(self.local, found, self.listed)

    def inventory_step(self):
        """S4: every device, self among them, and what the fleet's keys and fields say."""
        try:
            found, response = devices.fetch(self.session)
        except TailnetError as exc:
            self.failed(exc)
            self.add("S4", "FAIL", f"{exc.code}: {exc.message}", {}, exc.next)
            return
        self.saw(response, "S4")
        self.inventory = found
        me = self.me = self._self_from(found)
        self.fleet = [d for d in found if d.tags and d.key_expiry_disabled is False]
        expired = [d for d in found if d.key_expiry(self.now)["expired"] is True]
        doubled = [d for d in found if d.multiple_connections]
        fields = {name: sum(1 for d in found if name in d.raw)
                  for name in ("enabledRoutes", "advertisedRoutes", "sshEnabled")}
        tags = list(me.device.tags) if me.known else None
        parts = [f"{len(found)} of {len(found)} devices (the API does not paginate)"]
        if me.known:
            how = {"live": "its Tailscale addresses", "line": "the self line"}[me.source]
            parts.append(f"self {me.device.label()} by {how}, tags {', '.join(tags) or 'none'}")
        else:
            parts.append(f"self unknown: {me.reason}")
        if self.fleet:
            dated = [parse_time(d.expires) for d in self.fleet]
            dated = [when for when in dated if when is not None]
            earliest = f" (earliest {format_utc(min(dated))})" if dated else ""
            parts.append(f"{len(self.fleet)} tagged with key expiry on{earliest}: "
                         + ", ".join(d.hostname or d.node_id for d in self.fleet))
        if expired:
            parts.append("expired keys: " + ", ".join(d.label() for d in expired))
        if doubled:
            parts.append("node key in use twice: " + ", ".join(d.label() for d in doubled))
        parts.append("fields present: " + ", ".join(f"{name} on {count}"
                                                    for name, count in fields.items()))
        warn = not me.known or self.fleet or expired or doubled
        self.add("S4", "WARN" if warn else "PASS", "; ".join(parts), {
            "count": len(found), "self": me.to_dict(), "self_tags": tags,
            "self_is_tag_dev": None if tags is None else "tag:dev" in tags,
            "tagged_expiry_on": [{"nodeId": d.node_id, "hostname": d.hostname,
                                  "expires": d.expires} for d in self.fleet],
            "expired": [d.node_id for d in expired],
            "multiple_connections": [d.node_id for d in doubled], "fields_present": fields})

    def routes(self):
        """S5: one deliberate out-of-scope read, so a refusal's status is known (Q4)."""
        if not self.known_self():
            self.add("S5", "SKIP", "self is unknown, so there is no device of its own to ask about",
                     {})
            return
        because, entry = self.gated("S5")
        if because is None:
            self.reuse("S5", entry)
            return
        try:
            reply = api.get_routes(self.session, self.me.device.node_id)
        except ApiError as exc:
            self.failed(exc)
            status = exc.http_status
            if status is not None and 400 <= status < 500 and status != 429:
                self.refused.append(("S5", True))
                self.settled("S5", "INFO", f"a call outside the read scopes is refused with HTTP "
                                           f"{status}; {_FAILED_REQUEST}", {"status": status},
                             because)
                return
            self.unsettled("S5", because, f"{exc.code}: {exc.message}")
            return
        self.saw(reply.response, "S5")
        self.settled("S5", "WARN", "the routes read was allowed (HTTP 200): the read client holds "
                                   "more than the four read scopes", {"status": 200}, because)

    def live_policy(self):
        """S6: the live policy as HuJSON then JSON: raw ETags, sizes, sections, tagOwners."""
        try:
            hujson = api.get_policy(self.session, api.HUJSON)
            self.saw(hujson.response, "S6")
            as_json = api.get_policy(self.session, api.JSON)
            self.saw(as_json.response, "S6")
            doc = as_json.response.json()
        except ApiError as exc:
            self.failed(exc)
            self.add("S6", "FAIL", f"{exc.code}: {exc.message}", {}, exc.next)
            return
        if not isinstance(doc, dict):
            self.add("S6", "FAIL", "the policy's JSON form is not an object", {})
            return
        self.policy_json = doc
        etags = {"hujson": hujson.response.etag_raw, "json": as_json.response.etag_raw}
        quoted = all(e is not None and len(e) >= 2 and e[0] == e[-1] == '"' for e in etags.values())
        equal = etags["hujson"] == etags["json"]
        owners = doc.get("tagOwners")
        keys = {key.lower() for key in owners} if isinstance(owners, dict) else set()
        own = list(self.me.device.tags) if self.known_self() else []
        missing = [tag for tag in dict.fromkeys([*own, "tag:fleet"]) if tag.lower() not in keys]
        counted = policy.sections(doc)
        shown = ", ".join(f"{name} {counted[name]}" for name in ("acls", "grants", "ssh", "tests",
                                                                 "sshTests"))
        finding = (f"read as HuJSON ({len(hujson.data)} bytes) and JSON ({len(as_json.data)} "
                   f"bytes); ETag {policy.display_etag(etags['hujson'])} "
                   f"({'quoted' if quoted else 'not quoted'}, "
                   f"{'the same in both' if equal else 'different in each'}); {shown}; tagOwners "
                   + (f"lacks {', '.join(missing)}" if missing
                      else f"names {', '.join(dict.fromkeys([*own, 'tag:fleet']))}"))
        self.add("S6", "WARN" if missing else "PASS", finding,
                 {"etag_raw": etags, "etag_quoted": quoted, "etags_equal": equal,
                  "bytes": {"hujson": len(hujson.data), "json": len(as_json.data)},
                  "sections": counted, "tag_owners_missing": missing})

    def fleet_test(self):
        """S7a: may this host's identities reach every other tagged device on tcp:22?"""
        if not self.known_self():
            self.add("S7a", "SKIP", "self is unknown, so no identity can be tested", {})
            return
        me = self.me.device
        ids = diagnose.identities(me)
        targets = [d for d in self.inventory if d.tags and d.node_id != me.node_id and d.ipv4]
        if not ids:
            self.add("S7a", "SKIP", "self has no tag or user login a test can run as", {})
            return
        if not targets:
            self.add("S7a", "SKIP", "no other tagged device has an IPv4 address to test", {})
            return
        by_address = {f"{d.ipv4}:22": d for d in targets}
        results, unanswered = [], []
        for src in ids:
            tests = [{"src": src, "proto": "tcp", "accept": list(by_address)}]
            try:
                response = api.validate_tests(self.session, tests)
                found = policy.parse_verdict(response.status, response.body)
            except ApiError as exc:
                self.failed(exc)
                unanswered.append(f"{src}: {exc.code}")
                continue
            self.saw(response, "S7a")
            named = [f for f in found.failures if f.get("want") == "Accept"
                     and f.get("got") == "Drop" and f.get("target") in by_address]
            results.append({"src": src, **found.to_dict()})
            if found.passed:
                continue
            if found.reason == "errors" and named:
                for failure in named:
                    device = by_address[failure["target"]]
                    self.drops.append((src, failure["target"], device.hostname or device.node_id))
            else:
                unanswered.append(f"{src}: {found.reason}")
        evidence = {"identities": list(ids), "targets": list(by_address), "results": results}
        if self.drops:
            dropped = list(dict.fromkeys(by_address[target].node_id for _, target, _ in self.drops))
            names = ", ".join(f"{src} → {name} ({target})" for src, target, name in self.drops)
            step = {"who": "agent", "run": f"tailnet diagnose {' '.join(dropped)} --port 22",
                    "why": "says why each dropped host is unreachable, and what would fix it"}
            self.add("S7a", "WARN", f"the policy drops {names}", evidence, [step])
        elif unanswered:
            self.add("S7a", "WARN", f"no answer for {'; '.join(unanswered)}", evidence)
        else:
            self.add("S7a", "PASS", f"{', '.join(ids)} may reach all {len(targets)} other tagged "
                                    "devices on tcp:22", evidence)

    def member_test(self):
        """S7b, only when self is tagged: does autogroup:member cover a tagged source (Q20)?"""
        if not self.known_self() or not self.me.device.tags:
            why = "self is unknown" if not self.known_self() else "self is user-owned"
            self.add("S7b", "SKIP", f"runs only when self is tagged: {why}", {})
            return
        if self.policy_json is None:
            self.add("S7b", "SKIP", "the live policy was not read (S6)", {})
            return
        me = self.me.device
        others = [d for d in self.inventory if d.tags and d.node_id != me.node_id and d.ipv4]
        if not others:
            self.add("S7b", "SKIP", "no other tagged device has an IPv4 address to aim at", {})
            return
        because, entry = self.gated("S7b")
        if because is None:
            self.reuse("S7b", entry)
            return
        source, target = me.tags[0], others[0]
        try:
            candidate = member_candidate(self.policy_json, target.ipv4, source)
        except (TypeError, ValueError) as exc:
            self.unsettled("S7b", because, str(exc))
            return
        try:
            response = api.validate_policy(self.session, json.dumps(candidate).encode("utf-8"),
                                           api.JSON)
            found = policy.parse_verdict(response.status, response.body)
        except ApiError as exc:
            self.failed(exc)
            self.unsettled("S7b", because, f"{exc.code}: {exc.message}")
            return
        self.saw(response, "S7b")
        evidence = {"source": source, "probe": f"{target.ipv4}:22", "verdict": found.verdict}
        if found.passed:
            answer = (f"yes: a grant from autogroup:member admits the tagged source {source} "
                      f"(probe to {target.label()})")
        elif found.reason == "errors" and any(f.get("want") == "Accept" and f.get("got") == "Drop"
                                              for f in found.failures):
            answer = (f"no: a grant from autogroup:member does not admit the tagged source "
                      f"{source}; tagged sources need a rule of their own")
        else:
            self.unsettled("S7b", because, f"the probe gave no verdict ({found.reason})")
            return
        self.settled("S7b", "INFO", answer, evidence, because)

    def dns_step(self):
        """S8: /dns/configuration (settle-gated) beside /dns/nameservers, which runs every time.

        The pair separates "dns:read does not cover that endpoint" from "the scope is
        missing" (critic Q23).
        """
        because, entry = self.gated("S8")
        config_status = config_error = None
        if because is not None:
            try:
                reply = api.dns_configuration(self.session)
                self.saw(reply.response, "S8")
                config_status = reply.response.status
            except ApiError as exc:
                self.failed(exc)
                config_status, config_error = exc.http_status, exc
        try:
            names = api.dns_nameservers(self.session)
            self.saw(names.response, "S8")
            names_error = None
            names_line = f"; /dns/nameservers answers (HTTP {names.response.status})"
        except ApiError as exc:
            self.failed(exc)
            names_error = exc
            names_line = (f"; /dns/nameservers refused: {exc.code}: {exc.message}; dns:read looks "
                          "missing, so `tailnet dns` fails")
        if because is None:
            self.reuse("S8", entry, extra=names_line, status="FAIL" if names_error else None)
            return
        status = "FAIL" if names_error else None
        if config_error is None:
            answer = f"dns:read covers /dns/configuration (HTTP {config_status})"
            self.settled("S8", status or "PASS", answer, {"configuration": config_status},
                         because, extra=names_line)
        elif (config_status is not None and 400 <= config_status < 500 and config_status != 429
              and names_error is None):
            if config_status == 403:
                self.refused.append(("S8", False))
            answer = (f"/dns/configuration is refused (HTTP {config_status}) while "
                      "/dns/nameservers answers: dns:read does not cover that endpoint, and the "
                      "scope itself is present")
            self.settled("S8", "INFO", answer, {"configuration": config_status}, because,
                         extra=names_line)
        else:
            self.add("S8", status or "WARN",
                     f"not settled: /dns/configuration: {config_error.code}: "
                     f"{config_error.message}{names_line}; it is measured again next run",
                     {"measured_because": because})

    # -- the report --

    def mints(self):
        """Tokens issued in this run: each one console event (§16.4)."""
        return (self.session.read_token.mints if self.session else 0) + self.extra_mints

    def question_state(self):
        """What the questions are decided from (§16.4)."""
        return QuestionState(
            granted_scope=self.token.scope if self.token else None,
            scope_known=self.token is not None,
            protected_missing=self.protected_state == "unanswered",
            fleet_expiry=tuple((d.hostname or d.node_id, d.expires) for d in self.fleet),
            drops=tuple(self.drops), write_client=self.write_meta is not None)


def _line(check):
    """One check in the human view: status, id, value, its time, what it settles."""
    settles = f" · settles {check.settles}" if check.settles else ""
    return (f"{check.status:<4} {check.id:<3} {check.title}: {check.finding} "
            f"(as of {check.measured_at}){settles}")


def _ask(question):
    """A question as a next step (§5.4's ask_mc shape), for the agent to ask one per turn."""
    shown = question.to_dict()
    return {"who": "ask_mc", "question": {key: shown[key]
                                          for key in ("id", "text", "options", "safe_default")}}


def run(posture, args):
    """`tailnet doctor`: every local check, the read-only API steps, and the questions (§16).

    It never writes to the tailnet and never opens write.secret. Exit 0 when nothing
    FAILs, 8 on a FAIL, 3 when the read credential is missing or unsafe; a doctor.run
    line holding the questions in priority order is appended either way (A24).
    """
    now = datetime.now(timezone.utc)
    work = _Run(posture, args, os.environ, now)
    work.python()
    work.posture_check()
    work.local_tailscale()
    work.credentials_check()
    work.token_cache()
    work.protected_load()
    work.audit_log()
    work.integration()
    work.levers()
    if work.cred is None:
        work.skip_api("skipped: the read credential did not load (L4)")
    elif not work.read_token():
        work.skip_api("skipped: there is no read token (S1 failed)")
    else:
        for step in (work.narrowing, work.key_lookup, work.inventory_step, work.routes,
                     work.live_policy, work.fleet_test, work.member_test, work.dns_step):
            step()
    work.protected_check()
    work.clock()
    work.drift()
    checks = [work.checks[check_id] for check_id in ORDER]
    tally = counts(checks)
    asked = questions(work.question_state())
    events = audit_events_caused(work.mints(), work.refused)
    try:
        audit.append(posture, {"event": "doctor.run", "counts": tally,
                               "settled": work.settled_now, "mints_this_run": work.mints(),
                               "audit_events_caused": events,
                               "questions": [question.id for question in asked]})
        written = {"written": True, "error": None}
    except LocalError as exc:
        written = {"written": False, "error": f"{exc.code}: {exc.message}"}
        work.warnings.append(output.warn(exc.code, f"{exc.message}; this doctor run is not in the "
                                                   "audit log, so status cannot show its "
                                                   "questions"))
    steps = []
    for check in checks:
        steps += [step for step in check.next if step not in steps]
    steps += [_ask(question) for question in asked]
    data = {"checks": [check.to_dict() for check in checks], "counts": tally,
            "mode": work.mode, "self": work.me.to_dict() if work.me else None,
            "settle": work.settle, "settled": work.settled_view,
            "mints_this_run": work.mints(), "audit_events_caused": events,
            "questions": [question.to_dict() for question in asked],
            "protected_proposal": work.proposal, "audit_line": written}
    summary = (f"{tally['pass']} PASS, {tally['warn']} WARN, {tally['fail']} FAIL, "
               f"{tally['info']} INFO, {tally['skip']} SKIP")
    lines = []
    for check in checks:
        lines.append(_line(check))
        if check.id == "L9":
            # The last note is the finding itself; the others follow it.
            lines += [f"         {note}" for note in check.evidence["notes"][:-1]]
    lines.append(f"mints this run: {work.mints()} · audit events caused: "
                 f"{', '.join(events) or 'none'}")
    fields = {"data": data, "warnings": work.warnings, "request_ids": work.request_ids,
              "measured_at": format_utc(now), "lines": lines}
    if work.cred_error is not None:
        exc = LocalError(work.cred_error.code, work.cred_error.message, next=steps)
        return Envelope.from_error("doctor", posture.kind, exc,
                                   headline=f"LOCAL: {exc.code}: doctor: {summary}", **fields)
    failing = [check for check in checks if check.status == "FAIL"]
    if failing:
        named = "; ".join(f"{check.id} {check.title}" for check in failing)
        exc = Negative("DOCTOR_FAIL", f"{len(failing)} check{'s' if len(failing) > 1 else ''} "
                                      f"FAIL: {named}", next=steps)
        return Envelope.from_error("doctor", posture.kind, exc,
                                   headline=f"FAIL: doctor: {summary}", **fields)
    return Envelope("doctor", posture.kind, next=steps, headline=f"OK: doctor: {summary}",
                    **fields)
