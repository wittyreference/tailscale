# ABOUTME: `tailnet doctor` (DESIGN.md §16): local checks and the read-only API steps that settle the open
# ABOUTME: questions, the settled answers kept in its own audit lines, MC's questions, and the accounting.

import re
import shlex
from dataclasses import dataclass
from datetime import timedelta

from tailnet.credentials import READ_SCOPES
from tailnet.devices import parse_time
from tailnet.output import format_utc

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
