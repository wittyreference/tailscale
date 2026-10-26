# ABOUTME: The write flow of DESIGN.md §12.6: the apply lock, fresh pre-reads, the guard's plan, then for
# ABOUTME: --apply the write mint, one POST per target, a re-read with the read token, one audit line each.

import json
import re
import time
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from tailnet import (
    api,
    audit,
    credentials,
    devices,
    errors,
    gate,
    guard,
    output,
    protected,
    secure_files,
    selfnode,
    tokens,
)
from tailnet.errors import (
    ApiError,
    LocalError,
    Refused,
    Rejected,
    TailnetError,
    Unconfirmed,
)
from tailnet.http import NoResponse, server_says
from tailnet.output import Envelope, format_utc

# Which write each command plans; the CLI can send no other (§12.3).
OPS = {"device tag": guard.TAG, "device disable-key-expiry": guard.DISABLE}
LOCK_NAME = "apply.lock"
# §12.2 C10: a write token must hold one of these. `devices` is the legacy name for
# devices:core [OC L132] and `all` holds every scope; anything else cannot write a device.
WRITE_SCOPES = frozenset({"devices:core", "devices", "all"})
# §5.1: a write path takes only a nodeId of letters and digits, the shape the API gives.
_NODE_ID = re.compile(r"[A-Za-z0-9]+")
_COMMAND = {guard.TAG: "device tag", guard.DISABLE: "device disable-key-expiry"}
_MARK = {"pass": "ok  ", "fail": "FAIL", "skip": "skip"}
# The skill's rule after exit 6 (§12.6): never re-apply; read what the tailnet shows now.
_LOOK = {"who": "agent", "run": "tailnet device list --json",
         "why": "never re-apply: report what it shows, with its measured_at"}
# §10.2's write column, by status: what the API refusing a write most likely means.
_REJECTED = {
    400: "bad request", 401: "token rejected: the client may be revoked; console → Trust "
                             "credentials",
    402: "plan or billing refuses this [spec 479-494]",
    403: "forbidden: possibly a missing scope (devices:core) (unconfirmed, critic Q4); refused "
         "calls show in the console as 'Failed request' [AUDIT L316]",
    404: "not found: wrong ID, or possibly a missing scope (unconfirmed)",
    429: "rate limited",
}


@dataclass
class _Attempt:
    """One write command's shared facts: what its audit lines and its envelope are made from."""

    posture: object
    command: str
    op: str
    applying: bool
    reason: str | None
    confirm: str | None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    plans: list = field(default_factory=list)
    me: object = None
    listed: object = None
    write: object = None
    gate_present: bool | None = None
    request_ids: list = field(default_factory=list)
    logged: bool = False

    @property
    def mode(self):
        """The audit `mode`: only --apply can send anything."""
        return "apply" if self.applying else "dry-run"

    def note(self, request_id):
        """Keep a request ID for the envelope, once."""
        if request_id and request_id not in self.request_ids:
            self.request_ids.append(request_id)

    def record(self, *, outcome, plan=None, sent=False, confirmed=True, noop=False, failure=None,
               refusal=None, error=None, observed=None, http=(), checks=()):
        """Append this attempt's `write` line for one target, or for none (§13.3).

        Raises LocalError(AUDIT_UNWRITABLE) when it cannot be written: before anything is
        sent, a write command whose line cannot be written stops there (C9).
        """
        target = plan.target if plan is not None else None
        required = plan.confirm_required if plan is not None else None
        matched = None if required is None and self.confirm is None else self.confirm == required
        write = self.write
        audit.append(self.posture, {
            "event": "write", "op": self.op, "mode": self.mode, "outcome": outcome, "sent": sent,
            "confirmed": confirmed, "noop": noop, "failure": failure,
            "class": plan.cls if plan is not None else None, "reason": self.reason,
            "refusal": refusal, "error": error,
            "target": None if target is None else {"nodeId": target.node_id,
                                                   "hostname": target.hostname,
                                                   "addresses": list(target.addresses)},
            "before": plan.before if plan is not None else None,
            "requested": plan.after if plan is not None else None,
            "observed_after": observed,
            "checks": [*(plan.checks if plan is not None else ()), *checks],
            "confirm": {"required": required, "matched": matched},
            "self": self.me.to_dict() if self.me is not None else None,
            "write_client": None if write is None else {
                "client_id": write.client_id,
                "tags": None if write.tags is None else list(write.tags)},
            "http": list(http),
        })
        self.logged = True


@dataclass(frozen=True)
class _Result:
    """What happened to one target under --apply, decided by §12.6 step 9's table."""

    plan: object
    outcome: str
    exit: int
    audit_outcome: str
    sent: bool
    confirmed: bool
    failure: str | None
    observed: dict | None
    http: tuple
    message: str
    status: int | None = None
    request_id: str | None = None

    def to_dict(self):
        """The envelope's per-target result."""
        target = self.plan.target
        return {"nodeId": target.node_id, "hostname": target.hostname, "outcome": self.outcome,
                "sent": self.sent, "confirmed": self.confirmed, "noop": self.outcome == "noop",
                "observed_after": self.observed, "message": self.message,
                "http": list(self.http)}


def run(posture, args):
    """`tailnet device tag` and `device disable-key-expiry`: plan from fresh reads; with
    --apply, send each target's write once.

    The same code runs a dry run and an apply (§12.6). Tags are checked first, as grammar,
    so a malformed one is a usage error that reads and records nothing. Every attempt then
    leaves its audit lines, refusals before any device was resolved included, with no target.
    """
    op = OPS[args.command]
    if op == guard.TAG:
        changes = guard.parse_tags(args.add, args.remove)
        names = [args.device]
    else:
        changes, names = None, args.devices
    attempt = _Attempt(posture=posture, command=args.command, op=op,
                       applying=bool(args.apply), reason=args.reason, confirm=args.confirm)
    try:
        with ExitStack() as held:
            if attempt.applying:
                _take_lock(held, posture)
            return _run(attempt, names, changes)
    except TailnetError as exc:
        if not attempt.logged:
            _record_stop(attempt, exc)
        raise


def _take_lock(stack, posture):
    """C0: hold the apply lock on `stack`, before the pre-reads, so two applies never share one.

    Two concurrent applies on one device would each compute their change from the same
    pre-read and the second would undo the first (D14), so the second is refused, not queued.
    The lock sits beside the audit log, so a state directory that cannot hold it is reported
    as AUDIT_UNWRITABLE: a write that cannot be recorded is not sent either.
    """
    path = audit.state_dir(posture) / LOCK_NAME
    try:
        stack.enter_context(secure_files.lock_exclusive(path, code="AUDIT_UNWRITABLE"))
    except secure_files.Busy:
        raise Refused("APPLY_IN_PROGRESS",
                      f"another --apply holds {path}; nothing was read or sent; run the dry run "
                      "again once it has finished, since it may change what this would do",
                      next=[_LOOK]) from None


def _record_stop(attempt, exc):
    """Leave the line for a command that stopped before it sent anything.

    One line per planned target, or one without a target when it stopped before planning.
    A line that cannot be written turns the stop into AUDIT_UNWRITABLE, naming the first
    reason, because every write command needs its line (C9).
    """
    if exc.code == "AUDIT_UNWRITABLE":
        return
    refused = isinstance(exc, Refused)
    detail = {"code": exc.code, "message": exc.message}
    try:
        for plan in attempt.plans or [None]:
            attempt.record(outcome="refused" if refused else "failed", plan=plan,
                           refusal=detail if refused else None,
                           error=None if refused else detail,
                           failure=None if refused else "not-attempted")
    except LocalError as log:
        raise LocalError(log.code, f"{log.message}; the command had already stopped: "
                                   f"{exc.code}: {exc.message}") from None


def _targets(names, found):
    """Resolve each DEVICE to exactly one device (C1), in argument order, each once."""
    chosen = []
    for name in names:
        device = devices.resolve(name, found)
        if not _NODE_ID.fullmatch(device.node_id):
            raise ApiError("API_BAD_RESPONSE", f"{device.label()}: its nodeId is not plain letters "
                                               "and digits, so it is never put in a write path")
        if all(other.node_id != device.node_id for other in chosen):
            chosen.append(device)
    return chosen


def _read_policy(session, attempt):
    """Tag writes only: the live policy as JSON, for tagOwners and the rules a tag appears in.

    Returns (policy, None), or (None, why) when it cannot be read. That is the guard's
    POLICY_UNREADABLE refusal (§12.3), not an API error, because without tagOwners no tag
    write can be checked at all.
    """
    try:
        reply = api.get_policy(session, api.JSON)
    except ApiError as exc:
        attempt.note(exc.request_id)
        return None, f"{exc.code}: {exc.message}"
    attempt.note(reply.response.request_id)
    try:
        policy = json.loads(reply.data)
    except ValueError:
        return None, "the policy served as JSON does not parse as JSON"
    if not isinstance(policy, dict):
        return None, "the policy served as JSON is not a JSON object"
    return policy, None


def _run(attempt, names, changes):
    """Steps 3-10 of §12.6, under the lock when applying."""
    posture = attempt.posture
    session = api.session(posture)
    found, listing = devices.fetch(session)
    attempt.note(listing.request_id)
    targets = _targets(names, found)
    policy, policy_error = (_read_policy(session, attempt) if attempt.op == guard.TAG
                            else (None, None))
    attempt.listed = protected.load(posture)
    attempt.me = selfnode.resolve_self(posture, found, attempt.listed)
    attempt.write = credentials.load_write_meta(posture)
    attempt.gate_present = gate.gate_present(posture.claude_settings)
    ctx = guard.Context(me=attempt.me, protected=attempt.listed,
                        gate_present=attempt.gate_present,
                        settings_path=str(posture.claude_settings), write=attempt.write,
                        now=attempt.now, policy=policy, policy_error=policy_error)
    if attempt.op == guard.TAG:
        plans = [guard.plan_tag(targets[0], *changes, ctx)]
    else:
        plans = guard.plan_disable_key_expiry(targets, ctx)
    attempt.plans = plans
    refusals = guard.check_apply(plans, ctx, attempt.confirm, attempt.reason,
                                 applying=attempt.applying)
    if not attempt.applying:
        return _dry_run(attempt, plans, refusals)
    if refusals:
        return _refuse(attempt, plans, refusals)
    return _apply(attempt, session, plans)


def _plan_warnings(plans):
    """Print each plan's own warnings to stderr and return them for the envelope."""
    return [output.warn(w["code"], w["message"], w["source"]) for p in plans for w in p.warnings]


def _steps(refusals):
    """Every refusal's next steps, once each, in order."""
    steps = []
    for refusal in refusals:
        for step in refusal.next:
            if step not in steps:
                steps.append(step)
    return steps


def _c7(refusals):
    """The confirm check's audit entry, from whether check_apply refused on it."""
    [found] = [r for r in refusals if r.check == "C7"] or [None]
    if found is None:
        return {"id": "C7", "code": None, "result": "pass", "detail": "--confirm as required"}
    return {"id": "C7", "code": found.code, "result": "fail", "detail": found.message}


def _dry_run(attempt, plans, refusals):
    """Without --apply: show the plan and log it; an operation refusal makes it exit 5."""
    stops = [r for r in refusals if r.operation]
    raised = _plan_warnings(plans)
    raised += [output.warn(r.code, f"apply would be refused: {r.message}")
               for r in refusals if not r.operation]
    if stops:
        first = stops[0]
        for plan in plans:
            attempt.record(outcome="refused", plan=plan,
                           refusal=(plan.refusal or first).to_dict())
        error = Refused(first.code, first.message, next=_steps(stops))
        return _envelope(attempt, refusals, warnings=raised, error=error)
    for plan in plans:
        attempt.record(outcome="dry-run", plan=plan, noop=plan.noop)
    if all(plan.noop for plan in plans):
        return _envelope(attempt, refusals, warnings=raised, outcome="noop",
                         headline="NOOP: already as requested; nothing changed",
                         steps=_steps(refusals))
    apply = {"who": "agent", "run": plans[0].apply_line,
             "why": "applies this plan; replace <why> with one line for MC, who is asked to "
                    "approve that exact command"}
    return _envelope(attempt, refusals, warnings=raised, outcome="dry-run",
                     headline="DRY RUN: nothing changed", steps=[apply, *_steps(refusals)])


def _refuse(attempt, plans, refusals):
    """--apply that the guard refuses: nothing is sent, every target gets its refused line."""
    first = refusals[0]
    for plan in plans:
        attempt.record(outcome="refused", plan=plan, refusal=(plan.refusal or first).to_dict(),
                       checks=[_c7(refusals)])
    error = Refused(first.code, first.message, next=_steps(refusals))
    return _envelope(attempt, refusals, warnings=_plan_warnings(plans), error=error)


def _write_token(attempt, session):
    """C10, only now: open write.secret, mint the write token, and check it can write.

    The token lives in memory for this one command and is never cached (§9.2); its mint
    leaves a token.mint line, and a line that cannot be written stops the write (A15).
    """
    cred = credentials.load_write_secret(attempt.posture, attempt.write)
    token = tokens.mint(attempt.posture, session.transport, cred)
    granted = {item for item in re.split(r"[\s,]+", token.scope or "") if item}
    if not granted & WRITE_SCOPES:
        raise Refused("WRITE_SCOPE_MISSING",
                      f"the write client {cred.client_id} was granted {token.scope!r}, which holds "
                      "none of devices:core, devices or all; nothing was sent",
                      next=[{"who": "mc", "needs": "console",
                             "do": "check the write client's scopes in the admin console",
                             "why": "a write token without devices:core cannot change a device"}])
    return token


def _apply(attempt, session, plans):
    """--apply once every check has passed: C9, C10, then one POST per target, in order.

    POSTs stop at the first target that does not end OK; later ones are not attempted, and
    no-op targets are skipped without being sent (§12.5).
    """
    audit.check_writable(attempt.posture)
    sending = [plan for plan in plans if not plan.noop]
    token = _write_token(attempt, session) if sending else None
    results, stopped, raised = [], False, []
    for plan in plans:
        if stopped:
            result = _skipped(plan, "not-attempted", "not attempted: an earlier target did not "
                                                     "end OK")
        elif plan.noop:
            result = _skipped(plan, "noop", "already as requested; nothing was sent")
        else:
            result = _explained(send(session, plan, token), attempt.write)
            stopped = result.exit != errors.OK
        results.append(result)
        raised += _record_result(attempt, result, bool(sending))
    # The write token is dropped as soon as the last POST is made; it is never written down.
    token = None
    return _applied(attempt, plans, results, raised)


def _explained(result, write):
    """Add §10.2's explanation to a tag write the API answered 400: the rules it may have broken.

    Whether the API path applies the client-tag rule is unverified (critic Q8), so the
    message names both rules and the client's recorded tags, and lets MC judge.
    """
    if result.plan.op != guard.TAG or result.status != 400:
        return result
    tags = ", ".join(write.tags or ()) if write is not None else ""
    return replace(result, message=(
        f"{result.message}; a tag write is refused for a tag that is not a key of tagOwners "
        "[spec 548], and for a set the write client may not assign: the tags must exactly match "
        "the client's own, or each be owned by one of them in tagOwners [TAGS L324]; this write "
        f"client's recorded tags are [{tags}]"))


def _skipped(plan, outcome, message):
    """A target no POST went to: a no-op (OK) or one after a failure (not attempted)."""
    if outcome == "noop":
        return _Result(plan, "noop", errors.OK, "applied", False, True, None, None, (), message)
    return _Result(plan, "not-attempted", errors.OK, "failed", False, True, "not-attempted", None,
                   (), message)


def _record_result(attempt, result, minting):
    """Log one target's line after its POST; a log failure now is a warning, not a stop.

    The write has gone out by this point, so its outcome is what must be reported; the
    log was checked just before (C9), so this is rare, and it is said loudly.
    """
    try:
        minted = ({"id": "C10", "code": "WRITE_SCOPE_MISSING", "result": "pass",
                   "detail": "write token minted from write.secret; its scope can write"}
                  if minting else
                  {"id": "C10", "code": "WRITE_SCOPE_MISSING", "result": "skip",
                   "detail": "nothing to send, so write.secret was not opened"})
        checks = [_c7([]), {"id": "C9", "code": "AUDIT_UNWRITABLE", "result": "pass",
                            "detail": "the audit log takes a line"}, minted]
        attempt.record(outcome=result.audit_outcome, plan=result.plan, sent=result.sent,
                       confirmed=result.confirmed, noop=result.outcome == "noop",
                       failure=result.failure, observed=result.observed, http=result.http,
                       checks=checks)
    except LocalError as exc:
        return [output.warn(exc.code, f"{exc.message}; the write's outcome above is not in the "
                                      "local audit log; Tailscale's own log has it [AUDIT L31]")]
    return []


def _elapsed(started):
    """Milliseconds since `started`, for the audit line's http entries."""
    return round((time.monotonic() - started) * 1000)


def _tag_set(tags):
    """A tag list as the write compares it: lowercased and sorted (§12.6 step 8)."""
    return sorted({tag.lower() for tag in tags})


def _state(plan, device):
    """The field the write changes, as a device shows it now."""
    if plan.op == guard.TAG:
        return {"tags": _tag_set(device.tags)}
    return {"keyExpiryDisabled": device.key_expiry_disabled}


def _intended(plan):
    """The field the write changes, as the plan wants it."""
    return dict(plan.after)


def _prior(plan):
    """The field the write changes, as the pre-read showed it."""
    if plan.op == guard.TAG:
        return {"tags": _tag_set(plan.before["tags"])}
    return {"keyExpiryDisabled": plan.before["keyExpiryDisabled"]}


def _reread(session, plan):
    """§12.6 step 8: read the device back with the read token; (state, http entry, error)."""
    node = plan.target.node_id
    started = time.monotonic()
    try:
        reply = api.get_device(session, node)
        device = devices.normalise(reply.data)
        if device.node_id != node:
            raise ApiError("API_BAD_RESPONSE", f"asked for {node}, the API returned "
                                               f"{device.node_id}")
    except TailnetError as exc:
        entry = {"method": "GET", "path": f"/device/{node}", "status": exc.http_status,
                 "request_id": exc.request_id, "ms": _elapsed(started)}
        return None, entry, f"{exc.code}: {exc.message}"
    response = reply.response
    entry = {"method": "GET", "path": f"/device/{node}", "status": response.status,
             "request_id": response.request_id, "ms": _elapsed(started)}
    return _state(plan, device), entry, None


def _post(session, plan, token):
    """The write itself: one of the two functions in api.py that can change the tailnet.

    A tag write sends the whole new set, because the API replaces the list [api §5.7].
    """
    if plan.op == guard.TAG:
        return api.set_device_tags(session, plan.target.node_id, list(plan.after["tags"]), token)
    return api.disable_key_expiry(session, plan.target.node_id, token)


def send(session, plan, token):
    """POST one target's write exactly once, re-read it with the read token, and judge it.

    The judgement is §12.6 step 9's table: the status says whether the API took the write,
    and the re-read, never the status alone, says whether it is visible. A write that may
    have landed is never sent again from here or anywhere else.
    """
    started = time.monotonic()
    response, sent, problem, where = None, True, None, None
    try:
        response = _post(session, plan, token)
        where = response.where
    except NoResponse as exc:
        sent, problem, where = exc.sent, exc.message, exc.where
    status = response.status if response is not None else None
    request_id = response.request_id if response is not None else None
    # The transport names the method and path it used, so this module never spells a
    # method that writes: only api.py may (test_only_api_and_tokens_issue_post_requests).
    method, _, path = (where or " ").partition(" ")
    http = [{"method": method or None, "path": path or None, "status": status,
             "request_id": request_id, "ms": _elapsed(started)}]
    label = plan.target.label()
    if not sent:
        # The request never reached the API: nothing can have changed, so there is nothing
        # to re-read, and it is reported as not sent.
        return _Result(plan, "rejected", errors.REJECTED, "failed", False, True, "rejected", None,
                       tuple(http), f"{label}: the write never reached the API ({problem}); "
                                    "nothing was sent")
    observed, entry, reread_error = _reread(session, plan)
    http.append(entry)
    seen = (f"the re-read failed ({reread_error})" if observed is None
            else f"the re-read shows {_show(observed)}")
    matches = observed == _intended(plan)
    common = {"http": tuple(http), "status": status, "request_id": request_id}

    def outcome(name, exit_code, audit_outcome, confirmed, failure, message):
        """One result, with the HTTP facts every outcome shares."""
        return _Result(plan, name, exit_code, audit_outcome, True, confirmed, failure, observed,
                       message=message, **common)

    if status is not None and 200 <= status < 300:
        if matches:
            return outcome("applied", errors.OK, "applied", True, None,
                           f"{label}: applied (HTTP {status}); {seen}")
        return outcome("unconfirmed", errors.UNCONFIRMED, "failed", False, "unconfirmed",
                       f"{label}: the API accepted the write (HTTP {status}) but {seen}: not "
                       "yet visible; check `tailnet device list --json` in a minute; do not "
                       "re-apply")
    if status is not None and 300 <= status < 500:
        why = _REJECTED.get(status, "redirect refused (would carry the token)"
                            if status < 400 else f"refused with HTTP {status}")
        return outcome("rejected", errors.REJECTED, "failed", observed == _prior(plan),
                       "rejected",
                       f"{label}: the API rejected the write: HTTP {status}: {why}; server said: "
                       f"{server_says(response)}; nothing was retried; {seen}")
    # A 5xx, or no answer after the request went out: it may have landed, so the re-read
    # decides, and an unconfirmed write is never re-applied [api §12.9].
    what = f"HTTP {status}" if status is not None else problem
    if matches:
        return outcome("applied", errors.OK, "applied", True, None,
                       f"{label}: {what}, but {seen}: applied, confirmed by the re-read")
    return outcome("unconfirmed", errors.UNCONFIRMED, "failed", False, "unconfirmed",
                   f"{label}: {what} after the write was sent, and {seen}: the write may have "
                   "landed; do not re-apply")


def _show(state):
    """A re-read state in words, for messages."""
    return ", ".join(f"{key} {str(value).lower() if isinstance(value, bool) else value}"
                     for key, value in state.items())


def _applied(attempt, plans, results, raised):
    """The envelope after --apply: the first target that did not end OK decides the exit."""
    for result in results:
        for entry in result.http:
            attempt.note(entry["request_id"])
    raised = _plan_warnings(plans) + raised
    failed = next((r for r in results if r.exit != errors.OK), None)
    if failed is not None:
        if failed.exit == errors.UNCONFIRMED:
            error = Unconfirmed("WRITE_UNCONFIRMED", failed.message, http_status=failed.status,
                                request_id=failed.request_id, next=[_LOOK])
        else:
            error = Rejected("WRITE_REJECTED", failed.message, http_status=failed.status,
                             request_id=failed.request_id, next=[_LOOK])
        return _envelope(attempt, [], warnings=raised, error=error, results=results)
    if all(result.outcome == "noop" for result in results):
        return _envelope(attempt, [], warnings=raised, outcome="noop", results=results,
                         headline="NOOP: already as requested; nothing was sent")
    sent = sum(result.sent for result in results)
    return _envelope(attempt, [], warnings=raised, outcome="applied", results=results,
                     headline=f"APPLIED: {sent} of {len(results)} sent, each confirmed by a "
                              "re-read", steps=_after_tagging(results))


def _after_tagging(results):
    """After an applied tag write, offer to turn off the key expiry that tagging left on.

    Tagging never changes key expiry [TAGS L84], so a retagged box still drops off the
    tailnet when its old key lapses (P9) until someone disables it.
    """
    return [{"who": "agent", "run": f"tailnet device disable-key-expiry {r.plan.target.node_id}",
             "why": "tagging left its key expiry on: it drops off the tailnet when the key "
                    "lapses [TAGS L84]"}
            for r in results if r.plan.op == guard.TAG and r.outcome == "applied"
            and r.plan.target.key_expiry_disabled is not True]


def _envelope(attempt, refusals, *, warnings, outcome=None, error=None, headline="", steps=(),
              results=None):
    """The command's envelope: the plans, any results and refusals, and the human blocks."""
    by_plan = {id(r.plan): r for r in results or ()}
    lines = []
    for plan in attempt.plans:
        lines += _plan_lines(plan, attempt.now, by_plan.get(id(plan)))
    data = {
        "op": attempt.op, "mode": attempt.mode,
        "plans": [plan.to_dict() for plan in attempt.plans],
        "results": None if results is None else [r.to_dict() for r in results],
        "refusals": [{**r.to_dict(), "nodeId": r.node_id} for r in refusals],
        "self": attempt.me.to_dict(),
        "protected_file": "unanswered" if attempt.listed is None else "answered",
        "gate_present": attempt.gate_present,
        "write_client": None if attempt.write is None else {
            "client_id": attempt.write.client_id,
            "tags": None if attempt.write.tags is None else list(attempt.write.tags)},
    }
    fields = {"data": data, "warnings": warnings, "lines": lines,
              "request_ids": list(attempt.request_ids), "measured_at": format_utc(attempt.now)}
    if error is not None:
        return Envelope.from_error(attempt.command, attempt.posture.kind, error, **fields)
    return Envelope(attempt.command, attempt.posture.kind, outcome=outcome, next=list(steps),
                    headline=headline, **fields)


def _before_text(plan, now):
    """The plan's `before` line: what the pre-read showed of the field the write changes."""
    target = plan.target
    owner = f"tags ({', '.join(target.tags)})" if target.tags else f"user {target.user or '?'}"
    if plan.op == guard.TAG:
        return f"tags: {', '.join(target.tags) or 'none'}    owner: {owner}"
    expiry = target.key_expiry(now)
    if expiry["disabled"]:
        state = "OFF"
    elif expiry["disabled"] is None:
        state = "unknown"
    else:
        days = "" if expiry["days_left"] is None else f" ({expiry['days_left']} days)"
        state = f"ON, expires {target.expires}{days}"
    return f"key expiry {state}    owner: {owner}"


def _plan_lines(plan, now, result=None):
    """One target's block in the human view, as §12.7 lays a plan out."""
    target = plan.target
    if plan.op == guard.TAG:
        after = f"tags: {', '.join(plan.after['tags']) or 'none'}"
    else:
        after = "key expiry OFF"
    after += "  (already; nothing to send)" if plan.noop else ""
    lines = [(f"{_COMMAND[plan.op]}  {target.hostname or '?'}  {target.node_id}  "
              f"{target.ipv4 or '-'}"),
             f"  class    {plan.cls}  {guard.CLASS_MEANING[(plan.op, plan.cls)]}",
             f"  before   {_before_text(plan, now)}",
             f"  after    {after}"]
    for index, check in enumerate(plan.checks):
        lead = "  checks   " if index == 0 else "           "
        lines.append(f"{lead}{_MARK[check['result']]}  {check['id']}  {check['detail']}")
    lines += [f"  then     {line}" for line in plan.consequences]
    lines += [f"  warning  {w['code']}: {w['message']}" for w in plan.warnings]
    lines.append(f"  apply    {plan.apply_line}")
    if result is not None:
        lines.append(f"  result   {result.outcome}: {result.message}")
    return lines
