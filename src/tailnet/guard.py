# ABOUTME: The write guard, pure: risk classes, every check of DESIGN.md §12.2-12.5, confirm tokens, the tag
# ABOUTME: rules and the apply line. No I/O at all, so each rule between an agent and a write is testable.

import re
import shlex
from dataclasses import dataclass

from tailnet.errors import UsageError

TAG = "device.tag"
DISABLE = "device.disable-key-expiry"
PROG = "tailnet"
# The dry run prints the apply line with this placeholder for MC's reason (§12.6 step 4); the
# grammar refuses a --reason that still holds it.
PLACEHOLDER = "<why>"

# §5.2: a tag as the policy file spells it. Tailscale parses every tag in the policy file as
# lowercase [pol (f)], so input is lowercased before it is held to this.
_TAG = re.compile(r"tag:[a-z0-9][a-z0-9-]*")
# §12.2: refusals that hold only at apply time. A dry run prints them as "apply would be
# refused" and still exits 0, so MC can see the plan first; every other refusal means the
# operation cannot happen whatever MC does, and refuses the dry run too.
PRECONDITIONS = frozenset({
    "SELF_UNKNOWN", "SELF_LINE_DISAGREES", "PROTECTED_UNANSWERED", "GATE_MISSING",
    "CONFIRM_MISSING", "CONFIRM_MISMATCH", "WRITE_CREDENTIAL_MISSING",
})

# What each class means for its operation (§12.1, §12.3), for the plan's class line.
CLASS_MEANING = {
    (TAG, "R2"): "changes which policy rules match this device; reversible by retagging",
    (TAG, "R3"): "irreversible from the API: the device stops being owned by its user; recovery "
                 "needs hands at the device",
    (DISABLE, "R1"): "keeps the device on the tailnet; reversible in the console",
    (DISABLE, "R2"): "a stolen device's key would never expire; reversible in the console",
}

# §12.4, printed verbatim for a first tag on a user-owned device (R3).
_STRIP_OWNER = (
    "autogroup:self rules and the default SSH rule stop covering it [critic R13; tsssh L255-268]",
    "Taildrop and same-user netmap visibility end [pol (b)]",
)
_RECOVERY = "recovery: re-authenticate on the device as the user"
# What disabling leaves behind [spec 600-603]: the date is kept, so the console can restore it.
_KEPT_EXPIRY = ("the original expiry time is kept; re-enabling expiry in the console "
                "restores it [spec 600-603]")
_CONSOLE = {"who": "mc", "needs": "console",
            "do": "make the change in the admin console if it must happen",
            "why": "a guard refusal is final for the CLI; the console is MC's own way"}


@dataclass(frozen=True)
class Refusal:
    """Why a write may not go ahead: the check that failed, its stable code, and what to do next.

    `node_id` names the target it is about, or is None when it holds for the whole command
    (self, the gate, the confirm, the write client).
    """

    check: str
    code: str
    message: str
    node_id: str | None = None
    next: tuple = ()

    @property
    def operation(self):
        """True when the operation itself cannot happen, so a dry run is refused as well."""
        return self.code not in PRECONDITIONS

    def to_dict(self):
        """The audit record's `refusal` object (§13.3)."""
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class Context:
    """Everything the guard decides from besides the target, read fresh by the write flow.

    `me` is the SelfNode, `protected` MC's parsed list (None while unanswered), `write` the
    write client's metadata (None when there is no write.json), `policy` the live policy as
    JSON for tag writes (None with `policy_error` saying why it could not be read), `now`
    the time every expiry is judged at, and `devices` the fresh device list the protected
    entries are judged against (None when the caller has none to give).
    """

    me: object
    protected: object
    gate_present: bool
    settings_path: str
    write: object
    now: object
    policy: dict | None = None
    policy_error: str | None = None
    devices: tuple | None = None


@dataclass(frozen=True)
class _Check:
    """One check's result; it becomes an audit `checks` entry, and a Refusal when it fails."""

    id: str
    code: str | None
    result: str
    detail: str
    next: tuple = ()

    def to_dict(self):
        """The audit record's form: id, the code it would refuse with, result and detail."""
        return {"id": self.id, "code": self.code, "result": self.result, "detail": self.detail}

    def refusal(self, node_id=None):
        """This failed check as a Refusal."""
        return Refusal(self.id, self.code, self.detail, node_id, self.next)


def _order(check_id):
    """Sort key for a check: §12.2 runs them C0 to C10, in that order."""
    return int(check_id[1:])


@dataclass(frozen=True)
class Plan:
    """One target's write, decided from the fresh pre-read: what it is, what it would change,
    every check's result, and the exact line that applies it.

    `refusal` is the first operation refusal, or None. `noop` means the requested state
    already holds, so nothing would be sent. `apply_argv` names the device by nodeId and
    carries the confirm token, so the line MC approves is the plan the dry run showed.
    """

    op: str
    cls: str
    target: object
    before: dict
    after: dict
    checks: tuple
    refusal: Refusal | None
    confirm_required: str | None
    warnings: tuple
    consequences: tuple
    noop: bool
    apply_argv: tuple

    @property
    def apply_line(self):
        """The apply command as one shell line, the form an agent runs and MC is asked about."""
        return command_line(self.apply_argv)

    @property
    def dry_argv(self):
        """The same command without --confirm, --apply and --reason: the dry run that re-plans."""
        argv = list(self.apply_argv)
        cut = argv.index("--confirm") if "--confirm" in argv else argv.index("--apply")
        return tuple(argv[:cut])

    def to_dict(self):
        """The plan as the envelope's data shows it."""
        target = self.target
        return {
            "op": self.op, "class": self.cls,
            "target": {"nodeId": target.node_id, "hostname": target.hostname,
                       "addresses": list(target.addresses)},
            "before": self.before, "after": self.after, "checks": list(self.checks),
            "refusal": self.refusal.to_dict() if self.refusal else None,
            "confirm_required": self.confirm_required, "warnings": list(self.warnings),
            "consequences": list(self.consequences), "noop": self.noop,
            "apply_argv": list(self.apply_argv), "apply_line": self.apply_line,
        }


def command_line(argv):
    """Render argv as one shell line; the reason placeholder is shown as "<why>" for MC to fill."""
    return " ".join('"<why>"' if word == PLACEHOLDER else shlex.quote(word) for word in argv)


def parse_tags(add, remove):
    """Lowercase and validate --add and --remove (§5.2); return them as tuples, first use kept.

    A tag that is not `tag:` plus letters, digits and hyphens is a typo the API would only
    reject later, and a tag both added and removed has no meaning: both exit 2.
    """
    def clean(tags, flag):
        """One flag's tags, lowercased, checked and without repeats."""
        kept = []
        for text in tags:
            tag = text.lower()
            if not _TAG.fullmatch(tag):
                raise UsageError("TAG_MALFORMED", f"{flag} {text!r} is not a tag: a tag is tag: "
                                                  "then lowercase letters, digits and hyphens, "
                                                  "starting with a letter or digit")
            if tag not in kept:
                kept.append(tag)
        return tuple(kept)

    add, remove = clean(add, "--add"), clean(remove, "--remove")
    both = [tag for tag in add if tag in remove]
    if both:
        raise UsageError("TAG_ADD_AND_REMOVE", f"{', '.join(both)} is both added and removed")
    return add, remove


def _name(device):
    """What a confirm token calls a device: the hostname MC knows it by, fresh from the API."""
    return device.hostname or device.first_label() or device.node_id


def confirm_token(verb, device):
    """The typed confirm for a risky write (D11): the verb names the risk, the name the device."""
    return f"{verb}:{_name(device)}"


def _owners(tag_owners):
    """tagOwners with every tag and owner lowercased; a malformed entry owns nothing."""
    if not isinstance(tag_owners, dict):
        return {}
    return {tag.lower(): {o.lower() for o in owners if isinstance(o, str)}
            for tag, owners in tag_owners.items()
            if isinstance(tag, str) and isinstance(owners, list)}


def client_may_assign(new, client_tags, tag_owners):
    """Whether a client carrying `client_tags` may assign the tag set `new` (§12.4, TAGS L324).

    Either the set equals the client's own tags exactly, or every tag in it is owned by one
    of the client's tags in tagOwners. Whether the API path enforces this is unverified
    (critic Q8), so the CLI holds itself to it: refusing a write the server might have
    accepted is the safe direction. An empty set is never assignable (TAG_SET_EMPTY).
    """
    new = {tag.lower() for tag in new}
    client = {tag.lower() for tag in client_tags}
    if not new:
        return False
    if new == client:
        return True
    owners = _owners(tag_owners)
    return all(client & owners.get(tag, set()) for tag in new)


def _mention(tags):
    """A test for whether a policy string names one of `tags` as a whole tag.

    "tag:lab:22" names tag:lab (a port follows), "tag:lab2" does not: it is another tag.
    """
    patterns = [re.compile(r"(?<![\w:-])" + re.escape(tag.lower()) + r"(?![\w-])", re.IGNORECASE)
                for tag in tags]
    return lambda text: any(p.search(text) for p in patterns)


def _key_path(path, key):
    """The path to a dict key: dotted when it is a plain name, else quoted in brackets."""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{path}.{key}" if path else key
    return f'{path}["{key}"]'


def rule_references(policy_json, tags):
    """Every path in the policy JSON whose value or key names one of `tags`, in document order.

    A list of strings is named by its field (grants[2].dst), not each element, matching how
    MC reads a rule. Shown in a plan so MC sees which rules a tag change touches (§12.4).
    """
    mentions = _mention(tags)
    found = []

    def note(path):
        """Keep a path once."""
        if path not in found:
            found.append(path)

    def walk(node, path):
        """Visit every key and string below `node`."""
        if isinstance(node, dict):
            for key, value in node.items():
                child = _key_path(path, str(key))
                if mentions(str(key)):
                    note(child)
                walk(value, child)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                if isinstance(item, str):
                    if mentions(item):
                        note(path)
                else:
                    walk(item, f"{path}[{index}]")
        elif isinstance(node, str) and mentions(node):
            note(path)

    walk(policy_json, "")
    return found


def _pass(check_id, code, detail):
    """A check that holds."""
    return _Check(check_id, code, "pass", detail)


def _skip(check_id, code, detail):
    """A check that cannot be decided here; another check refuses the apply instead."""
    return _Check(check_id, code, "skip", detail)


def _fail(check_id, code, detail, *steps):
    """A check that refuses, with what to do about it."""
    return _Check(check_id, code, "fail", detail, tuple(steps))


def _self_known(ctx):
    """C3: self is known (§11.3). An unknown self refuses every --apply (invariant 8)."""
    me = ctx.me
    if me.known:
        how = ("joined by its Tailscale IPs" if me.source == "live"
               else "from the protected file's self line")
        agrees = "" if me.id_agrees is None else f"; id_agrees={str(me.id_agrees).lower()}"
        return _pass("C3", "SELF_UNKNOWN", f"self is {me.device.label()}, {how}{agrees}")
    code = me.refusal or "SELF_UNKNOWN"
    if code == "SELF_LINE_DISAGREES":
        step = {"who": "mc", "needs": "terminal",
                "do": "re-record the self line in the protected file with this host's nodeId",
                "why": "the live join and MC's self line name different devices"}
    else:
        step = {"who": "agent", "run": f"{PROG} status",
                "why": "shows the local view and why self is unknown"}
    return _fail("C3", code, f"self unknown ({me.reason})", step)


def _answered(ctx):
    """C4, tag writes only: MC has written the protected list (§11.4)."""
    if ctx.protected is None:
        return _fail("C4", "PROTECTED_UNANSWERED",
                     "the protected list is unanswered: MC has not written the protected file, "
                     "so no tag write is allowed (critic Q14: never inferred)",
                     {"who": "agent", "run": f"{PROG} doctor",
                      "why": "doctor proposes the protected file for MC to write over SSH"})
    count = len(ctx.protected.entries)
    entries = "1 entry" if count == 1 else f"{count} entries"
    return _pass("C4", "PROTECTED_UNANSWERED", f"protected list answered, {entries}")


def _gate(ctx):
    """C5: the ask rule that puts every --apply in front of MC is in Claude's settings (§11.5)."""
    if ctx.gate_present:
        return _pass("C5", "GATE_MISSING", f"gate rule present in {ctx.settings_path}")
    return _fail("C5", "GATE_MISSING",
                 f"the ask rule that puts this write in front of MC is missing from "
                 f"{ctx.settings_path}; re-run the installer",
                 {"who": "mc", "needs": "terminal", "do": "./install-tailnet.sh",
                  "why": "it restores the ask rule; without it nothing prompts MC for a write"})


def _write_client(ctx):
    """C8: write.json is there (metadata only; its secret is opened only after every check)."""
    if ctx.write is None:
        return _fail("C8", "WRITE_CREDENTIAL_MISSING",
                     "no write client: write.json is missing, so nothing can be sent; MC runs "
                     "`tailnet credentials set write` to arm writes",
                     {"who": "mc", "needs": "terminal", "do": f"{PROG} credentials set write",
                      "why": "it prompts for the write client's ID and secret at MC's terminal"})
    return _pass("C8", "WRITE_CREDENTIAL_MISSING",
                 f"write client present ({ctx.write.client_id}); the secret is opened only on "
                 "--apply")


def _preconditions(ctx, op):
    """The apply-time checks that do not depend on the target, in §12.2 order."""
    checks = [_self_known(ctx)]
    if op == TAG:
        checks.append(_answered(ctx))
    return [*checks, _gate(ctx), _write_client(ctx)]


def _shared_in(device):
    """C2: the target is a member of this tailnet, not shared in from another [spec 329-331].

    isExternal is not documented as ever omitted; when it is, membership is unknown, and a
    device that may not be ours is refused rather than assumed to be ours.
    """
    if device.external is False:
        return _pass("C2", "SHARED_IN", "a member of this tailnet, not shared in")
    if device.external is True:
        why = "is shared into this tailnet from another (isExternal); it is not ours to change"
    else:
        why = "has no isExternal field, so whether it is shared in is unknown"
    return _fail("C2", "SHARED_IN", f"{device.label()} {why} [spec 329-331]", _CONSOLE)


def _before(device):
    """The fields a write changes or depends on, as they were before it (§13.3 `before`)."""
    return {"tags": list(device.tags), "user": device.user,
            "keyExpiryDisabled": device.key_expiry_disabled, "expires": device.expires}


def _first_refusal(checks, device):
    """The first failing check that refuses the operation itself, as a Refusal; None if none."""
    for check in checks:
        if check.result == "fail" and check.code not in PRECONDITIONS:
            return check.refusal(device.node_id)
    return None


def _expiry_line(device, now):
    """What tagging leaves of key expiry: it is unchanged by tagging [TAGS L84]."""
    expiry = device.key_expiry(now)
    if expiry["disabled"]:
        return "key expiry is unchanged by tagging: OFF [TAGS L84]"
    days = "" if expiry["days_left"] is None else f" ({expiry['days_left']} days)"
    return (f"key expiry is unchanged by tagging: ON, expires {device.expires}{days}; follow up "
            f"with `{PROG} device disable-key-expiry {device.node_id}` [TAGS L84]")


def _is_self(device, ctx):
    """Whether the target is this host: True, False, or None when that cannot be known.

    Both sources count: the live IP join and MC's self line. When they disagree, each one's
    device is treated as self, the safe direction for a refusal.
    """
    me = ctx.me
    if me.device is not None and device.node_id == me.device.node_id:
        return True, f"{device.label()} is self, joined by its Tailscale IPs"
    if ctx.protected is not None and device.node_id == ctx.protected.self_node_id:
        return True, f"{device.label()} is self: MC's self line names it"
    if me.known:
        return False, f"not self (self = {me.device.label()})"
    return None, "self unknown, so whether this is self cannot be said"


def _tag_checks(device, current, new, remove, ctx):
    """The C6 checks of a tag write (§12.3, §12.4), in the order they refuse."""
    checks = []
    is_self, detail = _is_self(device, ctx)
    if is_self:
        checks.append(_fail("C6", "SELF_DEVICE",
                            f"{detail}: no command retags the host the agent runs on (§11.4)",
                            _CONSOLE))
    elif is_self is False:
        checks.append(_pass("C6", "SELF_DEVICE", detail))
    else:
        checks.append(_skip("C6", "SELF_DEVICE", detail))
    if ctx.protected is None:
        checks.append(_skip("C6", "PROTECTED_DEVICE", "the protected list is unanswered"))
    else:
        why = ctx.protected.protects(device)
        if why is None:
            checks.append(_pass("C6", "PROTECTED_DEVICE", "not on MC's protected list"))
        else:
            checks.append(_fail("C6", "PROTECTED_DEVICE",
                                f"{device.label()} is protected ({why}): every tag change on it "
                                "is refused", _CONSOLE))
    absent = [tag for tag in remove if tag not in current]
    if absent:
        have = ", ".join(current) or "none"
        checks.append(_fail("C6", "TAG_NOT_PRESENT",
                            f"{device.label()} does not carry {', '.join(absent)}, so it cannot "
                            f"be removed (a typo?); its tags are: {have}"))
    else:
        checks.append(_pass("C6", "TAG_NOT_PRESENT", "every removed tag is on the device"))
    if not new:
        checks.append(_fail("C6", "TAG_SET_EMPTY",
                            f"this would leave {device.label()} with no tags: you cannot remove "
                            "all tags from a device [TAGS L33; critic Q10]"))
    else:
        checks.append(_pass("C6", "TAG_SET_EMPTY", "the new set is not empty"))
    checks.extend(_policy_checks(new, ctx))
    return checks


def _policy_checks(new, ctx):
    """The C6 checks that need tagOwners and the write client's recorded tags."""
    if ctx.policy is None:
        unreadable = _fail("C6", "POLICY_UNREADABLE",
                           f"the policy JSON could not be read ({ctx.policy_error}): tagOwners "
                           "decides which tags exist and who may assign them, so no tag write is "
                           "planned without it")
        return [unreadable,
                _skip("C6", "TAG_UNDEFINED", "no policy to check against"),
                _skip("C6", "CLIENT_CANNOT_ASSIGN", "no policy to check against")]
    checks = [_pass("C6", "POLICY_UNREADABLE", "policy JSON read")]
    tag_owners = ctx.policy.get("tagOwners")
    owners = _owners(tag_owners)
    undefined = [tag for tag in new if tag not in owners]
    if undefined:
        checks.append(_fail("C6", "TAG_UNDEFINED",
                            f"{', '.join(undefined)} is not a key of the policy's tagOwners: "
                            "the API refuses a tag that is not defined there [spec 548]; MC "
                            "defines it in the console first", _CONSOLE))
    else:
        checks.append(_pass("C6", "TAG_UNDEFINED", "every tag in the new set is in tagOwners"))
    write = ctx.write
    if write is None:
        checks += [_skip("C6", "WRITE_CLIENT_TAGS_UNRECORDED", "no write client (C8)"),
                   _skip("C6", "CLIENT_CANNOT_ASSIGN", "no write client (C8)")]
        return checks
    if write.tags is None:
        checks += [_fail("C6", "WRITE_CLIENT_TAGS_UNRECORDED",
                         "write.json records no tags for the write client, so which tags it may "
                         "assign cannot be told [TAGS L324]; MC re-runs `tailnet credentials set "
                         "write`",
                         {"who": "mc", "needs": "terminal", "do": f"{PROG} credentials set write",
                          "why": "it records the write client's tags"}),
                   _skip("C6", "CLIENT_CANNOT_ASSIGN", "the client's tags are not recorded")]
        return checks
    checks.append(_pass("C6", "WRITE_CLIENT_TAGS_UNRECORDED", "the client's tags are recorded"))
    client = ", ".join(write.tags) or "none"
    wanted = ", ".join(new)
    if not client_may_assign(new, write.tags, tag_owners):
        checks.append(_fail("C6", "CLIENT_CANNOT_ASSIGN",
                            f"the write client [{client}] cannot assign [{wanted}]: requested "
                            "tags must exactly match the client's tags, or each be owned by one "
                            "of them in tagOwners [TAGS L324]; refused rather than sent, since "
                            "whether the API applies this rule is unverified (critic Q8)",
                            _CONSOLE))
    else:
        how = ("exact match" if {t.lower() for t in write.tags} == set(new)
               else "each tag owned by a client tag in tagOwners")
        checks.append(_pass("C6", "CLIENT_CANNOT_ASSIGN",
                            f"write client [{client}] may assign [{wanted}]: {how} (TAGS L324)"))
    return checks


def _tag_consequences(device, current, new, user_owned, ctx):
    """What the plan tells MC this change touches: the rules, key expiry, and for R3 the owner."""
    lines = []
    if user_owned:
        lines.append(f"removes {device.user or 'its user'} as owner; you cannot remove all tags "
                     "afterwards [TAGS L72, L33]")
        lines.extend(_STRIP_OWNER)
    if ctx.policy is not None:
        for tag in sorted(set(new) ^ set(current)):
            paths = rule_references(ctx.policy, [tag])
            where = ", ".join(paths) if paths else "no rule"
            lines.append(f"policy: {tag} appears in {where}")
    lines.append(_expiry_line(device, ctx.now))
    if user_owned:
        lines.append(_RECOVERY)
    return tuple(lines)


def _unmatched_warnings(ctx):
    """PROTECTED_LINE_UNMATCHED: protected lines that name no device protect nothing.

    C6 can only say a target is "not on MC's protected list"; when a line meant for it was
    left behind by a rename or a typo, that would read as MC's choice. Doctor's L6 says the
    same, but doctor is not on the path of a write. Lines by number only (A19).
    """
    if ctx.protected is None or ctx.devices is None:
        return ()
    lines = ctx.protected.unmatched(ctx.devices)
    if not lines:
        return ()
    numbers = ", ".join(str(n) for n in lines)
    which = (f"lines {numbers} match no device, so they protect" if len(lines) > 1
             else f"line {numbers} matches no device, so it protects")
    return ({"code": "PROTECTED_LINE_UNMATCHED",
             "message": f"protected file {which} nothing (a rename, a removed device or a "
                        "typo); MC fixes the file by hand",
             "source": "DESIGN.md §11.4"},)


def plan_tag(device, add, remove, ctx):
    """Plan a tag change on one device (§12.3, §12.4) from its fresh pre-read.

    The new set is the device's current tags plus `add` minus `remove`, so a tag the console
    added since the dry run is kept, never silently reverted (D9). Tagging a tagged device
    is R2 (`retag:`); tagging a user-owned one removes its owner for good, R3
    (`strip-owner:`). Self and protected devices are refused every tag change.
    """
    add, remove = parse_tags(add, remove)
    current = sorted({tag.lower() for tag in device.tags})
    new = sorted((set(current) | set(add)) - set(remove))
    user_owned = not device.tags
    cls, verb = ("R3", "strip-owner") if user_owned else ("R2", "retag")
    token = confirm_token(verb, device)
    checks = [_pass("C1", "DEVICE_NOT_FOUND", "resolved to exactly one device"),
              _shared_in(device), *_preconditions(ctx, TAG),
              *_tag_checks(device, current, new, remove, ctx)]
    checks.sort(key=lambda check: _order(check.id))
    argv = [PROG, "device", "tag", device.node_id]
    for flag, tags in (("--add", add), ("--remove", remove)):
        for tag in tags:
            argv += [flag, tag]
    argv += ["--confirm", token, "--apply", "--reason", PLACEHOLDER]
    return Plan(op=TAG, cls=cls, target=device, before=_before(device), after={"tags": new},
                checks=tuple(c.to_dict() for c in checks),
                refusal=_first_refusal(checks, device), confirm_required=token,
                warnings=_unmatched_warnings(ctx),
                consequences=_tag_consequences(device, current, new, user_owned, ctx),
                noop=new == current, apply_argv=tuple(argv))


def _expiry_warnings(device, now):
    """KEY_ALREADY_EXPIRED: disabling expiry on a lapsed key is allowed, but may not revive it."""
    if device.key_expiry(now)["expired"] is not True:
        return ()
    return ({"code": "KEY_ALREADY_EXPIRED",
             "message": f"{device.label()}: its key expired {device.expires}: disabling may not "
                        "reconnect it [unverified]; re-authentication at the device may be needed",
             "source": "spec 606-607"},)


def plan_disable_key_expiry(devices, ctx):
    """Plan turning key expiry off on each device, in argument order (§12.3, §12.5).

    A tagged device is R1; a user-owned one is R2 (a stolen device's key would never expire)
    and takes `no-expiry:`. Protected devices and self are allowed, and so is an unanswered
    protected list (D7): this is the write that keeps a box on the tailnet. Several targets
    are allowed only when every one is R1.
    """
    multi = len(devices) > 1
    plans = []
    for device in devices:
        user_owned = not device.tags
        cls = "R2" if user_owned else "R1"
        token = confirm_token("no-expiry", device) if user_owned else None
        checks = [_pass("C1", "DEVICE_NOT_FOUND", "resolved to exactly one device"),
                  _shared_in(device), *_preconditions(ctx, DISABLE)]
        if multi and user_owned:
            checks.append(_fail("C6", "MULTI_TARGET_NOT_R1",
                                f"{device.label()} is user-owned, so disabling its key expiry is "
                                "R2 and needs its own confirm: run it as the only target"))
        elif multi:
            checks.append(_pass("C6", "MULTI_TARGET_NOT_R1", "tagged (R1): may share a batch"))
        checks.sort(key=lambda check: _order(check.id))
        argv = [PROG, "device", "disable-key-expiry", *(d.node_id for d in devices)]
        if token and not multi:
            argv += ["--confirm", token]
        argv += ["--apply", "--reason", PLACEHOLDER]
        plans.append(Plan(op=DISABLE, cls=cls, target=device, before=_before(device),
                          after={"keyExpiryDisabled": True},
                          checks=tuple(c.to_dict() for c in checks),
                          refusal=_first_refusal(checks, device), confirm_required=token,
                          warnings=_expiry_warnings(device, ctx.now), consequences=(_KEPT_EXPIRY,),
                          noop=device.key_expiry_disabled is True, apply_argv=tuple(argv)))
    return plans


def _confirm(plans, confirm, applying):
    """C7: --confirm equals the token the plan requires, exactly and case-sensitively.

    A confirm where none is required is refused too: it may be the token of a stale plan. A
    dry run without one is not refused, because the apply line it prints carries the token.
    """
    plan = plans[0]
    # Several targets are allowed only when every one is R1, which takes no confirm.
    required = plan.confirm_required if len(plans) == 1 else None
    replan = {"who": "agent", "run": command_line(plan.dry_argv),
              "why": "prints the plan, and its confirm token, from the device as it is now"}
    if confirm is None:
        if required is None or not applying:
            return None
        return Refusal("C7", "CONFIRM_MISSING",
                       f"this {plan.cls} write needs --confirm {required}; the dry run prints it",
                       None, (replan,))
    if confirm == required:
        return None
    if required is None:
        message = (f"--confirm {confirm!r} was given, but this plan needs none: it may be the "
                   "token of a stale plan; re-run the dry run")
    else:
        message = (f"--confirm must be exactly {required}, the token for this plan now; "
                   f"got {confirm!r}")
        verb = required.split(":", 1)[0]
        if confirm.startswith(verb + ":"):
            message += (f"; the device is called {_name(plan.target)} now, so it may have been "
                        "renamed since the dry run")
    return Refusal("C7", "CONFIRM_MISMATCH", message, None, (replan,))


def check_apply(plans, ctx, confirm, reason, *, applying=True):
    """Every refusal that stands between these plans and an --apply, in §12.2 order (C3-C8).

    Run on the fresh plans of this very command: a plan from an earlier dry run is never
    trusted. Operation refusals come from the plans; the apply-time preconditions are judged
    here from `ctx`, for no-ops too (invariant 8: every --apply). Empty means the write may
    go ahead. With `applying=False` (a dry run) the result is what the plan prints as "apply
    would be refused", and a missing confirm is not counted.
    """
    if applying and (not isinstance(reason, str) or not reason.strip()):
        raise ValueError("--apply without --reason is a usage error the grammar refuses first")
    found = [plan.refusal for plan in plans if plan.refusal is not None]
    op = plans[0].op
    found += [check.refusal() for check in _preconditions(ctx, op) if check.result == "fail"]
    confirmed = _confirm(plans, confirm, applying)
    if confirmed is not None:
        found.append(confirmed)
    # sorted() is stable: refusals from the same check keep the targets' argument order.
    return sorted(found, key=lambda refusal: _order(refusal.check))
