# ABOUTME: Tests for tailnet.guard, the pure write guard: risk classes, the checks of DESIGN.md §12.2-12.5,
# ABOUTME: confirm tokens, the tag rules and the apply line, all decided without any I/O.

import ast
import shlex
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fixturefiles import body

from tailnet import credentials, devices, errors, guard, protected, selfnode

NOW = datetime(2026, 10, 27, 1, 2, 3, tzinfo=timezone.utc)
SETTINGS = "/home/mc/.claude/settings.json"

# A synthetic policy shaped like MC's, in the JSON form the API serves with Accept:
# application/json. tag:fleet owns itself, tag:lab and tag:ci, so the write client tagged
# tag:fleet may assign those (TAGS L324); tag:dev it may not.
POLICY = {
    "tagOwners": {
        "tag:fleet": ["autogroup:admin", "tag:fleet"],
        "tag:dev": ["autogroup:admin"],
        "tag:lab": ["tag:fleet"],
        "tag:ci": ["autogroup:admin", "tag:fleet"],
    },
    "grants": [
        {"src": ["autogroup:member"], "dst": ["tag:fleet"], "ip": ["*"]},
        {"src": ["tag:dev"], "dst": ["tag:lab", "tag:fleet"], "ip": ["22"]},
    ],
    "acls": [{"action": "accept", "src": ["tag:lab"], "dst": ["tag:fleet:22"]}],
    "ssh": [{"action": "accept", "src": ["tag:dev"], "dst": ["tag:lab"], "users": ["root"]}],
    "tests": [{"src": "tag:dev", "accept": ["tag:lab:22"], "deny": ["tag:lab2:22"]}],
    "sshTests": [{"src": "tag:dev", "dst": ["tag:lab"], "accept": ["root"]}],
    "autoApprovers": {"routes": {"10.0.0.0/24": ["tag:lab"]}, "exitNode": ["tag:fleet"]},
}


def device(name, /, **fields):
    """One of the scenario's six devices, by hostname, with API fields changed (None drops one)."""
    raw = next(d for d in body("scenario", "devices")["devices"] if d["hostname"] == name)
    for key, value in fields.items():
        if value is None:
            raw.pop(key, None)
        else:
            raw[key] = value
    return devices.normalise(raw)


def listed(text="self nFactory1CNTRL\nspec5\n"):
    """MC's protected list: by default self is the droplet and spec5 is protected."""
    return protected.parse(text)


def write_meta(tags=("tag:fleet",)):
    """write.json's metadata as `credentials set write` records it; no secret is involved."""
    return credentials.WriteMeta("kWrite0001CNTRL", Path("/nonexistent/write.secret"), tags,
                                 "self-lookup", "devices:core", "2026-10-26T20:00:00Z")


def known_self():
    """Self found the production way: the droplet, joined by its Tailscale IPs."""
    return selfnode.SelfNode(True, device("claude-factory"), "live", True, None, None)


def unknown_self(reason="tailscale is not running"):
    """Self not found: every --apply refuses on it."""
    return selfnode.SelfNode(False, None, None, None, reason, "SELF_UNKNOWN")


def context(**changes):
    """A context where every apply-time precondition holds; `changes` break one at a time."""
    fields = {"me": known_self(), "protected": listed(), "gate_present": True,
              "settings_path": SETTINGS, "write": write_meta(), "now": NOW, "policy": POLICY,
              "policy_error": None}
    fields.update(changes)
    return guard.Context(**fields)


def codes(plans, ctx, confirm=None, reason="why", **kwargs):
    """The refusal codes check_apply gives, in the order it gives them."""
    return [r.code for r in guard.check_apply(plans, ctx, confirm, reason, **kwargs)]


def check(plan, code):
    """The plan's check entry for one refusal code."""
    [found] = [c for c in plan.checks if c["code"] == code]
    return found


def test_unknown_self_refuses_every_apply():
    disagreeing = selfnode.SelfNode(False, device("claude-factory"), "live", True,
                                    "the self line names another device", "SELF_LINE_DISAGREES")
    for me in (unknown_self(), disagreeing):
        ctx = context(me=me)
        batches = [[guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)],
                   guard.plan_disable_key_expiry([device("pi5")], ctx),
                   # A no-op is no exception: invariant 8 says every --apply.
                   guard.plan_disable_key_expiry([device("claude-factory")], ctx)]
        for plans in batches:
            confirm = plans[0].confirm_required
            assert codes(plans, ctx, confirm) == [me.refusal]
            # It is an apply-time precondition: the dry run still shows the plan.
            assert plans[0].refusal is None
            assert check(plans[0], me.refusal)["result"] == "fail"
            assert codes(plans, ctx, applying=False) == [me.refusal]
            assert not guard.check_apply(plans, ctx, None, None, applying=False)[0].operation


def test_a_missing_gate_refuses_every_apply():
    ctx = context(gate_present=False)
    for plans in ([guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)],
                  guard.plan_disable_key_expiry([device("pi5"), device("spec5")], ctx),
                  guard.plan_disable_key_expiry([device("claude-factory")], ctx)):
        [refusal] = guard.check_apply(plans, ctx, plans[0].confirm_required, "why")
        assert refusal.code == "GATE_MISSING"
        assert SETTINGS in refusal.message and "installer" in refusal.message
        assert refusal.next and refusal.next[0]["who"] == "mc"


def test_an_unanswered_protected_list_refuses_tag_writes():
    ctx = context(protected=None)
    for target, confirm in ((device("pi5"), "retag:pi5"), (device("albini"), "strip-owner:albini")):
        plan = guard.plan_tag(target, ["tag:fleet"] if not target.tags else ["tag:lab"], [], ctx)
        assert codes([plan], ctx, confirm) == ["PROTECTED_UNANSWERED"]
        # Apply-time, not operation: the dry run prints the plan and the warning.
        assert plan.refusal is None
        assert check(plan, "PROTECTED_UNANSWERED")["result"] == "fail"


def test_an_unanswered_protected_list_allows_disable_key_expiry():
    # D7: the outcome does not depend on which devices are protected, and this is the write
    # that keeps a box on the tailnet; it must not wait on MC's list.
    ctx = context(protected=None)
    plans = guard.plan_disable_key_expiry([device("spec5"), device("nomad-b"), device("pi5")], ctx)
    assert codes(plans, ctx) == []
    [plan] = guard.plan_disable_key_expiry([device("albini")], ctx)
    assert codes([plan], ctx, "no-expiry:albini") == []
    assert not [c for c in plan.checks if c["code"] == "PROTECTED_UNANSWERED"]


def test_disable_key_expiry_on_a_tagged_device_needs_no_confirm():
    ctx = context()
    [plan] = guard.plan_disable_key_expiry([device("pi5")], ctx)
    assert (plan.op, plan.cls, plan.confirm_required) == ("device.disable-key-expiry", "R1", None)
    assert plan.after == {"keyExpiryDisabled": True}
    assert codes([plan], ctx) == []
    assert "--confirm" not in plan.apply_argv
    # A confirm where none is needed may be a stale plan's token: refused, not ignored.
    assert codes([plan], ctx, "no-expiry:pi5") == ["CONFIRM_MISMATCH"]


def test_disable_key_expiry_on_a_user_device_needs_the_no_expiry_confirm():
    ctx = context()
    [plan] = guard.plan_disable_key_expiry([device("albini")], ctx)
    assert (plan.cls, plan.confirm_required) == ("R2", "no-expiry:albini")
    assert codes([plan], ctx) == ["CONFIRM_MISSING"]
    assert codes([plan], ctx, "no-expiry:albini") == []
    # A dry run without --confirm is not refused: the apply line it prints carries the token.
    assert codes([plan], ctx, applying=False) == []


def test_disable_key_expiry_is_allowed_on_protected_devices_and_self():
    ctx = context(protected=listed("self nFactory1CNTRL\nspec5\nnomad-b\n"))
    factory = device("claude-factory", keyExpiryDisabled=False)
    plans = guard.plan_disable_key_expiry([factory, device("spec5"), device("nomad-b")], ctx)
    assert [p.refusal for p in plans] == [None, None, None]
    assert codes(plans, ctx) == []


def test_already_disabled_is_a_noop():
    ctx = context()
    [plan] = guard.plan_disable_key_expiry([device("claude-factory")], ctx)
    assert plan.noop is True and plan.refusal is None
    assert codes([plan], ctx) == []
    [plan] = guard.plan_disable_key_expiry([device("pi5")], ctx)
    assert plan.noop is False
    # An unknown expiry state is not taken as already off: the write is planned.
    [plan] = guard.plan_disable_key_expiry([device("pi5", keyExpiryDisabled=None)], ctx)
    assert plan.noop is False


def test_an_expired_key_warns_but_is_not_refused():
    ctx = context()
    [plan] = guard.plan_disable_key_expiry([device("pi5", expires="2026-10-01T00:00:00Z")], ctx)
    assert plan.refusal is None and codes([plan], ctx) == []
    [warning] = [w for w in plan.warnings if w["code"] == "KEY_ALREADY_EXPIRED"]
    assert "[unverified]" in warning["message"] and "re-authentication" in warning["message"]
    assert warning["source"] == "spec 606-607"
    [plan] = guard.plan_disable_key_expiry([device("pi5")], ctx)
    assert not plan.warnings


def test_shared_in_devices_are_refused():
    ctx = context()
    shared = device("pi5", isExternal=True)
    # Membership the API did not state is refused too, rather than assumed.
    unstated = device("pi5", isExternal=None)
    for target in (shared, unstated):
        for plan in (guard.plan_tag(target, ["tag:lab"], [], ctx),
                     guard.plan_disable_key_expiry([target], ctx)[0]):
            assert plan.refusal.code == "SHARED_IN"
            assert plan.refusal.operation
            assert codes([plan], ctx, plan.confirm_required) == ["SHARED_IN"]


def test_a_retag_needs_the_retag_confirm():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    assert (plan.op, plan.cls, plan.confirm_required) == ("device.tag", "R2", "retag:pi5")
    assert codes([plan], ctx) == ["CONFIRM_MISSING"]
    assert codes([plan], ctx, "retag:pi5") == []


def test_first_tag_on_a_user_device_needs_the_strip_owner_confirm():
    ctx = context()
    plan = guard.plan_tag(device("albini"), ["tag:fleet"], [], ctx)
    # Tagging a user-owned device removes its owner, and no tag removal brings them back.
    assert (plan.cls, plan.confirm_required) == ("R3", "strip-owner:albini")
    assert codes([plan], ctx, "retag:albini") == ["CONFIRM_MISMATCH"]
    assert codes([plan], ctx, "strip-owner:albini") == []


def test_the_confirm_must_match_exactly():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    for wrong in ("retag:PI5", "retag:pi5 ", " retag:pi5", "strip-owner:pi5", "retag:",
                  "retag:nPi5x001CNTRL", "no-expiry:pi5"):
        assert codes([plan], ctx, wrong) == ["CONFIRM_MISMATCH"], wrong
    assert codes([plan], ctx, "retag:pi5") == []
    # A dry run given a wrong token says so, so a stale token is caught before the prompt.
    assert codes([plan], ctx, "retag:PI5", applying=False) == ["CONFIRM_MISMATCH"]


def test_a_confirm_for_a_renamed_device_is_refused():
    ctx = context()
    renamed = device("pi5", hostname="pi5-lab")
    plan = guard.plan_tag(renamed, ["tag:lab"], [], ctx)
    assert plan.confirm_required == "retag:pi5-lab"
    [refusal] = guard.check_apply([plan], ctx, "retag:pi5", "why")
    assert refusal.code == "CONFIRM_MISMATCH"
    assert "pi5-lab" in refusal.message and "renamed" in refusal.message
    # The way out is a fresh dry run, which prints the token for the device as it is now.
    assert refusal.next[0]["run"].startswith("tailnet device tag nPi5x001CNTRL --add tag:lab")
    assert "--apply" not in refusal.next[0]["run"]


def test_a_tag_plan_warns_of_protected_lines_that_match_no_device_by_number_only():
    # A line for a device since renamed or removed, or a typo, protects nothing; the plan the
    # agent relays says so rather than a bare "not on MC's protected list" (A59). The file
    # sits behind a deny rule, so the warning names lines, never what they say (A19).
    found = [device(name) for name in ("claude-factory", "spec5", "pi5", "albini")]
    ctx = context(protected=listed("self nFactory1CNTRL\nspec5\noldbox\n100.64.9.9\n"),
                  devices=tuple(found))
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    [warning] = plan.warnings
    assert warning["code"] == "PROTECTED_LINE_UNMATCHED"
    assert "lines 3, 4" in warning["message"] and "oldbox" not in warning["message"]
    assert check(plan, "PROTECTED_DEVICE")["result"] == "pass"
    # Every line naming a device, or no inventory to judge by: nothing to say.
    assert guard.plan_tag(device("pi5"), ["tag:lab"], [], context(devices=tuple(found))) \
        .warnings == ()
    assert guard.plan_tag(device("pi5"), ["tag:lab"], [], context(
        protected=listed("self nFactory1CNTRL\noldbox\n"))).warnings == ()


def test_every_tag_change_on_a_protected_device_is_refused():
    by_name = listed("self nFactory1CNTRL\nspec5\n")
    by_node_id = listed("self nFactory1CNTRL\nnSpec5x1CNTRL\n")
    by_label = listed("self nFactory1CNTRL\nSPEC5\n")
    for protected_list in (by_name, by_node_id, by_label):
        ctx = context(protected=protected_list)
        for add, remove in ((["tag:lab"], []), ([], ["tag:fleet"]), (["tag:fleet"], []),
                            (["tag:ci"], ["tag:fleet"])):
            plan = guard.plan_tag(device("spec5"), add, remove, ctx)
            # A no-op included: the guard refuses the request, not only the change.
            assert plan.refusal.code == "PROTECTED_DEVICE", (add, remove)
            assert plan.refusal.operation
            assert "spec5" in plan.refusal.message
            assert codes([plan], ctx, "retag:spec5") == ["PROTECTED_DEVICE"]


def test_every_tag_change_on_self_is_refused_even_when_unlisted():
    ctx = context(protected=listed("self nFactory1CNTRL\n"))
    for add, remove in ((["tag:fleet"], []), ([], ["tag:dev"]), (["tag:dev"], [])):
        plan = guard.plan_tag(device("claude-factory"), add, remove, ctx)
        assert plan.refusal.code == "SELF_DEVICE", (add, remove)
    # When the live join and MC's self line disagree, both devices count as self.
    disagreeing = selfnode.SelfNode(False, device("claude-factory"), "live", True,
                                    "the self line names nNomadB1CNTRL", "SELF_LINE_DISAGREES")
    ctx = context(me=disagreeing, protected=listed("self nNomadB1CNTRL\n"))
    for name in ("claude-factory", "nomad-b"):
        plan = guard.plan_tag(device(name), ["tag:lab"], [], ctx)
        assert plan.refusal.code == "SELF_DEVICE", name


def test_the_new_set_is_computed_from_the_fresh_pre_read():
    ctx = context()
    planned = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    assert planned.before["tags"] == ["tag:fleet"]
    assert planned.after == {"tags": ["tag:fleet", "tag:lab"]}
    # The console added tag:ci in the meantime: the same request keeps it (D9).
    fresh = guard.plan_tag(device("pi5", tags=["tag:fleet", "tag:ci"]), ["tag:lab"], [], ctx)
    assert fresh.after == {"tags": ["tag:ci", "tag:fleet", "tag:lab"]}
    # The apply line carries the delta, never the full set, so it means the same either way.
    assert fresh.apply_argv == planned.apply_argv


def test_an_empty_resulting_set_is_refused():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), [], ["tag:fleet"], ctx)
    assert plan.after == {"tags": []}
    assert plan.refusal.code == "TAG_SET_EMPTY"
    assert "TAGS L33" in plan.refusal.message


def test_removing_an_absent_tag_is_refused():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), [], ["tag:lab"], ctx)
    assert plan.refusal.code == "TAG_NOT_PRESENT"
    assert "tag:lab" in plan.refusal.message and "tag:fleet" in plan.refusal.message
    # Also when the set would be unchanged: an absent tag is a typo, not a no-op.
    assert plan.noop is True


def test_a_tag_missing_from_tag_owners_is_refused():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:nope"], [], ctx)
    assert plan.refusal.code == "TAG_UNDEFINED"
    assert "tag:nope" in plan.refusal.message and "spec 548" in plan.refusal.message
    # Without the policy there is no tagOwners to check against: refused, never guessed.
    ctx = context(policy=None, policy_error="GET /tailnet/-/acl → 500")
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    assert plan.refusal.code == "POLICY_UNREADABLE"
    assert "500" in plan.refusal.message


def test_the_client_may_assign_its_exact_tag_set():
    # TAGS L324: an exact match needs no tagOwners at all.
    assert guard.client_may_assign(["tag:fleet"], ["tag:fleet"], {})
    assert guard.client_may_assign(["tag:lab", "tag:fleet"], ["TAG:Fleet", "tag:lab"], {})
    assert not guard.client_may_assign(["tag:fleet"], ["tag:fleet", "tag:lab"], {})
    assert not guard.client_may_assign([], [], {})


def test_the_client_may_assign_tags_its_tag_owns():
    owners = {"tag:lab": ["tag:fleet"], "tag:ci": ["autogroup:admin", "tag:fleet"]}
    assert guard.client_may_assign(["tag:ci", "tag:lab"], ["tag:fleet"], owners)
    assert guard.client_may_assign(["tag:lab"], ["tag:other", "tag:fleet"], owners)
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:lab", "tag:ci"], [], ctx)
    assert plan.refusal is None
    assert check(plan, "CLIENT_CANNOT_ASSIGN")["result"] == "pass"


def test_a_set_the_client_cannot_assign_is_refused():
    # tag:fleet does not own itself here, so the client may assign exactly [tag:fleet] and
    # nothing that includes it alongside another tag.
    owners = {"tag:fleet": ["autogroup:admin"], "tag:lab": ["tag:fleet"]}
    assert not guard.client_may_assign(["tag:fleet", "tag:lab"], ["tag:fleet"], owners)
    assert not guard.client_may_assign(["tag:dev"], ["tag:fleet"], POLICY["tagOwners"])
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:dev"], [], ctx)
    assert plan.refusal.code == "CLIENT_CANNOT_ASSIGN"
    assert "TAGS L324" in plan.refusal.message and "tag:fleet" in plan.refusal.message


def test_unrecorded_client_tags_refuse_tag_writes():
    ctx = context(write=write_meta(tags=None))
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    assert plan.refusal.code == "WRITE_CLIENT_TAGS_UNRECORDED"
    assert "credentials set write" in plan.refusal.message
    # No write client at all is C8's refusal, at apply time: the dry run still plans.
    ctx = context(write=None)
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx)
    assert plan.refusal is None
    assert check(plan, "CLIENT_CANNOT_ASSIGN")["result"] == "skip"
    assert codes([plan], ctx, "retag:pi5") == ["WRITE_CREDENTIAL_MISSING"]


def test_tags_are_lowercased():
    ctx = context()
    plan = guard.plan_tag(device("pi5", tags=["tag:Fleet"]), ["TAG:Lab"], [], ctx)
    assert plan.after == {"tags": ["tag:fleet", "tag:lab"]}
    assert "tag:lab" in plan.apply_argv and "TAG:Lab" not in plan.apply_argv
    assert guard.parse_tags(["TAG:Lab", "tag:lab"], ["Tag:CI"]) == (("tag:lab",), ("tag:ci",))
    for bad in ("lab", "tag:", "tag:-lab", "tag:la b", "tag:la_b", " tag:lab", "tag:lab:22", "*"):
        with pytest.raises(errors.UsageError) as caught:
            guard.parse_tags([bad], [])
        assert caught.value.code == "TAG_MALFORMED", bad
    with pytest.raises(errors.UsageError) as caught:
        guard.parse_tags(["tag:Lab"], ["tag:lab"])
    assert caught.value.code == "TAG_ADD_AND_REMOVE"


def test_an_unchanged_set_is_a_noop():
    ctx = context()
    plan = guard.plan_tag(device("pi5"), ["tag:fleet"], [], ctx)
    assert plan.noop is True and plan.refusal is None
    assert plan.after == {"tags": ["tag:fleet"]}
    assert guard.plan_tag(device("pi5"), ["tag:lab"], [], ctx).noop is False


def test_rule_references_list_every_policy_path_naming_the_tags():
    assert guard.rule_references(POLICY, ["tag:lab"]) == [
        'tagOwners["tag:lab"]', "grants[1].dst", "acls[0].src", "ssh[0].dst",
        "tests[0].accept", "sshTests[0].dst", 'autoApprovers.routes["10.0.0.0/24"]',
    ]
    # Whole tags only: tag:lab2 is another tag, and a port suffix still names the tag.
    assert "tests[0].deny" not in guard.rule_references(POLICY, ["tag:lab"])
    assert "acls[0].dst" in guard.rule_references(POLICY, ["TAG:FLEET"])
    assert guard.rule_references(POLICY, ["tag:none"]) == []
    # The plan shows them for each tag that changes, so MC sees what the change touches.
    plan = guard.plan_tag(device("pi5"), ["tag:lab"], [], context())
    assert any(line.startswith("policy: tag:lab appears in tagOwners") for line in
               plan.consequences)


def test_strip_owner_consequences_include_expiry_and_recovery():
    plan = guard.plan_tag(device("albini"), ["tag:fleet"], [], context())
    text = "\n".join(plan.consequences)
    assert "removes mc@example.com as owner; you cannot remove all tags afterwards" in text
    assert "autogroup:self rules and the default SSH rule stop covering it" in text
    assert "Taildrop and same-user netmap visibility end" in text
    assert ("key expiry is unchanged by tagging: ON, expires 2099-01-01T00:00:00Z" in text
            and "tailnet device disable-key-expiry nAlbini1CNTRL" in text)
    assert "recovery: re-authenticate on the device as the user" in text
    # A retag of an already tagged device carries none of the owner lines.
    retag = "\n".join(guard.plan_tag(device("pi5"), ["tag:lab"], [], context()).consequences)
    assert "as owner" not in retag and "key expiry is unchanged" in retag


def test_multi_target_requires_every_target_tagged():
    ctx = context()
    plans = guard.plan_disable_key_expiry([device("pi5"), device("albini")], ctx)
    assert plans[0].refusal is None
    assert plans[1].refusal.code == "MULTI_TARGET_NOT_R1" and plans[1].refusal.operation
    assert codes(plans, ctx) == ["MULTI_TARGET_NOT_R1"]
    plans = guard.plan_disable_key_expiry([device("spec5"), device("nomad-b"), device("pi5")], ctx)
    assert [p.cls for p in plans] == ["R1", "R1", "R1"]
    assert codes(plans, ctx) == []
    # Alone, a user-owned device is planned as R2 with its confirm.
    [alone] = guard.plan_disable_key_expiry([device("albini")], ctx)
    assert alone.refusal is None and alone.cls == "R2"


def test_a_refused_target_refuses_the_whole_batch():
    ctx = context()
    plans = guard.plan_disable_key_expiry([device("pi5"), device("spec5", isExternal=True)], ctx)
    [refusal] = guard.check_apply(plans, ctx, None, "why")
    assert (refusal.code, refusal.node_id) == ("SHARED_IN", "nSpec5x1CNTRL")
    # A no-op target is reported and skipped; it never refuses the batch.
    plans = guard.plan_disable_key_expiry([device("claude-factory"), device("pi5")], ctx)
    assert [p.noop for p in plans] == [True, False]
    assert codes(plans, ctx) == []


def test_the_apply_line_uses_the_node_id_and_the_printed_confirm():
    ctx = context()
    plan = guard.plan_tag(device("pi5", tags=["tag:fleet", "tag:lab"]), [], ["tag:lab"], ctx)
    assert plan.apply_argv == ("tailnet", "device", "tag", "nPi5x001CNTRL", "--remove", "tag:lab",
                               "--confirm", "retag:pi5", "--apply", "--reason", "<why>")
    assert plan.apply_line == ('tailnet device tag nPi5x001CNTRL --remove tag:lab --confirm '
                               'retag:pi5 --apply --reason "<why>"')
    plans = guard.plan_disable_key_expiry([device("spec5"), device("pi5")], ctx)
    assert {p.apply_line for p in plans} == {
        'tailnet device disable-key-expiry nSpec5x1CNTRL nPi5x001CNTRL --apply --reason "<why>"'}
    # A hostname a shell would split is quoted, and the line parses back to the same argv.
    odd = guard.plan_tag(device("albini", hostname="MC's Mac"), ["tag:fleet"], [], ctx)
    assert odd.confirm_required == "strip-owner:MC's Mac"
    assert tuple(shlex.split(odd.apply_line)) == odd.apply_argv


def test_the_guard_does_no_io():
    # Pure planning is what makes every rule above testable without a server or a file.
    tree = ast.parse(Path(guard.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported |= {f"{node.module}.{alias.name}" for alias in node.names}
    assert imported <= {"re", "shlex", "dataclasses.dataclass", "dataclasses.field",
                        "tailnet.errors.UsageError"}, imported
