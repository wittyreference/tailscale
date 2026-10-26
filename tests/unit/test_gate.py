# ABOUTME: Tests for tailnet.gate and src/tailnet/rules.json: the Claude Code ask and deny rules the CLI
# ABOUTME: relies on, and how it tells whether MC's settings still hold them (DESIGN.md §11.5, §20.4).

import json
import os

import pytest

from tailnet import gate
from tailnet.posture import Posture

GATE = "Bash(*tailnet*--apply*)"
# DESIGN.md §20.4, verbatim: the single source every reader of rules.json must agree with.
DESIGNED = {
    "v": 1,
    "gate": GATE,
    "ask": [
        "Bash(*tailnet*--apply*)",
        "Bash(*api.tailscale.com*)",
        "WebFetch(domain:api.tailscale.com)",
        "Edit(~/.claude/settings.json)",
        "Bash(*.claude/settings.json*)",
        "Bash(*install-tailnet*)",
    ],
    "deny": [
        "Read(~/.config/tailnet/**)",
        "Edit(~/.config/tailnet/**)",
        "Bash(*.config/tailnet*)",
        "Edit(~/.local/state/tailnet/audit.jsonl)",
    ],
}


def settings(path, *, ask=(), deny=(), **extra):
    """Write a Claude Code settings file holding these rules, and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": {"ask": list(ask), "deny": list(deny)}, **extra}))
    return path


def every_rule(claude_dir=None):
    """The ask and deny lists a full install writes for this Claude directory."""
    expected = gate.rules_for(claude_dir)
    return expected["ask"], expected["deny"]


def test_rules_json_is_the_designed_set():
    assert gate.rules() == DESIGNED
    # No Write(path) rules: they are accepted but never match [PERM L358-360]; and no allow
    # rules, because an installer an agent runs must never loosen MC's permissions (D25).
    strings = DESIGNED["ask"] + DESIGNED["deny"]
    assert not [rule for rule in strings if rule.startswith("Write(")]
    assert "allow" not in gate.rules()


def test_all_rules_present_reports_none_missing(tmp_path):
    ask, deny = every_rule()
    path = settings(tmp_path / "settings.json", ask=ask, deny=deny, defaultMode="default")
    assert gate.missing_rules(path) == []
    assert gate.gate_present(path)


def test_a_missing_gate_rule_is_reported(tmp_path):
    ask, deny = every_rule()
    path = settings(tmp_path / "settings.json", ask=[r for r in ask if r != GATE], deny=deny)
    assert gate.missing_rules(path) == [GATE]
    assert not gate.gate_present(path)
    # The gate counts only as an ask rule: in deny or allow it puts nothing in front of MC.
    path = settings(tmp_path / "settings.json", deny=[*deny, GATE], allow=[GATE])
    assert not gate.gate_present(path)
    # Each other rule is reported by its exact text, in rules.json order.
    path = settings(tmp_path / "settings.json", ask=ask[:-1], deny=deny[1:])
    assert gate.missing_rules(path) == [ask[-1], deny[0]]


@pytest.mark.parametrize("content", [
    "{not json", "", "[]", '"permissions"', '{"permissions": []}',
    '{"permissions": {"ask": "Bash(*tailnet*--apply*)", "deny": {}}}',
])
def test_an_unparseable_settings_file_counts_every_rule_missing(tmp_path, content):
    path = tmp_path / "settings.json"
    path.write_text(content)
    ask, deny = every_rule()
    assert gate.missing_rules(path) == ask + deny
    assert not gate.gate_present(path)


@pytest.mark.parametrize("extra", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_a_settings_file_claude_code_would_skip_holds_no_rule(tmp_path, extra):
    # Claude Code parses settings as strict JSON and skips a file that fails whole; Python's
    # json reads NaN and Infinity, and 1e400 only as inf, which it can never write back.
    ask, deny = every_rule()
    path = tmp_path / "settings.json"
    path.write_text('{"permissions": ' + json.dumps({"ask": ask, "deny": deny})
                    + ', "x-note": ' + extra + "}")
    assert gate.missing_rules(path) == ask + deny
    assert not gate.gate_present(path)


def test_a_missing_or_unreadable_settings_file_counts_every_rule_missing(tmp_path):
    ask, deny = every_rule()
    assert gate.missing_rules(tmp_path / "absent.json") == ask + deny
    assert not gate.gate_present(tmp_path / "absent.json")
    # A FIFO where the file belongs is never opened for a blocking read.
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    assert gate.missing_rules(fifo) == ask + deny
    directory = tmp_path / "dir.json"
    directory.mkdir()
    assert not gate.gate_present(directory)
    # A settings file far past any real one's size is not read at all.
    huge = settings(tmp_path / "huge.json", ask=ask, deny=deny, padding="x" * gate.SETTINGS_MAX)
    assert gate.missing_rules(huge) == ask + deny


def test_claude_config_dir_is_honoured(tmp_path):
    claude = "/home/mc/.claude-alt"
    ask, deny = every_rule(claude)
    # The two rules guarding the settings file name its real path (§20.4); `//` anchors a
    # Claude Code path rule at the filesystem root [PERM L370].
    assert "Edit(//home/mc/.claude-alt/settings.json)" in ask
    assert "Bash(*/home/mc/.claude-alt/settings.json*)" in ask
    assert "Edit(~/.claude/settings.json)" not in ask
    assert "Bash(*.claude/settings.json*)" not in ask
    # Every other rule, the gate above all, never changes.
    unchanged = [r for r in DESIGNED["ask"] if "settings.json" not in r]
    assert [r for r in ask if "settings.json" not in r] == unchanged
    assert deny == DESIGNED["deny"]
    assert gate.rules_for(claude + "/") == gate.rules_for(claude)
    # A settings file holding the default forms is missing exactly the two absolute ones.
    path = settings(tmp_path / "settings.json", ask=DESIGNED["ask"], deny=DESIGNED["deny"])
    assert gate.missing_rules(path, claude) == ["Edit(//home/mc/.claude-alt/settings.json)",
                                                "Bash(*/home/mc/.claude-alt/settings.json*)"]
    with pytest.raises(ValueError):
        gate.rules_for("relative/.claude")


def test_every_settings_rule_has_an_absolute_form():
    # rules_for rewrites the settings rules by their exact text, so a rule naming the settings
    # file that it does not know would be left pointing at the default path.
    named = [r for r in DESIGNED["ask"] + DESIGNED["deny"] if "settings.json" in r]
    assert sorted(named) == sorted(gate.SETTINGS_RULE_FORMS)


def test_the_claude_dir_comes_from_the_posture_and_claude_config_dir(tmp_path):
    production = Posture.from_env({}, real_home=tmp_path / "home")
    assert gate.claude_dir(production, {}) is None
    assert gate.claude_dir(production, {"CLAUDE_CONFIG_DIR": ""}) is None
    assert gate.claude_dir(production, {"CLAUDE_CONFIG_DIR": "/srv/claude"}) == "/srv/claude"
    test = Posture.from_env({"TAILNET_API_BASE": "http://127.0.0.1:9",
                             "TAILNET_HOME": str(tmp_path / "tn")}, real_home=tmp_path / "home")
    # Test posture's settings live under its own home, which acts as the Claude directory.
    assert gate.claude_dir(test, {"CLAUDE_CONFIG_DIR": "/srv/claude"}) == str(
        test.claude_settings.parent)
