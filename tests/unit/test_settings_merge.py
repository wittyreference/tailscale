# ABOUTME: Tests for installer/settings_merge.py: how tailnet's ask and deny rules go into MC's Claude Code
# ABOUTME: settings.json and come out again, never touching another entry (DESIGN.md §20.4).

import json
import os
from datetime import datetime, timezone

import pytest
import settings_merge

from tailnet import gate

NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)
RULES = gate.rules_for(None)
BACKUP = "settings.json.tailnet-bak-20261026T120000Z"


def write(path, doc, mode=0o600):
    """Write a settings document as Claude Code might have left it, with an exact mode."""
    path.write_text(json.dumps(doc), encoding="utf-8")
    path.chmod(mode)
    return path


def backups(directory):
    """Every backup the merge left in a directory."""
    return sorted(p.name for p in directory.iterdir() if ".tailnet-bak-" in p.name)


def test_a_missing_settings_file_is_created_with_only_our_rules(tmp_path):
    path = tmp_path / "settings.json"
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    assert outcome.status == "changed"
    assert outcome.added == {"ask": RULES["ask"], "deny": RULES["deny"]}
    assert json.loads(path.read_text()) == {"permissions": {"ask": RULES["ask"],
                                                            "deny": RULES["deny"]}}
    # A new settings file is MC's alone: 0600 whatever the umask. There was nothing to back up.
    assert path.stat().st_mode & 0o777 == 0o600
    assert outcome.backup is None and backups(tmp_path) == []
    # Pretty-printed, two spaces, with a trailing newline.
    assert path.read_text().endswith("]\n  }\n}\n")
    # Every rule is present for the gate check that status, doctor and the guard run.
    assert gate.missing_rules(path) == []


def test_existing_rules_and_keys_are_kept_in_order():
    settings = {
        "$schema": "https://json.schemastore.org/claude-code-settings.json",
        "permissions": {"allow": ["Bash(npm test)"], "ask": ["Bash(git push*)"],
                        "defaultMode": "acceptEdits", "deny": ["Read(./.env)"],
                        "additionalDirectories": ["/srv"]},
        "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}]},
        "env": {"EDITOR": "vi"},
    }
    before = json.loads(json.dumps(settings))
    new, added = settings_merge.merge(settings, RULES["ask"], RULES["deny"])
    assert added == {"ask": RULES["ask"], "deny": RULES["deny"]}
    # Our strings are appended after MC's own; nothing of MC's moves, changes or goes.
    assert new["permissions"]["ask"] == ["Bash(git push*)", *RULES["ask"]]
    assert new["permissions"]["deny"] == ["Read(./.env)", *RULES["deny"]]
    assert new["permissions"]["allow"] == ["Bash(npm test)"]
    assert list(new) == list(settings)
    assert list(new["permissions"]) == list(settings["permissions"])
    assert {k: v for k, v in new.items() if k != "permissions"} == {
        k: v for k, v in before.items() if k != "permissions"}
    # The input is never changed in place.
    assert settings == before
    # A rule MC already has is not added twice, and lists that are missing are created.
    new, added = settings_merge.merge({"permissions": {"ask": [RULES["ask"][0]]}},
                                      RULES["ask"], RULES["deny"])
    assert added["ask"] == RULES["ask"][1:]
    assert new["permissions"]["ask"] == RULES["ask"]
    assert new["permissions"]["deny"] == RULES["deny"]


def test_a_second_merge_adds_nothing_and_makes_no_backup(tmp_path):
    path = tmp_path / "settings.json"
    settings_merge.merge_file(path, RULES, now=NOW)
    first = path.read_bytes()
    stamp = path.stat().st_mtime_ns
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    assert outcome.status == "unchanged"
    assert outcome.added == {"ask": [], "deny": []}
    assert path.read_bytes() == first and path.stat().st_mtime_ns == stamp
    assert backups(tmp_path) == []
    # The pure merge agrees: nothing added means the same document back.
    settings = json.loads(first)
    assert settings_merge.merge(settings, RULES["ask"], RULES["deny"]) == (
        settings, {"ask": [], "deny": []})


@pytest.mark.parametrize("content", ["{not json", "", '{"permissions": {"ask": [}}',
                                     b"\xff\xfe{}"])
def test_invalid_json_aborts_without_writing(tmp_path, content):
    path = tmp_path / "settings.json"
    raw = content if isinstance(content, bytes) else content.encode()
    path.write_bytes(raw)
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    assert outcome.status == "aborted"
    assert "not valid JSON" in outcome.message
    assert path.read_bytes() == raw
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]
    # MC gets the rules to add by hand, every one of them, rather than a guessed repair.
    for rule in RULES["ask"] + RULES["deny"]:
        assert json.dumps(rule) in outcome.message


@pytest.mark.parametrize("doc, why", [
    ({"permissions": []}, "`permissions` is not an object"),
    ({"permissions": "ask"}, "`permissions` is not an object"),
    ({"permissions": None}, "`permissions` is not an object"),
    ({"permissions": {"ask": "Bash(*)"}}, "`permissions.ask` is not a list"),
    ({"permissions": {"ask": [], "deny": {}}}, "`permissions.deny` is not a list"),
    ([], "not a JSON object"),
])
def test_a_non_object_permissions_value_aborts_without_writing(tmp_path, doc, why):
    path = write(tmp_path / "settings.json", doc)
    raw = path.read_bytes()
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    assert outcome.status == "aborted" and why in outcome.message
    assert path.read_bytes() == raw
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]
    with pytest.raises(settings_merge.Unmergeable, match="not"):
        settings_merge.merge(doc, RULES["ask"], RULES["deny"])
    with pytest.raises(settings_merge.Unmergeable):
        settings_merge.remove(doc, RULES)


def test_a_symlinked_oversized_or_special_settings_file_aborts_without_writing(tmp_path):
    # A settings.json that is a link into MC's dotfiles stays a link: replacing it would
    # quietly cut the link and leave a plain file behind (amendment A36).
    real = write(tmp_path / "dotfiles-settings.json", {"permissions": {}})
    link = tmp_path / "claude" / "settings.json"
    link.parent.mkdir()
    link.symlink_to(real)
    outcome = settings_merge.merge_file(link, RULES, now=NOW)
    assert outcome.status == "aborted" and "symlink" in outcome.message
    assert link.is_symlink() and json.loads(real.read_text()) == {"permissions": {}}
    # One past the size status and doctor will read would never count as holding the rules.
    huge = write(tmp_path / "huge.json", {"pad": "x" * gate.SETTINGS_MAX})
    raw = huge.read_bytes()
    outcome = settings_merge.merge_file(huge, RULES, now=NOW)
    assert outcome.status == "aborted" and "byte limit" in outcome.message
    assert huge.read_bytes() == raw
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    assert settings_merge.merge_file(fifo, RULES, now=NOW).status == "aborted"


def test_a_backup_precedes_any_change(tmp_path, syscalls):
    path = write(tmp_path / "settings.json", {"permissions": {"ask": ["Bash(git push*)"]},
                                               "env": {"EDITOR": "vi"}}, mode=0o644)
    original = path.read_bytes()
    start = len(syscalls.events)
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    events = syscalls.events[start:]
    assert outcome.status == "changed" and outcome.backup == tmp_path / BACKUP
    # The backup holds the original bytes exactly, readable by MC alone whatever the
    # original's mode: settings can carry environment values.
    assert (tmp_path / BACKUP).read_bytes() == original
    assert (tmp_path / BACKUP).stat().st_mode & 0o777 == 0o600
    # The settings file keeps the mode it had.
    assert path.stat().st_mode & 0o777 == 0o644
    renames = [os.path.basename(os.fsdecode(args[1])) for event, args in events
               if event == "os.rename"]
    assert renames == [BACKUP, "settings.json"]
    # The settings file itself was never opened for writing: only its temp file was, and
    # that was renamed over it once the backup was in place.
    writes = [args for event, args in events if event == "open"
              and os.path.basename(os.fsdecode(args[0])) == "settings.json"
              and args[2] & (os.O_WRONLY | os.O_RDWR)]
    assert writes == []
    # A second change on the same second never overwrites the first backup.
    path.write_text(json.dumps({"permissions": {}}))
    settings_merge.merge_file(path, RULES, now=NOW)
    assert backups(tmp_path) == [BACKUP, BACKUP + "-1"]
    assert (tmp_path / BACKUP).read_bytes() == original


def test_a_write_that_does_not_read_back_is_restored_from_the_backup(tmp_path):
    path = write(tmp_path / "settings.json", {"permissions": {}}, mode=0o640)
    original = path.read_bytes()
    with pytest.raises(settings_merge.Unmergeable, match="did not read back"):
        settings_merge.replace_checked(path, b"{not json", 0o640, original)
    assert path.read_bytes() == original and path.stat().st_mode & 0o777 == 0o640
    # A file that did not exist before is removed again rather than left unreadable.
    fresh = tmp_path / "fresh.json"
    with pytest.raises(settings_merge.Unmergeable):
        settings_merge.replace_checked(fresh, b"[", 0o600, None)
    assert not fresh.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["settings.json"]


def test_remove_takes_out_only_recorded_rules(tmp_path):
    settings = {"permissions": {"ask": ["Bash(git push*)", *RULES["ask"]],
                                "deny": [*RULES["deny"], "Read(./.env)"],
                                "allow": ["Bash(npm test)"]},
                "env": {"EDITOR": "vi"}}
    recorded = {"ask": RULES["ask"][:2], "deny": RULES["deny"]}
    new, removed = settings_merge.remove(settings, recorded)
    assert removed == recorded
    assert new["permissions"]["ask"] == ["Bash(git push*)", *RULES["ask"][2:]]
    assert new["permissions"]["deny"] == ["Read(./.env)"]
    assert new["permissions"]["allow"] == ["Bash(npm test)"] and new["env"] == {"EDITOR": "vi"}
    # A copy MC keeps of one of our rules survives: only the one we added comes out.
    doubled = {"permissions": {"ask": [RULES["ask"][0], "Bash(x)", RULES["ask"][0]]}}
    new, removed = settings_merge.remove(doubled, {"ask": [RULES["ask"][0]], "deny": []})
    assert new["permissions"]["ask"] == [RULES["ask"][0], "Bash(x)"]
    # The file step backs up first and leaves every other byte of meaning in place.
    path = write(tmp_path / "settings.json", settings)
    outcome = settings_merge.remove_file(path, recorded, now=NOW)
    assert outcome.status == "changed" and outcome.removed == recorded
    assert json.loads(path.read_text()) == settings_merge.remove(settings, recorded)[0]
    assert backups(tmp_path) == [BACKUP]
    # Nothing recorded is left: a second removal changes nothing and backs up nothing.
    assert settings_merge.remove_file(path, recorded, now=NOW).status == "unchanged"
    assert backups(tmp_path) == [BACKUP]


def test_remove_leaves_an_entry_mc_edited(tmp_path):
    edited = "Bash(*install-tailnet.sh*)"
    settings = {"permissions": {"ask": [r if r != "Bash(*install-tailnet*)" else edited
                                        for r in RULES["ask"]], "deny": RULES["deny"]}}
    path = write(tmp_path / "settings.json", settings)
    outcome = settings_merge.remove_file(path, RULES, now=NOW)
    assert outcome.status == "changed"
    assert json.loads(path.read_text())["permissions"] == {"ask": [edited], "deny": []}
    # The recorded string MC changed is reported, not hunted for.
    assert outcome.not_found == {"ask": ["Bash(*install-tailnet*)"], "deny": []}
    assert "Bash(*install-tailnet*)" in outcome.message


def test_claude_config_dir_settings_paths_are_written_absolute(tmp_path):
    claude = tmp_path / "claude-alt"
    rules = gate.rules_for(str(claude))
    path = claude / "settings.json"
    outcome = settings_merge.merge_file(path, rules, now=NOW)
    assert outcome.status == "changed"
    ask = json.loads(path.read_text())["permissions"]["ask"]
    assert f"Edit(/{claude}/settings.json)" in ask
    assert f"Bash(*{claude}/settings.json*)" in ask
    assert "Edit(~/.claude/settings.json)" not in ask
    # The gate check, given the same directory, finds every rule the installer wrote.
    assert gate.missing_rules(path, str(claude)) == []
    # The directory Claude Code reads was created for MC alone.
    assert claude.stat().st_mode & 0o777 == 0o700


def test_a_conflicting_deny_and_a_bypass_default_produce_warnings(tmp_path):
    settings = {"permissions": {"defaultMode": "bypassPermissions",
                                "deny": ["Bash(tailnet:*)", "Bash(rm -rf*)", *RULES["deny"]]}}
    found = settings_merge.warnings(settings, RULES)
    # Our own deny rules name tailnet's paths; only a deny rule of MC's is a conflict.
    [conflict, bypass] = found
    assert "Bash(tailnet:*)" in conflict and "blocked" in conflict
    assert "bypassPermissions" in bypass and "still prompts" in bypass
    assert settings_merge.warnings({"permissions": {"deny": RULES["deny"]}}, RULES) == []
    # They are reported with the merge and never acted on: the conflicting rule stays.
    path = write(tmp_path / "settings.json", settings)
    outcome = settings_merge.merge_file(path, RULES, now=NOW)
    assert outcome.warnings == found
    permissions = json.loads(path.read_text())["permissions"]
    assert permissions["defaultMode"] == "bypassPermissions"
    assert "Bash(tailnet:*)" in permissions["deny"]


def test_a_dry_run_shows_the_change_as_a_diff_and_writes_nothing(tmp_path):
    path = write(tmp_path / "settings.json", {"env": {"TOKEN_HELPER": "x"},
                                               "permissions": {"ask": ["Bash(git push*)"]}})
    raw = path.read_bytes()
    outcome = settings_merge.merge_file(path, RULES, now=NOW, dry_run=True)
    assert outcome.status == "would" and outcome.added["ask"] == RULES["ask"]
    assert path.read_bytes() == raw and backups(tmp_path) == []
    lines = outcome.diff.splitlines()
    assert lines[0].startswith("--- ") and lines[1].startswith("+++ ")
    assert f'+      "{RULES["ask"][0]}",' in lines
    # No context lines: what else the file holds, environment values included, never reaches
    # the agent's transcript through the diff.
    assert not [line for line in lines[2:] if line.startswith(" ")]
    assert "TOKEN_HELPER" not in outcome.diff
