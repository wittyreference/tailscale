# ABOUTME: The ask gate: reads the Claude Code rules in rules.json and checks MC's settings still hold them.
# ABOUTME: Every --apply refuses without the gate rule; status and doctor report each missing rule (§11.5).

import json
import os
import stat
from pathlib import Path

RULES_FILE = Path(__file__).with_name("rules.json")
# A settings file is a few kilobytes; one far larger is not read, and counts as unreadable.
SETTINGS_MAX = 1024 * 1024
# The two rules that guard the settings file itself, and their form when CLAUDE_CONFIG_DIR
# moves it: a rule naming ~/.claude/settings.json would then guard a file Claude Code does
# not read (§20.4). `//` anchors a path rule at the filesystem root [PERM L370].
SETTINGS_RULE_FORMS = {
    "Edit(~/.claude/settings.json)": "Edit(/{path})",
    "Bash(*.claude/settings.json*)": "Bash(*{path}*)",
}


def rules():
    """The rules shipped with the package: the gate, and every ask and deny string (§20.4).

    A rules.json that is not the expected shape is a packaging bug, and raises: nothing can
    be judged present against rules that cannot be read, so --apply must not go ahead.
    """
    doc = json.loads(RULES_FILE.read_text(encoding="utf-8"))
    lists_ok = all(isinstance(doc.get(key), list) and all(isinstance(r, str) for r in doc[key])
                   for key in ("ask", "deny"))
    if not (isinstance(doc, dict) and doc.get("v") == 1 and lists_ok
            and doc.get("gate") in doc["ask"]):
        raise ValueError(f"{RULES_FILE} is not a v1 rules file whose gate is one of its ask rules")
    return doc


def rules_for(claude_dir):
    """The ask and deny strings an install writes for this Claude directory; pure.

    `claude_dir` is CLAUDE_CONFIG_DIR's absolute value, or None when it is unset. The
    installer writes this output and missing_rules compares against it, so the two always
    agree. The gate rule never changes.
    """
    doc = rules()
    if claude_dir is None:
        return {"ask": list(doc["ask"]), "deny": list(doc["deny"])}
    if not os.path.isabs(claude_dir):
        raise ValueError(f"the Claude directory must be an absolute path, not {claude_dir!r}")
    path = os.path.join(os.path.normpath(claude_dir), "settings.json")

    def placed(rule):
        """The rule as it must read for settings at `path`."""
        form = SETTINGS_RULE_FORMS.get(rule)
        return rule if form is None else form.format(path=path)

    return {"ask": [placed(r) for r in doc["ask"]], "deny": [placed(r) for r in doc["deny"]]}


def claude_dir(posture, environ):
    """The Claude directory whose settings this run checks: rules_for's argument.

    In test posture the settings live under the test home, which stands in for
    CLAUDE_CONFIG_DIR; in production it is that variable, absolute, or None when unset,
    read the same way the posture reads it.
    """
    if posture.kind == "test":
        return str(posture.claude_settings.parent)
    value = environ.get("CLAUDE_CONFIG_DIR")
    return os.path.abspath(value) if value else None


def _read(path):
    """The settings file's bytes, or None when it is missing, not a regular file or too large.

    It is opened without blocking, so a FIFO put where the file belongs cannot hang status,
    which must always answer.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks, total = [], 0
        while total <= SETTINGS_MAX:
            chunk = os.read(fd, SETTINGS_MAX + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    return b"".join(chunks) if total <= SETTINGS_MAX else None


def _permissions(path):
    """The settings file's ask and deny rules as two sets; both empty when it cannot be read.

    Anything that is not the shape Claude Code reads (no object, a `permissions` that is not
    one, lists that are not lists) holds no rules, so every rule counts as missing: a
    settings file the CLI cannot read is not one it can vouch for.
    """
    data = _read(path)
    try:
        doc = json.loads(data) if data is not None else None
    except ValueError:
        doc = None
    permissions = doc.get("permissions") if isinstance(doc, dict) else None
    if not isinstance(permissions, dict):
        return set(), set()

    def strings(key):
        """One permission list's strings; nothing if it is not a list."""
        value = permissions.get(key)
        return {r for r in value if isinstance(r, str)} if isinstance(value, list) else set()

    return strings("ask"), strings("deny")


def missing_rules(settings_path, claude_dir=None):
    """Every rules.json string absent from the settings file, ask rules first, in file order."""
    expected = rules_for(claude_dir)
    ask, deny = _permissions(settings_path)
    return ([r for r in expected["ask"] if r not in ask]
            + [r for r in expected["deny"] if r not in deny])


def gate_present(settings_path):
    """Whether the gate rule is among the settings file's ask rules: the rule that puts each
    --apply in front of MC. In deny or allow it would not prompt, so it does not count."""
    ask, _ = _permissions(settings_path)
    return rules()["gate"] in ask
