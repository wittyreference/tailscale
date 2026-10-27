# ABOUTME: The ask gate: reads the Claude Code rules in rules.json and checks MC's settings still hold them,
# ABOUTME: and finds hooks there that can answer its prompt; every --apply refuses without it (§11.5, A67).

import json
import math
import os
import re
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


def _not_json(token):
    """parse_strict's answer to NaN, Infinity and -Infinity, which Python reads and JSON lacks."""
    raise ValueError(f"{token} is not JSON")


def _finite(text):
    """A JSON number with a fraction or exponent, refused when no double holds it (1e400)."""
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("a number is beyond a double's range")
    return value


def parse_strict(data):
    """Parse a settings file as strictly as Claude Code does, or stricter; raise ValueError.

    Claude Code parses settings as strict JSON and skips a file that fails, every rule in it
    with it, so a file holding NaN or Infinity, which Python's json reads, holds no rule at
    all. Python reads 1e400 as inf and can only write it back as the bare token Infinity,
    and Claude Code reads it as Infinity, which its schema may refuse: such a file holds no
    rule this CLI vouches for, and none the installer may rewrite.
    """
    return json.loads(data, parse_constant=_not_json, parse_float=_finite)


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
        doc = parse_strict(data) if data is not None else None
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


# A matcher of only these characters is an exact tool name, or a list of them split on `|`
# or `,`; any other character makes it an unanchored JavaScript regular expression, and
# empty, `*` or absent fires on every tool [hooks.md "Matcher patterns", fetched 2026-10-27].
_EXACT_MATCHER = re.compile(r"[A-Za-z0-9_\- ,|]*")


def _fires_on_bash(matcher):
    """Whether a hook group's matcher fires on the Bash tool; True whenever it cannot be told.

    Python's `re.search` stands in for JavaScript's unanchored `RegExp.test`; the two agree
    on the patterns matchers use, and a pattern Python cannot compile is assumed to fire.
    """
    if matcher is None or matcher in ("", "*"):
        return True
    if not isinstance(matcher, str):
        return True
    if _EXACT_MATCHER.fullmatch(matcher):
        return "Bash" in {name.strip() for name in re.split(r"[|,]", matcher)}
    try:
        return re.search(matcher, "Bash") is not None
    except re.error:
        return True


def permission_request_hooks(settings_path):
    """The matchers of the settings file's PermissionRequest hooks that fire on Bash; [] when
    it holds none or is missing, None when it cannot be read as settings.

    A PermissionRequest hook that returns allow answers the prompt the gate's ask rule
    raises, in every mode that asks and in `claude -p`, where it stands in for MC [hooks.md
    PermissionRequest; permission-modes.md L924]. So one that fires on Bash can approve an
    --apply MC never sees. Deny rules still beat it. Only this file is read: project
    settings, `--settings` and plugins can carry such hooks too, and are not this CLI's to
    find. A missing matcher is reported as "", the spelling that also fires on every tool.
    """
    data = _read(settings_path)
    if data is None:
        return [] if not os.path.lexists(settings_path) else None
    try:
        doc = parse_strict(data)
    except ValueError:
        return None
    hooks = doc.get("hooks", {}) if isinstance(doc, dict) else None
    groups = hooks.get("PermissionRequest", []) if isinstance(hooks, dict) else None
    if not isinstance(groups, list) or not all(isinstance(group, dict) for group in groups):
        return None
    return [str(group.get("matcher", "")) for group in groups
            if _fires_on_bash(group.get("matcher"))]
