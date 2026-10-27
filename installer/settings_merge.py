# ABOUTME: Puts tailnet's Claude Code ask and deny rules into MC's settings.json and takes them out again,
# ABOUTME: never touching another entry: pure merge and remove, plus a backed-up, atomic, re-read file step.

import copy
import difflib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

from tailnet import errors, gate, secure_files

LISTS = ("ask", "deny")
# Settings are written the way Claude Code's own examples show them. Non-ASCII text stays
# as itself rather than turning into \u escapes, so MC's own entries read as they did.
INDENT = 2
_TEMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class Unmergeable(ValueError):
    """A settings file this merge will not guess about: it stops the step and writes nothing.

    Claude Code reads `permissions.ask` and `permissions.deny` as lists inside an object.
    Anything else is a file MC (or a tool) shaped on purpose or by mistake, and a repair
    would be a guess about which, so MC adds the rules by hand instead (§20.4 step 1).
    """


def _check_shape(settings):
    """Raise Unmergeable unless the document has the shape the rules can be added to."""
    if not isinstance(settings, dict):
        raise Unmergeable("the settings file is not a JSON object")
    if "permissions" not in settings:
        return
    permissions = settings["permissions"]
    if not isinstance(permissions, dict):
        raise Unmergeable("`permissions` is not an object")
    for key in LISTS:
        if key in permissions and not isinstance(permissions[key], list):
            raise Unmergeable(f"`permissions.{key}` is not a list")


def merge(settings, ask, deny):
    """Add each of our rules not already present; return (new settings, added per list).

    Pure: the input is never changed. Rules are matched by exact text and appended after
    MC's own, and no other entry or key is removed, reordered or rewritten (§20.4 step 2),
    because the installer must never loosen, or quietly change, what MC has set.
    """
    _check_shape(settings)
    new = copy.deepcopy(settings)
    added = {"ask": [], "deny": []}
    for key, ours in (("ask", ask), ("deny", deny)):
        current = new.get("permissions", {}).get(key, [])
        missing = [rule for rule in dict.fromkeys(ours) if rule not in current]
        if missing:
            new.setdefault("permissions", {}).setdefault(key, []).extend(missing)
            added[key] = missing
    return new, added


def remove(settings, recorded):
    """Take out each recorded rule still present; return (new settings, removed per list).

    Pure. Only strings the installer recorded adding come out, and of each only one copy,
    the last, since ours was appended: a copy MC added by hand stays. A recorded rule MC
    has since edited no longer matches and is left where it is (§20.4 step 7).
    """
    _check_shape(settings)
    new = copy.deepcopy(settings)
    removed = {"ask": [], "deny": []}
    for key in LISTS:
        current = new.get("permissions", {}).get(key)
        for rule in recorded.get(key, []):
            if current and rule in current:
                del current[len(current) - 1 - current[::-1].index(rule)]
                removed[key].append(rule)
    return new, removed


def warnings(settings, rules):
    """What MC should know about settings the merge leaves alone (§20.4 step 6); never acted on.

    `rules` is what gate.rules_for gave. Our own deny rules name tailnet's directories, so
    only a deny rule that is not ours counts as one that could block a tailnet command.
    """
    permissions = settings.get("permissions") if isinstance(settings, dict) else None
    if not isinstance(permissions, dict):
        return []
    found = []
    deny = permissions.get("deny")
    for rule in deny if isinstance(deny, list) else []:
        if isinstance(rule, str) and "tailnet" in rule.lower() and rule not in rules["deny"]:
            found.append(f"the deny rule {rule} names tailnet: tailnet commands it matches, "
                         "--apply writes included, would be blocked; it was left as it is")
    if permissions.get("defaultMode") == "bypassPermissions":
        found.append("INFO: defaultMode is bypassPermissions; the ask rule still prompts for "
                     "every --apply in bypass mode, and headless `claude -p` runs deny writes "
                     "instead [PM L34-36, L56]")
    return found


def dump(settings):
    """A settings document as the file step writes it: indented, with a trailing newline."""
    # allow_nan=False: NaN and Infinity are not JSON, and Claude Code would skip the file.
    return json.dumps(settings, indent=INDENT, ensure_ascii=False, allow_nan=False) + "\n"


def by_hand(rules, removing=False):
    """The rules for MC to add (or remove) by hand when the file cannot be merged safely."""
    block = json.dumps({"permissions": {"ask": rules["ask"], "deny": rules["deny"]}},
                       indent=INDENT)
    what = "Remove these rules from" if removing else "Add these rules to"
    return f"{what} the settings file by hand:\n{block}"


def diff(path, before, after):
    """The change as a unified diff of the pretty-printed JSON, with no context lines.

    Context lines would carry whatever sits beside the permissions, environment values
    included, into the agent's transcript; the changed lines are the rules alone.
    """
    return "".join(difflib.unified_diff(before.splitlines(keepends=True),
                                        after.splitlines(keepends=True),
                                        fromfile=str(path), tofile=f"{path} (after)", n=0))


@dataclass
class Current:
    """A settings file as read: its document, its bytes (None when absent) and its mode."""

    settings: dict
    raw: bytes | None
    mode: int | None


def load(path):
    """Read a settings file for merging, or raise Unmergeable saying why it will not be.

    Absent is an empty document. A symlink is refused rather than followed: replacing it
    would cut MC's link (to a dotfiles checkout, say) and leave a plain file in its place.
    So is anything over the size status and doctor read (gate.SETTINGS_MAX), since rules
    written there would never count as present.
    """
    path = Path(path)
    try:
        raw = secure_files.read_regular(path, gate.SETTINGS_MAX)
        mode = stat.S_IMODE(os.lstat(path).st_mode)
    except FileNotFoundError:
        return Current({}, None, None)
    except secure_files.Unreadable as exc:
        raise Unmergeable(f"{path}: {exc}") from None
    except OSError as exc:
        raise Unmergeable(f"{path}: {exc.strerror}") from None
    try:
        settings = gate.parse_strict(raw.decode("utf-8"))
    except json.JSONDecodeError:
        raise Unmergeable(f"{path} is not valid JSON") from None
    except ValueError as exc:
        raise Unmergeable(f"{path} is not valid JSON, or not JSON this merge can write back: "
                          f"{exc}") from None
    try:
        _check_shape(settings)
    except Unmergeable as exc:
        raise Unmergeable(f"{path}: {exc}") from None
    try:
        dump(settings).encode("utf-8")
    except ValueError:
        # JSON can escape half of a surrogate pair, and Claude Code reads it, but no UTF-8
        # file can hold one, so the document could never be written back.
        raise Unmergeable(f"{path} holds half of a surrogate pair (a \\ud800-\\udfff escape "
                          "alone), which no UTF-8 file can hold") from None
    return Current(settings, raw, mode)


def _fsync_directory(directory):
    """Make a rename in `directory` durable: the entry is on disk only once the directory is."""
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path, data, mode):
    """Replace `path` with `data` at `mode` through a synced temp file and one rename."""
    temp = path.parent / f".{path.name}.tailnet-{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(temp, _TEMP_FLAGS, 0o600)
    try:
        # The create mode passes through the umask; fchmod sets exactly the mode wanted.
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temp, path)
    except BaseException:
        if fd is not None:
            os.close(fd)
        temp.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _write_backup(path, data):
    """Create the backup at `path`, which must not exist yet, as a synced 0600 file.

    O_EXCL means an earlier backup is never overwritten (A36). The settings directory is
    not held to the credential-directory rule (§8.2 item 6): Claude Code creates ~/.claude
    as 0777 less the umask, so 0775 under the umask 002 stock Ubuntu gives a user with a
    private group, and refusing it would leave the gate rule out of MC's settings.
    """
    fd = os.open(path, _TEMP_FLAGS, 0o600)
    try:
        # The create mode passes through the umask; fchmod sets exactly 0600.
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)
    _fsync_directory(path.parent)


def replace_checked(path, data, mode, original):
    """Write `data` over `path`, then read it back as JSON; undo the write if it does not parse.

    `original` is the file's bytes from before (None when it did not exist), the same bytes
    the backup holds: they go back in place, or a file this step created is removed, and
    Unmergeable says so (§20.4 step 4).
    """
    path = Path(path)
    _write_atomic(path, data, mode)
    try:
        gate.parse_strict(secure_files.read_regular(path, gate.SETTINGS_MAX).decode("utf-8"))
        return
    except (ValueError, OSError, secure_files.Unreadable):
        pass
    if original is None:
        path.unlink(missing_ok=True)
        raise Unmergeable(f"{path} did not read back as JSON after the write; it was removed")
    _write_atomic(path, original, mode)
    raise Unmergeable(f"{path} did not read back as JSON after the write; the original bytes "
                      "were put back")


def backup_path(path, now):
    """A backup name beside the settings file that no earlier backup holds."""
    base = f"{path.name}.tailnet-bak-{now.strftime('%Y%m%dT%H%M%SZ')}"
    candidate, number = path.with_name(base), 0
    while os.path.lexists(candidate):
        number += 1
        candidate = path.with_name(f"{base}-{number}")
    return candidate


@dataclass
class Outcome:
    """What one settings step did: `changed`, `unchanged`, `would` (a dry run) or `aborted`."""

    status: str
    message: str
    added: dict = field(default_factory=lambda: {"ask": [], "deny": []})
    removed: dict = field(default_factory=lambda: {"ask": [], "deny": []})
    not_found: dict = field(default_factory=lambda: {"ask": [], "deny": []})
    backup: Path | None = None
    diff: str = ""
    warnings: list = field(default_factory=list)


def _commit(path, current, new, now):
    """Back up the original bytes, then write the new document; return the backup path.

    The backup is written first and 0600 whatever the original's mode, since settings can
    carry environment values. A file that did not exist has nothing to back up and is
    created 0600; an existing one keeps its mode.
    """
    # Encoded first, so a document that cannot be written leaves no backup behind either.
    data = dump(new).encode("utf-8")
    backup = None
    if current.raw is not None:
        backup = backup_path(path, now)
        _write_backup(backup, current.raw)
    else:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = current.mode if current.mode is not None else 0o600
    replace_checked(path, data, mode, current.raw)
    return backup


def _why(exc):
    """One line saying why a write failed: a refusal's own message, without its CLI code."""
    if isinstance(exc, errors.TailnetError):
        return exc.message
    if isinstance(exc, OSError) and exc.filename:
        return f"{exc.filename}: {exc.strerror}"
    return str(exc)


def _count(lists):
    """How many rules two per-list lists hold together."""
    return sum(len(lists[key]) for key in LISTS)


def merge_file(path, rules, *, now, dry_run=False):
    """The installer's settings step: add `rules` (gate.rules_for's output) to the file at `path`.

    Nothing to add means no write and no backup. A dry run computes the diff and writes
    nothing. Any reason to stop leaves the file exactly as it was and hands MC the rules.
    """
    path = Path(path)
    try:
        current = load(path)
    except Unmergeable as exc:
        return Outcome("aborted", f"{exc}; nothing was written. {by_hand(rules)}")
    new, added = merge(current.settings, rules["ask"], rules["deny"])
    found = warnings(current.settings, rules)
    if not _count(added):
        return Outcome("unchanged", f"every rule is already present in {path}", warnings=found)
    change = diff(path, dump(current.settings) if current.raw is not None else "", dump(new))
    if dry_run:
        return Outcome("would", f"add {_count(added)} rules to {path}", added=added,
                       diff=change, warnings=found)
    try:
        backup = _commit(path, current, new, now)
    except (ValueError, errors.LocalError, OSError) as exc:
        return Outcome("aborted", f"{_why(exc)}; {by_hand(rules)}", warnings=found)
    saved = f" (backup {backup})" if backup else ""
    return Outcome("changed", f"added {_count(added)} rules to {path}{saved}", added=added,
                   backup=backup, diff=change, warnings=found)


def remove_file(path, recorded, *, now, dry_run=False):
    """The uninstaller's settings step: take out the rules the install record says were added.

    Recorded rules no longer present (removed or edited by MC) are reported in `not_found`
    and left alone; nothing is searched for by likeness.
    """
    path = Path(path)
    recorded = {key: [r for r in recorded.get(key, []) if isinstance(r, str)] for key in LISTS}
    try:
        current = load(path)
    except Unmergeable as exc:
        return Outcome("aborted", f"{exc}; nothing was written. {by_hand(recorded, removing=True)}")
    new, removed = remove(current.settings, recorded)
    not_found = {key: [r for r in recorded[key] if r not in removed[key]] for key in LISTS}
    missing = [r for key in LISTS for r in not_found[key]]
    note = (f"; not present, so left to MC (edited or already removed): {', '.join(missing)}"
            if missing else "")
    if not _count(removed):
        return Outcome("unchanged", f"no recorded rule is present in {path}{note}",
                       not_found=not_found)
    change = diff(path, dump(current.settings), dump(new))
    if dry_run:
        return Outcome("would", f"remove {_count(removed)} rules from {path}{note}",
                       removed=removed, not_found=not_found, diff=change)
    try:
        backup = _commit(path, current, new, now)
    except (ValueError, errors.LocalError, OSError) as exc:
        return Outcome("aborted", f"{_why(exc)}; {by_hand(recorded, removing=True)}",
                       not_found=not_found)
    return Outcome("changed", f"removed {_count(removed)} rules from {path} (backup {backup})"
                   f"{note}", removed=removed, not_found=not_found, backup=backup, diff=change)
