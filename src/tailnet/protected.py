# ABOUTME: MC's protected list: the hand-written file naming self and the devices the CLI must never retag.
# ABOUTME: A pure parser plus a loader held to the private-file checks; a missing file means "unanswered".

import re
from dataclasses import dataclass

from tailnet import secure_files
from tailnet.errors import LocalError

FILE_NAME = "protected"
# §8.2 item 7: the list is a few lines per device; anything near this is not one.
MAX_BYTES = 64 * 1024
# Every refusal about this file carries one code. §5.5 names no separate code for an unsafe
# protected file, and pointing the reader at the credentials would send them to the wrong
# file (amendment A19).
CODE = "PROTECTED_MALFORMED"
_NODE_ID = re.compile(r"[A-Za-z0-9]+")
_SELF_WHY = "the self line: self is always protected"


@dataclass(frozen=True)
class Entry:
    """One protected device as MC wrote it, in any form a DEVICE argument takes, and the why."""

    text: str
    why: str | None
    line: int

    def matches(self, device):
        """Whether this entry names the device, by the DEVICE resolver's own rule (§5.1): its
        nodeId or legacy id exactly, its hostname, MagicDNS name or first label in any case,
        or a Tailscale address. An entry MC writes the way a command names the device must
        protect it, and the rule lives on the device so the two cannot drift (A59)."""
        return device.named_by(self.text)


@dataclass(frozen=True)
class Protected:
    """The parsed list: the one `self` nodeId and every entry, in file order.

    Matching is deliberately broad (every form a DEVICE argument takes): an entry that
    matches more devices protects more of them, which is the safe direction.
    """

    self_node_id: str
    entries: tuple

    @property
    def self_only(self):
        """True when the file names nothing but self: tag writes are then open on every other device."""
        return not self.entries

    def unmatched(self, devices):
        """The line numbers of entries that name none of `devices`: a device renamed or
        removed, or a typo. Such a line protects nothing, so doctor and every tag plan say
        so, by number only, since the file is MC's and sits behind a deny rule (A19)."""
        return [entry.line for entry in self.entries
                if not any(entry.matches(device) for device in devices)]

    def protects(self, device):
        """Why this device is protected, or None. The self line's device is always protected."""
        for entry in self.entries:
            if entry.matches(device):
                return f"listed as {entry.text}" + (f": {entry.why}" if entry.why else "")
        if device.node_id == self.self_node_id:
            return _SELF_WHY
        return None


def _malformed(origin, line, problem):
    """A refusal that says where the file is wrong; it never quotes the file, which is MC's."""
    where = f"{origin} line {line}" if line else str(origin)
    return LocalError(CODE, f"{where}: {problem}; MC fixes the file by hand (DESIGN.md §11.4)",
                      next=[{"who": "mc", "needs": "terminal",
                             "do": f"edit {origin} so it has exactly one `self <nodeId>` line "
                                   "and one device per line",
                             "why": "tag writes are refused until the protected list parses"}])


def parse(text, origin=FILE_NAME):
    """Parse the protected list (§11.4): blank lines and `#` comments are ignored.

    `self <nodeId>` names this host, exactly once. Every other line is one entry, any form a
    DEVICE argument takes (§5.1), with an optional `# why`. A line naming two things is
    refused rather than guessed at, and so is a missing or repeated self line.
    """
    selves, entries = [], []
    for number, line in enumerate(text.splitlines(), start=1):
        content, _, comment = line.partition("#")
        words = content.split()
        if not words:
            continue
        why = comment.strip() or None
        if words[0] == "self":
            if len(words) != 2 or not _NODE_ID.fullmatch(words[1]):
                raise _malformed(origin, number, "a self line is `self <nodeId>`, the nodeId "
                                                 "in letters and digits")
            selves.append(words[1])
        elif len(words) == 1:
            entries.append(Entry(words[0], why, number))
        else:
            raise _malformed(origin, number, "one device per line: its nodeId, legacy id, "
                                             "hostname, MagicDNS name, first label or "
                                             "Tailscale address, then an optional # why")
    if len(selves) != 1:
        raise _malformed(origin, None, f"it has {len(selves)} self lines; exactly one "
                                       "`self <nodeId>` line is required")
    return Protected(selves[0], tuple(entries))


def load(posture):
    """Read and parse the posture's protected file; None when it does not exist (unanswered).

    It goes through the same checks as a credential (0600, owned, one link, not a symlink,
    in a directory only its owner can write), because an agent able to swap it could
    unprotect a device.
    """
    path = posture.config_dir / FILE_NAME
    try:
        raw = secure_files.read_private(path, MAX_BYTES, code=CODE)
    except FileNotFoundError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _malformed(path, None, "it is not UTF-8 text") from None
    return parse(text, origin=path)
