# ABOUTME: The TailnetError hierarchy: one class per exit code in DESIGN.md §5.3, each carrying a
# ABOUTME: stable code from §5.5. Agents and tests branch on codes; messages may change, codes may not.

OK = 0
INTERNAL = 1
USAGE = 2
LOCAL = 3
API = 4
REFUSED = 5
UNCONFIRMED = 6
REJECTED = 7
NEGATIVE = 8

# The Name column of §5.3; the human verdict line leads with it.
EXIT_NAMES = {
    OK: "OK", INTERNAL: "INTERNAL", USAGE: "USAGE", LOCAL: "LOCAL", API: "API",
    REFUSED: "REFUSED", UNCONFIRMED: "UNCONFIRMED", REJECTED: "REJECTED", NEGATIVE: "NEGATIVE",
}

# §5.5. INTERNAL is the one code for exit 1: a bug has no stable reason. A code is added here
# only together with the spec, because an agent cannot act on a code it has never seen.
STABLE_CODES = {
    INTERNAL: frozenset({"INTERNAL"}),
    USAGE: frozenset({
        "USAGE", "REASON_REQUIRED", "REASON_PLACEHOLDER", "TAG_MALFORMED", "TAG_ADD_AND_REMOVE",
        "TEST_WILDCARD", "TEST_SRC_IS_IP", "TEST_PORT", "VALIDATE_ARRAY_BODY",
    }),
    LOCAL: frozenset({
        "CREDENTIAL_MISSING", "CREDENTIAL_UNSAFE", "CREDENTIAL_MALFORMED", "WRITE_SECRET_INLINE",
        "TEST_POSTURE_REAL_SECRET", "ENV_UNSAFE_OVERRIDE", "HOME_WITHOUT_BASE",
        "TAILSCALE_CLI_MISSING", "NOT_A_TTY", "RUN_AS_ROOT", "TOKEN_REJECTED", "AUDIT_UNWRITABLE",
        "PROTECTED_MALFORMED",
    }),
    API: frozenset({
        "API_BAD_REQUEST", "API_FORBIDDEN", "API_NOT_FOUND", "API_PAYMENT", "API_RATE_LIMITED",
        "API_SERVER", "API_REDIRECT", "API_BAD_RESPONSE", "NETWORK",
    }),
    REFUSED: frozenset({
        # targeting
        "DEVICE_NOT_FOUND", "DEVICE_AMBIGUOUS", "SHARED_IN",
        # self
        "SELF_UNKNOWN", "SELF_LINE_DISAGREES", "SELF_DEVICE",
        # protected list
        "PROTECTED_UNANSWERED", "PROTECTED_DEVICE",
        # gate and confirm
        "GATE_MISSING", "CONFIRM_MISSING", "CONFIRM_MISMATCH",
        # tags
        "TAG_UNDEFINED", "TAG_NOT_PRESENT", "TAG_SET_EMPTY", "CLIENT_CANNOT_ASSIGN",
        "WRITE_CLIENT_TAGS_UNRECORDED", "POLICY_UNREADABLE",
        # write client
        "WRITE_CREDENTIAL_MISSING", "WRITE_SCOPE_MISSING",
        # batch and concurrency
        "MULTI_TARGET_NOT_R1", "APPLY_IN_PROGRESS",
    }),
    UNCONFIRMED: frozenset({"WRITE_UNCONFIRMED"}),
    REJECTED: frozenset({"WRITE_REJECTED"}),
    NEGATIVE: frozenset({
        "POLICY_TEST_FAILED", "POLICY_INVALID", "DRAFT_NOT_READY", "DIAGNOSE_BLOCKED", "DOCTOR_FAIL",
    }),
}

# error.kind in the envelope (§5.4). Exit 8 is an answer, not a failure, but it still carries a
# stable code, so it gets the kind "negative" (amendment A8).
KINDS = {
    INTERNAL: "internal", USAGE: "usage", LOCAL: "local", API: "api", REFUSED: "refused",
    UNCONFIRMED: "unconfirmed", REJECTED: "rejected", NEGATIVE: "negative",
}

# The envelope outcome each error exit produces. Exit 6 and 7 keep their own outcomes because
# they differ in the one way that matters after a write: whether it may have landed.
ERROR_OUTCOMES = {
    INTERNAL: "error", USAGE: "error", LOCAL: "error", API: "error", REFUSED: "refused",
    UNCONFIRMED: "unconfirmed", REJECTED: "rejected", NEGATIVE: "negative",
}


class TailnetError(Exception):
    """A failure or a negative answer the CLI reports with a stable code and exit status.

    Raising one is how any module ends a command: cli.py turns it into the envelope and the
    exit code, so the code-to-exit mapping lives in one place and cannot drift per command.
    """

    # `exit` and `next` shadow builtins on purpose: they are the envelope's field names (§5.4).
    def __init__(self, exit, code, message, *, http_status=None, request_id=None, next=None):
        if exit not in STABLE_CODES:
            raise ValueError(f"exit {exit} is not in the exit-code table (DESIGN.md §5.3)")
        if code not in STABLE_CODES[exit]:
            raise ValueError(f"{code} is not a stable code for exit {exit} (DESIGN.md §5.5)")
        super().__init__(f"{code}: {message}")
        self.exit = exit
        self.code = code
        self.message = message
        self.http_status = http_status
        self.request_id = request_id
        self.next = list(next or [])

    @property
    def kind(self):
        """The envelope's error.kind for this exit."""
        return KINDS[self.exit]

    @property
    def outcome(self):
        """The envelope outcome this error produces."""
        return ERROR_OUTCOMES[self.exit]

    def to_dict(self):
        """The envelope's error object (§5.4); `next` travels separately, in the envelope."""
        return {"code": self.code, "kind": self.kind, "message": self.message,
                "http_status": self.http_status, "request_id": self.request_id}


class _FixedExit(TailnetError):
    """Base for the per-exit classes: the exit comes from the class, the caller gives the code."""

    exit_code = None

    def __init__(self, code, message, **details):
        super().__init__(self.exit_code, code, message, **details)


class UsageError(_FixedExit):
    """Exit 2: bad arguments. Nothing was sent."""

    exit_code = USAGE


class LocalError(_FixedExit):
    """Exit 3: a local precondition failed (credential, override, TTY, audit log). Nothing was sent."""

    exit_code = LOCAL


class ApiError(_FixedExit):
    """Exit 4: a read failed at the API or on the network. No write was sent."""

    exit_code = API


class Refused(_FixedExit):
    """Exit 5: the write guard declined. Nothing was sent."""

    exit_code = REFUSED


class Unconfirmed(_FixedExit):
    """Exit 6: a write was sent and may have landed. The agent must never re-apply."""

    exit_code = UNCONFIRMED


class Rejected(_FixedExit):
    """Exit 7: a write was sent and the API rejected it."""

    exit_code = REJECTED


class Negative(_FixedExit):
    """Exit 8: the command ran and the answer is no (a failed test, a block, a doctor FAIL)."""

    exit_code = NEGATIVE
