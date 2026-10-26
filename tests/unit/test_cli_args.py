# ABOUTME: Tests for the CLI contract in DESIGN.md §5. This part covers how every exit code in the
# ABOUTME: §5.3 table is produced; the parser cases join it with cli.py (§29 item 14).

import pytest

from tailnet import errors
from tailnet.output import Envelope

# §5.3, row by row: exit code, how a command produces it, the outcome agents branch on, and
# the error kind the envelope carries (None when there is no error).
EXIT_TABLE = [
    (0, lambda: Envelope(command="status", posture="production"), "ok", None),
    (1, lambda: Envelope.from_error("status", "production", RuntimeError("a bug")), "error",
     "internal"),
    (2, lambda: errors.UsageError("REASON_REQUIRED", "--apply needs --reason"), "error", "usage"),
    (3, lambda: errors.LocalError("CREDENTIAL_MISSING", "no read.json"), "error", "local"),
    (4, lambda: errors.ApiError("API_SERVER", "502", http_status=502), "error", "api"),
    (5, lambda: errors.Refused("CONFIRM_MISMATCH", "token differs"), "refused", "refused"),
    (6, lambda: errors.Unconfirmed("WRITE_UNCONFIRMED", "re-read differs"), "unconfirmed",
     "unconfirmed"),
    (7, lambda: errors.Rejected("WRITE_REJECTED", "400"), "rejected", "rejected"),
    (8, lambda: errors.Negative("POLICY_TEST_FAILED", "drop"), "negative", "negative"),
]


def as_envelope(made):
    """Turn whatever a table row produced into the envelope the CLI would print."""
    if isinstance(made, Envelope):
        return made
    return Envelope.from_error("device tag", "production", made)


def test_every_exit_code_in_the_table_is_reachable():
    assert [row[0] for row in EXIT_TABLE] == list(range(9))
    for exit_code, produce, outcome, kind in EXIT_TABLE:
        env = as_envelope(produce())
        assert (env.exit, env.outcome, env.ok) == (exit_code, outcome, exit_code == 0)
        assert (env.error or {}).get("kind") == kind
        assert errors.EXIT_NAMES[exit_code]


@pytest.mark.parametrize("cls,exit_code", [
    (errors.UsageError, 2), (errors.LocalError, 3), (errors.ApiError, 4), (errors.Refused, 5),
    (errors.Unconfirmed, 6), (errors.Rejected, 7), (errors.Negative, 8),
])
def test_each_error_class_carries_its_table_exit(cls, exit_code):
    code = min(errors.STABLE_CODES[exit_code])
    assert cls(code, "m").exit == exit_code
