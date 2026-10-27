# ABOUTME: Tests for tailnet.errors: the stable codes of DESIGN.md §5.5 and the error shape of §5.4.
# ABOUTME: Codes are what tests and agents branch on, so the registry must match the spec exactly.

import pytest

from tailnet import errors

# DESIGN.md §5.5, transcribed. A code added to errors.py without changing the spec and this
# table fails here, because codes are a contract.
SPEC_CODES = {
    1: {"INTERNAL"},
    2: {"USAGE", "REASON_REQUIRED", "REASON_PLACEHOLDER", "TAG_MALFORMED", "TAG_ADD_AND_REMOVE",
        "TEST_WILDCARD", "TEST_SRC_IS_IP", "TEST_PORT", "VALIDATE_ARRAY_BODY"},
    3: {"CREDENTIAL_MISSING", "CREDENTIAL_UNSAFE", "CREDENTIAL_MALFORMED", "WRITE_SECRET_INLINE",
        "TEST_POSTURE_REAL_SECRET", "ENV_UNSAFE_OVERRIDE", "HOME_WITHOUT_BASE",
        "TAILSCALE_CLI_MISSING", "NOT_A_TTY", "RUN_AS_ROOT", "TOKEN_REJECTED", "AUDIT_UNWRITABLE",
        "PROTECTED_MALFORMED"},
    4: {"API_BAD_REQUEST", "API_FORBIDDEN", "API_NOT_FOUND", "API_PAYMENT", "API_RATE_LIMITED",
        "API_SERVER", "API_REDIRECT", "API_BAD_RESPONSE", "NETWORK"},
    5: {"DEVICE_NOT_FOUND", "DEVICE_AMBIGUOUS", "SHARED_IN", "SELF_UNKNOWN", "SELF_LINE_DISAGREES",
        "SELF_DEVICE", "PROTECTED_UNANSWERED", "PROTECTED_DEVICE", "GATE_MISSING",
        "CONFIRM_MISSING", "CONFIRM_MISMATCH", "TAG_UNDEFINED", "TAG_NOT_PRESENT", "TAG_SET_EMPTY",
        "CLIENT_CANNOT_ASSIGN", "WRITE_CLIENT_TAGS_UNRECORDED", "POLICY_UNREADABLE",
        "WRITE_CREDENTIAL_MISSING", "WRITE_SCOPE_MISSING", "MULTI_TARGET_NOT_R1",
        "APPLY_IN_PROGRESS"},
    6: {"WRITE_UNCONFIRMED"},
    7: {"WRITE_REJECTED"},
    8: {"POLICY_TEST_FAILED", "POLICY_INVALID", "DRAFT_NOT_READY", "DIAGNOSE_BLOCKED", "DOCTOR_FAIL"},
}


def test_the_stable_codes_are_exactly_the_spec_table():
    assert {exit_code: set(codes) for exit_code, codes in errors.STABLE_CODES.items()} == SPEC_CODES


@pytest.mark.parametrize("exit_code,code", sorted(
    (exit_code, code) for exit_code, codes in SPEC_CODES.items() for code in codes))
def test_every_stable_code_maps_to_its_table_exit(exit_code, code):
    err = errors.TailnetError(exit_code, code, "message")
    assert (err.exit, err.code) == (exit_code, code)


def test_a_code_from_another_exit_is_refused():
    # A typo or a misfiled code would print a code no agent knows how to read.
    with pytest.raises(ValueError, match="REASON_REQUIRED"):
        errors.Refused("REASON_REQUIRED", "--apply needs --reason")
    with pytest.raises(ValueError):
        errors.TailnetError(9, "USAGE", "no such exit")


def test_the_error_shape_matches_the_envelope_contract():
    nxt = [{"who": "mc", "do": "chmod 600 read.json", "why": "unsafe mode", "needs": "terminal"}]
    err = errors.ApiError("API_FORBIDDEN", "forbidden: possibly a missing scope",
                          http_status=403, request_id="REQ-1", next=nxt)
    assert err.to_dict() == {"code": "API_FORBIDDEN", "kind": "api",
                             "message": "forbidden: possibly a missing scope",
                             "http_status": 403, "request_id": "REQ-1"}
    assert err.next == nxt
    assert err.outcome == "error"
    assert str(err) == "API_FORBIDDEN: forbidden: possibly a missing scope"
