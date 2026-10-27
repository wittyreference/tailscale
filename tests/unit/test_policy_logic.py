# ABOUTME: Tests for tailnet.policy's pure half: the /acl/validate verdict, want/got lines, the array-body
# ABOUTME: scan, the ETag kept raw, draft readiness and `policy test`'s argument rules, decided without I/O.

import json
from datetime import datetime, timezone

import pytest
from fixturefiles import body

from tailnet import policy
from tailnet.errors import ApiError, UsageError

SHA_BASE = "b" * 64
SHA_CANDIDATE = "c" * 64
ETAG = '"e0b2816b418"'


def encoded(doc):
    """A JSON body as the server would send it."""
    return json.dumps(doc).encode("utf-8")


def test_empty_body_and_empty_object_are_pass():
    # "An empty response body implies passing" [spec 2642]; the spec's own example is {}
    # [spec 2676-2678]. A Go server ends its JSON with a newline, which is still empty.
    for raw in (b"", b"\n", b"{}", b"{}\n", encoded(body("api", "validate-success"))):
        verdict = policy.parse_verdict(200, raw)
        assert (verdict.verdict, verdict.passed, verdict.reason) == ("pass", True, None), raw
        assert (verdict.failures, verdict.warnings, verdict.messages()) == ([], (), [])


def test_errors_in_a_200_are_fail():
    # A failed test is HTTP 200: only the body says it failed (critic R2).
    verdict = policy.parse_verdict(200, encoded(body("api", "validate-tests-failed")))
    assert (verdict.verdict, verdict.passed, verdict.reason) == ("fail", False, "errors")
    assert verdict.message == "test(s) failed"
    assert verdict.failures == [{"user": "user1@example.com", "target": "2.2.2.2:22",
                                 "want": "Drop", "got": "Accept"}]
    assert verdict.messages() == [
        "test(s) failed", 'user1@example.com: address "2.2.2.2:22": want: Drop, got: Accept']
    # Errors decide it even beside warnings, and wherever in the list they sit.
    mixed = {"message": "test(s) failed", "data": [
        {"user": "a@example.com", "warnings": ["a warning"]},
        {"user": "b@example.com", "errors": ["a failure"], "warnings": []}]}
    verdict = policy.parse_verdict(200, encoded(mixed))
    assert (verdict.verdict, verdict.reason) == ("fail", "errors")
    assert verdict.failures == [{"user": "b@example.com", "raw": "a failure"}]
    assert verdict.warnings == ({"user": "a@example.com", "line": "a warning"},)


def test_warnings_only_is_pass_with_warnings():
    verdict = policy.parse_verdict(200, encoded(body("api", "validate-scim-warnings")))
    assert (verdict.verdict, verdict.passed, verdict.reason) == ("pass-with-warnings", True,
                                                                 "warnings")
    assert verdict.warnings == ({"user": "group:unknown@example.com",
                                 "line": "group is not syncing from SCIM and will be ignored by "
                                         "rules in the policy file"},)
    assert verdict.failures == []
    # An empty or null error list beside the warnings is still no error.
    for errors in ([], None):
        doc = {"message": "warning(s) found",
               "data": [{"user": "x@example.com", "errors": errors, "warnings": ["w"]}]}
        assert policy.parse_verdict(200, encoded(doc)).verdict == "pass-with-warnings"


def test_a_message_without_data_is_fail():
    for doc in ({"message": "test(s) failed"}, {"message": "test(s) failed", "data": None}):
        verdict = policy.parse_verdict(200, encoded(doc))
        assert (verdict.verdict, verdict.reason, verdict.message) == (
            "fail", "message without data", "test(s) failed")


@pytest.mark.parametrize("doc", [
    [], None, "passed", 1, {"data": []}, {"data": [{}]}, {"data": "x"}, {"message": 3},
    {"status": "ok"}, {"data": [{"user": "u@example.com", "errors": "not a list"}]},
    {"data": [{"user": "u@example.com", "errors": [7]}]},
    {"data": [{"user": 7, "warnings": ["w"]}]},
    # A key the parser does not know could carry a failure in a form it cannot read, so it
    # must never let warnings alone read as a pass.
    {"data": [{"user": "u@example.com", "warnings": ["w"], "failed": ["hidden"]}]},
    {"data": [{"user": "u@example.com", "warnings": ["w"]}], "errors": ["hidden"]},
], ids=repr)
def test_an_unknown_200_shape_is_fail(doc):
    verdict = policy.parse_verdict(200, encoded(doc))
    assert (verdict.verdict, verdict.passed, verdict.reason) == ("fail", False, "unknown shape")


def test_a_400_is_a_parse_failure_verdict():
    # A 400 from validate means the candidate did not parse: a verdict on the draft, not an
    # API failure (§10.2, §14.3).
    verdict = policy.parse_verdict(400, encoded({"message": "line 3, column 5: invalid character"}))
    assert (verdict.verdict, verdict.passed, verdict.reason) == ("fail", False, "HTTP 400")
    assert verdict.message == "line 3, column 5: invalid character"
    assert verdict.messages() == ["line 3, column 5: invalid character"]
    # A body that is not the API's error shape is quoted as an excerpt, redacted.
    secret = "tskey-" + "client-" + "kVal1dCNTRL-" + "v" * 24
    verdict = policy.parse_verdict(400, f"<html>bad {secret}</html>".encode())
    assert verdict.verdict == "fail"
    assert verdict.message == "<html>bad tskey-…[REDACTED]</html>"


@pytest.mark.parametrize("status", [201, 204, 403, 404, 500])
def test_any_other_status_is_an_api_error(status):
    with pytest.raises(ApiError) as caught:
        policy.parse_verdict(status, b"{}")
    assert (caught.value.code, caught.value.http_status) == ("API_BAD_RESPONSE", status)


def test_a_200_body_that_is_not_json_is_a_bad_response():
    # Neither empty nor JSON: nothing in it can be read as a pass, and it is not a verdict on
    # the candidate either, so it is a malformed answer (§10.3).
    with pytest.raises(ApiError) as caught:
        policy.parse_verdict(200, b"ok")
    assert (caught.value.code, caught.value.http_status) == ("API_BAD_RESPONSE", 200)


def test_want_got_is_parsed_per_address_and_unparsed_lines_are_kept():
    lines = [
        'address "2.2.2.2:22": want: Drop, got: Accept',
        'address "tag:fleet:22": want: Accept, got: Drop',
        '"group:example": user not found: "user1@example.com"',
        'address "[fd7a:115c:a1e0::1]:443": want: Accept, got: Drop',
        'address "spec5:22": want: Accept, got: Drop (and something the parser has not seen)',
    ]
    assert policy.parse_want_got(lines) == [
        {"target": "2.2.2.2:22", "want": "Drop", "got": "Accept"},
        {"target": "tag:fleet:22", "want": "Accept", "got": "Drop"},
        {"raw": '"group:example": user not found: "user1@example.com"'},
        {"target": "[fd7a:115c:a1e0::1]:443", "want": "Accept", "got": "Drop"},
        {"raw": 'address "spec5:22": want: Accept, got: Drop (and something the parser has '
                'not seen)'},
    ]
    # In a verdict, each line keeps the user whose test produced it.
    doc = {"message": "test(s) failed", "data": [
        {"user": "tag:dev", "errors": lines[:2]}, {"user": "mc@example.com", "errors": lines[2:3]}]}
    assert policy.parse_verdict(200, encoded(doc)).failures == [
        {"user": "tag:dev", "target": "2.2.2.2:22", "want": "Drop", "got": "Accept"},
        {"user": "tag:dev", "target": "tag:fleet:22", "want": "Accept", "got": "Drop"},
        {"user": "mc@example.com", "raw": '"group:example": user not found: "user1@example.com"'},
    ]


ARRAYS = [
    '[{"src": "mc@example.com", "accept": ["spec5:22"]}]',
    "  \n\t[",
    "// the tests I want\n[",
    "/* a block\n   comment */ [",
    "﻿// a byte-order mark first\n[",
    "// one\n/* two */\n// three\n  [",
]
NOT_ARRAYS = [
    '{"acls": []}',
    "// [ inside a comment\n{}",
    "/* [ */ {}",
    "",
    "// only a comment",
    "/* never closed [",
    '"[" is a string',
]


def test_an_array_shaped_file_is_refused_even_after_leading_comments():
    # The server picks its mode from the body's shape [api §6.3]: an array would run tests
    # against the live policy and say nothing about the candidate.
    for text in ARRAYS:
        assert policy.is_array_body(text.encode("utf-8")), text
        with pytest.raises(UsageError) as caught:
            policy.check_validate_body(text.encode("utf-8"))
        assert caught.value.code == "VALIDATE_ARRAY_BODY"
        assert "tailnet policy test" in caught.value.message
    for text in NOT_ARRAYS:
        assert not policy.is_array_body(text.encode("utf-8")), text
        policy.check_validate_body(text.encode("utf-8"))


def test_the_etag_is_stored_raw_and_shown_with_one_quote_pair_stripped():
    # The header carries its quotes [critic R3]; If-Match wants them back, so they are kept.
    meta = policy.new_meta("fix-ssh", ETAG, SHA_BASE, "2026-10-27T01:02:03Z", "REQ-acl")
    assert meta == {"v": 1, "name": "fix-ssh", "base_etag_raw": ETAG, "base_sha256": SHA_BASE,
                    "fetched_at": "2026-10-27T01:02:03Z", "request_id": "REQ-acl",
                    "validated": None}
    assert policy.display_etag(ETAG) == "e0b2816b418"
    # One pair only, and only a surrounding pair.
    assert policy.display_etag('""e0b""') == '"e0b"'
    assert policy.display_etag('W/"e0b"') == 'W/"e0b"'
    assert policy.display_etag("e0b") == "e0b"
    assert policy.display_etag('"') == '"'
    assert policy.display_etag(None) is None


def validated_meta(verdict="pass", sha=SHA_CANDIDATE, etag=ETAG):
    """A draft's meta.json after a validate of the candidate with this hash."""
    meta = policy.new_meta("fix-ssh", etag, SHA_BASE, "2026-10-27T01:02:03Z", "REQ-acl")
    meta["validated"] = {"sha256": sha, "verdict": verdict, "at": "2026-10-27T01:05:00Z",
                         "request_id": "REQ-validate", "messages": []}
    return meta


def ready(meta, **changed):
    """Readiness with everything unchanged since the draft, except what `changed` says."""
    facts = {"base_sha256": SHA_BASE, "candidate_sha256": SHA_CANDIDATE,
             "live_etag_raw": ETAG, "live_sha256": SHA_BASE, **changed}
    return policy.readiness(meta, **facts)


def test_readiness_needs_the_validated_hash_and_an_unmoved_live_etag():
    assert ready(validated_meta()) == policy.Readiness(True, ())
    assert ready(validated_meta("pass-with-warnings")).ready
    unvalidated = policy.new_meta("fix-ssh", ETAG, SHA_BASE, "2026-10-27T01:02:03Z", "REQ-acl")
    assert ready(unvalidated).reasons == (policy.NOT_VALIDATED,)
    assert ready(validated_meta(sha="d" * 64)).reasons == (policy.CHANGED,)
    assert ready(validated_meta("fail")).reasons == (policy.FAILED,)
    # A candidate edited after a failed validate needs validating again, not just fixing.
    assert ready(validated_meta("fail", sha="d" * 64)).reasons == (policy.CHANGED,)
    assert ready(validated_meta(), live_etag_raw='"f00"').reasons == (policy.MOVED,)
    assert ready(validated_meta(), live_sha256="e" * 64).reasons == (policy.BYTES_MOVED,)
    assert ready(validated_meta(), live_etag_raw=None).reasons == (policy.NO_ETAG,)
    assert ready(validated_meta(etag=None), live_etag_raw=None).reasons == (policy.NO_ETAG,)
    assert ready(validated_meta(), base_sha256="e" * 64).reasons == (policy.BASE_CHANGED,)
    # Drift comes first: when the live policy moved, validating again would be wasted work.
    moved = ready(unvalidated, live_etag_raw='"f00"')
    assert (moved.ready, moved.reasons) == (False, (policy.MOVED, policy.NOT_VALIDATED))
    assert "re-run `policy validate`" in policy.CHANGED
    assert "ETag moved" in policy.MOVED and "re-draft" in policy.MOVED


@pytest.mark.parametrize("src,accept,deny,proto,code", [
    ("*", ["tag:fleet:22"], [], None, "TEST_WILDCARD"),
    ("tag:dev", ["tag:fleet:*"], [], None, "TEST_WILDCARD"),
    ("tag:dev", [], ["*:22"], None, "TEST_WILDCARD"),
    ("tag:dev", ["tag:fleet:22"], [], "*", "TEST_WILDCARD"),
    ("100.64.0.1", ["tag:fleet:22"], [], None, "TEST_SRC_IS_IP"),
    ("fd7a:115c:a1e0::1", ["tag:fleet:22"], [], None, "TEST_SRC_IS_IP"),
    ("[fd7a:115c:a1e0::1]", ["tag:fleet:22"], [], None, "TEST_SRC_IS_IP"),
    ("100.64.0.0/10", ["tag:fleet:22"], [], None, "TEST_SRC_IS_IP"),
    ("100.64", ["tag:fleet:22"], [], None, "TEST_SRC_IS_IP"),
    ("tag:dev", ["tag:fleet:22-23"], [], None, "TEST_PORT"),
    ("tag:dev", ["tag:fleet:65536"], [], None, "TEST_PORT"),
    ("tag:dev", [], ["tag:fleet:ssh"], None, "TEST_PORT"),
    ("tag:dev", ["tag:fleet:"], [], None, "TEST_PORT"),
    ("tag:dev", ["tag:fleet:22,443"], [], None, "TEST_PORT"),
    # Port 0 is for ICMP, and ICMP has no port [pol (c)]: either mismatch tests nothing real.
    ("tag:dev", ["tag:fleet:0"], [], None, "TEST_PORT"),
    ("tag:dev", ["tag:fleet:0"], [], "tcp", "TEST_PORT"),
    ("tag:dev", ["tag:fleet:22"], [], "icmp", "TEST_PORT"),
    ("", ["tag:fleet:22"], [], None, "USAGE"),
    ("mc example", ["tag:fleet:22"], [], None, "USAGE"),
    ("autogroup:member", ["tag:fleet:22"], [], None, "USAGE"),
    ("tag:", ["tag:fleet:22"], [], None, "USAGE"),
    ("tag:dev", [], [], None, "USAGE"),
    ("tag:dev", ["22"], [], None, "USAGE"),
    ("tag:dev", ["fd7a:115c:a1e0::1:22"], [], None, "USAGE"),
    ("tag:dev", ["[not-an-address]:22"], [], None, "USAGE"),
    ("tag:dev", ["100.64.0.0/10:22"], [], None, "USAGE"),
    ("tag:dev", ["tag:fleet:22"], [], "t c p", "USAGE"),
])
def test_policy_test_refuses_wildcards_ip_sources_and_port_ranges(src, accept, deny, proto, code):
    with pytest.raises(UsageError) as caught:
        policy.build_tests(src, accept, deny, proto)
    assert caught.value.code == code


def test_policy_test_builds_one_test_and_sends_proto_only_when_given():
    # Array mode runs these against the live policy [spec 2508-2516]; omitting proto tests
    # "either TCP or UDP" [pol (c)], so it is sent only when asked for.
    assert policy.build_tests("tag:dev", ["tag:fleet:22", "[fd7a:115c:a1e0::1]:22"],
                              ["100.64.0.11:443"], "TCP") == [
        {"src": "tag:dev", "proto": "tcp", "accept": ["tag:fleet:22", "[fd7a:115c:a1e0::1]:22"],
         "deny": ["100.64.0.11:443"]}]
    assert policy.build_tests("mc@example.com", ["spec5:22"], [], None) == [
        {"src": "mc@example.com", "accept": ["spec5:22"]}]
    assert policy.build_tests("group:admins", [], ["tag:fleet:0"], "icmp") == [
        {"src": "group:admins", "proto": "icmp", "deny": ["tag:fleet:0"]}]
    # A bare host alias is a source too [spec 2533-2540].
    assert policy.build_tests("example-host-1", ["tag:fleet:443"], [], None)[0]["src"] == \
        "example-host-1"


def test_a_draft_name_is_short_lowercase_and_names_its_directory():
    # §5.2: --name is checked before any request; a draft without one is still named.
    assert policy.check_name(None) == "draft"
    assert policy.check_name("fix-ssh") == "fix-ssh"
    for bad in ("Fix", "a" * 41, "", "fix_ssh", "../up", "fix ssh"):
        with pytest.raises(UsageError) as caught:
            policy.check_name(bad)
        assert caught.value.code == "USAGE", bad
    moment = datetime(2026, 10, 27, 1, 2, 3, tzinfo=timezone.utc)
    assert policy.draft_dir_name(moment, "fix-ssh") == "20261027T010203Z-fix-ssh"


def test_sections_count_each_part_of_a_json_policy():
    # Counted only from the JSON form: HuJSON is never parsed (§14.1).
    assert policy.sections(body("api", "policy")) == {
        "acls": 1, "grants": 0, "ssh": 0, "tests": 0, "sshTests": 0, "hosts": 1, "groups": 1,
        "tagOwners": 0}
    doc = {"grants": [{}, {}], "ssh": [{}], "tests": [{}], "sshTests": [], "hosts": {},
           "groups": {"group:a": []}, "tagOwners": {"tag:a": [], "tag:b": []}}
    assert policy.sections(doc) == {"acls": 0, "grants": 2, "ssh": 1, "tests": 1, "sshTests": 0,
                                    "hosts": 0, "groups": 1, "tagOwners": 2}
    # A part in a shape a policy file never has is unknown, not zero.
    assert policy.sections({"acls": {"not": "a list"}, "hosts": ["x"]})["acls"] is None
    assert policy.sections({"hosts": ["x"]})["hosts"] is None


def test_meta_json_must_be_one_this_cli_wrote():
    fresh = policy.new_meta("fix-ssh", ETAG, SHA_BASE, "2026-10-27T01:02:03Z", "REQ-acl")
    for meta in (fresh, validated_meta(), validated_meta("pass-with-warnings"),
                 policy.new_meta("x", None, SHA_BASE, "2026-10-27T01:02:03Z", None)):
        assert policy.parse_meta(encoded(meta)) == meta
    missing = {key: value for key, value in fresh.items() if key != "base_sha256"}
    for raw in (b"not json", encoded([]), encoded({**fresh, "v": 2}), encoded({**fresh, "v": True}),
                encoded(missing), encoded({**fresh, "base_sha256": "short"}),
                encoded({**fresh, "base_etag_raw": 7}), encoded({**fresh, "name": None}),
                encoded({**fresh, "validated": "yes"}),
                encoded(validated_meta(sha="not a hash")), encoded(validated_meta("maybe"))):
        with pytest.raises(ValueError):
            policy.parse_meta(raw)


def test_the_diff_numbers_each_line_by_base_and_candidate():
    # difflib's unified diff (§14.4) with each line's number in base and in candidate, so MC
    # can find it in the console's editor.
    base = b"// MC's policy\n{\n  \"acls\": [],\n}\n"
    candidate = b"// MC's policy\n{\n  \"grants\": [],\n  \"tests\": [],\n}\n"
    text, numbered = policy.diff_lines(base, candidate)
    assert text == ('--- base.hujson\n+++ candidate.hujson\n@@ -1,4 +1,5 @@\n'
                    ' // MC\'s policy\n {\n-  "acls": [],\n+  "grants": [],\n'
                    '+  "tests": [],\n }\n')
    assert numbered == [
        "--- base.hujson", "+++ candidate.hujson", "@@ -1,4 +1,5 @@",
        "    1     1   // MC's policy",
        "    2     2   {",
        "    3       -   \"acls\": [],",
        "          3 +   \"grants\": [],",
        "          4 +   \"tests\": [],",
        "    4     5   }",
    ]
    # A hunk that only adds lines numbers from where they land.
    _, numbered = policy.diff_lines(b"", b"{}\n")
    assert numbered[2:] == ["@@ -0,0 +1 @@", "          1 + {}"]
    assert policy.diff_lines(base, base) == ("", [])
