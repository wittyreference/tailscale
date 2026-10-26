# ABOUTME: Tests for tailnet.redact, the filter every byte of output passes through (DESIGN.md §10.4).
# ABOUTME: Key-shaped strings are assembled at runtime so no literal key is ever staged.

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tailnet.redact import Redactor

SRC = Path(__file__).resolve().parents[2] / "src"


def client_key():
    """A key-shaped OAuth client secret, built from parts (CLAUDE.md invariant 14)."""
    return "tskey-" + "client-" + "kAbc123CNTRL-" + "x" * 24


def test_a_client_secret_is_redacted_by_pattern():
    out = Redactor().redact(f"minting with {client_key()} failed")
    assert out == "minting with tskey-…[REDACTED] failed"


@pytest.mark.parametrize("header", ["Authorization: Bearer abc.DEF~123+/=-", "authorization: bearer abc"])
def test_a_bearer_token_is_redacted(header):
    out = Redactor().redact(header + " (sent once)")
    assert out.endswith("Bearer …[REDACTED] (sent once)")
    assert "abc" not in out


def test_a_registered_secret_without_the_tskey_prefix_is_redacted():
    redactor = Redactor()
    secret = "test-client-" + "read0001"
    redactor.add_secret(secret)
    assert redactor.redact(f"token for {secret}: {secret}.") == "token for [REDACTED]: [REDACTED]."


def test_form_encoded_and_json_secret_fields_are_redacted():
    redactor = Redactor()
    form = "client_id=k123456CNTRL&client_secret=s3cr3t-value&grant_type=client_credentials"
    assert redactor.redact(form) == (
        "client_id=k123456CNTRL&client_secret=…[REDACTED]&grant_type=client_credentials")
    body = '{"access_token":"opaque-token-value","token_type":"Bearer","client_secret" : "s3"}'
    out = redactor.redact(body)
    assert out == '{"access_token": "…[REDACTED]","token_type":"Bearer","client_secret": "…[REDACTED]"}'


def test_a_json_secret_field_with_escaped_quotes_is_redacted_whole():
    out = Redactor().redact(json.dumps({"client_secret": 'ab"cd\\ef'}))
    assert out == '{"client_secret": "…[REDACTED]"}'


def test_json_escaped_secrets_are_redacted_after_serialisation():
    redactor = Redactor()
    # A registered value with characters JSON escapes: the serialised text no longer
    # contains the raw value, so matching on it alone would miss it.
    secret = 'opaque"tok\\en/é-0001'
    redactor.add_secret(secret)
    for ensure_ascii in (True, False):
        text = json.dumps({"message": f"server echoed {secret}"}, ensure_ascii=ensure_ascii)
        out = redactor.redact(text)
        assert json.loads(out) == {"message": "server echoed [REDACTED]"}


def test_url_encoded_forms_of_a_registered_secret_are_redacted():
    redactor = Redactor()
    redactor.add_secret("tok/en+value=0001")
    out = redactor.redact("GET /x?a=tok%2Fen%2Bvalue%3D0001 and ?b=tok%2Fen%2Bvalue%3D0001")
    assert "tok" not in out
    assert out.count("[REDACTED]") == 2


def test_a_secret_containing_another_is_redacted_whole():
    redactor = Redactor()
    redactor.add_secret("abcd1234")
    redactor.add_secret("abcd1234efgh5678")
    assert redactor.redact("x abcd1234efgh5678 y") == "x [REDACTED] y"


def test_an_empty_secret_is_refused():
    # Registering "" would insert the marker between every character of every output.
    with pytest.raises(ValueError):
        Redactor().add_secret("")


def test_a_tailscale_ssh_check_url_is_redacted():
    out = Redactor().redact("check mode: visit https://login.tailscale.com/a/1a2b3c4d5e6f to approve")
    assert out == "check mode: visit https://login.tailscale.com/a/…[REDACTED] to approve"


def test_text_without_secrets_is_unchanged():
    text = ("12 of 12 devices (the API does not paginate) as of 2026-10-27T01:02:03Z\n"
            'client_id=k123456CNTRL {"client_id": "k123456CNTRL", "client_secret": null}\n'
            "the tskey- prefix alone, https://login.tailscale.com/admin, and token: none")
    assert Redactor().redact(text) == text


def run_python(code, env=None):
    """Run code in a fresh isolated interpreter that imports tailnet from src/."""
    prelude = f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
    return subprocess.run([sys.executable, "-I", "-c", prelude + code], capture_output=True,
                          text=True, env={"PATH": "/usr/bin:/bin", **(env or {})}, check=False)


CRASH = """
from tailnet import redact
secret = "s3cr3t-" + "value-" + "0001"
redact.REDACTOR.add_secret(secret)
redact.install_excepthook()
raise RuntimeError("boom with " + secret + " and " + "tskey-" + "auth-" + "kAbc1CNTRL-q7q7q7")
"""
# The assembled values. Fragments of them may appear (3.13 prints -c source in tracebacks).
CRASH_SECRETS = ("s3cr3t-" + "value-" + "0001", "tskey-" + "auth-" + "kAbc1CNTRL-q7q7q7")


def test_the_excepthook_redacts_and_exits_1():
    result = run_python(CRASH)
    assert result.returncode == 1
    assert result.stdout == ""
    assert not any(secret in result.stderr for secret in CRASH_SECRETS)
    assert "RuntimeError: boom with [REDACTED] and tskey-…[REDACTED]" in result.stderr
    assert "Traceback" not in result.stderr
    assert "TAILNET_DEBUG=1" in result.stderr


def test_the_traceback_is_shown_redacted_only_with_tailnet_debug():
    result = run_python(CRASH, env={"TAILNET_DEBUG": "1"})
    assert result.returncode == 1
    assert "Traceback" in result.stderr
    assert not any(secret in result.stderr for secret in CRASH_SECRETS)


def test_an_exception_in_a_thread_is_redacted_too():
    code = """
import threading
from tailnet import redact
secret = "s3cr3t-" + "value-" + "0001"
redact.REDACTOR.add_secret(secret)
redact.install_excepthook()
def work():
    raise RuntimeError("thread saw " + secret)
thread = threading.Thread(target=work, name="probe")
thread.start()
thread.join()
"""
    result = run_python(code)
    assert "s3cr3t-" + "value-" + "0001" not in result.stderr
    assert "RuntimeError: thread saw [REDACTED]" in result.stderr
    assert "probe" in result.stderr
