# ABOUTME: Tests for the local halves of `tailnet credentials set` (DESIGN.md §8.4): who may run it, on
# ABOUTME: what kind of terminal, and how typed tags are read. The terminal flow itself is integration.

import io
import os

import pytest

from tailnet import enrol, errors
from tailnet.posture import Posture


def production(tmp_path):
    """A production posture whose real directories are a temporary home."""
    return Posture.from_env({}, real_home=tmp_path)


def test_root_is_refused_only_in_production(tmp_path):
    # Run as root, the files would land in /root, where MC's own commands never look (§8.4).
    with pytest.raises(errors.LocalError) as caught:
        enrol.check_user(production(tmp_path), 0)
    assert caught.value.code == "RUN_AS_ROOT"
    enrol.check_user(production(tmp_path), 1000)
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    enrol.check_user(Posture.from_env(environ, real_home=tmp_path / "real"), 0)


def test_only_a_real_terminal_on_both_ends_counts():
    controller, terminal = os.openpty()
    # Unbuffered: a terminal cannot seek, so it is opened as raw file I/O, which isatty() needs.
    with os.fdopen(terminal, "rb", buffering=0) as tty:
        assert enrol.Terminal(stdin=tty, stdout=tty, stderr=tty).is_terminal()
        # A pipe on either end, as the agent's Bash tool has, is not MC at a terminal.
        assert not enrol.Terminal(stdin=io.StringIO(), stdout=tty, stderr=tty).is_terminal()
        assert not enrol.Terminal(stdin=tty, stdout=io.StringIO(), stderr=tty).is_terminal()
        with pytest.raises(errors.LocalError) as caught:
            enrol.check_terminal(enrol.Terminal(stdin=tty, stdout=io.StringIO(), stderr=tty))
        assert caught.value.code == "NOT_A_TTY"
        assert any(step.get("needs") == "terminal" for step in caught.value.next)
    os.close(controller)


def test_a_prompt_goes_to_the_terminal_and_reads_one_line():
    shown = io.StringIO()
    asked = enrol.Terminal(stdin=io.StringIO("kRead0003CNTRL\nrest\n"), stdout=io.StringIO(),
                           stderr=shown)
    assert asked.ask("Client ID: ") == "kRead0003CNTRL"
    assert shown.getvalue() == "Client ID: "
    closed = enrol.Terminal(stdin=io.StringIO(""), stdout=io.StringIO(), stderr=io.StringIO())
    assert closed.ask("Client ID: ") == ""


def test_typed_tags_are_lowercased_tags_or_refused():
    assert enrol.parse_tags("tag:fleet, TAG:CI") == ("tag:fleet", "tag:ci")
    assert enrol.parse_tags(" tag:fleet ,tag:fleet") == ("tag:fleet",)
    for typed in ("", " ", "fleet", "tag:fleet,,", "tag:fleet tag:ci", "tag:", "tag:-x"):
        with pytest.raises(errors.UsageError) as caught:
            enrol.parse_tags(typed)
        assert caught.value.code == "TAG_MALFORMED", typed
