# ABOUTME: Strips secrets from every outbound string: registered values exactly, known shapes by pattern.
# ABOUTME: Also installs the excepthooks, so even a crash prints nothing a transcript should not hold.

import json
import os
import re
import sys
import threading
import traceback
from urllib.parse import quote, quote_plus

_VALUE_MARKER = "[REDACTED]"

# Applied after registered values, in this order: a field or header pattern runs before the
# bare tskey- pattern, so "Bearer tskey-…" collapses to one marker that still names its kind.
# The JSON field pattern steps over escaped quotes, so an escaped quote inside a value
# cannot end the match early and leave the rest of the secret showing.
_PATTERNS = (
    (re.compile(r'"(access_token|client_secret)"\s*:\s*"(?:[^"\\]|\\.)*"'), r'"\1": "…[REDACTED]"'),
    (re.compile(r'client_secret=[^&\s"]+'), "client_secret=…[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer …[REDACTED]"),
    # One-time Tailscale SSH check-mode links are login links: whoever opens one approves it.
    (re.compile(r"https://login\.tailscale\.com/a/[A-Za-z0-9]+"),
     "https://login.tailscale.com/a/…[REDACTED]"),
    (re.compile(r"tskey-[A-Za-z0-9_-]+"), "tskey-…[REDACTED]"),
)


def _forms(value):
    """Every spelling of a value that can reach output: raw, JSON-escaped, and URL-encoded.

    Redaction runs on final serialised text, where a value containing a quote, a backslash
    or a non-ASCII character no longer appears as itself.
    """
    return {
        value,
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
        quote(value, safe=""),
        quote_plus(value),
    }


class Redactor:
    """Holds the secrets loaded in this process and removes them, and known secret shapes, from text.

    Matching by value does not depend on what a secret or token looks like (the OAuth token's
    prefix is unverified [api §2]); the patterns catch secrets this process never loaded.
    """

    def __init__(self):
        self._values = ()
        self._lock = threading.Lock()

    def add_secret(self, value):
        """Register a secret so every later redact() removes it, in every spelling."""
        if not value:
            raise ValueError("refusing to register an empty secret: it would match everywhere")
        with self._lock:
            values = set(self._values) | _forms(value)
            # Longest first, so a secret that contains another is removed whole.
            self._values = tuple(sorted(values, key=len, reverse=True))

    def redact(self, text):
        """Return text with every registered value and every known secret shape replaced."""
        for value in self._values:
            text = text.replace(value, _VALUE_MARKER)
        for pattern, marker in _PATTERNS:
            text = pattern.sub(marker, text)
        return text


REDACTOR = Redactor()


def redact(text):
    """Redact text with the process-wide redactor; every output path calls this."""
    return REDACTOR.redact(text)


def _write_crash(headline, exc_type, exc, tb):
    """Print a redacted one-line crash report, and the redacted traceback with TAILNET_DEBUG=1."""
    stream = sys.stderr
    if stream is None:
        return
    stream.write(redact(f"{headline}: {exc_type.__name__}: {exc}\n"))
    if os.environ.get("TAILNET_DEBUG") == "1":
        stream.write(redact("".join(traceback.format_exception(exc_type, exc, tb))))
    else:
        stream.write("tailnet: run again with TAILNET_DEBUG=1 to see the redacted traceback.\n")
    stream.flush()


def _excepthook(exc_type, exc, tb):
    """Replace Python's crash printout; the interpreter still exits 1, the INTERNAL code."""
    _write_crash("tailnet: internal error (a bug, exit 1)", exc_type, exc, tb)


def _thread_excepthook(args):
    """Same for a crash on another thread, which Python would otherwise print unredacted."""
    name = args.thread.name if args.thread is not None else "unknown"
    _write_crash(f"tailnet: internal error in thread {name}", args.exc_type, args.exc_value,
                 args.exc_traceback)


def install_excepthook():
    """Route uncaught exceptions, on any thread, through redaction before anything prints."""
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
