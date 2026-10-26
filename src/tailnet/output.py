# ABOUTME: The single exit point for text: the tailnet.v1 JSON envelope, human output, and warnings.
# ABOUTME: Everything is redacted as final serialised text on its way out (DESIGN.md §5.4, §10.4).

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

from tailnet import __version__, errors
from tailnet.redact import redact

SCHEMA = "tailnet.v1"

# Exit 0 covers four outcomes (D16): agents branch on outcome, not on exit 0 alone.
_SUCCESS_OUTCOMES = frozenset({"ok", "dry-run", "noop", "applied"})


def format_utc(moment):
    """Format an aware datetime as UTC ISO 8601 with a Z, to the second: every value's time."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc():
    """The current time as `measured_at` text. MC's rule: every reported value carries its time."""
    return format_utc(datetime.now(timezone.utc))


@dataclass
class Envelope:
    """One command's result: what --json prints as a tailnet.v1 object and what the human view shows.

    `headline` and `lines` are the human verdict and compact block; they never appear in JSON.
    An envelope whose exit and outcome disagree is refused at construction, because agents
    act on the outcome and a mismatch would tell them the wrong thing.
    """

    command: str
    posture: str
    exit: int = errors.OK
    outcome: str = "ok"
    data: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    error: dict | None = None
    next: list = field(default_factory=list)
    request_ids: list = field(default_factory=list)
    measured_at: str = field(default_factory=now_utc)
    headline: str = ""
    lines: list = field(default_factory=list)

    def __post_init__(self):
        allowed = _SUCCESS_OUTCOMES if self.exit == errors.OK else {errors.ERROR_OUTCOMES.get(self.exit)}
        if self.outcome not in allowed:
            raise ValueError(f"outcome {self.outcome!r} cannot go with exit {self.exit}")

    @property
    def ok(self):
        """True only for exit 0; §5.4 defines `ok` as exactly that."""
        return self.exit == errors.OK

    @classmethod
    def from_error(cls, command, posture, exc, **fields):
        """Build the envelope for an exception; anything not a TailnetError is a bug (exit 1)."""
        if not isinstance(exc, errors.TailnetError):
            exc = errors.TailnetError(errors.INTERNAL, "INTERNAL", f"{type(exc).__name__}: {exc}")
        request_ids = list(fields.pop("request_ids", []))
        if exc.request_id and exc.request_id not in request_ids:
            request_ids.append(exc.request_id)
        return cls(command, posture, exit=exc.exit, outcome=exc.outcome, error=exc.to_dict(),
                   next=list(exc.next), request_ids=request_ids, **fields)

    def to_dict(self):
        """The tailnet.v1 object, keys in the order §5.4 documents them."""
        return {
            "schema": SCHEMA, "command": self.command, "cli_version": __version__,
            "posture": self.posture, "measured_at": self.measured_at, "ok": self.ok,
            "exit": self.exit, "outcome": self.outcome, "data": self.data,
            "warnings": self.warnings, "error": self.error, "next": self.next,
            "request_ids": self.request_ids,
        }


def _headline(env):
    """The verdict line before its time: the command's own, else one built from the outcome."""
    if env.headline:
        return env.headline
    if env.error:
        return f"{errors.EXIT_NAMES[env.exit]}: {env.error['code']}: {env.error['message']}"
    return env.outcome.upper().replace("-", " ")


def _next_lines(step):
    """Render one `next` entry, naming who acts, as §5.4 requires."""
    who = step.get("who")
    if who == "agent":
        lines = [f"Next (agent): {step['run']}"]
    elif who == "mc":
        needs = f", {step['needs']}" if step.get("needs") else ""
        lines = [f"Next (MC{needs}): {step['do']}"]
    else:
        lines = [f"Next (ask MC): {step['question']['text']}"]
    if step.get("why"):
        lines.append(f"  why: {step['why']}")
    return lines


def render_human(env):
    """The human view: verdict with its time, the compact block, then who acts next."""
    lines = [f"{_headline(env)} (as of {env.measured_at})", *env.lines]
    for step in env.next:
        lines.extend(_next_lines(step))
    return "\n".join(lines) + "\n"


def emit(env, json_mode, stream=None):
    """Write the envelope to stdout: exactly one JSON object with --json, else the human view.

    Redaction runs on the finished text, so JSON-escaped and nested secrets are caught in the
    form they would actually be printed.
    """
    if json_mode:
        text = json.dumps(env.to_dict(), indent=2) + "\n"
    else:
        text = render_human(env)
    stream = sys.stdout if stream is None else stream
    stream.write(redact(text))
    stream.flush()


def warn(code, message, source=None, stream=None):
    """Print a warning to stderr as `tailnet: CODE: message [source]`, and return it for the envelope."""
    message = redact(message)
    suffix = f" [{source}]" if source else ""
    stream = sys.stderr if stream is None else stream
    stream.write(redact(f"tailnet: {code}: {message}{suffix}\n"))
    stream.flush()
    return {"code": code, "message": message, "source": source}
