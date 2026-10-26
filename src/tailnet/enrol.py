# ABOUTME: `tailnet credentials set {read|write}`: MC enrols an OAuth client at a real terminal, and one
# ABOUTME: mint (plus, for writes, the key self-lookup) verifies it before anything is stored (§8.4).

import getpass
import os
import re
import sys
from datetime import datetime, timezone

from tailnet import api, audit, credentials, output, tokens, writes
from tailnet.credentials import READ_SCOPES
from tailnet.errors import ApiError, LocalError, TailnetError, UsageError
from tailnet.output import Envelope, format_utc
from tailnet.redact import redact

# §5.2's tag rule, applied to tags MC types: lowercase, `tag:` and a name.
_TAG = re.compile(r"tag:[a-z0-9][a-z0-9-]*")
TAGS_PROMPT = "Tags on this write client, comma-separated, as the console shows them: "
# Every mint is one event in MC's console [critic F6], so MC is told what this one cost.
REMINDER = "each mint is one 'Create OAuth access token' event in your Tailscale audit log"
_RUN_IT = {"who": "mc", "needs": "terminal",
           "why": "it prompts for the client ID and secret at your terminal, so neither passes "
                  "through chat, argv or the environment"}


class Terminal:
    """MC's terminal for `credentials set`: prompts on stderr, answers on stdin, the secret by getpass.

    Prompts go to stderr so stdout keeps the one envelope --json promises. getpass reads the
    secret from the controlling terminal with echo off, so it never shows on screen.
    """

    def __init__(self, stdin=None, stdout=None, stderr=None):
        self.stdin = sys.stdin if stdin is None else stdin
        self.stdout = sys.stdout if stdout is None else stdout
        self.stderr = sys.stderr if stderr is None else stderr

    def is_terminal(self):
        """Whether both ends are a terminal: the agent's Bash tool has none (§8.4 step 1)."""
        return self.stdin.isatty() and self.stdout.isatty()

    def ask(self, prompt):
        """Show a prompt and read one typed line; an empty answer when the terminal closes."""
        self.stderr.write(redact(prompt))
        self.stderr.flush()
        return self.stdin.readline().rstrip("\r\n")

    def secret(self, prompt):
        """Read a secret with echo off, from the controlling terminal."""
        return getpass.getpass(prompt)


def check_terminal(io):
    """Refuse unless a person is at a terminal: this is MC's command, run over SSH (§8.4 step 1)."""
    if not io.is_terminal():
        raise LocalError("NOT_A_TTY", "`tailnet credentials set` needs a terminal on stdin and "
                                      "stdout: MC runs it over SSH, where the secret is typed and "
                                      "never passes through chat",
                         next=[{**_RUN_IT, "do": "tailnet credentials set read"}])


def check_user(posture, euid):
    """Refuse root in production, where the files would land in /root (§8.4 step 2)."""
    if posture.kind == "production" and euid == 0:
        raise LocalError("RUN_AS_ROOT", "refusing to run as root: the credentials would land in "
                                        "/root, where MC's own commands never look; run it as MC")


def parse_tags(text):
    """Tags MC typed, comma-separated: lowercased (Tailscale reads tags that way [pol (f)]),
    each held to the tag rule, duplicates dropped. Anything else is refused, never guessed at.
    """
    items = [item.strip().lower() for item in text.split(",")]
    if not text.strip() or not all(_TAG.fullmatch(item) for item in items):
        raise UsageError("TAG_MALFORMED", "type the write client's tags as the console shows them, "
                                          "comma-separated, each like tag:fleet; nothing was stored")
    return tuple(dict.fromkeys(items))


def _single_client(posture, client_id):
    """Whether a read client being set is the write client too, so its mint must be narrowed."""
    try:
        meta = credentials.load_write_meta(posture)
    except LocalError:
        return False
    return meta is not None and meta.client_id == client_id


def _write_power(token):
    """Whether a write client's grant can change a device: devices:core, or a legacy name for it."""
    granted = {item for item in re.split(r"[\s,]+", token.scope or "") if item}
    return bool(granted & writes.WRITE_SCOPES)


def _lookup(session, cred, token):
    """The write client's self-lookup with its own token: (tags it reports or None, outcome).

    Which ID the endpoint takes is unverified (critic Q3), so any answer but a 200 with tags
    falls back to tags MC types; the outcome is recorded either way.
    """
    try:
        reply = api.get_key(session, cred.client_id, as_token=token)
    except (ApiError, LocalError) as exc:
        return None, {"status": exc.http_status, "request_id": exc.request_id, "error": exc.code}
    response = reply.response
    found = reply.data.get("tags")
    outcome = {"status": response.status, "request_id": response.request_id, "error": None}
    if isinstance(found, list) and found and all(isinstance(tag, str) for tag in found):
        return tuple(dict.fromkeys(tag.lower() for tag in found)), outcome
    return None, outcome


def set_interactive(posture, role, io):
    """Enrol the `role` client MC types at `io`, verified before it is stored (§8.4).

    The order is: the terminal and root checks, the config directory, `replace? [y/N]` when
    the role exists, the two prompts, then one verification mint. A write client must hold
    devices:core and has its tags read by the self-lookup, or typed. Only then are the files
    written; nothing a failed verification would leave behind is ever stored (amendment
    A34). Returns the envelope's data, or None when MC kept the existing client.
    """
    check_terminal(io)
    check_user(posture, os.geteuid())
    config = credentials.ensure_config_dir(posture)
    if (config / f"{role}.json").exists():
        answer = io.ask(f"replace the existing {role} client? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            return None
    client_id = io.ask("Client ID: ").strip()
    cred = credentials.typed(posture, role, client_id, io.secret("Client secret: "))
    session = api.session(posture)
    narrowed = role == "read" and _single_client(posture, client_id)
    token = tokens.mint(posture, session.transport, cred,
                        scope=" ".join(READ_SCOPES) if narrowed else None)
    data = {"role": role, "client_id": cred.client_id, "granted_scope": token.scope,
            "cacheable": token.cacheable, "cached": False, "tags": None, "tags_source": None,
            "self_lookup": None, "request_ids": [token.request_id] if token.request_id else []}
    if role == "write":
        if not _write_power(token):
            raise LocalError("CREDENTIAL_MALFORMED",
                             f"the write client {cred.client_id} was granted {token.scope!r}, "
                             "which holds none of devices:core, devices or all: it cannot write, "
                             "so nothing was stored",
                             next=[{"who": "mc", "needs": "console",
                                    "do": "give the write client Devices Core Write and its tag "
                                          "in the admin console, then run `tailnet credentials "
                                          "set write` again",
                                    "why": "a write client without devices:core cannot change "
                                           "a device"}])
        tags, data["self_lookup"] = _lookup(session, cred, token)
        if data["self_lookup"]["request_id"]:
            data["request_ids"].append(data["self_lookup"]["request_id"])
        source = "self-lookup"
        if tags is None:
            tags, source = parse_tags(io.ask(TAGS_PROMPT)), "typed"
        data.update(tags=list(tags), tags_source=source)
    set_at = format_utc(datetime.now(timezone.utc))
    written = credentials.store(posture, cred, granted_scope=token.scope, set_at=set_at,
                                tags=data["tags"], tags_source=data["tags_source"])
    data["files"] = [str(path) for path in written]
    if role == "read":
        data["cached"] = _cache(posture, token)
    # The write token is simply dropped here: it was held for this command only (invariant 3).
    return data


def _cache(posture, token):
    """Cache the read client's verification token if its grant may sit on disk (§9.2)."""
    if not token.cacheable:
        # A grant that can write lives in memory only, and an older cache is now stale.
        tokens.discard_cache(posture)
        return False
    try:
        tokens.store_cache(posture, token)
    except (LocalError, OSError):
        return False
    return True


def _lines(data):
    """The human view's block: what was stored, what the grant is, what the mint cost."""
    lines = [f"{data['role']} client {data['client_id']}: granted {data['granted_scope']}"]
    if data["role"] == "read":
        lines.append("read token cached for its hour" if data["cached"]
                     else "read token not cached: the grant can write, or the cache could not be "
                          "written")
    else:
        lookup = data["self_lookup"]
        lines.append(f"tags {', '.join(data['tags'])} ({data['tags_source']}); key self-lookup: "
                     f"HTTP {lookup['status'] if lookup['status'] is not None else '-'}")
    lines.append("wrote " + " and ".join(data["files"]) + " (0600)")
    lines.append(REMINDER)
    return lines


def run_set(posture, args, *, io=None):
    """`tailnet credentials set {read|write}`: MC's hands only, one command (§8.4)."""
    data = set_interactive(posture, args.role, Terminal() if io is None else io)
    now = format_utc(datetime.now(timezone.utc))
    request_ids = data.pop("request_ids") if data is not None else []
    if data is None:
        return Envelope("credentials set", posture.kind, data={"role": args.role, "kept": True},
                        measured_at=now,
                        headline=f"OK: nothing changed: the existing {args.role} client stays")
    raised = []
    if data["role"] == "read" and not data["cacheable"]:
        raised.append(output.warn("READ_CLIENT_CAN_WRITE",
                                  f"the read client {data['client_id']} was granted "
                                  f"{data['granted_scope']!r}, which can write: this is "
                                  "single-client mode; L2 is absent", "§8.3"))
    record = {"event": "credential.set", "role": data["role"], "client_id": data["client_id"],
              "granted_scope": data["granted_scope"], "tags": data["tags"],
              "tags_source": data["tags_source"]}
    if data["role"] == "write":
        record["self_lookup"] = data["self_lookup"]
    try:
        audit.append(posture, record)
        data["audit_error"] = None
    except TailnetError as exc:
        # The client is stored and verified; only the narrative is missing, so say so loudly.
        data["audit_error"] = f"{exc.code}: {exc.message}"
        raised.append(output.warn(exc.code, f"{exc.message}; this credential change is not in "
                                            "the local audit log"))
    steps = [{"who": "agent", "run": "tailnet doctor",
              "why": "checks the new client end to end and settles what it can"}]
    if data["role"] == "write":
        steps.append({"who": "mc", "needs": "terminal", "do": "tailnet credentials forget write",
                      "why": "after a write session: removes the write secret again, the "
                             "posture that holds against a determined agent (L2)"})
    return Envelope("credentials set", posture.kind, data=data, warnings=raised, next=steps,
                    request_ids=request_ids, measured_at=now,
                    headline=f"OK: {data['role']} client {data['client_id']} verified and stored",
                    lines=_lines(data))
