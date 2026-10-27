# ABOUTME: `tailnet status`: the local state at a glance, which the skill injects when it loads. No API
# ABOUTME: call, no secret opened, at most six lines with --brief, and always exit 0 (DESIGN.md §17).

import json
import os
from datetime import datetime, timedelta, timezone

from tailnet import (
    __version__,
    audit,
    credentials,
    gate,
    localts,
    protected,
    secure_files,
    selfnode,
    tokens,
)
from tailnet.devices import parse_time
from tailnet.errors import LocalError, TailnetError
from tailnet.output import Envelope, format_utc, warn
from tailnet.redact import REDACTOR

# §17: the local `tailscale status --json` gets three seconds; status must answer quickly.
LOCAL_TIMEOUT = 3
# Shorter than any real token; registering one this short would blank it out of all output.
_MIN_TOKEN = 8


def _failure(exc):
    """One line for why a section could not be read: its stable code, or that it was a bug."""
    if isinstance(exc, TailnetError):
        return f"{exc.code}: {exc.message}"
    return f"internal error: {type(exc).__name__}: {exc}"


def _safe(read, fallback):
    """Run one section's read; any failure becomes `fallback` with its error.

    A non-zero exit would abort the skill invocation that injects this status [SK L772-774],
    so no section may stop the command, not even a bug; the bug is still named in the output.
    """
    try:
        return read()
    # Deliberately broad: status always answers, and says what it could not read.
    except Exception as exc:  # noqa: BLE001
        return {**fallback, "error": _failure(exc)}


def _exists(path):
    """Whether a file is there, by lstat alone: a secret file is never opened to find out."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True


def _credential(posture, role):
    """One role's non-secret facts from its JSON file; the secret file is only stat'ed (D20)."""
    present = _exists(posture.config_dir / f"{role}.json")
    entry = {"role": role, "present": present, "client_id": None, "secret": None,
             "secret_file": None, "granted_scope": None, "set_at": None, "error": None}
    if role == "write":
        entry.update(tags=None, tags_source=None)

    def read():
        """Load the metadata, never the secret."""
        meta = (credentials.load_read_meta if role == "read" else
                credentials.load_write_meta)(posture)
        if meta is None:
            return entry
        found = {**entry, "client_id": meta.client_id, "granted_scope": meta.granted_scope,
                 "set_at": meta.set_at, "secret": "file" if meta.secret_path else "inline",
                 "secret_file": _exists(meta.secret_path) if meta.secret_path else None}
        if role == "write":
            found.update(tags=list(meta.tags) if meta.tags is not None else None,
                         tags_source=meta.tags_source)
        return found

    return _safe(read, entry)


def _token_cache(posture, read_client_id):
    """The read-token cache: whose it is, when it expires, and whether a read would use it.

    The cache is read through the same checks as a credential, and its token is registered
    for redaction the moment it is in memory. An unsafe cache is reported and left alone:
    status only reports, and the next read removes it.
    """
    empty = {"present": False, "client_id": None, "scope": None, "expires_at": None,
             "minutes_left": None, "usable": False, "error": None}

    def read():
        """Parse the cache and judge it by the reads' own rule."""
        try:
            raw = secure_files.read_private(posture.config_dir / tokens.CACHE_NAME,
                                            tokens.CACHE_MAX)
        except FileNotFoundError:
            return empty
        except LocalError as exc:
            return {**empty, "present": True,
                    "error": f"{exc.code}: {exc.message}; the next read removes it"}
        try:
            doc = json.loads(raw)
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            # Reads ignore such a cache and mint; status says what it saw.
            return {**empty, "present": True, "error": "the token cache is not a JSON object"}
        token = doc.get("access_token")
        if isinstance(token, str) and len(token) >= _MIN_TOKEN:
            REDACTOR.add_secret(token)
        now = datetime.now(timezone.utc)
        expires = tokens.cache_expiry(doc)
        return {**empty, "present": True, "client_id": doc.get("client_id"),
                "scope": doc.get("scope"), "expires_at": doc.get("expires_at"),
                "minutes_left": (expires - now) // timedelta(minutes=1) if expires else None,
                "usable": read_client_id is not None and tokens.cache_usable(doc, read_client_id,
                                                                             now)}

    return _safe(read, {**empty, "present": True})


def _protected(posture):
    """MC's protected list: answered (with its self line and entry count), unanswered, unreadable."""
    def read():
        """Load and summarise the list."""
        listed = protected.load(posture)
        if listed is None:
            return {"state": "unanswered", "self_node_id": None, "entries": None, "error": None}
        return {"state": "answered", "self_node_id": listed.self_node_id,
                "entries": len(listed.entries), "error": None}

    return _safe(read, {"state": "unreadable", "self_node_id": None, "entries": None})


def _gate(posture):
    """Which rules.json strings MC's settings hold (D21): checked on every run, so tampering shows."""
    def read():
        """Compare the settings file with the rules an install writes for it."""
        claude = gate.claude_dir(posture, os.environ)
        expected = gate.rules_for(claude)
        return {"present": gate.gate_present(posture.claude_settings),
                "missing": gate.missing_rules(posture.claude_settings, claude),
                "total": len(expected["ask"]) + len(expected["deny"]),
                "settings": str(posture.claude_settings), "error": None}

    return _safe(read, {"present": False, "missing": None, "total": None,
                        "settings": str(posture.claude_settings)})


def _self_local(posture):
    """This host as its local tailscale sees it; never joined to the API, which status never calls."""
    view = {"run": posture.runs_tailscale, "hostname": None, "ips": [], "backend_state": None,
            "online": None, "reason": None, "error": None}
    if not posture.runs_tailscale:
        return {**view, "reason": "not run (test posture)"}

    def read():
        """Ask the local daemon, briefly."""
        try:
            text = localts.status_json(posture, timeout=LOCAL_TIMEOUT)
        except LocalError as exc:
            return {**view, "reason": f"{exc.code}: {exc.message}"}
        except localts.Failed as exc:
            return {**view, "reason": exc.reason}
        local = selfnode.parse_status(text)
        return {**view, "hostname": local.hostname, "ips": list(local.ips),
                "backend_state": local.backend_state, "online": local.online,
                "reason": local.reason}

    return _safe(read, view)


def _last_doctor(posture):
    """The newest doctor.run line: when, its counts, and the questions it left for MC."""
    def read():
        """Read the newest doctor run back from the audit log (D3)."""
        record = audit.last(posture, "doctor.run")
        if record is None:
            return {"ran": False, "ts": None, "counts": None, "questions": None, "error": None}
        counts = record.get("counts")
        questions = record.get("questions")
        if isinstance(questions, list):
            questions = [q if isinstance(q, str) else (q or {}).get("id") for q in questions
                         if isinstance(q, (str, dict))]
        else:
            questions = None
        return {"ran": True, "ts": record.get("ts"),
                "counts": counts if isinstance(counts, dict) else None,
                "questions": questions, "error": None}

    return _safe(read, {"ran": None, "ts": None, "counts": None, "questions": None})


def _audit(posture):
    """Where the audit log is and how many records it holds."""
    path = str(audit.log_path(posture))
    return _safe(lambda: {"path": path, "lines": audit.count_lines(posture), "error": None},
                 {"path": path, "lines": None})


def _count(n, noun, plural=None):
    """`n noun`, with the noun plural unless n is one."""
    return f"{n} {noun if n == 1 else plural or noun + 's'}"


def _credentials_line(data):
    """Brief line 2: the mode, each client, and the read token's state."""
    mode = data["mode"]
    read, write = data["credentials"]
    if mode == "none":
        text = "credentials: none (no read client)"
    elif mode == "unknown":
        text = f"credentials: unknown ({data['mode_error'] or 'unreadable'})"
    else:
        parts = [f"read {read['client_id']}"]
        if write["error"]:
            parts.append(f"write unreadable ({write['error'].split(':')[0]})")
        elif write["client_id"]:
            secret = {True: "present", False: "absent", None: "unknown"}[write["secret_file"]]
            parts.append(f"write {write['client_id']}, secret {secret}")
        else:
            parts.append("no write client")
        text = f"credentials: {mode} ({'; '.join(parts)})"
        if mode == "single-client":
            # §8.3: one client holds both powers, so there is no separate write secret (L2).
            text += " · L2 absent"
    cache = data["token_cache"]
    if cache["error"]:
        token = "read token cache unreadable (the next read removes it)"
    elif not cache["present"]:
        token = "no read token cached"
    elif cache["usable"]:
        token = f"read token cached, {cache['minutes_left']} min left"
    else:
        token = "read token cached but not usable (expired, or for another client)"
    return f"{text} · {token}"


def _protected_line(data):
    """Brief line 3: the protected list and the gate rules."""
    listed = data["protected"]
    if listed["state"] == "answered":
        entries = _count(listed["entries"], "entry", "entries")
        text = f"protected: answered ({entries}, self {listed['self_node_id']})"
    elif listed["state"] == "unanswered":
        text = "protected: unanswered (tag writes refused)"
    else:
        text = f"protected: unreadable ({(listed['error'] or '').split(':')[0]})"
    rules = data["gate"]
    if rules["error"]:
        rules_text = f"gate rules: unknown ({rules['error'].split(':')[0]})"
    else:
        total, missing = rules["total"], rules["missing"]
        rules_text = f"gate rules: {total - len(missing)}/{total} present"
        if missing and len(missing) == total:
            rules_text += " (MISSING: all; re-run the installer)"
        elif missing:
            rules_text += f" (MISSING: {', '.join(missing)})"
    return f"{text} · {rules_text}"


def _self_line(data):
    """Brief line 4: this host as its local tailscale sees it."""
    view = data["self_local"]
    if not view["run"]:
        return "self (local view): not run (test posture)"
    if view["reason"] or view["error"]:
        return f"self (local view): unknown ({view['reason'] or view['error']})"
    return (f"self (local view): {view['hostname']} {view['ips'][0]} "
            f"BackendState={view['backend_state']}")


def _doctor_line(data):
    """Brief line 5: when doctor last ran, what it found, and what it asked MC."""
    run = data["last_doctor"]
    if run["error"]:
        return f"last doctor: unreadable ({run['error'].split(':')[0]})"
    if not run["ran"]:
        return "last doctor: never run"
    when = parse_time(run["ts"])
    stamp = when.strftime("%Y-%m-%dT%H:%MZ") if when else run["ts"]
    counts = run["counts"]
    found = (f"{counts.get('fail', '?')} FAIL, {counts.get('warn', '?')} WARN" if counts
             else "counts unknown")
    questions = data["open_questions"]
    asked = (f"{_count(len(questions), 'question')} for MC" if questions is not None
             else "questions unknown")
    return f"last doctor: {stamp} · {found} · {asked}"


def _audit_line(data):
    """Brief line 6: the audit log and its size."""
    log = data["audit"]
    if log["error"]:
        return f"audit: {log['path']} (unreadable: {log['error'].split(':')[0]})"
    return f"audit: {log['path']} ({_count(log['lines'], 'line')})"


def _details(data):
    """The full view's extra lines: each client, the cache, every missing rule, the questions."""
    lines = []
    for entry in data["credentials"]:
        if entry["error"]:
            lines.append(f"{entry['role']} client: {entry['error']}")
        elif entry["client_id"]:
            facts = [f"secret {entry['secret']}", f"scope {entry['granted_scope'] or '?'}",
                     f"set {entry['set_at'] or '?'}"]
            if entry["role"] == "write":
                facts.insert(0, f"tags {','.join(entry['tags'] or []) or '?'} "
                                f"({entry['tags_source'] or 'unrecorded'})")
            lines.append(f"{entry['role']} client: {entry['client_id']} · {' · '.join(facts)}")
    cache = data["token_cache"]
    if cache["present"] and not cache["error"]:
        lines.append(f"token cache: for {cache['client_id']}, expires {cache['expires_at']}")
    for rule in data["gate"]["missing"] or []:
        lines.append(f"missing rule: {rule} (in {data['gate']['settings']})")
    if data["open_questions"]:
        lines.append(f"open questions: {', '.join(data['open_questions'])}")
    return lines


def _next_steps(data):
    """Who acts next, for the full view; the brief one has no room for them."""
    steps = []
    if data["mode"] == "none":
        steps.append({"who": "mc", "needs": "terminal", "do": "tailnet credentials set read",
                      "why": "there is no read client; it prompts for the client ID and secret, "
                             "so neither passes through chat"})
    if data["gate"]["missing"]:
        steps.append({"who": "mc", "needs": "terminal",
                      "do": "./install-tailnet.sh (from the tailnet checkout)",
                      "why": f"it re-adds the missing rules to {data['gate']['settings']}; they "
                             "put each --apply in front of MC and keep the secrets out of the "
                             "agent's reach"})
    if data["protected"]["state"] == "unanswered" or data["last_doctor"]["ran"] is False:
        steps.append({"who": "agent", "run": "tailnet doctor",
                      "why": "it checks everything end to end and proposes the protected list "
                             "for MC to write"})
    return steps


def run(posture, args):
    """`tailnet status`: every section of the local state, always exit 0 (§17)."""
    read = _credential(posture, "read")
    mode = _safe(lambda: {"mode": credentials.mode(posture), "error": None}, {"mode": "unknown"})
    data = {"version": __version__, "posture": posture.kind, "mode": mode["mode"],
            "credentials": [read, _credential(posture, "write")],
            "token_cache": _token_cache(posture, read["client_id"]),
            "protected": _protected(posture), "gate": _gate(posture),
            "self_local": _self_local(posture), "last_doctor": _last_doctor(posture),
            "audit": _audit(posture)}
    data["open_questions"] = data["last_doctor"]["questions"]
    brief = [_credentials_line({**data, "mode_error": mode["error"]}), _protected_line(data),
             _self_line(data), _doctor_line(data), _audit_line(data)]
    lines = brief if args.brief else brief + _details(data)
    data["last_doctor"] = {k: v for k, v in data["last_doctor"].items() if k != "questions"}
    return Envelope("status", posture.kind, data=data,
                    next=[] if args.brief else _next_steps(data),
                    measured_at=format_utc(datetime.now(timezone.utc)),
                    headline=f"tailnet {__version__} · {posture.kind} posture", lines=lines)


def refused(exc):
    """The status for a run whose posture override was refused: still exit 0, and it says why.

    Every other command exits 3 here. Status answers 0, because a non-zero exit would abort
    the skill's injection [SK L772-774], and reports that neither posture holds; it reads
    nothing, since no path can be trusted until a posture is decided.
    """
    raised = [warn(exc.code, exc.message)]
    return Envelope("status", "unknown", data={"version": __version__, "posture": "unknown",
                                               "posture_error": exc.to_dict()},
                    warnings=raised, measured_at=format_utc(datetime.now(timezone.utc)),
                    headline=f"tailnet {__version__} · posture refused",
                    lines=[f"posture: refused ({exc.code}): {exc.message}",
                           "nothing else was read: no file, no API, no tailscale"])
