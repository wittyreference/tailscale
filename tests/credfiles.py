# ABOUTME: Writes the files a configured client leaves behind (read.json, write.json, their secrets, the
# ABOUTME: token cache) for tests that need one, with exact 0600 modes and secrets assembled at runtime.

import json
from datetime import datetime, timedelta, timezone

from tailnet.output import format_utc

READ_SCOPES = "devices:core:read policy_file:read devices:posture_attributes:read dns:read"
WRITE_SCOPE = "devices:core"


def fixture_secret(tag):
    """A test-posture client secret: no tskey- prefix, so test posture accepts it (§7.1)."""
    return "test-client-" + tag


def access_token(tag):
    """An access token as the loopback seam hands it out, assembled from parts."""
    return "test-access-" + tag


def put(path, text, mode=0o600):
    """Write a file with an exact mode and return its path."""
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def write_role(posture, role, secret=None, /, **fields):
    """Write <role>.secret and <role>.json as `credentials set` would; `fields` override the JSON.

    The client ID is kRead0001CNTRL or kWrite0001CNTRL unless a field says otherwise.
    """
    posture.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret = fixture_secret(role + "0001") if secret is None else secret
    config = posture.config_dir
    doc = {"v": 1, "role": role, "client_id": f"k{role.title()}0001CNTRL",
           "client_secret": f"file:{config / (role + '.secret')}",
           "set_at": "2026-10-26T20:00:00Z",
           "granted_scope": READ_SCOPES if role == "read" else WRITE_SCOPE}
    if role == "write":
        doc.update(tags=["tag:fleet"], tags_source="self-lookup")
    doc.update(fields)
    put(config / f"{role}.secret", secret + "\n")
    return put(config / f"{role}.json", json.dumps(doc))


def write_cache(posture, token, *, expires_in, client_id="kRead0001CNTRL", scope=READ_SCOPES,
                mode=0o600):
    """Write a read-token cache (§9.3) whose token expires `expires_in` seconds from now."""
    now = datetime.now(timezone.utc)
    doc = {"v": 1, "client_id": client_id, "access_token": token, "scope": scope,
           "minted_at": format_utc(now - timedelta(seconds=60)),
           "expires_at": format_utc(now + timedelta(seconds=expires_in))}
    return put(posture.config_dir / "read-token.json", json.dumps(doc), mode)


def token_reply(token, *, scope=READ_SCOPES, expires_in=3600, request_id="REQ-mint"):
    """A loopback reply in the token endpoint's documented shape [OC L132]."""
    return (200, {"X-Tailscale-Request-Id": request_id},
            {"access_token": token, "token_type": "Bearer", "expires_in": expires_in,
             "scope": scope})
