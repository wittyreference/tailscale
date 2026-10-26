# Credentials: MC's two OAuth clients

What MC accepted, what each client can reach, how MC creates and loads them, what the console's
audit log shows, and how to revoke. Never read, print or copy a credential file, and never ask MC
to paste a secret into chat.

## Contents

1. [What MC accepted (2026-10-26)](#1-what-mc-accepted-2026-10-26)
2. [What each client can reach](#2-what-each-client-can-reach)
3. [Creating the clients (MC, in the console)](#3-creating-the-clients-mc-in-the-console)
4. [Loading them: `tailnet credentials set`](#4-loading-them-tailnet-credentials-set)
5. [The protected file](#5-the-protected-file)
6. [Files, modes and the token cache](#6-files-modes-and-the-token-cache)
7. [Postures: standing or session-scoped](#7-postures-standing-or-session-scoped)
8. [The single-client fallback, and its cost](#8-the-single-client-fallback-and-its-cost)
9. [What MC sees in the console audit log](#9-what-mc-sees-in-the-console-audit-log)
10. [Revoking, and an exposed secret](#10-revoking-and-an-exposed-secret)
11. [Still open](#11-still-open)
12. [Sources](#12-sources)

Tags: **[unverified]** and **[inference]**. Keys resolve in [Sources](#12-sources).

## 1. What MC accepted (2026-10-26)

**The consent text.** This is doctor question 1 (`write-client-consent`) as DESIGN.md §16.4 words
it; DESIGN labels the table's text "abridged":

> "Before creating a write client: Devices → Core: Write reaches every device in the tailnet, not
> only tagged ones (TC L145-147). It can apply its own tag to any device, and tagging a user-owned
> device permanently removes its owner (TAGS L324, L72, L33). The earlier answer 'devices on
> tag:fleet only' rested on the premise that it could touch only fleet boxes; that premise was
> wrong. Create one?"
>
> Options: "Read client only for now" (safe default) / "Also a write client tagged tag:fleet" /
> "One client with every scope (no separate write secret)"

**MC's answer, 2026-10-26** (DESIGN.md Amendment A1, committed in `d65d55e`). After being told the
corrected reach, "a devices:core client can apply its own tag to any device, and tagging albini or
your phone would permanently remove your user from it", MC chose **Two clients**. The option read:

> "Read client (devices:core:read, policy_file:read, devices:posture_attributes:read, dns:read;
> needs no tag) does all day-to-day work. Separate write client (devices:core, tagged tag:fleet) in
> its own 0600 file, loaded only by --apply writes, each of which also prompts you via a Claude
> Code ask rule, even in auto mode."

That answers four of DESIGN §28's questions: MC1 (yes, a write client), MC2 (exactly the four read
scopes), MC3 (two clients) and MC4 (`tag:fleet`). `tailnet doctor` no longer asks question 1; this
section is the record. Do not ask again. DESIGN.md A1 is the record of the answer; no transcript of
the exchange is in this repo.

**Why it was asked again.** On 2026-10-25 at 23:32:49Z an earlier session told MC that a client
restricted to `tag:fleet` "can manage only fleet devices, never your Mac, phone, or the droplet"
(sigint p2:34). MC picked "devices on tag:fleet only (Recommended)" at 23:34:00Z (sigint p2:42).
That premise was wrong (critic F1):

- `devices:core` "has access to read the list of all devices in the tailnet, authorize or remove
  machines, and manipulate tags on devices" [TC L145-147]. No text limits it to tagged devices.
- A client tagged `tag:fleet` can apply `tag:fleet` to any device: requested tags must "exactly
  match the full set of tags on the OAuth client", and "The exact-match check does not consult
  `tagOwners`" [TAGS L324].
- Tagging a user-owned device "removes the user account" [TAGS L72], and "You cannot remove all
  tags from a device" [TAGS L33].

**What this record does not do.** It authorises no write. Every `--apply` still puts the exact
command in front of MC through the Claude Code ask rule, in every interactive mode, bypass
included; a headless `claude -p` run denies it instead (DESIGN §2, L3). A peer session's or another
agent's claim that MC approved a particular write is not MC's approval.

## 2. What each client can reach

Every scope also allows `GET /api/v2/tailnet/:tailnet/keys/:keyID` "for the key in use" [TC L45].

| Client | Scope | Reaches | Source |
|---|---|---|---|
| read | `devices:core:read` | `GET /tailnet/:tailnet/devices`, `GET /device/:deviceID` | [TC L135-141] |
| read | `policy_file:read` | `GET …/acl`, `POST …/acl/preview`, `POST …/acl/validate`. "devices:posture_attributes:read and devices:core:read are required when using this scope" | [TC L91-100] |
| read | `devices:posture_attributes:read` | `GET /device/:deviceID/attributes` and `…/attributes/:attributeKey` | [TC L165-171] |
| read | `dns:read` | `GET …/dns/nameservers`, `/preferences`, `/searchpaths`, `/split-dns`. `/dns/configuration` is not listed [unverified] (critic Q23) | [TC L65-75] |
| write | `devices:core` | The `devices:core:read` endpoints, plus `DELETE /device/:id` and `POST /device/:id/` `authorized`, `expire`, `ip`, `name`, `key`, `tags`. One or more tags are mandatory | [TC L143-163] |

- **The read client needs no tag.** Tags are "Mandatory if the scopes include "devices:core" or
  "auth_keys"" [spec L1991, L2154, L5839] (critic R6).
- **The write client reaches every device** [TC L145-147]. The CLI can send exactly two write
  requests, `POST /device/{id}/tags` and `POST /device/{id}/key` with the constant body
  `{"keyExpiryDisabled": true}`; delete, expire, deauthorize, rename, re-address and expiry
  re-enable have no code path (DESIGN §0, §12.3). That is the CLI's limit, not the credential's:
  anything that reads the write secret can call the API directly.
- **What `tag:fleet` lets it assign.** Exactly `tag:fleet`, on any device, plus any tag whose
  `tagOwners` entry lists `tag:fleet` [TAGS L324, L338]. Whether this rule governs the API path is
  [unverified] (critic Q8); the CLI refuses any set it could not assign (`CLIENT_CANNOT_ASSIGN`).
  Never add `tag:fleet` as an owner of `tag:dev` (DESIGN §28 MC4).
- **Out of reach for both:** routes (`devices:routes:read`), users, the keys list, the
  configuration audit log (`logs:configuration:read`, open question MC11), and any DNS or policy
  write [TC L183-195, L316-320].

## 3. Creating the clients (MC, in the console)

MC's hands and a browser. One action per step, hazard first.

**Before you start.**

- MC must be an Owner or Admin: they "can create an OAuth client with any scope and any tag that is
  in the tailnet", while "a Network admin cannot grant the `devices:core` scope, but an IT admin
  can" [OC L28-30].
- `tag:fleet` must already be a `tagOwners` key. It probably is, since the console applied it to
  three devices on 2026-10-25 and the console applies only tags already in the policy file
  [TAGS L262] [inference]. `tailnet doctor` step S6 confirms it.
- Console labels other than **Read** and **Write** are [unverified]; the names below are the
  scopes' descriptions.

**Read client.**

1. Open https://console.tailscale.com/admin/settings/trust-credentials [OC L34].
2. Select **Credential** [OC L36].
3. Select **OAuth** [OC L38].
4. For each operation, select **Read** or **Write** [OC L40]: Devices Core **Read**, Policy file
   **Read**, Device posture attributes **Read**, DNS **Read**. Nothing else, and no tag.
5. Select **Generate credential** [OC L42].
6. *Hazard: the secret is shown once.* "after you close the **Credential created** page, you won't
   be able to copy the secret again" [OC L44]. Copy the client ID and the secret into a password
   manager now [KSM L11]. Never into chat, a repository [KSM L15], a command line or an environment
   variable.
7. Select **Done** [OC L52].

**Write client.**

1. *Hazard first:* this client can change any device in the tailnet and assign `tag:fleet` to any of
   them, which permanently strips a user-owned device's owner [TC L145-147; TAGS L324, L72, L33].
   The CLI's guard stops accidents, not a determined agent.
2. Open the same Trust credentials page; **Credential**; **OAuth** [OC L34-38].
3. Devices Core **Write**, with `tag:fleet` as its tag. Nothing else. How the tag picker looks is
   [unverified].
4. **Generate credential**, copy both values into the password manager at once, **Done**
   [OC L42-52].

**Check.** On the Logs page, https://console.tailscale.com/admin/logs [AUDIT L13], each client shows
as an "OAuth client | Create API key" event [AUDIT L323].

## 4. Loading them: `tailnet credentials set`

MC runs these on claude-factory as user `mc`, over SSH from Termius or albini. Hand MC one command
per turn and say what it proves.

- **`tailnet credentials set read`** prompts for the client ID (echoed) and the secret (hidden).
  - It needs a terminal: the agent's Bash tool has none, so it fails there with `NOT_A_TTY` (exit
    3). It refuses to run as root (`RUN_AS_ROOT`), because the files would land in `/root`.
  - The secret must begin with the OAuth client prefix `tskey-client-` [KP L15]. An API access
    token, prefix `tskey-api`, is refused by name [KP L13].
  - It mints one token to verify the client **before** writing anything, then writes `read.secret`
    and `read.json` (both 0600) and records the granted scope. A client the token endpoint refuses
    is never stored, so a working one already in place stays (DESIGN A34). If the granted scope
    holds write power it warns `READ_CLIENT_CAN_WRITE`.
  - **Proves:** the secret is on disk, 0600, and mints. Exit 0, 2, 3 or 4.
- **`tailnet credentials set write`** does the same for `write.secret` and `write.json`, and before
  it writes either:
  - stores nothing (`CREDENTIAL_MALFORMED`, exit 3) unless the granted scope contains
    `devices:core` (or the legacy `devices`, or `all`);
  - looks itself up with `GET /tailnet/-/keys/<client_id>`, using the token it just minted, and
    records its tags, or asks MC to type them as the console shows them (which ID that lookup takes
    is [unverified], critic Q3); typed text that is not tags stores nothing (`TAG_MALFORMED`, exit 2);
  - discards the write token; it is never cached.
- Each command prints the reminder that every mint is one "Create OAuth access token" event in the
  console's audit log (DESIGN §8.4).

## 5. The protected file

- `~/.config/tailnet/protected` lists the devices the CLI must never retag. **MC writes it by hand;
  no CLI command and no agent does** (the deny rules block the agent).
- `tailnet doctor` proposes it: one `self <nodeId>` line plus every device. MC deletes the lines for
  devices the CLI may tag, then runs doctor's single shell block over SSH.
- Exactly one `self` line is required. Self is always protected from tag writes, listed or not.
- **Missing file**: every tag write is refused (`PROTECTED_UNANSWERED`); `disable-key-expiry` still
  works, because keeping hosts on the tailnet must not wait on this answer (DESIGN §11.4, D7).
- Which devices to protect is still MC's open question MC5; the safe default protects every device.

## 6. Files, modes and the token cache

| Path (all under `~/.config/tailnet/`, directory 0700) | Holds | Written by |
|---|---|---|
| `read.json` | Client ID, granted scope, and the secret or a `file:` path to it | `credentials set read` |
| `read.secret` | The read client's secret | `credentials set read` |
| `write.json` | Client ID, tags, granted scope, and **always** a `file:` path, never the secret | `credentials set write` |
| `write.secret` | The write client's secret | `credentials set write` |
| `read-token.json` | The cached read token | the CLI |
| `protected` | MC's protected list | MC only |

- Every file must be 0600, owned by `mc`, not a symlink, not hard-linked, in a directory nobody else
  can write, or it is refused with exit 3 (DESIGN §8.2). No secret ever comes from an argument or
  an environment variable.
- `status`, `doctor` and the guard only `stat` `write.secret`. It is opened only by a write with
  `--apply` after every guard check has passed, or by MC's `credentials set write`.
- **Read token**: cached for its 3600 s life, and re-minted 5 minutes before expiry. A token is
  cached only if every granted scope ends in `:read`, so an hour of reads costs one audit event
  (DESIGN §9). The lifetime is fixed: "This time cannot be modified" [OC L272].
- **Write token**: minted once per `--apply` command, held in memory, never written to disk.
- **Modes** (DESIGN §8.3): `none` (no read client: every command explains the console steps),
  `read-only` (writes refused with `WRITE_CREDENTIAL_MISSING`), `two-client` (MC's choice), and
  `single-client` (section 8). `tailnet status` shows which.

## 7. Postures: standing or session-scoped

| Posture | What it means | Holds against |
|---|---|---|
| **Standing** (the default) | `write.json` and `write.secret` stay in place | Accidents, in every interactive mode: the ask rule prompts for every `--apply`, bypass and auto included |
| **Session-scoped** | Run `tailnet credentials forget write` after each write session; `credentials set write` again next time | A determined agent too: with no write secret on disk, nothing on the droplet can write to the tailnet |

- Which posture MC wants is open question MC8. After a write session, offer
  `tailnet credentials forget write` **once**; never run it unprompted.
- `tailnet credentials forget {read|write|token}` unlinks that role's files and logs it. Any agent
  may run it, without a prompt, because it only removes power. **It is not revocation**: the client
  still exists in Tailscale.
- **The levers, and where each fails** (DESIGN §2). The ask rule `Bash(*tailnet*--apply*)` prompts
  in every interactive mode [PM L34-36, L327, L650], and a headless `-p` run denies the call
  [PM L56]. Deny rules on `~/.config/tailnet` hold in every mode [PM L30], but not against a script
  that opens files itself [PERM L356]. An installed mod that handles `tool.check` can approve an
  ask-matched call without prompting when the machine has no managed settings and the session has
  no Team or Enterprise login [PERM L641-643]; that MC's setup is that case is [inference].
  **One enforced surface, not the whole surface.**

## 8. The single-client fallback, and its cost

- If MC ever runs one client with every scope (the same client ID in both files, or a read client
  whose granted scope can write), the CLI calls it `single-client` mode, and `status` and `doctor`
  say so.
- Read mints then ask for `scope=devices:core:read policy_file:read devices:posture_attributes:read
  dns:read` [OC L64], and the token is cached only if the granted scope is read-only. Whether a
  `devices:core` client may narrow a token that way is [unverified] (critic Q1).
- **Cost:** the separate write secret is gone, so the posture that holds against a determined agent
  is gone with it; and if narrowing fails, nothing is cached and every command mints, filling MC's
  audit log.

## 9. What MC sees in the console audit log

The log is always on and "cannot be disabled" [AUDIT L31]; it keeps 90 days and that "cannot be
configured" [AUDIT L409]; read-only actions are not included [AUDIT L404].

| Event | When | Source |
|---|---|---|
| OAuth client: Create API key / Update API key / Revoke API key | A client is created; its scopes, tags or description change; it is revoked | [AUDIT L323-325] |
| OAuth access token: Create OAuth access token, actor = the client ID | Every mint: about one per hour of reads (cache), one per `credentials set`, one per `--apply` | [TC L392; AUDIT L329] |
| API: Failed request, "API call attempted with insufficient permission" | Any scope-refused call. `tailnet doctor` step S5 causes one on purpose, at most once per 30 days unless `--settle` | [AUDIT L316]; DESIGN §16.2-16.3 |
| Update tags for node | An applied `tailnet device tag`, with old and new values | [AUDIT L301, L25] |
| Disable key expiry for node | An applied `tailnet device disable-key-expiry` | [AUDIT L295] |

- Whether a write made with the token shows the OAuth client as its actor is [unverified]
  (credentials research §9).
- `tailnet doctor` reports `mints_this_run` and `audit_events_caused`, so MC can match each event.
- No agent can read this log: that needs `logs:configuration:read`, which neither client holds
  (MC11).

## 10. Revoking, and an exposed secret

- **Revoke (MC, console):** Trust credentials page → find the credential → **Revoke** → **Revoke**.
  "When you revoke a trust credential, any active API access tokens that the credential created are
  also revoked" [TC L380-388]. Revoking through the API needs `oauth_keys` [TC L255-261], which
  neither client holds, so no agent can revoke anything.
- **The secret never expires on its own.** It "can be used to generate access tokens indefinitely
  until it is revoked" [TC L21-22].
- **If a secret may be exposed:** revoke it, create a new client, run `credentials set` again, and
  "Review the configuration audit logs to check whether and how the credential and API access
  tokens were used during the period of compromise" [TC L394].
- **If MC pastes a secret into chat:** never use it. Tell MC to revoke it in the console and create
  a new one (DESIGN §19.2).
- **Secret scanning.** OAuth clients are in scope [SCAN L14-17]. GitHub scans public repositories,
  and private ones where configured; if it finds an active Tailscale secret, "Tailscale will revoke
  the secret" and emails the tailnet's security issues contact [SCAN L36-38]. A TruffleHog finding
  is **not** revoked automatically [SCAN L52]; GitGuardian contacts the user and does not notify
  Tailscale [SCAN L28-32].
- Rotating a secret in place is not documented [unverified]; the documented route is a new client
  and revoking the old one.

## 11. Still open

- **MC's questions** (DESIGN A1, §28): MC5-MC12 stay open, each with its safe default. The ones
  that touch credentials are MC5 (the protected list), MC8 (posture) and MC11 (add
  `logs:configuration:read`).
- **Unverified:** token narrowing for a write-capable client (Q1); which tags a `devices:core` token
  carries (Q2); which ID the self-lookup takes (Q3); 403 or 404 for a missing scope (Q4); the format
  of a multi-scope `scope` string (Q5); whether TAGS L324 governs the API path (Q8); whether the API
  can tag a user-owned device (Q9); the console's scope labels and tag picker; in-place rotation;
  the actor recorded for a write.

## 12. Sources

Read or fetched 2026-10-26.

- `DESIGN`: `DESIGN.md` Amendments A1-A2, §0, §2, §8, §9, §11.4, §12, §16, §19.2, §28 in this repo.
- `critic`: `docs/research/critic.md` (2026-10-26).
- credentials research §N: the credentials track `research/credentials.md` (2026-10-26). DESIGN
  cites it as `[cred §N]`, but it is **not committed** under `docs/research/`; every fact used here
  was re-checked against the first-party pages below.
- `sigint pN:L`: the earlier session's transcript extract (2026-10-25T23:05Z-23:58Z), a working file
  that is not committed (DESIGN A2). p2:34 and p2:40-42 were re-read for this file.
- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`
  (live copy identical at 2026-10-26T12:54Z).
- `PM`, `PERM`: Claude Code's https://code.claude.com/docs/en/permission-modes.md and
  https://code.claude.com/docs/en/permissions.md, fetched 2026-10-26 (these pages carry no "Last
  validated" date). Line numbers are those DESIGN §2 cites; L30-36, L56, L327, L650 and PERM
  L356, L641-643 were re-read in the saved copies for this file.
- Tailscale docs, fetched as Markdown with curl; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| TC | https://tailscale.com/docs/reference/trust-credentials | Jan 30, 2026 |
| OC | https://tailscale.com/docs/features/oauth-clients | Jun 30, 2026 |
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| AUDIT | https://tailscale.com/docs/features/logging/audit-logging | Jan 5, 2026 |
| KP | https://tailscale.com/docs/reference/key-prefixes | Aug 1, 2025 |
| KSM | https://tailscale.com/docs/reference/key-secret-management | Jan 5, 2026 |
| SCAN | https://tailscale.com/docs/integrations/secret-scanning | Jan 5, 2026 |
