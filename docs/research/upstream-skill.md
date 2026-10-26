# Upstream skill audit: `tailscale/tailscale-skill` @ 4f05d35

Audit date: 2026-10-26. Audited by reading every file in the clone, then checking claims against the
live Tailscale docs (fetched as `.md`, exact text via curl) and the OpenAPI spec. Every fact below
carries a source tag; the tags resolve in [Sources](#sources). Line numbers for docs pages refer to the
copies fetched on 2026-10-26 and kept in `scratchpad/dl-upstream-audit/` for re-checking. Anything not
confirmed by a source is marked **[unverified]**.

Notation: `U:<file>:<line>` is the upstream clone (`skills/tailscale/` prefix omitted for
`SKILL.md` and `references/`). `S:<line>` is the OpenAPI spec file. `Dn:<line>` is docs page *n*.

---

## 1. Identity and freshness

| Fact | Source |
|---|---|
| Local clone HEAD is `4f05d353efc56962546aa26ccc59bb08ca699ad1`, one commit, "Public alpha release", 2026-07-09 22:49:15 -0500 | `git log` in clone |
| Remote `HEAD`, `refs/heads/main` and tag `refs/tags/1.0.0-alpha-1` all point at `4f05d353…` on 2026-10-26, so **no commits newer than 4f05d35 exist** | `git ls-remote https://github.com/tailscale/tailscale-skill` (run 2026-10-26) |
| License: BSD 3-Clause, "Copyright (c) 2026 Tailscale Inc & contributors" | `U:LICENSE:1-3` |
| Status: "public Alpha release and is not yet supported"; output is "a starting point rather than a final answer" | `U:README.md:8`; D2:5, D2:13 |
| Docs page states: "The skill supplies reference material, not access. It does not authenticate to your tailnet and does not change your configuration." | D2:104 |
| Size: SKILL.md 269 lines + 17 reference files, 3,241 lines in total including README and LICENSE | `wc -l` in clone |

Open issues or PRs on the GitHub repo that might already fix the defects below: **[unverified]**. The
GitHub API is not enabled for this session, and the GitHub MCP server failed to connect.

---

## 2. Structure, frontmatter, triggers, conventions

### Layout
```
README.md  LICENSE
skills/tailscale/SKILL.md            # router + core concepts + authoring defaults + CLI quick ref
skills/tailscale/references/*.md     # 17 topic files
```
The repo root has no `SKILL.md`. The installable unit is `skills/tailscale/` (D2:42-49).

### Frontmatter (`U:SKILL.md:1-17`)
- Only two keys, `name: tailscale` and `description`. There is no `license`, `metadata`/version,
  `compatibility` or `allowed-tools` (all optional per X4:28-35).
- The `description` is **971 characters** against the Agent Skills limit of 1024 (X4:31, X4:101).
- Agent Skills requires `name` to match the parent directory name (X4:67), so this skill owns the
  directory name `tailscale`.

### Triggers
- The description triggers on a wide surface: Tailscale, headscale, mesh VPN, VPN replacement,
  Docker/Kubernetes, CI/CD runners, device management, session recording, audit logging, LLM API
  access, AI cost control, file sharing, exposing services, tsnet, "even when they describe the
  scenario without naming the product" (`U:SKILL.md:3-16`).
- Explicit invocation is `/tailscale`; implicit invocation "isn't 100% reliable" (`U:README.md:22-27`; D2:53-58).
- The body routes through 13 scenario decision trees (`U:SKILL.md:67-197`) and a topic index table
  (`U:SKILL.md:200-254`).

### Descriptive versus operational convention (`U:SKILL.md:25-33`)
- **Descriptive** (aperture, containers, enterprise, device-management, session-recording, **api**,
  tsnet): a stable mental model inline, plus curated `tailscale.com/docs/...` URLs to "WebFetch for
  current detail". When WebFetch is unavailable, the agent answers inline and names the page.
- **Operational** (only `cli.md`): concrete commands inline "because wrong flags break real systems",
  with a *local* fallback (`tailscale help <subcommand>`) before the docs URL.
- **Self-contained**: access-control, common-tasks, connectivity, exit-nodes, installation,
  subnet-routers. The agent reads the file and answers. (error-messages, border0 and
  sharing-and-publishing are not classified in that paragraph.)
- Observation: `api.md` is classed as *descriptive*, yet it contains executable destructive calls
  (`DELETE /device/{id}`, expire, authorize, retag, bulk-delete loop) (`U:references/api.md:46-60, 108`).
  Under the skill's own rule, anything an agent executes deserves the operational treatment. The API
  has no equivalent of `tailscale help`; the nearest local source of truth would be the OpenAPI spec.
- Observation: the skill relies on **WebFetch** and tells the agent to "quote ... verbatim from the
  fetched content" (`U:references/aperture.md:171`, `containers.md:245`, `session-recording.md:140`).
  In Claude Code, WebFetch "answers `prompt` against [the page] using a small fast model" (X5), so it
  returns a model summary, not verbatim text. Exact text needs the `.md` page fetched raw.

---

## 3. Coverage map

| File | Lines | Shape | Topics and depth |
|---|---|---|---|
| `SKILL.md` | 269 | router | Core concepts; **authoring default "use grants, not ACLs"**; 13 scenario trees; topic index; 10-row CLI quick reference |
| `api.md` | 137 | descriptive | Base URL, `-` tailnet, three auth types, HuJSON, pagination and rate-limit notes; curl for list/get/delete/authorize/expire/tags, create auth key, GET/POST ACL with If-Match, ACL preview; 4 automation patterns; 11 fetch links. **Shallow: no users, routes, DNS, webhooks, logs, settings, services or validate endpoints inline** |
| `cli.md` | 383 | **operational** | up/down/login/logout/switch, status/ip/whois/version/netcheck/ping, `set` (14 flags), serve/funnel, file/drive, nc/dns, lock/cert, update/bugreport/configure/metrics/syspolicy, completion, an "operating the CLI" section (verify-before-guess, prefer `--json`, confirm before destructive commands, diagnostics flow, privilege) |
| `access-control.md` | 186 | self-contained | Grants-first rule, ACL-to-grant conversion, policy sections, groups, tags, grants (ip/app), legacy ACLs, SSH rules, autoApprovers, selectors and autogroups, default policy, JIT (Accessbot, posture, check mode), 3 fetch links |
| `common-tasks.md` | 120 | self-contained | MagicDNS (FQDN, caveats), Tailscale SSH (setup, policy, check mode, platforms), auth key types, node key expiry |
| `error-messages.md` | 52 | lookup table | 19 client and 9 console message pages, plus the hub; answering pattern. **In sync with the live hub: 28 of 28 pages match, none missing, none extra** (compared with D25) |
| `connectivity.md` | 207 | descriptive | Direct/peer-relay/DERP model, NAT matrix, peer-relay config, DERP map, Tailnet Lock concepts and CLI, RDP/VNC/RustDesk; large troubleshooting link table |
| `device-management.md` | 164 | descriptive | Approval, posture (`postures`, `srcPosture`, `defaultSrcPosture`), SCIM, API approval, 8-step rollout; vendor link tables |
| `enterprise.md` | 143 | descriptive | Ephemeral nodes, GitHub Action, site-to-site, Terraform, OAuth clients; reference-architecture links |
| `containers.md` | 245 | descriptive | Docker standalone and sidecar, env vars, k8s operator Helm install, CRD skeletons; about 45 links |
| `session-recording.md` | 140 | descriptive | tsrecorder Docker/k8s, SSH and k8s recording policy, viewing |
| `exit-nodes.md` / `subnet-routers.md` | 119 / 133 | self-contained | Per-platform setup, approval, LAN access, HA, longest-prefix match, SNAT |
| `sharing-and-publishing.md` | 190 | self-contained | Taildrop, Taildrive, Serve, Funnel |
| `installation.md` | 75 | self-contained | Linux script, static binaries, macOS variants, Windows, mobile, update, uninstall |
| `tsnet.md` | 368 | descriptive | Go library: Server, auth modes, policy, capabilities, Services, methods, checklist |
| `aperture.md` / `border0.md` | 174 / 50 | descriptive | AI gateway and PAM; mostly link tables; beta products |

The README calls `cli.md` "every `tailscale` subcommand with flags and examples" (`U:README.md:40`).
It is not: 10 commands in the live CLI reference are absent from `cli.md`. They are `exit-node`
(list/suggest), `get`, `licenses`, `service`, `ssh`, `systray`, `wait`, `web`, `whoami` and
`appc-routes` (D10 command headings, checked mechanically against `cli.md`). For an operator, the
read-only `tailscale get [--json]` (D10:409-428) and `tailscale whoami [--json]` (D10:1034-1046) are
the useful ones.

Link health: 282 distinct `tailscale.com/docs` URLs are cited. With `.md` appended, 277 return 200 and
**5 return 404**. All 5 redirect correctly as HTML, so they have moved:
`aperture/how-to/use-vertex-ai` and `.../use-vertex-ai-express` now go to
`.../use-gemini-enterprise-agent-platform`; `aperture/reference/dashboard` goes to `.../reference/chat`;
`solutions/connect-github-CICD-...` goes to the lower-case `cicd` path; and
`use-cases/infrastructure-access/manage-least-priviledged-and-jit-access` goes to the
`least-privileged` spelling. (curl run on 2026-10-26.)

---

## 4. Stale or wrong claims, with evidence

The "Impact" column rates the harm to an agent that *operates* a tailnet. **High** means a failed or
wrong call, or a wrong security conclusion. **Med** means misleading. **Low** means cosmetic.

### 4a. API, auth and credentials

| # | Upstream claim | Evidence | Verdict | Impact |
|---|---|---|---|---|
| A1 | OAuth clients are "scope-restricted (`devices:read`, `devices:write`, `dns:read`, others)" (`U:references/api.md:13`) | Current scopes are `devices:core:read` / `devices:core` (D3:135-163). `devices:read` is a **legacy** scope (D3:482). Since 2024-11-14, new credentials use the new scopes (D3:400). `devices:write` appears in neither the current nor the legacy list (D3:47-374, D3:404-550). The spec labels device ops `devices:core:read` / `devices:core` (S:126-160, S:295-560) | **Wrong** (one legacy name, one non-existent name) | High |
| A2 | Three auth types: API tokens, OAuth clients, and "Trust credentials — delegated fine-grained access with attribute-based limits ... tied to specific key/value claims" (`U:references/api.md:11-14`) | "Trust credentials come in two forms: OAuth clients and federated OIDC workload identities" (D3:9). The spec says "a trust credential (OAuth client or federated identity)" (S:33). Trust credential is the **umbrella**; the claims-based one is the federated identity | **Wrong taxonomy** | Med |
| A3 | ACL preview: `POST .../acl/preview` with body `{"src":"alice@example.com","dst":"tag:server"}`, captioned "Preview / validate before applying" (`U:references/api.md:100-103`) | Requires the query params `type` (`user` or `ipport`) and `previewFor`, both `required: true` (S:2381-2420). The body is a **policy file** (S:2424-2440, requestBody at S:2427). Validation is a separate endpoint, `POST .../acl/validate`, not mentioned upstream (S:2502-2520) | **Wrong** (the request as written would fail) | High |
| A4 | "No pagination today — list endpoints return everything in one response" (`U:references/api.md:16`) | The spec says "The Tailscale API does not currently support pagination. All results are returned at once." (S:47-49). The one exception is `GET /organizations/{organization}/tailnets` (Alpha), which takes `limit` (max 100) and `cursor` and returns `cursor` (S:3951-3983, S:6595-6597) | **Correct for tailnet-scoped endpoints**; the spec contradicts its own global statement for one Alpha org endpoint | Low |
| A5 | "No published rate limits — ... back off on 429s" (`U:references/api.md:17`) | The spec defines a `429 Too Many Requests` response (S:6701-6708), referenced only on the posture-attribute set and delete ops (S:747, S:770). It publishes one explicit limit: "Invite resends are rate limited to one per minute" (S:1040, S:1105). No general numeric limit is published | **Essentially correct**; misses the one stated limit | Low |
| A6 | Tag scoping: "Scopes are tag-restricted (the client can only operate on tags it owns)" (`U:references/enterprise.md:97`) | `devices:core` "has access to read the list of all devices in the tailnet, authorize or remove machines, and manipulate tags"; the tags chosen on the credential constrain **auth keys created with it** (D3:145-147). "Tags are only relevant for tokens with the `devices:core`, `auth_keys`, or `all` scopes" (D4:66) | **Wrong, and it is a dangerous understatement of blast radius** | High |
| A7 | "Append `?ephemeral=true` to the secret when minting ephemeral nodes" (`U:references/enterprise.md:97`, also `:12`) | For OAuth secrets, `ephemeral` "defaults to `true`" (D4:207). To register a *persistent* node, append `?ephemeral=false` (D17:30) | **Misleading**: redundant for ephemeral, and silent about the default that matters | Med |
| A8 | `TS_AUTHKEY` — "auth key (append `?ephemeral=true` for short-lived containers ...)" (`U:references/containers.md:63`) | For an **auth key**, "set the key's ephemeral property when you create the key"; the `?ephemeral=` suffix applies to OAuth client secrets (D17:28-31) | **Wrong** for auth keys | Med |
| A9 | OAuth scope names: "fetch the OAuth clients page" (`U:references/api.md:118, 133`) | That page now says "Information about our scopes has moved to the trust credentials topic" (D4:261-263) | **Stale pointer** (one extra hop) | Low |
| A10 | "HuJSON (JSON with comments + trailing commas) for the ACL endpoint" (`U:references/api.md:15`) | `POST /acl` accepts both JSON and HuJSON (S:2278). `GET /acl` returns JSON only if `Accept: application/json`, otherwise HuJSON (S:4387-4393) | **Imprecise** | Low |

Verified correct in `api.md`: the base URL (S:9; servers block); the `-` tailnet shorthand (D4:161-177);
basic or bearer auth (S:15-25); API access tokens prefixed `tskey-api-`, 1-90 days (S:31; D5:16); OAuth
secrets prefixed `tskey-client-` (S:33); the token endpoint `/api/v2/oauth/token` (D4:60); the
authorize body `{"authorized": bool}` (S:453-475); expire (S:350-366); the tags body `{"tags":[...]}`
(S:539-570); the create-key `capabilities.devices.create` shape and `expirySeconds`, defaulting to 90 days
(S:1937-1972, schema `KeyCapabilities` S:5725); the key returned only once (S:1927); `lastSeen` and `tags` among the default device
fields (S:4084-4113); If-Match/ETag on `POST /acl` (S:2291-2303), with a 412 on mismatch
(S:2342-2349). Omitted upstream but in the spec: `If-Match: "ts-default"` (S:2302-2303), the
`fields=all` and server-side `<field>=<value>` device filters (S:126-145), and the preference for
`nodeId` over the numeric `id` in device paths (S:4125-4129).

### 4b. CLI (`cli.md`, the file that claims to be operational)

| # | Upstream claim | Evidence | Verdict | Impact |
|---|---|---|---|---|
| C1 | Serve examples `tailscale serve https / http://localhost:3000`, `serve https /docs /path`, `serve https /health text:"OK"`, `serve tcp:5432 tcp://...`, `serve tls-terminated-tcp:5432 ...`, `serve https /docs off` (`U:references/cli.md:160-183`) | "The CLI commands for both Tailscale Funnel and Tailscale Serve have changed in the 1.52 version" (D11:7). The current form is `tailscale serve [flags] <target>` with `--https=<port>`, `--set-path`, `--tcp=<port>`, `--tls-terminated-tcp=<port>` and trailing `off` (D11:12, D11:35-40, D11:49-50, D11:123-124, D11:187). Upstream's own `sharing-and-publishing.md:112` uses the new `tailscale serve 3000` | **Wrong (pre-1.52 syntax)**, and inconsistent within the skill | High |
| C2 | `tailscale funnel https / http://localhost:3000` (`U:references/cli.md:194`) | Current form is `tailscale funnel [flags] <target>` / `--https=<port> <target> [off]` (D12:12, D12:39). `funnel status` and `funnel reset` are valid (D12:17-18) | **Wrong (pre-1.52 syntax)** | High |
| C3 | `tailscale ping <hostname> # Ping via Tailscale (TSMP)` and `--tsmp` as "Explicit TSMP" (`U:references/cli.md:124-125`) | "By default, the Tailscale ping command uses the DISCO protocol" (D14:20). `--tsmp` "Defaults to false" (D10:643) | **Wrong** | Med |
| C4 | `tailscale lock add <node-key>` / `lock remove <node-key>` (`U:references/cli.md:273-274`); `lock init` and `lock revoke-keys` shown without arguments (`:271`, `:277`) | `lock add <tlpub:trusted-key1 ...>` (D13:144); `lock remove [flags] <tlpub:...>` (D13:158); `lock init [flags] <tlpub:...>`, which must include the local node's TLK (D13:49, D13:57-59); `lock revoke-keys <tlpub:...>` (D13:299). `connectivity.md:95-97` gets `tlpub:` right | **Wrong argument type**; inconsistent within the skill | Med (tailnet-lock state is hard to undo) |
| C5 | `tailscale update --check # Check only, don't install` (`U:references/cli.md:298`) | Documented flags are `--dry-run`, `--track`, `--version` and `--yes` (D10:920-925). `--check` is not documented. Whether the binary accepts it: **[unverified]** | **Undocumented flag** (documented equivalent is `--dry-run`) | Med |
| C6 | `--track=stable # Switch release track (stable/unstable)` (`U:references/cli.md:300`) | Tracks are "stable", "release-candidate", or unstable (D10:921) | **Incomplete** | Low |
| C7 | `tailscale metrics # Prometheus-format metrics`; `metrics print # Human-readable` (`U:references/cli.md:323-324`) | Subcommands are `print` ("Shows client metrics in the current terminal session") and `write` (to a text file) (D10:563-566). Bare `tailscale metrics` producing Prometheus output is not documented: **[unverified]** | **Unsupported** | Low |
| C8 | `--accept-routes` "(Linux)" (`U:references/cli.md:34`, `SKILL.md:269`) | The default is to accept on Windows, iOS, Android and both macOS GUI variants; "All other platforms default to not accepting routes" (D10:147), which includes the macOS open-source variant | **Simplified** | Low |

### 4c. Policy, ACLs versus grants (`access-control.md`, `SKILL.md`)

| # | Upstream claim | Evidence | Verdict | Impact |
|---|---|---|---|---|
| P1 | "Use grants, not ACLs ... every new access rule you write should be a grant" (`U:SKILL.md:47`; `access-control.md:7`) | "Grants are the recommended approach for all new tailnets and for updating existing deployments" (D6:50). Grants are "feature complete with ACLs" (D6:20) | **Correct** as an authoring default | — |
| P2 | ACLs are "legacy — read-only ... Do not write new ACLs" (`U:references/access-control.md:106-108`, `:18`) | "Tailscale will always support ACLs ... You may continue to use ACLs indefinitely"; ACLs remain appropriate for existing deployments and ACL-expecting tools; "Grants and ACLs can coexist in the same policy file" (D6:64-72). The **default policy every tailnet starts with is written as ACLs** (D9:41, D9:49-79). Tailscale's own k8s API-event recipe adds an `acls` rule (D26:79-85), as upstream itself notes (`session-recording.md:112`) | **Overstated**: ACLs are supported, not read-only | Med |
| P3 | SSH rule "Actions: `accept` (allow), `check` (require re-authentication), `deny`" (`U:references/access-control.md:141`) | `"action": "check", // "accept" or "check"`; the `action` field defines only `accept` and `check` (D8:551, D8:561-566) | **Wrong** (`deny` is not an SSH action) | High (policy POST would fail validation, or the agent believes a deny exists) |
| P4 | `autogroup:self` "(same device)"; `autogroup:member` "(all users)" (`U:references/access-control.md:163`) | `autogroup:self`: "Select a user's devices", meaning the user's own devices; it "Does not apply to tags" (D8:128, D8:214, D8:230). `autogroup:member`: "direct member (including all invited users) ... Does not include users from shared devices" (D8:217) | **Wrong** (self) / **imprecise** (member) | High (self is a security boundary) |
| P5 | Default policy "lets SSH to all devices as non-root users" (`U:references/access-control.md:168`) | Default: "all users establish a Tailscale SSH session to **their own devices** using **check mode**, as **either root or non-root**"; the rule is `check`, `autogroup:member` to `autogroup:self`, users `["autogroup:nonroot","root"]` (D9:47, D9:64-77) | **Wrong** on scope, mode and users | Med |
| P6 | Grant examples with `"ip": ["*:*"]` (`U:references/access-control.md:88`; `subnet-routers.md:63`; `enterprise.md:87`) | Documented grant `ip` selectors are `*`, `<port>`, `<proto>:*` and `<proto>:<port>` (D7:96-105). `*:*` is ACL `dst` syntax (D9:58-61). Upstream's own conversion note says `"ip": ["*"]` means all ports (`access-control.md:37`). Whether the parser accepts `*:*` in grants: **[unverified]** | **Undocumented form**; inconsistent within the skill | Low-Med |
| P7 | Device-management rollout turns on Device approval (step 3) **and** Tailnet Lock (step 8) (`U:references/device-management.md:89, 94`) | "You cannot enable both Tailnet Lock and device approval—they are mutually exclusive features" (D15:371). Upstream `connectivity.md:107` says the same | **Self-contradiction**; the rollout as written is not achievable | Med |

### 4d. Other references

| # | Upstream claim | Evidence | Verdict | Impact |
|---|---|---|---|---|
| O1 | k8s `enableEvents` "is an **alpha** feature (Tailscale v1.90+) that additionally requires `TS_EXPERIMENTAL_KUBE_API_EVENTS=true`" (`U:references/session-recording.md:112`) | "API request event recording is in beta" (D26:73-74). The current page does not mention the env var; whether it is still required: **[unverified]** | **Stale release stage** | Low |
| O2 | macOS MagicDNS caveat: "Use `ping` or `dig` instead" (`U:references/common-tasks.md:28`) | Docs name `host`/`nslookup` as bypassing system DNS and give `ping` as working (D20:35). `dig` is not mentioned: **[unverified]** | **Unsupported addition** | Low |
| O3 | Peer relay hosts: "Linux/macOS/Windows — not iOS/Android" (`U:references/connectivity.md:34`) | "any operating system other than iOS, Apple TV, or Android" (D24:49) | **Incomplete** (Apple TV) | Low |

Spot-checked and **correct**: node key expiry defaults to 180 days and tagged devices have expiry
disabled (D19:8, D19:61; D18:34, D18:40); auth keys default to and max out at 90 days (D18:30);
ephemeral nodes are removed 30-60 minutes after last activity (D16:74); MagicDNS is on by default for
tailnets created on or after 2022-10-20 (D20:19); SSH check period defaults to 12 h (D8:600;
D21:502); a Tailscale SSH server requires Linux or the macOS open-source variant (D21:49, D21:544);
Funnel ports are 443/8443/10000, it is beta and needs 1.38.3+ (D22:5, D22:76, D22:84), and the
34-hour Let's Encrypt wait is real (D22:97); Taildrop and Taildrive are alpha (D23); Tailnet Lock allows
20 signing nodes, key rotation at most once a year, and Android cannot sign (D15:369-373); the peer
relay flag `--relay-server-port` and capability `tailscale.com/cap/relay: []` are right (D24:79,
D24:104); the k8s operator OAuth scopes are Write on General/Services, Devices/Core and Keys/Auth Keys
(D27:39-43); the SCIM "suspended in IdP keeps access until keys expire" claim holds (D28:82);
`tsnet` needs the `auth_keys` scope for OAuth (consistent with D4:193); and `error-messages.md`
matches the hub row for row (D25).

Several defects were **wrong at release time, not later drift**. The scope rename dates to 2024-11-14
(D3:400), and the serve/funnel CLI change to v1.52 (D11:7). Both predate the 2026-07-09 commit.

---

## 5. Contradictions inside Tailscale's own sources

These are not upstream defects, but our skill must not inherit them silently.

1. **Users endpoints.** The trust-credentials page lists `GET /api/v2/user/:userID` and
   `POST /api/v2/user/:userID/role|approve|suspend|restore|delete` (singular, D3:111-133). The spec paths
   are `/users/{userId}...` (plural) (spec operation list: `getUser`, `updateUserRole`, …).
2. **Scope list lag.** The spec names scopes that are absent from the trust-credentials page (validated
   Jan 30, 2026): `services`/`services:read`, `networking_settings`/`networking_settings:read`,
   `oauth_apps`/`oauth_apps:read`, `tailnets`/`tailnets:read` (spec operation descriptions for
   services, settings, oauth-apps and organizations).
3. **Pagination.** Global "no pagination" (S:47-49) against the cursor-paginated org tailnets list (S:3951-3983).
4. **DNS scopes.** No DNS operation in the spec carries an "OAuth Scope:" line. The trust-credentials
   `dns:read` list covers nameservers, preferences, searchpaths and split-dns (D3:65-75), but not
   `GET /tailnet/{tailnet}/dns/configuration` (S:1789). Whether `dns:read` covers it: **[unverified]**.
   The oauth-clients page's `dns:read` example omits split-dns (D4:11-16).
5. **Tailnet Lock disablement secrets.** The feature page says init "creates and displays ten" (D15:82).
   The CLI reference says `--gen-disablements` "defaults to one disablement secret" (D13:57).
6. **Funnel on macOS.** "To use Funnel on macOS, you must use one of the open source variants" (D22:88)
   against "You can only use Funnel to share ports if you installed Tailscale for macOS from the App Store or
   as a Standalone variant" (D22:123).
7. **Render gap.** The ACL examples page shows a literal `[Missing snippet: prefer_grant_examples.mdx]` (D9:35).
8. **Token endpoint.** `/oauth/token` is documented on the oauth-clients page (D4:58-66) but is not a path in the spec.

---

## 6. Installation and update

| Path | What happens | Source |
|---|---|---|
| `npx skills add https://github.com/tailscale/tailscale-skill` | Tailscale's docs say it "installs the skill into your agent's skills directory"; the only prerequisite named is Node.js | D2:30, D2:36-40; `U:README.md:14-18` |
| What the `skills` CLI actually does | npm `skills` 1.7.4 (vercel-labs/skills, HEAD `a80e4c9` on 2026-10-26). Needs **Node.js 22.20+**. Installs **to the current project by default**; `-g` makes it global (X1:22-29). For Claude Code the project path is `.claude/skills/` and the global path `~/.claude/skills/` (X2:18). Interactive install offers **Symlink (recommended)** "from each agent to a canonical copy", or `--copy` (X3:72, X3:120-123). Updates: `npx skills check` / `npx skills update [-g|-p]` (X3:166-199). **Telemetry on by default**; opt out with `DISABLE_TELEMETRY=1` or `DO_NOT_TRACK=1` (X1:102-106) | X1, X2, X3 |
| Manual | `git clone ...; cp -r tailscale-skill/skills/tailscale ~/.claude/skills/tailscale`. Copy the subdirectory, not the root. "Keeping a manually installed skill current is your responsibility" | D2:42-51 |
| Directory claimed | `~/.claude/skills/tailscale` (manual, Claude Code), or `.claude/skills/tailscale` (project) / `~/.claude/skills/tailscale` (`-g`) through `npx skills` | D2:46; X2:18 |
| Version identity | No version field in frontmatter (`U:SKILL.md:1-17`). The repo has the tag `1.0.0-alpha-1`. An installed copy shows its version only through git or the skills CLI's lock or symlink | `git ls-remote`; X3:317 |

Docs caveat: "The skill's reference material reflects the state of its repository at the time you
installed it, so verify output against this documentation" (D2:102).

---

## 7. The docs MCP server (from `develop-with-ai.md`, D1)

Not connected to, per instructions.

- Endpoint: a remote MCP server at `https://tailscale.mcp.kapa.ai/` (D1:13). The host is a kapa.ai
  domain, not tailscale.com (observed from the URL).
- What it does: "the model gains a tool that searches the Tailscale documentation and returns the
  passages that match a question, along with the source URL for each passage" (D1:13).
- Configuration: `{"mcpServers": {"tailscale-docs": {"type": "http", "url": "https://tailscale.mcp.kapa.ai/"}}}`;
  syntax varies by client (D1:15-28).
- **Auth:** "The first time you connect, your client opens a browser window to authorize access. Complete the
  prompt, and the connection persists for that client" (D1:38). What identity it asks for and what it
  retains: **[unverified]**.
- Positioning: the skill "carries [packaged guidance] into every request"; the MCP server "search[es]
  current published documentation on demand"; install both (D1:40).
- Other routes on the same page: an "Ask AI" assistant on every page (D1:44-46), and a Markdown version of
  every page (append `.md`; "Copy/View as Markdown") (D1:50-55).

---

## 8. What upstream does not do that an operator skill needs

1. **Authentication.** Stated outright: "does not authenticate to your tailnet" (D2:104). `api.md`
   shows raw curl with a bare `$TOKEN` and puts `client_secret=$CLIENT_SECRET` directly in curl
   arguments (`U:references/api.md:25-34`). It has no guidance on secret storage, the 1-hour token
   lifetime (D4:20, D4:272), token reuse or renewal, or minting narrower tokens.
2. **Least-privilege scoping.** It never maps operations to the minimum scope (D3), and it
   understates `devices:core` reach (A6).
3. **Safe writes.** The API examples include `DELETE`, expire, authorize and retag (`api.md:46-60`).
   A "Bulk delete stale devices" recipe loops `DELETE` over a `lastSeen` filter (`api.md:108`). There is
   no dry-run, no preview of affected devices, no confirmation, and no allowlist. The only
   confirm-before-destructive guidance is for three **CLI** commands: `logout`, `lock disable`,
   `set --reset` (`cli.md:368`). `If-Match` is the only concurrency guard, and only for the policy file.
4. **Audit.** Nothing records what the agent did. The server-side configuration audit log does record
   token creation with the client ID as actor (D3:392), but reading it needs `logs:configuration:read`
   (S: `listConfigurationAuditLogs`), which upstream never mentions.
5. **Tailnet-specific knowledge.** Every example is generic (`alice@example.com`, `tag:server`). There
   is no inventory, naming, tag map, or record of which policy form (ACL or grant) the tailnet uses.
6. **Pinning and drift control.** It has no version field, defects that were stale at release (section
   4), and 5 dead `.md` links.
7. **A local fallback for the API.** The CLI has `tailscale help`; the API side relies on WebFetch,
   which summarises (X5), and has no equivalent offline source of truth such as the OpenAPI spec.

---

## 9. Implications for MC's CLI and skill

- **Name and directory.** Do **not** use `name: tailscale` or `~/.claude/skills/tailscale`. Both are
  claimed by upstream (D2:46), Agent Skills requires name to equal directory (X4:67), and `/tailscale`
  is upstream's slash command. Pick a distinct name, for example `tailnet-ops`, so both can coexist,
  and defer general knowledge to upstream.
- **Defer selectively.** Point to upstream for descriptive topics. Carry corrections for A1-A3, A6,
  C1-C4, P3-P5 and P7 in our skill, because an agent that loads both will see conflicting text.
  Flag the specific upstream file:line as known-wrong rather than restating it.
- **Credential reality for MC's chosen scopes** (`devices:core`, `policy_file:read`, `dns:read`):
  - `policy_file:read` says "`devices:posture_attributes:read` and `devices:core:read` are required when
    using this scope" (D3:91-94). MC's set includes `devices:core`, which subsumes the `devices:core:read`
    endpoints (D3:149), but **not** `devices:posture_attributes:read`. Whether the console refuses the
    combination, auto-adds the scope, or whether ACL reads fail: **[unverified]**. Check when creating
    the credential.
  - `devices:core` requires choosing tags at creation (D3:146; S:1991). It can delete, expire,
    authorize, rename, retag, re-IP and change the key-expiry of **any** device (D3:145-163; spec
    `devices:core` ops). Only a Network admin is barred from granting it; Owner, Admin and IT admin can (D4:30).
  - Tokens last 1 hour, and the lifetime cannot be changed (D4:20, D4:272). The token request can carry
    space-delimited `scope` and `tags` to narrow the token (D4:64-66). A design option is to mint a
    read-only token (`devices:core:read policy_file:read dns:read`) for reads and a `devices:core`
    token only inside a guarded write. Whether a `devices:core` client may request
    `devices:core:read`: **[unverified]**.
  - Revoking the credential revokes its live tokens (D3:388). The client keeps working after its
    creator leaves (D4:56).
  - No read scope for the server audit log is in MC's set, so the CLI's local append-only log is the
    only audit trail it can read back. The server log independently records each token mint (D3:392).
- **Write guard.** It should cover every `devices:core` op: DELETE device, expire, authorized, name,
  tags, key, ip (S operation list). Bulk operations should require an explicit device list, never a
  filter-derived loop. Policy-file writes are out of scope for MC's credential (`policy_file:read` only),
  so the guard does not need ACL POST.
- **API correctness.** Use `type`/`previewFor` for preview (S:2381-2420). Use `/acl/validate` for
  validation (S:2502-2520). Send `Accept: application/json` for parseable ACL reads (S:4387-4393). Use
  `nodeId` in device paths (S:4125-4129). Use `fields=all` when needed (S:4084-4113). Handle 429 with
  backoff (S:6701). Do not assume pagination on tailnet endpoints (S:47-49).
- **Policy reads.** MC's tailnet may still hold the ACL-form default (D9:49-79). The skill should read
  whatever form is there and never "convert to grants" unprompted. ACLs are supported indefinitely (D6:64).
- **Docs access.** Fetch `https://tailscale.com/docs/<path>.md` with curl for exact text. Ship a check
  that the cited `.md` URLs still return 200, given the 5 upstream 404s. The docs MCP server is optional
  and needs browser authorization (D1:38).
- **Versioning.** Put `metadata.version` and `license` in our frontmatter (X4:32-34). Record the
  upstream commit we audited against (`4f05d35`, tag `1.0.0-alpha-1`) so drift is detectable with
  `git ls-remote`.

---

## 10. Unverified items

- Whether the upstream GitHub repo has open issues or PRs addressing any defect above (no GitHub API access in this session).
- Whether the policy parser accepts `"ip": ["*:*"]` in a grant (P6).
- Whether the admin console allows MC's scope set without `devices:posture_attributes:read`, and whether ACL GET then succeeds.
- Whether an OAuth client holding `devices:core` may request a token scoped to `devices:core:read` only.
- Whether `dns:read` covers `GET /tailnet/{tailnet}/dns/configuration`.
- Whether `tailscale update --check` is accepted by current binaries, and what bare `tailscale metrics` prints (checked against docs only, not a binary; `tailscale help` would settle both).
- Whether `TS_EXPERIMENTAL_KUBE_API_EVENTS=true` is still required for k8s API event recording.
- `dig` behaviour with MagicDNS on macOS.
- Funnel support on the macOS App Store and Standalone variants (the docs contradict themselves).
- What identity and data the kapa.ai docs MCP server's authorization flow uses.
- The original download URL of the local `openapi.json` (this audit used the file as provided; sha256 below).
- What `npx skills add` does interactively for this repo specifically (not run).

---

## Sources

**Upstream**
- U — `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/upstream/tailscale-skill` @ `4f05d353efc56962546aa26ccc59bb08ca699ad1` (2026-07-09), every file read in full.
- `git ls-remote https://github.com/tailscale/tailscale-skill` run 2026-10-26: HEAD = main = tag `1.0.0-alpha-1` = `4f05d353…`.

**OpenAPI spec**
- S — `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/tsdocs/openapi.json` (YAML despite the name; `openapi: 3.1.0`, `info.version: v2`, 60 paths; sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`). Line numbers are file lines.

**Tailscale docs** (fetched 2026-10-26 as `.md`; copies in `scratchpad/dl-upstream-audit/`)
- D1 — https://tailscale.com/docs/develop-with-ai — Last validated Jul 28, 2026
- D2 — https://tailscale.com/docs/features/tailscale-skill — Last validated Jul 24, 2026
- D3 — https://tailscale.com/docs/reference/trust-credentials — Last validated Jan 30, 2026 (https://tailscale.com/kb/1623/trust-credentials redirects here)
- D4 — https://tailscale.com/docs/features/oauth-clients — Last validated Jun 30, 2026
- D5 — https://tailscale.com/docs/reference/tailscale-api — Last validated Jun 24, 2026
- D6 — https://tailscale.com/docs/reference/grants-vs-acls — Last validated Aug 1, 2025
- D7 — https://tailscale.com/docs/reference/syntax/grants — Last validated Jan 5, 2026
- D8 — https://tailscale.com/docs/reference/syntax/policy-file — Last validated Apr 8, 2026
- D9 — https://tailscale.com/docs/reference/examples/acls — Last validated Feb 2, 2026
- D10 — https://tailscale.com/docs/reference/tailscale-cli — Last validated Jul 30, 2026
- D11 — https://tailscale.com/docs/reference/tailscale-cli/serve — Last validated Jan 26, 2026
- D12 — https://tailscale.com/docs/reference/tailscale-cli/funnel — Last validated Jan 26, 2026
- D13 — https://tailscale.com/docs/reference/tailscale-cli/lock — Last validated Jan 5, 2026
- D14 — https://tailscale.com/docs/reference/ping-types — Last validated Jan 13, 2026
- D15 — https://tailscale.com/docs/features/tailnet-lock — Last validated Dec 2, 2025
- D16 — https://tailscale.com/docs/features/ephemeral-nodes — Last validated Dec 4, 2025
- D17 — https://tailscale.com/docs/features/containers/docker/docker-params — Last validated Mar 23, 2026
- D18 — https://tailscale.com/docs/features/access-control/auth-keys — Last validated Jun 30, 2026
- D19 — https://tailscale.com/docs/features/access-control/key-expiry — Last validated Jan 5, 2026
- D20 — https://tailscale.com/docs/features/magicdns — Last validated Jan 5, 2026
- D21 — https://tailscale.com/docs/features/tailscale-ssh — Last validated Jan 5, 2026
- D22 — https://tailscale.com/docs/features/tailscale-funnel — Last validated Jan 20, 2026
- D23 — https://tailscale.com/docs/features/taildrop and https://tailscale.com/docs/features/taildrive — both Last validated Jan 5, 2026
- D24 — https://tailscale.com/docs/features/peer-relay — Last validated Feb 4, 2026
- D25 — https://tailscale.com/docs/reference/messages — Last validated Jan 30, 2026
- D26 — https://tailscale.com/docs/kubernetes-operator/recorder/kubectl-session-recording — Last validated Jun 5, 2026
- D27 — https://tailscale.com/docs/kubernetes-operator/install-operator — Last validated Jun 5, 2026
- D28 — https://tailscale.com/docs/features/user-group-provisioning — Last validated Dec 8, 2025
- Index — https://tailscale.com/docs/llms.txt (no validated date)
- Link check — all 282 `tailscale.com/docs` URLs in U, requested with `.md` appended on 2026-10-26 (277 x 200, 5 x 404; the 404s re-requested as HTML with redirects followed).

**Third-party and tooling**
- X1 — https://raw.githubusercontent.com/vercel-labs/skills/main/README.md (repo HEAD `a80e4c9d12d607631249d4d7d059f835d4b2f13a`, npm `skills` 1.7.4, modified 2026-10-19)
- X2 — https://raw.githubusercontent.com/vercel-labs/skills/main/docs/agents.md
- X3 — https://raw.githubusercontent.com/vercel-labs/skills/main/docs/commands.md
- X4 — https://agentskills.io/specification.md (no validated date)
- X5 — Claude Code `WebFetch` tool definition as loaded in this session ("answers `prompt` against it using a small fast model")
