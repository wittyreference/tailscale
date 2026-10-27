# Upstream corrections

**The official skill at `~/.claude/skills/tailscale` (`tailscale/tailscale-skill@4f05d35`) is wrong
on these points. This file wins.**

Before relying on any upstream file, search this file for its name. Paths below are relative to
upstream's `skills/tailscale/`.

## Contents

1. [Trust order](#1-trust-order)
2. [API, auth and credentials](#2-api-auth-and-credentials)
3. [Stale lines in `references/api.md`](#3-stale-lines-in-referencesapimd)
4. [CLI](#4-cli)
5. [Policy, ACLs and grants](#5-policy-acls-and-grants)
6. [Other references](#6-other-references)
7. [Operational habits this skill does not copy](#7-operational-habits-this-skill-does-not-copy)
8. [Sources](#8-sources)

## 1. Trust order

1. First-party sources: the trust credentials page (TC), the pinned OpenAPI spec, and the other
   Tailscale docs pages, each with its "Last validated" date.
2. This skill (`tailnet`), including this file.
3. The upstream skill.

**About the pin.** Upstream commit `4f05d353efc56962546aa26ccc59bb08ca699ad1`, tag
`1.0.0-alpha-1`, committed 2026-07-09. It was still `HEAD` of `tailscale/tailscale-skill` on
2026-10-26T12:54Z (`git ls-remote`). Every upstream line below was re-read in the pinned clone on
2026-10-26, and every docs page was re-fetched that day and found byte-identical to the copy the
audit used. Upstream calls itself "public Alpha release and is not yet supported" (`README.md:8`).
Several rows were already wrong when it was committed: the scope rename dates to 2024-11-14
[TC L400], and the serve and funnel change to client 1.52 [serve L7].

Verdicts: **Wrong**; **Misleading** or **Overstated** (true in part); **Incomplete**;
**Correct** (kept so the row is not re-audited). Impact is for an agent that operates a tailnet.

## 2. API, auth and credentials

| # | Upstream | Claim | First-party evidence | Verdict |
|---|---|---|---|---|
| A1 | `references/api.md:13` | OAuth clients are "scope-restricted (`devices:read`, `devices:write`, `dns:read`, others)" | Current scopes are `devices:core:read` and `devices:core` [TC L135-163]. `devices:read` is a **legacy** scope [TC L482]; since November 14, 2024 new credentials use the new scopes [TC L400]. `devices:write` appears in neither list | **Wrong.** High |
| A2 | `references/api.md:11-14` | Three auth options: API tokens, OAuth clients, and "Trust credentials" with "attribute-based limits … tied to specific key/value claims" | "Trust credentials come in two forms: OAuth clients and federated OIDC workload identities" [TC L9]. An OAuth client *is* a trust credential | **Wrong** taxonomy. Medium |
| A3 | `references/api.md:100-103` | "Preview / validate before applying": `POST …/acl/preview` with body `{"src":"alice@example.com","dst":"tag:server"}` | Preview requires the query parameters `type` (`user` or `ipport`) and `previewFor` [spec L2381-2420], and its body is **a policy file** [spec L2421-2440]. Validation is a separate endpoint, `POST …/acl/validate` [spec L2502-2520]. `policy-workflow.md` §8 | **Wrong**: the request as written fails. High |
| A4 | `references/api.md:16` | "No pagination today" | "The Tailscale API does not currently support pagination. All results are returned at once" [spec L47-49]. The one exception is the Alpha `GET /organizations/{organization}/tailnets` [spec L3951-3983] | **Correct** for every tailnet endpoint. Low |
| A5 | `references/api.md:17` | "No published rate limits … back off on 429s" | The spec defines a 429 response [spec L6701-6708], used only by the posture-attribute set and delete operations; it states one limit, "Invite resends are rate limited to one per minute" [spec L1040, L1105] | **Correct** in substance. Low |
| A6 | `references/enterprise.md:97` | "Scopes are tag-restricted (the client can only operate on tags it owns)" | `devices:core` "has access to read the list of all devices in the tailnet, authorize or remove machines, and manipulate tags on devices"; the credential's tags constrain the auth keys it creates [TC L145-147] and which tags it may assign [TAGS L324], not which devices it reaches | **Wrong**, and it understates the blast radius. High |
| A7 | `references/enterprise.md:97` (also `:12`) | "Append `?ephemeral=true` to the secret when minting ephemeral nodes" | For an OAuth secret, `ephemeral` "defaults to `true`" [OC L207]; "To register a non-ephemeral node, append `?ephemeral=false` to the secret" [docker L30] | **Misleading**. Medium |
| A8 | `references/containers.md:63` | `TS_AUTHKEY`: "append `?ephemeral=true`" for short-lived containers | For an auth key, "set the key's ephemeral property when you create the key"; the suffix applies to OAuth client secrets [docker L28-31] | **Wrong** for auth keys. Medium |
| A9 | `references/api.md:118, 133` | For scope names, "fetch the OAuth clients page" | "Information about our scopes has moved to the trust credentials topic" [OC L261-263] | **Stale pointer**. Low |
| A10 | `references/api.md:15` | "HuJSON … for the ACL endpoint" | `GET …/acl` returns JSON when `Accept: application/json` is sent, otherwise HuJSON [spec L2217, L4387-4393]; `POST …/acl` accepts either [spec L2304-2317] | **Imprecise**. Low |

## 3. Stale lines in `references/api.md`

From api-surface §10, re-read in the pinned clone.

| Upstream | Claim | First-party evidence | Verdict |
|---|---|---|---|
| `references/api.md:63`, `:108` | `lastSeen` is "the standard field for 'is this device still active?' filtering"; "Bulk delete stale devices" by `lastSeen` | `lastSeen` is "Omitted if the device has never been online or `connectedToControl` is true" [spec L4548], so a naive filter treats online and never-seen devices alike. `id` is the legacy ID; `nodeId` is preferred [spec L4482-4495] | **Wrong**, and the bulk delete is the anti-pattern this CLI refuses (DESIGN §23). High |
| `references/api.md:91` | "GET returns HuJSON + an ETag" | HuJSON only without `Accept: application/json` [spec L4387-4393]; the ETag is described in prose only [spec L2218] | **Imprecise**. Low |
| `references/api.md:96` | `-H "If-Match: \"$ETAG\""` | The ETag header already carries its quotes [inference from Tailscale's gitops-pusher; critic R3], so this double-quotes it. Upstream also omits `If-Match: "ts-default"` [spec L2302-2303] and the 412 on a mismatch [spec L2342-2349] | **Wrong** in all likelihood [inference]. Medium |
| `references/api.md:117`, `:131` | For "endpoints, fields, query parameters", fetch `https://tailscale.com/docs/reference/tailscale-api` | That page (Last validated Jun 24, 2026) has no endpoint reference [API L1-41]. The machine-readable source is the OpenAPI spec; this skill's copy is `~/.local/share/tailnet/spec/tailscale-openapi.yaml` | **Stale pointer**. Medium |
| `references/api.md:108` | "Throttle to avoid 429s" when deleting | No source states a limit for device delete; `DELETE /device/{id}` lists no 429 [spec L337-349] | **Unsupported**. Low |
| `references/api.md:31-34` | The token request sends `grant_type=client_credentials` | RFC-correct; the docs' own example omits it [OC L123]. This CLI sends it too (DESIGN §9.1) | **Correct**. — |

## 4. CLI

| # | Upstream | Claim | First-party evidence | Verdict |
|---|---|---|---|---|
| C1 | `references/cli.md:160-183` | `tailscale serve https / http://localhost:3000`, `serve tcp:5432 tcp://…`, `serve https /docs off` and similar | "The CLI commands for both Tailscale Funnel and Tailscale Serve have changed in the 1.52 version" [serve L7]. The form is `tailscale serve [flags] <target>` [serve L12] with `--https=<port>`, `--set-path`, `--tcp=<port>`, `--tls-terminated-tcp=<port>` [serve L35-40] and a trailing `off` [serve L123-124]. Upstream's own `references/sharing-and-publishing.md:112` uses the new `tailscale serve 3000` | **Wrong** (pre-1.52 syntax). High |
| C2 | `references/cli.md:194` | `tailscale funnel https / http://localhost:3000` | `tailscale funnel [flags] <target>` [funnel L12]; `tailscale funnel --https=<port> <target> [off]` [funnel L39] | **Wrong** (pre-1.52 syntax). High |
| C3 | `references/cli.md:124-125` | `tailscale ping <hostname>  # Ping via Tailscale (TSMP)` | "By default, the Tailscale ping command uses the DISCO protocol" [ping-types L20]; `--tsmp` "Defaults to false" [cli L643]. TSMP stops before the policy check [manage L29] | **Wrong**: it misreads a diagnosis. Medium |
| C4 | `references/cli.md:271-277` | `lock add <node-key>`, `lock remove <node-key>`; `lock init` and `lock revoke-keys` with no arguments | `lock add <tlpub:…>` [lock L144]; `lock remove [flags] <tlpub:…>` [lock L158]; `lock init [flags] <tlpub:…>` [lock L49]; `lock revoke-keys <tlpub:…>` [lock L299]. Upstream's `references/connectivity.md:95-97` gets `tlpub:` right | **Wrong** argument type. Medium: Tailnet Lock state is hard to undo |
| C5 | `references/cli.md:298` | `tailscale update --check` | Documented flags are `--dry-run`, `--track`, `--version`, `--yes` [cli L920-923]. Whether a binary accepts `--check` is [unverified] | **Undocumented**; use `--dry-run`. Medium |
| C6 | `references/cli.md:300` | Release tracks "stable/unstable" | "either "stable", "release-candidate", or unstable" [cli L921] | **Incomplete**. Low |
| C7 | `references/cli.md:323-324` | Bare `tailscale metrics` prints Prometheus format | Subcommands are `print` and `write` [cli L563-566]; what bare `tailscale metrics` does is [unverified] | **Unsupported**. Low |
| C8 | `references/cli.md:34`; `SKILL.md:269` | `--accept-routes` "(Linux)" | The default depends on the OS; Windows, iOS, Android and both macOS GUI variants accept by default [cli L147] | **Simplified**. Low |

## 5. Policy, ACLs and grants

Rows U1-U13 are policy-access's list; where one repeats a P row, it points there.

| # | Upstream | Claim | First-party evidence | Verdict |
|---|---|---|---|---|
| P1 | `SKILL.md:47`; `references/access-control.md:7` | Write new rules as grants | "Grants are the recommended approach for all new tailnets and for updating existing deployments" [gva L50]; grants are "feature complete with ACLs" [gva L20] | **Correct** as an authoring default |
| P2 | `references/access-control.md:18`, `:106-108` | ACLs are "legacy — read-only … Do not write new ACLs" | "You may continue to use ACLs indefinitely" [gva L64]; grants and ACLs "can coexist in the same policy file" [gva L72]. The default policy every tailnet starts with is written as ACLs [acls L41, L52-80]. Read whatever form MC's policy uses; never convert unprompted | **Overstated**. Medium |
| P3 = U2 | `references/access-control.md:141` | SSH actions: "`accept` (allow), `check` (require re-authentication), `deny`" | `"action": "check", // "accept" or "check"` [policy-file L551]; the field defines only `accept` and `check` [policy-file L563-566]. `deny` exists only as an `sshTests` user list | **Wrong**: a policy with it fails, or an agent believes a deny exists. High |
| P4 = U3 | `references/access-control.md:163` | `autogroup:self` "(same device)"; `autogroup:member` "(all users)" | `autogroup:self`: "Select a user's devices" [policy-file L128]; it "only applies to user-owned devices. It does not apply to tagged devices" [policy-file L230]. `autogroup:member`: "any user who is a direct member (including all invited users) of the tailnet. Does not include users from shared devices" [policy-file L217] | **Wrong** (self) and **imprecise** (member). High: `self` is a security boundary |
| P5 = U5 | `references/access-control.md:168` | The default policy "lets SSH to all devices as non-root users" | The default lets "all users establish a Tailscale SSH session to their own devices using check mode, as either root or non-root" [acls L48]; the rule is `check`, `autogroup:member` → `autogroup:self`, users `autogroup:nonroot` and `root` [acls L65-79; SSH L258-271] | **Wrong** on scope, mode and users. Medium |
| P6 = U1 | `references/access-control.md:88`; `references/subnet-routers.md:63`; `references/enterprise.md:87` | Grants with `"ip": ["*:*"]` | The documented grant `ip` forms are `*`, `<port>`, `<proto>:*` and `<proto>:<port>` [grants L100-103]; `*:*` is ACL `dst` syntax [acls L61]. Upstream's own `references/access-control.md:37` says `"ip": ["*"]`. Whether the parser accepts `*:*` is [unverified] | **Undocumented form**. Low to medium: an agent may copy it |
| P7 | `references/device-management.md:89`, `:94` | A rollout that turns on device approval (step 3) and Tailnet Lock (step 8) | "You cannot enable both Tailnet Lock and device approval—they are mutually exclusive features" [tailnet-lock L371]; upstream's `references/connectivity.md:107` says the same | **Self-contradiction**: the rollout cannot be done. Medium |
| U4 | `references/access-control.md:163` | Lists `autogroup:nonroot` among grant and ACL sources and destinations | `autogroup:nonroot` is allowed "As an SSH user" only [policy-file L225] | **Wrong**. Low to medium |
| U6 | `references/access-control.md:75`; `references/common-tasks.md:118` | "Tagged devices have key expiry disabled by default" | Only "When you apply a tag to a device for the first time and authenticate it" [TAGS L78]. Retagging from the console, CLI or API leaves expiry unchanged until re-authentication [TAGS L84] | **Incomplete**. **High for MC**: spec5, nomad-b and pi5 were retagged from the console on 2026-10-25 (`tailnet-facts.md` §4) |
| U7 | `references/access-control.md:41` | "The policy file is JSON" | It is "human JSON (HuJSON)" [policy-file L5]; upstream's own examples carry `//` comments | **Imprecise**. Low |
| U8 | `references/access-control.md:102` | SSH rules live in a separate `ssh` section (true) | It omits that Tailscale SSH also needs "An access rule to allow connections from the source to the destination on port 22" [policy-file L542-545], and that `ssh` rules do nothing for a host running plain OpenSSH [policy-access (a), inference] | **Incomplete**. **High: this is MC's failure mode** |
| U9 | `references/access-control.md:11` | grants-vs-acls holds "the most up-to-date list of capability schemas" | It has none; they are on the grants app-capabilities page (Last validated Dec 1, 2025) [policy-access U9] | **Wrong pointer**. Low |
| U10 | `references/access-control.md:94-96` | Taildrive capability `{"shares": [...]}` | The docs example also carries `"access": "rw"` or `"ro"`; whether it is required is [unverified] [policy-access U10] | **Incomplete**. Low, off topic |
| U11 | `references/cli.md:124` | Same as C3 | — | See C3 |
| U12 | `references/api.md:100-103` | Same as A3 | — | See A3 |
| U13 | `references/access-control.md` (whole file) | — | No coverage of `tests`, `sshTests`, `/acl/validate`, `/acl/preview`, `tailscale ping --tsmp` versus `--icmp`, or the ACL drop metric | **Gap**, not an error. This skill fills it: `policy-workflow.md`, `diagnose-port.md` |

## 6. Other references

| # | Upstream | Claim | First-party evidence | Verdict |
|---|---|---|---|---|
| O1 | `references/session-recording.md:112` | Kubernetes `enableEvents` is "an **alpha** feature" that also needs `TS_EXPERIMENTAL_KUBE_API_EVENTS=true` | "API request event recording is in beta" [k8s L75]; the page no longer mentions the variable, and whether it is still required is [unverified] | **Stale**. Low |
| O2 | `references/common-tasks.md:28` | On macOS, use `ping` or `dig` instead of `host`/`nslookup` for MagicDNS names | The docs name `host` and `nslookup` as bypassing system DNS and give `ping` as working [magicdns L35]; `dig` is not mentioned [unverified] | **Unsupported addition**. Low |
| O3 | `references/connectivity.md:34` | Peer relays run on "Linux/macOS/Windows — not iOS/Android" | "any operating system other than iOS, Apple TV, or Android" [peer-relay L49] | **Incomplete**. Low |

## 7. Operational habits this skill does not copy

- **Secrets on the command line.** `references/api.md:30-34` passes `client_secret=$CLIENT_SECRET`
  to curl as an argument. This skill never puts a secret in argv or the environment; secrets enter
  only through `tailnet credentials set` in MC's terminal (repo CLAUDE.md invariant 2).
- **Raw API calls.** `references/api.md:44-60` shows curl for delete, authorize, expire and
  retag, with no dry run, preview of affected devices, or confirmation. This skill makes every
  call through `tailnet`; it has no delete, expire or authorize at all (P9).
- **WebFetch for exact text.** After a WebFetch, upstream tells the agent to quote values
  "verbatim from the page" (`references/aperture.md:171`; also `references/containers.md:245` and
  `references/session-recording.md:140`). Claude Code's WebFetch answers through a small model, so
  it returns a summary, not the page (upstream-skill §2). For exact wording use
  `curl -fsSL https://tailscale.com/docs/<path>.md`.

## 8. Sources

Read or fetched 2026-10-26.

- `upstream-skill`, `api-surface`, `policy-access`, `critic`: the files of those names in
  `docs/research/` (2026-10-26). Rows A1-A10, C1-C8, P1-P7 and O1-O3 are upstream-skill §4; the
  `api.md` lines are api-surface §10; U1-U13 are policy-access "Discrepancies".
- Upstream: `tailscale/tailscale-skill` at `4f05d353efc56962546aa26ccc59bb08ca699ad1`, every cited
  line re-read on 2026-10-26.
- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`
  (live copy identical at 2026-10-26T12:54Z).
- `DESIGN`: `DESIGN.md` in this repo.
- Tailscale docs, fetched as Markdown with curl; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| TC | https://tailscale.com/docs/reference/trust-credentials | Jan 30, 2026 |
| OC | https://tailscale.com/docs/features/oauth-clients | Jun 30, 2026 |
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| API | https://tailscale.com/docs/reference/tailscale-api | Jun 24, 2026 |
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| grants | https://tailscale.com/docs/reference/syntax/grants | Jan 5, 2026 |
| gva | https://tailscale.com/docs/reference/grants-vs-acls | Aug 1, 2025 |
| acls | https://tailscale.com/docs/reference/examples/acls | Feb 2, 2026 |
| SSH | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| cli | https://tailscale.com/docs/reference/tailscale-cli | Jul 30, 2026 |
| serve | https://tailscale.com/docs/reference/tailscale-cli/serve | Jan 26, 2026 |
| funnel | https://tailscale.com/docs/reference/tailscale-cli/funnel | Jan 26, 2026 |
| lock | https://tailscale.com/docs/reference/tailscale-cli/lock | Jan 5, 2026 |
| ping-types | https://tailscale.com/docs/reference/ping-types | Jan 13, 2026 |
| manage | https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies | Mar 13, 2026 |
| tailnet-lock | https://tailscale.com/docs/features/tailnet-lock | Dec 2, 2025 |
| docker | https://tailscale.com/docs/features/containers/docker/docker-params | Mar 23, 2026 |
| k8s | https://tailscale.com/docs/kubernetes-operator/recorder/kubectl-session-recording | Jun 5, 2026 |
| magicdns | https://tailscale.com/docs/features/magicdns | Jan 5, 2026 |
| peer-relay | https://tailscale.com/docs/features/peer-relay | Feb 4, 2026 |
