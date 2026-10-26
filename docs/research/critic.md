# Completeness critic: open questions, contradictions and spot-checks

Topic `completeness-critic`, written 2026-10-26. It reviews the six research tracks in
`scratchpad/research/`: `api-surface.md`, `credentials.md`, `policy-access.md`, `mc-tailnet.md`,
`upstream-skill.md` and `skill-packaging.md`. I read all six in full.

The next step designs five things:

- credential loading and token minting;
- device commands: list, show, tag, authorize, expire, rename, key-expiry and delete;
- policy commands: get (with ETag), draft, validate with tests, and preview;
- DNS reads;
- a client-side write guard, an append-only audit log, and a skill that composes with the
  official one.

This file lists:

- what that design still cannot answer;
- contradictions between the track files;
- answers to the open questions that first-party sources settle;
- 22 spot-checks of load-bearing facts against their cited sources.

**Tags used here**

- **[unverified]**: no confirmed source settles it.
- **[inference]**: a conclusion drawn from cited facts that no source states outright.
- **[observed]**: seen in a file, tool output or live response, with the time recorded.

`TC`, `OC`, `TAGS` and the other bracketed keys resolve in [Sources](#sources). Line numbers
refer to the copies fetched on 2026-10-26. I re-fetched TC, OC, TAGS, AUDIT and the Claude Code
skills page live today, and each one is byte-identical to the copy the tracks saved.

`sigint/pageN.txt` is this workflow's extract of an earlier Claude Code session's transcript.
Its events are dated 2026-10-25 23:05–23:58Z. In that file, `[TOOL_RESULT …]` lines are tool
output and count as observed. Assistant prose lines are claims, not observations.

---

## 0. Findings that change the design (read first)

### F1. MC approved the credential on a premise the docs do not support

- On 2026-10-25 at 23:32:49Z the earlier session told MC: *"Restrict the client to `tag:fleet`.
  A `devices` client acts as a tagged identity. Set its tag to `tag:fleet` and it can manage only
  fleet devices, never your Mac, phone, or the droplet."* (`sigint/page2.txt:34`)
- The option MC picked in the question that followed read: *"I can tag and manage fleet boxes,
  never your Mac/phone/droplet, and never touch the policy"* (`page2.txt:40`). MC answered
  "devices on tag:fleet only (Recommended)" (`page2.txt:42`), and it went into the plan as D13
  (`page2.txt:50`).
- The docs say `devices:core` *"has access to read the list of all devices in the tailnet,
  authorize or remove machines, and manipulate tags on devices"* (TC L145-147). No text limits
  the write endpoints to tagged devices.
- The client's tag makes it worse, not better. *"When an OAuth client or auth key assigns tags to
  a device, the requested tags must either exactly match the full set of tags on the OAuth
  client … The exact-match check does not consult `tagOwners`"* (TAGS L324). So a client tagged
  `tag:fleet` can apply `tag:fleet` to **any** device.
- Tagging a user-owned device is permanent:
  - *"Applying a tag to a device previously authenticated with a user account removes the user
    account"* (TAGS L72).
  - *"You cannot remove all tags from a device"* (TAGS L33).
  - The recommended client could therefore turn albini or iphone192 into a `tag:fleet` device.
- **This is a consent question, not a research one.** MC should decide again, knowing the real
  reach, before creating the client. The computed task's correction ("devices:core reaches every
  device") has not reached D13 in MC's plan file.

### F2. Where the scope set came from is not recorded

- MC's recorded answer excludes policy access (`page2.txt:40-42`).
- The computed task's set adds `policy_file:read` and `dns:read`. Both are read-only, but no file
  I could read records MC approving them.
- `policy_file:read` also needs `devices:posture_attributes:read` (TC L94-95). Confirm the full
  set with MC.

### F3. MC's tailnet changed on 2026-10-25, after every record mc-tailnet read

**What was observed.**

- At 23:05:34Z, nomad-b, spec5 and pi5 showed `tags= None` (`page3.txt:2-4`).
- At 23:27:40Z, run from the droplet, all three showed `tags= ['tag:fleet']`
  (`page3.txt:138-140`). Port 22 was still "blocked" (`page3.txt:141-144`).
- The tags were applied "in the Machines page" (`page3.txt:49`, `:134`).

**What follows.**

1. **Stale records.** mc-tailnet's "pi5 tags: None … user-owned [derived]" is now out of date,
   and so is its design note on tagging "a user-owned node (pi5, and probably spec5)".
2. **Key expiry may still be on for all three hosts.** *"If you change the tags on the device
   from the admin console … the device's key expiry will not change unless you re-authenticate"*
   (TAGS L84). They may still carry the key expiry they had as user-owned devices. When it
   lapses they drop off the tailnet, which breaks P9 ("never take a lab host off the tailnet").
   **The first read should be `keyExpiryDisabled` and `expires` for these three** (spec `Device`
   schema).
3. **spec5 runs Tailscale SSH.**
   - Records: `fleet/fleet.yaml:86` ("its tailnet login is Tailscale SSH, which waits on a
     browser check") and mc-tailnet §2.
   - With Tailscale SSH on, *"Tailscale claims port `22` for the Tailscale IP address"*
     (tailscale-ssh L40, L410).
   - Now that spec5 is tagged, the default SSH rule (`autogroup:member` → `autogroup:self`,
     check mode; tailscale-ssh L255-268) no longer reaches it. `autogroup:self` *"includes all
     devices owned by the same user"* (selectors L96).
   - MC's own phone and albini therefore need an explicit user-to-tagged `ssh` rule to reach
     spec5. P7 records that the phone "may rely on it".
   - A tagged droplet needs a tagged-to-tagged rule, which *"cannot be in check mode"*
     (tailscale-ssh L218).
4. **policy-access's premise is wrong for spec5.** It assumes "the hosts run plain OpenSSH"
   (`policy-access.md:14`). For spec5, a `grants`/`acls` rule for tcp:22 is necessary but not
   sufficient: the `ssh` section decides. The diagnosis recipe has to branch per host on whether
   Tailscale SSH is on.
5. **The droplet's `tag:dev` is still unconfirmed.** It appears only in assistant prose
   (`page3.txt:128`), never in a tool result. **[unverified]**
6. **MagicDNS did not resolve on the droplet.** `spec5.taild02cf8.ts.net` failed with "Temporary
   failure in name resolution" (`page2.txt:13`, 2026-10-25T23:30Z) **[observed]**. The skill
   should address hosts by 100.x address or `nodeId` from the droplet, not by MagicDNS name.

### F4. A client-side write guard cannot stop the agent that drives it

- skill-packaging recommends "explicit confirmation flags for destructive operations". The agent
  can pass any flag the CLI accepts, so this stops accidents only.
- Three first-party levers do hold:
  1. **Claude Code `ask` rules.**
     - Rules are evaluated *"deny, then ask, then allow"* (permissions L58-60).
     - An `ask` rule *"still prompts you … even in auto mode"* (permissions L223).
     - *"Deny and ask rules still override `allowed-tools`"* (skills L791).
     - Limits: `bypassPermissions` skips prompts (permissions L83), and a PreToolUse hook can
       block before rules are evaluated (permissions L653).
  2. **Two OAuth clients.**
     - A read client (`devices:core:read`, `policy_file:read`, `devices:posture_attributes:read`,
       `dns:read`) needs **no tag**: tags are *"Mandatory if the scopes include "devices:core" or
       "auth_keys""* (spec 1991, 2154, 5839).
     - A separate `devices:core` client holds the write power. Its secret stays off disk unless
       MC supplies it for a write.
     - This also removes the design's dependence on the unverified token-narrowing question (Q1).
  3. **The secret is the real boundary.** Elmer's CLAUDE.md says of its TX guard that it is "one
     enforced surface, not the whole surface". The same holds here: an agent that can read the
     write secret can call the API with curl and skip the CLI.
- The design has to say which of these levers it relies on.

### F5. `key-expiry` on re-enable can take a device off the tailnet at once

- Spec 606-607: re-enabling *"Sets the key to expire at the original expiry time prior to
  disabling. The key may already have expired. In that case, the device must be
  re-authenticated."*
- The guard must compare `expires` with the current time and refuse when it is in the past (P9).
  No track turned this into a guard rule.

### F6. Minting a token per command fills MC's audit log

- Each token mint writes a configuration-audit event, with the Client ID as actor (TC L390-392;
  AUDIT L329: "Create OAuth access token").
- Reads are not logged (AUDIT L404), and the log keeps 90 days (AUDIT L409). Minting per command
  therefore fills MC's log with mint events and nothing else.
- Cache each token for its life instead (3600 s, fixed: OC L20, L272).
- Refused calls are logged as "API | Failed request | API call attempted with insufficient
  permission" (AUDIT L316). MC can see refusals in the console, which helps when debugging
  scopes.

### F7. Settled: validate in policy-file mode runs the candidate's own tests

This was policy-access unverified #6. See R1 in §2.

---

## 1. Questions the design still cannot answer

"Moot" means a design choice removes the need for an answer. "First read" and "first run" mean
a read-only call with MC's real credential.

### Credential and token

| # | Question | Why it matters | Status after this pass | How to settle |
|---|---|---|---|---|
| Q1 | May a `devices:core` client mint a token with only `devices:core:read` plus the other read scopes? | Least-privilege minting per command | **[unverified]**. OC L64 shows only `all` → `devices:core` + tag. The Terraform provider exposes a `scopes` request option (tf `docs/index.md:114`) but states no subset rule | Mint on first run and assert on the response's `scope`. **Moot under the two-client design (F4).** |
| Q2 | Which tags does a `devices:core` token carry when no `tags` parameter is sent? | Decides what `devices tag` can apply | **[unverified]**. `Key.tags` "Only applies to OAuth clients and federated identities" (spec `Key` schema), so the token's own record may not show them | Only an observed tag write would settle it; needs MC |
| Q3 | Which ID does the self-lookup `GET /tailnet/-/keys/{keyId}` take: client ID or token ID? | `whoami` | **[unverified]**. `keyId` is "The id of the key", example `k123456CNTRL`, found in the admin console (spec `components.parameters.keyId`) | Try the client ID on first run. Keep `whoami` best-effort |
| Q4 | What status does a valid token get when it lacks the scope: 403 or 404? | Error messages | **[unverified]**. Such calls are logged as "Failed request" (AUDIT L316) | One deliberate out-of-scope read on first run (for example `GET /device/{id}/routes`) |
| Q5 | Format of a multi-scope `scope` string | Asserting granted scopes | **[unverified]**. OC L62 claims RFC 6749 conformance, so space-delimited per RFC §3.3 **[inference]** | First mint |
| Q6 | Is `grant_type` required? Is HTTP Basic client auth accepted? | Token request shape | **[unverified]**. Live probes at 2026-10-26T02:12:58-59Z returned 401 `{"message":"API token invalid"}` for all four variants (no `grant_type`, `grant_type=bogus`, a Basic header, no credentials). The server checks the credential first, so neither question can be settled without a real secret | **Moot.** Form-POST `client_id`, `client_secret` and `grant_type=client_credentials`. Tailscale's own Go callers all send `grant_type` through `clientcredentials` (`gitops-pusher.go:245-249`; `get-authkey/main.go`; `oauthkey.go:51-55`) |
| Q7 | Does the console enforce, or auto-add, `devices:posture_attributes:read`? | Credential creation | **[unverified]** | **Moot.** Select it (TC L94) |

### Devices

| # | Question | Why it matters | Status after this pass | How to settle |
|---|---|---|---|---|
| Q8 | Does TAGS L324 govern `POST /device/{id}/tags` called with an OAuth token? | `tag` command, blast radius | Leans yes. The note is worded generally ("When an OAuth client … assigns tags to a device"), sits right after "Apply a tag to a device using the API" (TAGS L303-324), and its worked example has an OAuth client applying tags "to devices" (TAGS L338). Not stated for the API path **[unverified]** | Design as if it applies. A live check is a write and needs MC |
| Q9 | Can `devices:core` tag a user-owned device? | An irreversible identity strip (TAGS L72, L33) | **[unverified]**. Nothing in `setDeviceTags` restricts it (spec 541-582), and TAGS L303-313 shows API tagging with no caveat | Design for yes. Put "first tag on an untagged device" in the guard's highest class |
| Q10 | What does an empty tag list do? | Replace semantics | The docs say *"You cannot remove all tags from a device"* (TAGS L33). API behaviour **[unverified]** | Refuse an empty list in the CLI |
| Q11 | What do DELETE and POST tags return for a nonexistent ID? | Error messages | **[unverified]** (404 not listed: spec 337-349, 574-582) | **Moot.** The guard's pre-read `GET /device/{id}` returns 404 (spec 309-325) |
| Q12 | Does `fields=all` include routes without `devices:routes:read`? | `show` output | **[unverified]** | First read. Tolerate absent fields |
| Q13 | Does MC's tailnet require device approval? | `authorize` may do nothing; `authorized=false` takes a device off the tailnet (P9) | Unknown. `devicesApprovalOn` needs `feature_settings:read` (TC L354-362), which is outside the set. The endpoint matters only "for tailnets where device authorization is required" (spec 459) | MC answers, or the command is dropped |
| Q14 | Which devices does P9 protect, as hard refusals? | delete, expire, deauthorize, key-expiry re-enable | Needs MC. mc-tailnet §2 is a candidate list, at least 16 days old | An explicit protected list in config, never inferred |
| Q15 | What is the key-expiry state of spec5, nomad-b and pi5 after the 2026-10-25 retag? | P9 (F3.2) | Unknown | First read: `keyExpiryDisabled`, `expires` |
| Q16 | Which tag does the write client carry? | What `tag` can do, and how far it reaches | Conflict between tracks and MC (X4). `tag:fleet` lets the client apply `tag:fleet` to any device (TAGS L324). An inert tag can apply only itself, unless `tagOwners` delegates other tags to it (TAGS L324, L338; OC `tagOwners` example) | MC decides, knowing F1 |
| Q17 | Are `ip` and `routes` left out of the command set on purpose? | `setDeviceIp` breaks `from=` pins and pf anchors (mc-tailnet) | `devices:core` can still call `POST /device/{id}/ip` (TC L157) | Confirm, and never expose `ip` |

### Policy

| # | Question | Why it matters | Status after this pass | How to settle |
|---|---|---|---|---|
| Q18 | How does `policy draft` edit HuJSON with stdlib only? | MC's comments; the CLI is stdlib-only | Open design choice. Stdlib `json` cannot parse HuJSON with comments or trailing commas (policy-access §f). The server can parse it: validate accepts `application/hujson` with comments (spec `aclValidateHuJSON`, 2620-2639), and gitops-pusher posts standardized JSON under that content type (`gitops-pusher.go:340, 351`) | Pick one: (a) a text-level draft with the server's validate as the parser; or (b) a JSON draft, marked as losing comments and never handed to MC to paste |
| Q20 | Does `autogroup:member` as a source match tagged devices? | Whether the droplet needs its own rule | **[unverified]**. Selectors L24 says "all members of the tailnet" and does not say | Validate array test on first run (read-only) |
| Q21 | What is in the current policy: `acls` or `grants`, the `ssh` rules MC "added", the `tag:dev` → `tag:fleet:22` rule? | Diagnosis and draft | The earlier session contradicts itself (X13) | First read: `GET /tailnet/-/acl` |
| Q22 | Can preview take an empty body? | Preview shape | **[unverified]** | **Moot.** Send the live policy as the body |

Q19 (which tests validate runs in policy-file mode) is answered in §2 as R1.

### DNS

| # | Question | Why it matters | Status after this pass | How to settle |
|---|---|---|---|---|
| Q23 | Does `dns:read` cover `GET /dns/configuration`? | `dns` command | **[unverified]**. Not in TC L65-75 | Best-effort. Test on first run |

### Skill and packaging

| # | Question | Why it matters | Status after this pass | How to settle |
|---|---|---|---|---|
| Q24 | What is the skill called? | Clash with upstream's `tailscale` directory and `/tailscale` command | Both upstream-skill and skill-packaging rule out `tailscale`. The user said "a tail scale skill" | MC picks the name |
| Q25 | Where do the CLI and the skill run? | Secret location; whether the skill loads | The earlier plan, D14: "All development and agent work runs on the droplet" (`page1.txt:947, 953`). The secret goes "into a gitignored `0600` file on the droplet only" (`page2.txt:36`). Cloud and Cowork sessions don't read `~/.claude/skills/` (skills L223) and would have no secret | Confirm the droplet is the only host |
| Q26 | Which Python is on the droplet? | Stdlib floor | **[unverified]**. Elmer's 3.11 note covers the Pi | Check on the droplet |
| Q27 | Where is the audit log kept, and how is "append-only" enforced? | Elmer invariant 4 | No Tailscale source covers it; it is local design. The agent can write any file the CLI can | Design. Elmer's `elmer.events` is the precedent |

---

## 2. Answered from first-party sources in this pass

| # | Question | Answer | Source |
|---|---|---|---|
| R1 | Which tests does `/acl/validate` run when the body is a full policy file? | The candidate file's own tests. GitHub GitOps's `test` action *"will send your tailnet policy file to Tailscale to determine whether the access control policy is valid and whether all tests pass"*. Tailscale's `gitops-pusher test` posts the local file to `/acl/validate`. The spec's wording ("runs tests to validate the existing rules") is ambiguous, and these two sources settle it | https://tailscale.com/docs/integrations/github/gitops (Last validated Dec 5, 2025) L33, L45; `tailscale/tailscale@de16943c cmd/gitops-pusher/gitops-pusher.go:333-351`; spec 2513-2516 |
| R2 | On a pass, is the body empty or `{}`? | Treat both as a pass. A 200 that carries `message` or `data` is a failure. gitops-pusher decodes the body as JSON unconditionally and returns any decode error (`:360-363`). An empty body would make that fail, which implies the server sends `{}` in policy-file mode **[inference from first-party code]**. It counts any `message` or `data` as failure (`:365`) | `gitops-pusher.go:360-365`; spec 2640-2678 |
| R3 | Does the ETag header value include double quotes? | Yes **[inference from first-party code]**. gitops-pusher's `Shuck` drops the first and last character of the header, then re-adds quotes for `If-Match`. The spec's example is `If-Match: "e0b2816b418"`. Store the raw header and strip one pair of quotes for display. gitops-pusher also compares the ETag with the sha256 of `hujson.Format(file)` | `cmd/gitops-pusher/cache.go:64-66`; `gitops-pusher.go:448, 310, 274-292, 79`; spec 2291-2303 |
| R4 | Does the token endpoint use `client_id`? | Not to identify the client. Tailscale's own CLI sends `ClientID: "some-client-id", // ignored` with a `tskey-client-` secret, so the secret alone identifies the client. Send the real ID anyway: the docs show it (OC L123), and the audit log uses the Client ID as actor (TC L392) | `tailscale/tailscale@de16943c feature/oauthkey/oauthkey.go:51-55` |
| R5 | Does the token endpoint check `grant_type` before credentials? | No. The credential is checked first. All four unauthenticated variants returned 401 `{"message":"API token invalid"}`, request IDs `REQ-2026102602125827bf439daaae0c0d`, `REQ-20261026021258e665376797d38ab2`, `REQ-202610260212593c985887605249a0` and `REQ-20261026021259119a6ebda32a0bf2`. Whether a valid client may omit `grant_type` stays open (Q6) | Live probe 2026-10-26T02:12:58-59Z |
| R6 | Does a read-only client need a tag? | No: tags are *"Mandatory if the scopes include "devices:core" or "auth_keys""*. This makes the two-client design (F4) possible | spec 1991, 2154, 5839 |
| R7 | Can an existing client's scopes change without a new secret? | Yes, through the API. `setKey` "Set[s] the configuration for an existing OAuth client" and takes `scopes`, `tags` and `description`; it needs `oauth_keys`. The audit log has "Update API key: OAuth client scopes, tags, or description were updated". The console path is **[unverified]**. The description is at most 50 alphanumeric characters; hyphens and spaces are allowed | spec 2111-2154, 1964; AUDIT L324 |
| R8 | Which source is authoritative for the `dns:read` endpoints? | TC. It lists four GETs, including `split-dns`. OC says tokens with `dns:read` "can access **only** the following" and lists three, which directly contradicts TC. But OC also says scope information "has moved to the trust credentials topic" | TC L65-75; OC L11-16, L261-263 |
| R9 | Is policy-access's source pin real? | Yes. On 2026-10-26, `refs/heads/main` of `tailscale/tailscale` was `de16943cbf03…`. The saved `ts-src/main-commit.json` is a GitHub API error body, not a commit record, but the pin is right | `git ls-remote https://github.com/tailscale/tailscale` |
| R10 | Do Claude Code `ask` rules hold in auto mode? | Yes. The order is deny, ask, allow, and an `ask` rule "still prompts you … even in auto mode". `bypassPermissions` skips prompts. `permissions.disableBypassPermissionsMode` / `disableAutoMode` can lock those modes out | permissions L58-60, L223, L83, L89 |
| R11 | Does Tailscale log refused (scope-denied) calls and reads? | It logs refused calls ("Failed request … insufficient permission"). It does not log reads | AUDIT L316, L404 |
| R12 | Is there first-party precedent for loading a secret from a file? | Yes. The Terraform provider's `oauth_client_secret`: *"If the value starts with 'file:' then it is treated as a path to a file on disk that contains the client secret."* | `tailscale/terraform-provider-tailscale@bccc075 docs/index.md:113` |
| R13 | Does `autogroup:self` cover tagged devices? | No. It *"includes all devices owned by the same user"*. Tagged devices have no user owner (TAGS L72). See F3.3 for spec5 | selectors L96; TAGS L72 |
| R14 | Can a tagged source Tailscale-SSH to an untagged host? | No: *"Devices with a tag-based identity can only SSH into other tagged devices"* | selectors L389; tailscale-ssh L218 |

---

## 3. Contradictions

### Between track files

| # | Track A says | Track B / evidence says | Resolution |
|---|---|---|---|
| X1 | policy-access:14: "The hosts run plain OpenSSH" | mc-tailnet §2 and `fleet.yaml:86`: spec5 runs Tailscale SSH in check mode | Decide per host. For spec5, the network rule is necessary but the `ssh` section decides (F3.3-4) |
| X2 | mc-tailnet §2: pi5 tags "None … user-owned [derived]", from `AdvertiseTags: null` as of 2026-09-27 | Observed `pi5 tags= ['tag:fleet']` at 2026-10-25T23:27:40Z (`page3.txt:140`) | The newer observation wins. The local `AdvertiseTags` pref was also weak evidence, because console tagging is a separate path from `--advertise-tags` (TAGS L253, L271) **[inference]** |
| X3 | mc-tailnet §3: "No `tag:` string appears in any of MC's records" | The earlier session's plan file `/home/mc/.claude/plans/eager-spinning-frost.md` on the droplet records `tag:fleet` and `tag:dev` (`page2.txt:50`, `page3.txt:128`) | A coverage gap, not a conflict. mc-tailnet did not read the plan or the transcript |
| X4 | credentials §12 step 1: give the client "a tag that no device and no ACL rule uses today" | MC's recorded choice was a client tagged `tag:fleet` (`page2.txt:34, 42`) | MC decides (Q16, F1) |
| X5 | api-surface §4: "the client's tags **do** constrain which tags `set tags` may apply" | credentials §3: whether this applies to the API is [unverified]; the note "sits in the section about tagging at authentication time" | The note sits under "Apply a tag from another tag", directly after "Apply a tag to a device using the API" (TAGS L303-338). Treat it as applying; still unproven for the API (Q8) |
| X6 | mc-tailnet implication: "Paginate fully and never truncate listings" | api-surface and upstream-skill: tailnet endpoints don't paginate (spec 47-49) | The real rule is "never truncate output". There is no paging to do |
| X7 | upstream-skill §9: "Handle 429 with backoff" | api-surface §12.9: "No retry on 429 by default … never retry a non-idempotent write" | Reads may back off, capped, honouring `Retry-After` if present. Writes are never retried automatically |
| X8 | skill-packaging: "explicit confirmation flags for destructive operations" | F4: the agent can pass any flag | Flags guard against accidents. The human gate is an `ask` rule plus the absent write secret |
| X9 | mc-tailnet implication: "setDeviceTags on a user-owned node (pi5, and probably spec5)" | X2 | Stale |
| X10 | policy-access TL;DR step 3: a validate test on `<spec5>:22` decides the policy question | X1 | For spec5, passing tcp:22 does not prove Tailscale SSH admission; that is the `ssh` section and `sshTests` |

### Earlier-session claims made to MC, against first-party docs

| # | Claim | Evidence |
|---|---|---|
| X11 | "A `devices` client acts as a tagged identity … can manage only fleet devices, never your Mac, phone, or the droplet" (`page2.txt:34`) | TC L145-147; TAGS L324, L72. See F1 |
| X12 | "`acl` scope is whole-tailnet with no sub-scoping" (`page2.txt:35`) | `acl` is a legacy name. The current scopes are `policy_file` and `policy_file:read` (TC L91-109; legacy map at TC L552-564) |
| X13 | "Policy rule is in" (`page3.txt:128`, 23:27Z) | "the `acls` section … is the piece still missing" (`page2.txt:21`, 23:32Z). Unresolved; read the policy (Q21) |

### Inside first-party sources (in addition to the tracks' lists)

| # | Inconsistency |
|---|---|
| X14 | OC L11-16: `dns:read` tokens "can access **only**" three DNS GETs. TC L65-75 lists four. The word "only" makes this a hard contradiction, not an omission. TC is authoritative (R8) |
| X15 | Selectors L24 defines `autogroup:member` as "all members of the tailnet". The `autogroup:<role>` entry (selectors L153) describes it as "all members in the tailnet with a specific role". Neither says whether tagged devices are excluded (Q20) |

---

## 4. Spot-checks of load-bearing facts

22 checks: 20 hold, 2 do not, and one holds only in part (#4).

| # | Claim (track) | Cited source | Check | Result |
|---|---|---|---|---|
| 1 | `policy_file:read` requires `devices:posture_attributes:read` and `devices:core:read` (credentials, api-surface, policy-access, upstream-skill) | TC L94 | Live fetch, byte-identical (sha256 `1580aae8…`); read L91-100 | Holds |
| 2 | `devices:core` wording; no tag limit on delete, expire or authorize (all tracks) | TC L143-163 | Read | Holds. credentials' point that this rests on a missing restriction also holds |
| 3 | `dns:read` = four GETs, no `/dns/configuration` (api-surface, credentials) | TC L65-75 | Read | Holds |
| 4 | OAuth tag-assignment rule (api-surface, credentials) | TAGS L324 | Read L300-340 | Holds. credentials' description of where the note sits holds only in part (X5) |
| 5 | Retagging does not change key expiry (policy-access) | TAGS L84 | Read | Holds |
| 6 | Token example omits `grant_type`; one-hour lifetime cannot be modified; `scope`/`tags` parameters (api-surface, credentials) | OC L122-125, L20, L272, L64 | Read | Holds |
| 7 | `lastSeen` omitted when `connectedToControl` is true (api-surface) | spec 4548 | Read | Holds |
| 8 | DELETE device lists no 404; 501 "Device not owned by tailnet" (api-surface) | spec 326-349 | Read | Holds |
| 9 | Re-enabling key expiry may leave the device already expired (api-surface §5.8) | spec 606-607 | Read | Holds, and it deserves more weight than it got (F5) |
| 10 | Validate modes; a 200 with `message` is a failure; `{}` example (api-surface, policy-access) | spec 2502-2520, 2640-2678 | Read | Holds |
| 11 | Local spec equals live spec (api-surface) | sha256 `b3532da7…ac38` | Re-fetched live 2026-10-26 | Holds |
| 12 | Audit: failed requests logged, mint events, reads not logged, 90 days (credentials) | AUDIT L316, L329, L404, L409 | Live fetch, identical (`313b48a0…`) | Holds |
| 13 | Upstream HEAD = tag `1.0.0-alpha-1` = `4f05d35` (upstream-skill) | `git ls-remote` | Re-ran | Holds |
| 14 | `tailscale/tailscale` source pin `de16943c` = main (policy-access) | Sources section | `git ls-remote` | Holds (R9) |
| 15 | ICMP allowed whenever any port is open; a policy-dropped SYN gets a TSMP reject and no RST (policy-access) | `filter.go:520`; `wrap.go:1234-1252` | Read saved source | Holds |
| 16 | Tailscale SSH claims port 22; tagged-to-tagged cannot use check mode; default rule targets `autogroup:self` (mc-tailnet, policy-access) | tailscale-ssh L40, L218, L255-268, L410 | Read | Holds |
| 17 | Metrics need v1.78.0+ and carry `reason="acl"`; `tailscale ping` defaults to DISCO (policy-access) | client-metrics L9, L142-144; ping-types L20 | Read | Holds |
| 18 | Compaction keeps a skill's first 5,000 tokens within a 25,000 budget; `allowed-tools` does not restrict; cloud sessions skip `~/.claude/skills`; the upload key list (skill-packaging) | skills.md | Live fetch, identical (`acb1f138…`); L613, L619, L223, L434 | Holds |
| 19 | elmer learning "rename is not in the API"; Serve + HTTPS enabled 2026-09-02 (mc-tailnet) | `learnings.md:609-610`; `DESIGN_DECISIONS.md:336` | Read | Holds as quoted. The learning itself is stale (mc-tailnet C1) |
| 20 | claude-factory "(tagged-devices)"; pi5 `AdvertiseTags: null`, `RunSSH: false` (mc-tailnet) | `fleet.yaml:66`; `kraken-config/MANIFEST.txt` | Read | Holds as records of 2026-09-27 and 2026-10-06; superseded by X2 |
| 21 | "The hosts run plain OpenSSH" (policy-access:14, a stated premise, not observed) | — | `fleet.yaml:86` | **Does not hold for spec5** |
| 22 | pi5 is user-owned (mc-tailnet §2, derived) | — | `page3.txt:138-140` | **Does not hold as of 2026-10-25T23:27:40Z** |

---

## 5. Which [unverified] items matter

**Settle before or during the design.** Each has a fallback that is safe in the worst case.

- Q1, downscoping: the two-client design makes it moot.
- Q2, Q8, Q9, tag semantics: design for the worst case. The client can apply its own tag to any
  device, permanently.
- Q4, the scope-denied status: report "possibly missing scope" without asserting it.
- Q13 and Q14, device approval and the protected list: ask MC.
- Q15 and Q21, key expiry on the retagged hosts and the current policy: first reads.
- Q18, the HuJSON draft: a design choice.
- Q20, `autogroup:member` and tagged sources: one validate test.

**Moot by design.**

- `grant_type`, Basic auth and console posture-scope enforcement (Q6, Q7).
- The preview body (Q22).
- ETag quoting: answered (R3).
- The empty tag list: refused client-side (Q10).
- Status for a nonexistent device: the pre-read catches it (Q11).
- Write retries after 504: never retry a write, and re-read state afterwards.
- Pagination: there is none (spec 47-49).

**Low impact or out of the command set.**

- `settings` partial reads; routes inside `fields=all` (Q12); the `POST /ip` error status.
- `keys list`; rate limits and `Retry-After`.
- kapa.ai docs MCP authorization; the `npx skills` interactive flow; `skills-ref validate`.
- `${CLAUDE_SKILL_DIR}` inside `references/*.md` (keep the invocation in SKILL.md); symlink path
  resolution; `bin/` in a skills-dir plugin; relative hook paths.

---

## 6. First run with MC's real credential: what each call settles

Steps 1-8 are read-only. Each token mint writes one audit event (F6).

1. `POST /oauth/token` with form parameters and `grant_type`, no `scope`. Record `scope` and
   `expires_in`. Settles Q5.
2. `POST /oauth/token` with `scope=devices:core:read`. Accepted or refused? Settles Q1 (moot if
   there are two clients).
3. `GET /tailnet/-/keys/<client-id>`. Settles Q3.
4. `GET /tailnet/-/devices?fields=all`. Read `tags`, `keyExpiryDisabled` and `expires` for
   spec5, nomad-b, pi5 and the droplet, and check whether the route fields are present. Settles
   Q15, F3.5 (`tag:dev`) and Q12.
5. `GET /device/<id>/routes`. Expect a refusal; record the status. It appears in the console as a
   "Failed request". Settles Q4.
6. `GET /tailnet/-/acl`, once as HuJSON and once with `Accept: application/json`. Record the raw
   ETag. Settles Q21 and confirms R3.
7. `POST /tailnet/-/acl/validate` with
   `[{"src":"tag:dev","proto":"tcp","accept":["<spec5-100.x>:22"]}]`, plus one probe whose only
   matching rule has an `autogroup:member` source. Settles Q20 and part of X13.
8. `GET /tailnet/-/dns/configuration`. Settles Q23.
9. Writes. Only if MC approves each one: tag semantics through the API (Q8, Q9). Never against a
   P9-protected host.

---

## Sources

**Track files reviewed**, all in `scratchpad/research/`: `api-surface.md`, `credentials.md`,
`policy-access.md`, `mc-tailnet.md`, `upstream-skill.md`, `skill-packaging.md`.

**Tailscale first-party docs**, fetched 2026-10-26 with curl as `.md`. "Live" means re-fetched
and byte-compared today.

| Key | URL | Last validated |
|---|---|---|
| TC | https://tailscale.com/docs/reference/trust-credentials (live, identical) | Jan 30, 2026 |
| OC | https://tailscale.com/docs/features/oauth-clients (live, identical) | Jun 30, 2026 |
| TAGS | https://tailscale.com/docs/features/tags (live, identical) | Dec 4, 2025 |
| AUDIT | https://tailscale.com/docs/features/logging/audit-logging (live, identical) | Jan 5, 2026 |
| GITOPS | https://tailscale.com/docs/integrations/github/gitops (copy `cred-docs/gh-gitops.md`) | Dec 5, 2025 |
| tailscale-ssh | https://tailscale.com/docs/features/tailscale-ssh (copy `docs-policy/features_tailscale-ssh.md`) | Jan 5, 2026 |
| selectors | https://tailscale.com/docs/reference/targets-and-selectors (copy `docs-policy/reference_targets-and-selectors.md`) | Jan 5, 2026 |
| client-metrics | https://tailscale.com/docs/reference/tailscale-client-metrics | Jul 28, 2026 |
| ping-types | https://tailscale.com/docs/reference/ping-types | Jan 13, 2026 |
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file (Tests section L853-857) | Apr 8, 2026 |
| KP | https://tailscale.com/docs/reference/key-prefixes | Aug 1, 2025 |

**OpenAPI spec.** `scratchpad/tsdocs/openapi.json` (YAML), sha256
`b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`. It equals
https://api.tailscale.com/api/v2?outputOpenapiSchema=true as re-fetched 2026-10-26. Line
numbers are file lines. Also used: `components.parameters.keyId`, `components.schemas.Key` and
`components.schemas.Device`.

**First-party code.** Fetched from raw.githubusercontent.com on 2026-10-26; local copies in
`scratchpad/critic-src/go/`.

- `tailscale/tailscale` @ `de16943cbf034d2c8238052dae4b2380837fe765` (main on 2026-10-26, by
  `git ls-remote`):
  - `cmd/gitops-pusher/gitops-pusher.go`: 79, 245-249, 274-292, 294-331, 333-372, 424-448
  - `cmd/gitops-pusher/cache.go`: 64-66
  - `feature/oauthkey/oauthkey.go`: 28-77
  - `cmd/get-authkey/main.go`
  - Already saved by policy-access: `wgengine/filter/filter.go:520`, `net/tstun/wrap.go:1234-1252`
- `tailscale/terraform-provider-tailscale` @ `bccc075cf5e52bd2a7da20c24e7fd7ae836d6280`:
  `docs/index.md:37-38, 113-114`.

**Claude Code docs**, fetched 2026-10-26. These pages carry no "Last validated" date.

- skills: https://code.claude.com/docs/en/skills.md (live, identical to
  `skilldocs/skills.md`), L223, L434, L491-508, L613, L619, L791.
- permissions: https://code.claude.com/docs/en/permissions.md, L58-60, L83, L89, L223, L653.

**Earlier-session transcript extract.** `scratchpad/sigint/page1.txt`, `page2.txt` and
`page3.txt`, produced by `sigint/extract.py` from a list_events result; events dated
2026-10-25 23:05–23:58Z. Lines cited: page1 947, 953; page2 13, 15, 21, 34-36, 40, 42, 50;
page3 2-4, 49, 128, 134, 138-144.

**MC's records.** Read-only, line numbers as of 2026-10-26.

- `/home/user/tailnet-ssh/fleet/fleet.yaml`: 65-73, 85-93
- `/home/user/elmer/.claude/learnings.md`: 609-612
- `/home/user/elmer/DESIGN_DECISIONS.md`: 334-337
- `/home/user/elmer/.claude/references/hardware/onboarding-ledger.md`: 53-57
- `/home/user/elmer/analysis/host-migration-2026-09/kraken-config/MANIFEST.txt`: 30-36, 60-80
- `/home/user/elmer/CLAUDE.md`: RF invariant 1, "one enforced surface"

**Live probes.** 2026-10-26T02:12:58-59Z, `POST https://api.tailscale.com/api/v2/oauth/token`
with fake credentials, four variants, all 401 `{"message":"API token invalid"}`. Nothing was
modified.

**Local copies made by this pass:** `scratchpad/critic-src/`.
