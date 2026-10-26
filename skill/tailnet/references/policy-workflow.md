# Policy workflow: draft, validate, diff, MC applies, verify

The agent drafts and validates; MC applies in the console. Facts about MC's tailnet here are dated
records: read the live policy before drafting anything.

## Contents

1. [Who does what](#1-who-does-what)
2. [The loop, with exact commands](#2-the-loop-with-exact-commands)
3. [Where drafts live, and why](#3-where-drafts-live-and-why)
4. [Reading validate and diff](#4-reading-validate-and-diff)
5. [Rule shapes](#5-rule-shapes)
6. [Candidate text for the blocker](#6-candidate-text-for-the-blocker)
7. [Never](#7-never)
8. [Preview, and why `policy test` replaces it](#8-preview-and-why-policy-test-replaces-it)
9. [For whoever holds `policy_file` (not this CLI)](#9-for-whoever-holds-policy_file-not-this-cli)
10. [Reverting](#10-reverting)
11. [Sources](#11-sources)

Tags: **[unverified]** and **[inference]**. Keys resolve in [Sources](#11-sources).

## 1. Who does what

- The read client holds `policy_file:read`, which reaches `GET …/acl`, `POST …/acl/preview` and
  `POST …/acl/validate` [TC L91-100]. Changing the policy needs `policy_file` [TC L102-109], which
  no client of MC's holds. That is decided: **MC applies every policy change in the console.**
- The server is the only parser. The CLI never parses HuJSON; drafts are text, edited as text, and
  `/acl/validate` both parses them and runs their tests (DESIGN §14, D17; critic R1).
- Policy changes are proposals, and additive (P18 in `tailnet-facts.md`).

## 2. The loop, with exact commands

1. `tailnet policy draft --name <topic> --json`. Note `data.path`. `--name` matches
   `^[a-z0-9-]{1,40}$`.
2. Edit `<path>/candidate.hujson` **as text** with the Edit tool. Keep MC's comments. Add `tests`
   (and `sshTests` for a Tailscale SSH host) asserting the intended access, so validate proves it and
   every later save is guarded by it [policy-file L857].
3. `tailnet policy validate <path>` until it exits 0.
4. `tailnet policy diff <path>` until it prints READY (exit 0). Relay the hunks to MC in a few
   lines.
5. Ask MC one question: applied / not now / change something. The `next` entry is
   `who=mc needs=console`.
6. After MC applies it: run `tailnet policy test …` with the same assertions against the live
   policy, then `tailnet diagnose …`. Byte equality is not the proof, because the console may
   reformat; the live assertions are.

| Command | Exit codes (DESIGN §5.2) |
|---|---|
| `tailnet policy get [--format hujson\|json] [--out FILE]` | 0 / 3 / 4. Bytes go to stdout exactly as served; the ETag, sha256 and `measured_at` go to stderr |
| `tailnet policy draft [--name NAME]` | 0 / 3 / 4 |
| `tailnet policy validate TARGET` (a draft directory or a file) | 0 pass, with or without warnings / 8 fail / 2 array-shaped file / 3 / 4 |
| `tailnet policy diff DRAFT` | 0 READY / 8 NOT READY / 3 / 4 |
| `tailnet policy test --src SRC (--accept HOST:PORT)... (--deny HOST:PORT)... [--proto PROTO]` | 0 pass / 8 fail / 2 / 3 / 4 |

Rules for `policy test`, checked before any API call (exit 2): `SRC` is a user email, `group:…`,
`tag:…` or a bare host alias, never a raw IP; no `*` anywhere [policy-file L918]; one numeric port
per entry, 0-65535, with port 0 for `--proto icmp` [policy-file L889]; IPv6 as `[addr]:port`.
Pass `--proto tcp` for SSH questions: without it the test "checks for either TCP or UDP access"
[policy-file L887].

## 3. Where drafts live, and why

- `~/.local/state/tailnet/drafts/<YYYYMMDDTHHMMSSZ>-<name>/`, directory 0700, files 0600:
  `base.hujson` and `candidate.hujson` (identical bytes at draft time) and `meta.json` (name, base
  ETag stored raw, base sha256, `fetched_at`, request ID, and later the validate verdict).
- Outside every repository, on purpose. The policy names MC's people and hosts, and MC kept an
  earlier draft out of git deliberately (P13: the superseded MESH-15 draft, tailnet-ssh
  `raptop/README.md:32`; mc §4). Never copy a draft into a repository.

## 4. Reading validate and diff

`tailnet policy validate` posts the candidate bytes with `Content-Type: application/hujson`. In this
mode the server runs **the candidate's own** `tests` and `sshTests` [spec L2513-2516; GITOPS L33]
(critic R1). A 200 does not mean a pass [spec L2640-2678]:

| Server answer | Verdict | Exit |
|---|---|---|
| 200, empty body or `{}` | `pass` | 0 |
| 200, `data[].errors` non-empty | `fail` | 8 |
| 200, only `data[].warnings` | `pass-with-warnings` (warnings printed) | 0 |
| 200, `message` and no `data` | `fail` | 8 |
| 200, any other JSON | `fail` (`unknown shape`) | 8 |
| 400 | `fail` with the server's message: a parse error in the draft | 8 |
| other statuses | an API error | 4 |

Failure lines have the shape `address "2.2.2.2:22": want: Drop, got: Accept` [spec L2659-2667]; the
CLI splits them into `{target, want, got}` and keeps any line it cannot parse verbatim. On a draft,
the verdict and the candidate's sha256 are written into `meta.json`.

`tailnet policy diff` is READY only when the validated sha256 equals the current
`candidate.hujson` with a `pass` or `pass-with-warnings` verdict, **and** the live ETag and body are
unchanged since the draft. Otherwise it is NOT READY with one reason: "candidate changed since
validate: re-run `policy validate`", "not validated", "validation failed", or "MC's console changed
the policy since this draft (ETag moved): re-draft". It ends with the console hand-off:
`https://console.tailscale.com/admin/acls/file` → make the edits shown → Save; "Saving re-runs the
policy's tests; a failing test blocks the save" (DESIGN §14.4).

## 5. Rule shapes

**Prefer grants for new rules, and read whatever form the live policy uses.** The syntax reference
says "Prefer grants for access control policies" [policy-file L11]; grants are "feature complete
with ACLs" [gva L20]; but "You may continue to use ACLs indefinitely" [gva L64], and the two
"can coexist in the same policy file" [gva L72].

- **Grant.** `{"src": [...], "dst": [...], "ip": ["tcp:22"]}`. Each grant implies accept. The `ip`
  forms are `*` (all ports; implies TCP, UDP and ICMP), `<port>` or a range (also implies TCP, UDP
  and ICMP), `<proto>:*`, and `<proto>:<port>` [grants L100-103]. So `"22"` alone also opens UDP 22.
- **Legacy ACL equivalent.** `{"action": "accept", "src": [...], "proto": "tcp", "dst": ["tag:fleet:22"]}`.
  "The only possible `action` is `accept`" [policy-file L63]; without `proto` a rule covers "all TCP
  and UDP traffic" [policy-file L85].
- **`ssh` rule.** `{"action": "accept" | "check", "src": [...], "dst": [...], "users": [...]}`
  [policy-file L549-566]. `dst` can be a tag, `autogroup:self` (when the sources are only users or
  groups), or the same single user [policy-file L580]. No port: "the only allowed port is `22`"
  [policy-file L582]. A check period defaults to 12 hours [policy-file L600]. An `ssh` rule opens no
  network path; port 22 still needs a grant or ACL [policy-file L542-545].
- **`tests`.** `{"src": "...", "proto": "tcp", "accept": ["host:port"], "deny": ["host:port"]}`
  [policy-file L863-875]. A destination host is a Tailscale IP, host alias, user, group, tag or
  service; no CIDR [policy-file L903-916]. Use `accept`, not the legacy `allow` [policy-file L922].
- **`sshTests`.** `{"src": "...", "dst": [...], "accept": [users], "check": [users], "deny": [users]}`
  [policy-file L938-951]. The field text calls `accept` and `check` "usernames to disallow"
  [policy-file L967, L971], a wording error: the example says `accept` accepts and `check` checks
  [policy-file L934-936] (policy-access D4).
- **Tests run on every save.** "If an assertion fails, Tailscale rejects the updated tailnet policy
  file" [policy-file L857]. So a new test and the rule it asserts go in the same change.
- **Tags** must already be `tagOwners` keys [policy-file L340]; tag names are parsed as lowercase
  [TAGS L224].

## 6. Candidate text for the blocker

**Adapt this after reading the live policy; never paste it blind.** It answers the 2026-10-25
blocker (`tailnet-facts.md` §6) and was written before anyone read MC's policy (Q21).

Read first, with `tailnet policy draft`:

- Which section the policy uses (`acls`, `grants` or both) and its existing `ssh` rules.
- That `tag:dev` and `tag:fleet` are `tagOwners` keys.
- MC's login email exactly as the policy spells it. It is recorded nowhere else (mc §1).
- The existing port-22 rule that names iphone192's addresses (P14, P15). It may already cover part
  of this.

The four pieces, in HuJSON (comments are allowed in the policy file):

```jsonc
"grants": [
  // (1) The droplet (tag:dev) may open TCP 22 on the fleet hosts.
  {"src": ["tag:dev"], "dst": ["tag:fleet"], "ip": ["tcp:22"]},
  // (2) MC's own devices may open TCP 22 on the fleet hosts. Name MC's login email, not
  // autogroup:member, until `tailnet doctor` S7b settles whether autogroup:member also matches
  // tagged sources such as the droplet (Q20).
  {"src": ["<MC login email>"], "dst": ["tag:fleet"], "ip": ["tcp:22"]},
],
"ssh": [
  // (3a) MC's phone and albini keep Tailscale SSH to spec5 now that it is tagged. Check mode
  // stays for people (P7). spec5's recorded SSH user is "spec5".
  {"action": "check", "src": ["<MC login email>"], "dst": ["tag:fleet"], "users": ["spec5"]},
  // (3b) ONLY if MC answers yes to MC6: the droplet to spec5 over Tailscale SSH. A tagged
  // source cannot use check mode, so this has to be accept.
  // {"action": "accept", "src": ["tag:dev"], "dst": ["tag:fleet"], "users": ["spec5"]},
],
"tests": [
  // (4) Assert each rule, so every later save is guarded by it.
  {"src": "tag:dev", "proto": "tcp", "accept": ["tag:fleet:22"]},
  {"src": "<MC login email>", "proto": "tcp", "accept": ["tag:fleet:22"]},
],
"sshTests": [
  {"src": "<MC login email>", "dst": ["tag:fleet"], "check": ["spec5"]},
  // With (3b) only: {"src": "tag:dev", "dst": ["tag:fleet"], "accept": ["spec5"]},
],
```

Why each piece:

- **(1)** The droplet's network path to port 22 [policy-access (e)]. For nomad-b and pi5, which run
  plain OpenSSH, this rule alone decides [policy-file L542-545; inference].
- **(2)** Narrower than `autogroup:member`, whose match on tagged sources is unsettled
  [selectors L24] (critic Q20). The `ssh` section also warns that granting `autogroup:member`
  reaches external invited users when a device is shared with them [policy-file L576]; whether
  that applies to grants is [unverified] (policy-access (e)). Whether MC's devices also lost
  other ports to the retagged hosts, such as spec5's Serve on 443 (P1), is unknown until the
  live policy is read [unverified]. Check with
  `tailnet policy test --src <MC login email> --accept <spec5 100.x>:443 --proto tcp`.
- **(3a)** Tagging removed spec5 from `autogroup:self` [policy-file L230], so the default
  `autogroup:member` → `autogroup:self` check rule no longer covers it [SSH L258-271]. A user may
  Tailscale-SSH to a tagged device [SSH L216] (critic F3.3, R13, R14).
- **(3b)** "An SSH access rule from a tagged device cannot be in check mode" [SSH L218]. It is MC's
  decision (open question MC6); drafts leave it out until MC says yes.
- **(4)** `tests` cover the network rules; `sshTests` cover the `ssh` section only.
- `dst: ["tag:fleet"]` in the `ssh` rules also matches nomad-b and pi5, where Tailscale SSH is off,
  so the rule has no effect there [inference].
- How a tag destination such as `tag:fleet:22` behaves in a test when several devices carry the tag
  is [unverified] (policy-access unverified 5). If validate reports something odd, test against a
  host alias whose value is the live 100.x from `tailnet device list --json`.

## 7. Never

- `"ip": ["*:*"]` in a grant. It is ACL `dst` syntax, not a documented grant `ip` form
  [grants L100-103]; whether it parses is [unverified] (upstream P6, U1).
- `deny` as an `ssh` action. The action is `accept` or `check` [policy-file L551, L563-566]
  (upstream P3, U2).
- Pressing or emulating **Convert to grants** unprompted. It rewrites the whole `acls` section in
  the editor at once: "The conversion takes effect in the editor immediately with no confirmation
  dialog" [migrate L154].
- Round-tripping HuJSON through `json.dumps` or any formatter. That drops MC's comments
  (policy-access (f), inference).
- A raw IP as a test `src`, or `*` in any test [policy-file L918].
- Writing the policy by any route. No client holds `policy_file`, and the decision is that MC applies.
- Putting a draft, or policy text, in a repository (P13), or in a query to the `tailscale-docs` MCP
  server, which is a third-party host (DESIGN §19.2 item 8).

## 8. Preview, and why `policy test` replaces it

- The endpoint is `POST /api/v2/tailnet/-/acl/preview?type=ipport&previewFor=<IP:PORT>` (or
  `type=user&previewFor=<email>`), with **a policy file as the body**, JSON or HuJSON
  [spec L2381-2440]. It returns `{matches: [{users, ports, lineNumber}], type, previewFor}`
  [spec L2442-2492].
- To preview the live policy, GET it first and post it back; whether an empty body works is
  [unverified] (critic Q22). `type=user` takes a user's email, so it cannot preview a tag as the
  source (policy-access (d) step 3).
- The console equivalent is the **Preview rules** tab [manage L18].
- **Why no command:** MC's question is "accept or drop, for this identity and port". `policy test`
  answers that directly against the live policy, tag sources included; preview answers "which rule
  lines mention this destination" (DESIGN §14.5, D17).
- Upstream's `references/api.md:100-103` posts `{"src","dst"}` to preview. That is the wrong shape
  (`upstream-corrections.md` A3).

## 9. For whoever holds `policy_file` (not this CLI)

- `POST /api/v2/tailnet/{tailnet}/acl` replaces the file. Send `If-Match` with the ETag from a GET:
  "Tailscale compares the `ETag` value in your request to that of the current tailnet file and only
  replaces the file if there's a match" [spec L2299-2301].
- The ETag header carries its quotes [inference from Tailscale's gitops-pusher; critic R3]. Send it
  as received; do not add a second pair, as upstream's `-H "If-Match: \"$ETAG\""` would.
- A mismatch is **412**, body `{"message": "precondition failed, invalid old hash"}`
  [spec L2342-2349].
- `If-Match: "ts-default"` replaces the file "*only if the current policy file is still the
  untouched default created automatically* for each tailnet" [spec L2302-2303].

## 10. Reverting

- A console change can be reverted "to a previous date and time from the Configuration logs page"
  [manage L47], but not under GitOps [manage L51].
- Every policy change is logged as "Update policy file for tailnet" [AUDIT L225], with "a full diff
  of the previous and new files" [AUDIT L9].

## 11. Sources

Read or fetched 2026-10-26.

- `DESIGN`: `DESIGN.md` §5.2, §14, §19.2, D17 in this repo.
- `critic`, `policy-access`, `mc`: `docs/research/critic.md`, `policy-access.md`,
  `mc-tailnet.md` (all 2026-10-26). P-numbers are MC's decisions as listed in `tailnet-facts.md` §5.
- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`
  (live copy identical at 2026-10-26T12:54Z); installed at
  `~/.local/share/tailnet/spec/tailscale-openapi.yaml`.
- Tailscale docs, fetched as Markdown with curl; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| grants | https://tailscale.com/docs/reference/syntax/grants | Jan 5, 2026 |
| gva | https://tailscale.com/docs/reference/grants-vs-acls | Aug 1, 2025 |
| migrate | https://tailscale.com/docs/reference/migrate-acls-grants | Mar 13, 2026 |
| manage | https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies | Mar 13, 2026 |
| SSH | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| selectors | https://tailscale.com/docs/reference/targets-and-selectors | Jan 5, 2026 |
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| TC | https://tailscale.com/docs/reference/trust-credentials | Jan 30, 2026 |
| AUDIT | https://tailscale.com/docs/features/logging/audit-logging | Jan 5, 2026 |
| GITOPS | https://tailscale.com/docs/integrations/github/gitops | Dec 5, 2025 |
