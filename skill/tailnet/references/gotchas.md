# Gotchas

One line each, grouped, each with its source. Lines about MC's own hosts are dated records, not
live state: re-verify with `tailnet device list --json` before acting on one.

## Contents

1. [Identity and tags](#identity-and-tags)
2. [Key expiry](#key-expiry)
3. [Tailscale SSH](#tailscale-ssh)
4. [Reachability](#reachability)
5. [API](#api)
6. [Records and hosts](#records-and-hosts)
7. [Sources](#sources)

Tags: **[unverified]** means no confirmed source settles it; **[inference]** means no source states
it outright; **[source-code]** means read from Tailscale's client at `de16943c`, undocumented and
liable to change. Keys resolve in [Sources](#sources).

## Identity and tags

- **The first tag strips the owner, permanently.** "Applying a tag to a device previously authenticated with a user account removes the user account" [TAGS L72]; only re-authenticating as a user reverses it [TAGS L72]. The CLI treats it as R3 and wants `--confirm strip-owner:<hostname>` (DESIGN §12.3).
- **You cannot remove all tags.** "A device with a tag-based identity must have at least one tag" [TAGS L33]. The CLI refuses an empty set (`TAG_SET_EMPTY`); what the API does with `{"tags": []}` is [unverified] (critic Q10).
- **Tags are lowercase.** "Tailscale ignores tag name case and parses all tags in the tailnet policy file as lowercase" [TAGS L224]. The CLI lowercases `--add` and `--remove`.
- **A tag must be a `tagOwners` key before anyone can use it** [policy-file L340; spec L548]. The console applies only tags that already exist in the policy file [TAGS L262].
- **A tagged device's identity is the union of its tags.** "A tagged device's identity is the combination of all its tags (not the intersection)" [TAGS L66].
- **`autogroup:self` excludes tagged devices.** It "only applies to user-owned devices. It does not apply to tagged devices" [policy-file L230]. Upstream calls it "same device"; that is wrong (upstream-corrections P4).
- **Whether `autogroup:member` matches a tagged source is unsettled** [unverified]. The docs say "Includes all members of the tailnet" [selectors L24] and "direct member" [policy-file L129], and neither mentions tags (critic Q20, X15). `tailnet doctor` step S7b settles it.
- **A tagged source can Tailscale-SSH only to tagged hosts, and never under a check-mode rule.** "An SSH access rule from a tagged device cannot be in check mode" [SSH L218]; tagged devices "cannot SSH into devices with a user-based identity" [TAGS L36; selectors L389].
- **An OAuth client's own tags limit which tags it may assign.** Requested tags must "exactly match the full set of tags on the OAuth client … or each requested tag must be owned by one of the authenticating entity's tags" in `tagOwners` [TAGS L324]. Whether this governs `POST /device/{id}/tags` called with an OAuth token is [unverified] (critic Q8); the CLI assumes it does.
- **`tagOwners` keys may be case-insensitive, or not** [unverified]. One docs example writes `"TagOwners"` [TAGS L329]; use `tagOwners` (policy-access D2).

## Key expiry

- **Retagging keeps the old expiry.** "If you change the tags on the device from the admin console, Tailscale CLI, or the Tailscale API, the device's key expiry will not change unless you re-authenticate" [TAGS L84]. Expiry is off by default only when a tag is first applied *and* the device authenticates [TAGS L78]. Upstream omits this (U6).
- **Re-enabling expiry can drop a device at once.** Re-enabling "Sets the key to expire at the original expiry time prior to disabling. The key may already have expired. In that case, the device must be re-authenticated" [spec L607]. The CLI cannot send `false` (critic F5; DESIGN §12.3).
- **Disabling expiry on a key that has already expired may not reconnect the device** [unverified] (DESIGN §12.3, warning `KEY_ALREADY_EXPIRED`).
- **For a new host, tag at authentication.** `--advertise-tags` at first authentication leaves expiry off [TAGS L78]; tagging later from the console or API does not [TAGS L84].

## Tailscale SSH

- **It claims port 22 on the Tailscale IP.** "Tailscale claims port `22` for the Tailscale IP address" [SSH L40, L410]. nomad-b's own sshd was unreachable over the tailnet until `tailscale set --ssh=false` (2026-09-09; mc §5).
- **It needs two rules.** "An access rule to allow connections from the source to the destination on port 22" and "An SSH access rule" [policy-file L542-545].
- **Check mode blocks unattended logins.** It "requires re-authentication on the device initiating the connection" through a sign-in URL [SSH L475]; a BatchMode hop to spec5 stalls on that link (MC's records 2026-09-20, 2026-09-28; mc §5). The default check period is 12 hours [SSH L182].
- **The default `ssh` rule covers only a user's own devices, in check mode**: `autogroup:member` → `autogroup:self` [SSH L258-271]. Upstream says "SSH to all devices as non-root users"; wrong (P5).
- **An `ssh` rule's `action` is only `accept` or `check`** [policy-file L551, L563-566]. `deny` exists only as an `sshTests` user list (upstream P3).
- **macOS GUI builds have no Tailscale SSH server.** A server needs Linux or the open-source `tailscaled` [SSH L49, L544]; albini cannot be one (mc §5).
- **Check-mode URLs are login links.** Redact them from anything committed (MC's `fleet/audit.sh:246-247`, 2026-10-09; mc §5). The CLI masks `https://login.tailscale.com/a/…` (DESIGN §10.4).
- **Restarting `tailscaled` ends every open Tailscale SSH session** [SSH L546].

## Reachability

- **Ping proves nothing about port 22.** "If traffic is allowed for a given pair of IP addresses, then ICMP will also be allowed" [policy-file L109]; the client filter answers an echo when any port is open (`wgengine/filter/filter.go:520` [source-code]).
- **`tailscale ping` with no flag is DISCO, not TSMP** [ping-types L20; cli L643]. TSMP stops "before the access control policy check"; ICMP includes it [manage L29, L35]. Upstream labels the default TSMP (C3).
- **A policy drop looks like a timeout.** The receiver answers a dropped SYN with a TSMP reject and no TCP RST (`net/tstun/wrap.go:1234-1252` [source-code]), so `ssh` waits rather than seeing "refused" [inference].
- **`ssh` rules open no network.** Port 22 needs an `acls` or `grants` rule; for plain OpenSSH the `ssh` section plays no part [policy-file L542-545; inference, policy-access (a)]. Upstream omits this (U8).
- **A stopped backend still shows a stale peer list.** Require `BackendState == "Running"`, `Self.Online` and a non-empty `Peer` map before concluding anything (MC's `fleet/audit.sh:63`, `lib/tailnet_health.jq:3-6`; mc §5). But an empty `Peer` map on a Running, online host can be the policy, not an outage: the netmap holds only devices the policy lets it reach or be reached by [visibility L37-42], so `diagnose` warns and goes on (DESIGN A52).
- **A peer in `tailscale status` is not permission.** The netmap holds "All devices that can connect to your device, even if you aren't permitted to connect to them" [visibility L42].
- **MagicDNS failed on the droplet.** Address hosts by 100.x or `nodeId` (observed 2026-10-25T23:30:30Z; critic F3.6).
- **Network flow logs never show a denial.** "Tailscale only logs successful connects" [flowlogs L480], and flow logs are Premium and Enterprise only [flowlogs L11].
- **The tailnet address does not change with the physical network.** If SSH broke after a network change, look at Tailscale connectivity (MC's `docs/TROUBLESHOOTING.md:37-40`; mc §5).

## API

- **A 200 from `/acl/validate` is not a pass.** Failures and warnings also return 200, with `message` and `data[]` [spec L2640-2678]; read the body (critic R2).
- **Validate chooses its mode from the body.** A JSON array runs tests against the live policy; an object or HuJSON is a candidate policy whose own `tests` run [spec L2508-2516; GITOPS L33] (critic R1).
- **Preview's body is a policy file**, with `type` and `previewFor` as query parameters [spec L2381-2440]. Upstream's `{"src","dst"}` body is the wrong shape (A3).
- **The ETag header carries its quotes.** Store it raw; strip one pair only for display [inference from Tailscale's gitops-pusher, critic R3].
- **`lastSeen` is omitted while a device is connected.** "Omitted if the device has never been online or `connectedToControl` is true" [spec L4548]. Never infer offline from its absence.
- **Each token mint is one audit event**, with the client ID as actor [TC L392; AUDIT L329]. The CLI caches the read token for its hour (DESIGN §9).
- **There is no pagination.** "All results are returned at once" [spec L49]: nothing to page, and nothing may be cut short.
- **`dns:read` may not cover `/dns/configuration`.** TC lists four DNS GETs and not that one [TC L65-75] [unverified] (critic Q23).
- **401 is undocumented but real.** A bad token returns 401 `{"message":"API token invalid"}` (live, 2026-10-26; api §3.3); the spec lists no 401.
- **A scope refusal shows in the console as "Failed request"** [AUDIT L316]; whether the status is 403 or 404 is [unverified] (critic Q4).
- **`devices:core` reaches every device.** It can "read the list of all devices in the tailnet, authorize or remove machines, and manipulate tags on devices" [TC L145-147]; the client's tag does not fence it (critic F1; upstream A6).
- **`sshEnabled` and `multipleConnections` arrive only with `fields=all`** [api §5.1]. `multipleConnections` is not sticky: true only while two devices share one node key, "usually a sign of node state being copied" [spec L4579-4581].
- **A write that got a 5xx or a timeout may have landed** [inference; api §12.9]. The spec's 504 text is only "Request took too long to process, please try again later" [spec L173]. The CLI never retries a write; it re-reads, and exits 6 when the outcome is unconfirmed (DESIGN §12.6).

## Records and hosts

- **A listing whose length equals its print limit is truncated.** MESH-39 was misreported from `srcs[:8]` when the rule held 9 (tailnet-ssh `docs/STATUS.md:127-136`, 2026-10-09; mc §5).
- **A cloned SD card carries the same node key.** nomad-b's machine-id equals spec5's (cloned image); identify a Nomad by SoC serial (elmer `onboarding-ledger.md:56`; mc §5). The API flags live sharing as `multipleConnections` [spec L4579].
- **Renaming breaks MagicDNS URLs.** "any existing Magic DNS URLs using the old name will no longer work" [spec L504]; spec5's Serve URL depends on its name (P2).
- **A name set in the console overrides the advertised hostname** (spectre after the `a25` rename; mc §5; [machine-names]).
- **`tailscale serve` hangs instead of failing when Serve is not enabled.** Wrap it in `timeout` (observed on spec5 2026-09-02; mc §5); the docs do not mention the hang.
- **`tailscale health` is not a subcommand** (1.102.3). Read `Health` from `tailscale status --json`; `[]` means clean (mc §5; cli lists no `health`).
- **`tailscale status --json` prints a space after each colon** (`"DNSName": "…"`). Parse it as JSON; never grep it (elmer `learnings.md:951-955`; mc §5).
- **Sideloading Tailscale on Android re-registers the node** as a new machine and loses its console rename (2026-09-09; mc §5, P5).
- **"Device rename is not in the API" is stale.** `POST /device/{deviceId}/name` exists (spec `setDeviceName`); the elmer learning dates from 2026-09-09 (mc C1). The CLI still offers no rename (DESIGN D8).
- **On Windows, a non-desktop account cannot use the CLI.** `tailscale status` as `mesh` returns 401 or "already in use by" (2026-10-09; mc §5).
- **Stubs hid three bugs.** A stubbed `tailscale` returned instantly, printed compact JSON and modelled no permissions (elmer `learnings.md:956-962`; mc §5). Tests here never use a fake `tailscale`.
- **`tailscale debug …` is hidden and "not a stable interface"** (`cmd/tailscale/cli/debug.go:69` [source-code]). Use `debug netmap` for a human's confirmation, never automation.

## Sources

Read or fetched 2026-10-26.

- `mc`, `critic`, `api`, `policy-access`: `docs/research/mc-tailnet.md`, `critic.md`,
  `api-surface.md`, `policy-access.md` (all 2026-10-26). `mc` names the record file and line
  behind every fact about MC's hosts.
- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`
  (live copy identical at 2026-10-26T12:54Z); installed at
  `~/.local/share/tailnet/spec/tailscale-openapi.yaml`.
- `[source-code]`: `github.com/tailscale/tailscale` at `de16943cbf034d2c8238052dae4b2380837fe765`
  (main on 2026-10-26), as read by policy-access.
- `DESIGN`: `DESIGN.md` in this repo.
- Tailscale docs, fetched as Markdown with curl; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| TC | https://tailscale.com/docs/reference/trust-credentials | Jan 30, 2026 |
| AUDIT | https://tailscale.com/docs/features/logging/audit-logging | Jan 5, 2026 |
| SSH | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| selectors | https://tailscale.com/docs/reference/targets-and-selectors | Jan 5, 2026 |
| ping-types | https://tailscale.com/docs/reference/ping-types | Jan 13, 2026 |
| cli | https://tailscale.com/docs/reference/tailscale-cli | Jul 30, 2026 |
| manage | https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies | Mar 13, 2026 |
| visibility | https://tailscale.com/docs/concepts/device-visibility | Jan 5, 2026 |
| flowlogs | https://tailscale.com/docs/features/logging/network-flow-logs | Jan 23, 2026 |
| GITOPS | https://tailscale.com/docs/integrations/github/gitops | Dec 5, 2025 |
| machine-names | https://tailscale.com/docs/concepts/machine-names | Jan 5, 2026 |
