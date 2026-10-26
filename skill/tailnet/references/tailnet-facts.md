# MC's tailnet: dated facts

> **Staleness rule.** Every row in this file is a dated claim about the past, never live state.
> Before acting on one, re-verify it with `tailnet device list --json` (or the command its row
> names) and relay the live value with its `measured_at`. When live state disagrees with this
> file, live state wins, and say so.

## Contents

1. [How to read this file](#1-how-to-read-this-file)
2. [The tailnet](#2-the-tailnet)
3. [Hosts](#3-hosts)
4. [The 2026-10-25 change](#4-the-2026-10-25-change)
5. [Decisions that bind](#5-decisions-that-bind)
6. [The open blocker](#6-the-open-blocker)
7. [Unknowns](#7-unknowns)
8. [Sources](#8-sources)

## 1. How to read this file

- Compiled 2026-10-26. MC's own records date from 2026-08-23 to 2026-10-10, so most rows were at
  least 16 days old when this file was written (`mc` staleness note). The 2026-10-25 rows come from
  an earlier session's transcript.
- **Recorded** is when a record says the fact held, not when it was last true.
- Tags: **[observed]** means tool output or a measurement with its time; **[MC]** means MC decided
  or reported it; **[record]** means a file says it without stating evidence; **[unverified]**
  means no record or doc settles it; **[inference]** means a conclusion no source states outright.
- Source keys resolve in [Sources](#8-sources). `mc §N` is `docs/research/mc-tailnet.md`, which
  names the underlying record file and line for every fact.
- From the droplet, address hosts by 100.x address or `nodeId`, never by MagicDNS name (§2).

## 2. The tailnet

| Fact | Value | Recorded | Source |
|---|---|---|---|
| Tailnet DNS name | `taild02cf8.ts.net` | 2026-09-02 → 2026-09-25 [record] | mc §1 |
| Tailnet ID | **Not recorded** [unverified]. The DNS name is not the tailnet ID. The CLI always uses `-`, meaning the token's own tailnet | — | mc §1; spec `components.parameters.tailnet`; DESIGN §3.1 |
| MagicDNS | On; Serve URLs resolved | 2026-09-02 → 2026-09-25 [record] | mc §1 |
| HTTPS certificates and Serve | Enabled for the tailnet on 2026-09-02. Who enabled them is not recorded | 2026-09-02 [record] | mc §1, P2 |
| What HTTPS publishes | Machine names that get a certificate (at least `spec5`) and the tailnet DNS name go into the public Certificate Transparency ledger | doc | [HTTPS L18, L21-24] |
| MagicDNS **from the droplet** | **Failed.** `ssh` to `spec5.taild02cf8.ts.net` returned "Could not resolve hostname … Temporary failure in name resolution" | 2026-10-25T23:30:30Z [observed] | critic F3.6 (sigint p2:13) |
| Account, identity provider, MC's login email | **Not recorded anywhere** [unverified]. A policy draft needs the email exactly as the live policy spells it: read it with `tailnet policy get` | — | mc §1 |
| Ranges the hosts' own firewalls trust | `100.64.0.0/10` and `fd7a:115c:a1e0::/48`; both match the docs | undated [record] | mc §1 |

## 3. Hosts

Every host's owner is MC; the records never name which tailnet user registered each node (mc §2).
Usernames differ per host, and a wrong username fails the same way as a missing key (tailnet-ssh
`docs/FINDINGS.md` §12, via mc §2).

| Host | Role | OS / arch | Tailnet IPv4 / IPv6 | SSH user | Tailscale SSH | Tags (observed at) | Recorded | Source |
|---|---|---|---|---|---|---|---|---|
| **claude-factory** (the droplet; this skill runs here) | MC's DigitalOcean dev droplet | Linux, x86_64 | **not recorded** [unverified] | `mc` | not recorded | **`tag:dev` [unverified]**: it appears only in the earlier session's prose (sigint p3:128), never in tool output. fleet.yaml says "(tagged-devices)" without naming a tag (2026-10-06) | 2026-10-06 → 2026-10-09 | mc §2; critic F3.5; fleet.yaml:65-73 |
| **spec5** | The OG Nomad (Pi 4, green case). Runs the Elmer console; Serve URL `https://spec5.taild02cf8.ts.net` | Debian 12, arm64 | `100.90.68.20` / not recorded | `spec5` | **On, check mode.** MC kept it on 2026-09-28; still check mode 2026-10-10 | `tag:fleet` at 2026-10-25T23:27:40Z [observed]; none at 23:05:34Z [observed] | 2026-09-20 → 2026-10-25 | mc §2, P7; critic F3; fleet.yaml:85-93 |
| **nomad-b** | The second Nomad (Pi 4, blue-grey case). OS hostname `spec5b` | Linux, aarch64 | `100.108.20.20` / not recorded | `spec5` | **Off**: `tailscale set --ssh=false` on 2026-09-09; the ledger says "Keep `--ssh=false`" (2026-09-25) | `tag:fleet` at 2026-10-25T23:27:40Z [observed]; none at 23:05:34Z [observed] | 2026-09-09 → 2026-10-25 | mc §2, P6; critic F3; fleet.yaml:134-142 |
| **pi5** | MC's daily driver. Raspberry Pi 5 16 GB, the ex-`kraken` board | Debian 12, aarch64 | `100.126.132.9` / `fd7a:115c:a1e0::5b33:840b` | `mc` | **Off**: prefs show `RunSSH: false` in the 2026-09-27 backup | `tag:fleet` at 2026-10-25T23:27:40Z [observed]; none at 23:05:34Z [observed]. The older `AdvertiseTags: null` (2026-09-27) is superseded | 2026-09-27 → 2026-10-25 | mc §2; critic F3, X2; fleet.yaml:75-83 |
| **albini** | Hub. MacBook Pro M4 Max, travelling laptop; holds the admin keys for the Windows hosts | macOS 27, arm64 | `100.126.116.15` / `fd7a:115c:a1e0::7c33:740f` | `michael` | **Off; cannot run.** The GUI (`macsys`) build has no Tailscale SSH server | not recorded | 2026-10-01 → 2026-10-09 [observed] | mc §2; fleet.yaml:47-63 |
| **iphone192** | iPhone 18 Pro, MC's current phone; runs Termius | iOS | `100.92.107.24` / `fd7a:115c:a1e0::a533:6b19` | client only | n/a | not recorded | 2026-10-09 [MC] | mc §2; fleet.yaml:162-165 |
| **iphone182** | The previous iPhone; removed from the port-22 policy (P14) | iOS | not recorded | client only | n/a | not recorded | 2026-10-09 | mc §2; fleet.yaml:157-160 |
| **pi3** | Raspberry Pi 3B; not part of the Elmer runtime | Debian 13, aarch64 | `100.79.56.86` / not recorded | `mc` | not recorded [unverified] | not recorded | 2026-09-20 → 2026-10-09 | mc §2; fleet.yaml:124-132 |
| **raptop** | ASUS ROG laptop | Windows 11 Pro, x86_64 | `100.100.253.41` / `fd7a:115c:a1e0::f833:fd2a` | `mesh`; admin `micha` via `raptop-admin`, from albini only | n/a: a Tailscale SSH server runs only on Linux and open-source macOS [SSH L544]; sshd is OpenSSH 9.5p2 | not recorded | 2026-10-03 → 2026-10-07 | mc §2; fleet.yaml:104-112 |
| **cybrpwrpc** | Windows desktop, always on | Windows 11 Pro, x86_64 | `100.108.249.110` / `fd7a:115c:a1e0::9233:f96f` | `mesh`; admin `michael` via `cybrpwrpc-admin` (an older committed config block disagrees: mc C3) | n/a; sshd is the OpenSSH 10.0p2 MSI | not recorded | 2026-10-03 → 2026-10-08 | mc §2, C3; fleet.yaml:114-122 |
| **surface** | Windows laptop; its sshd routes into WSL2 | Windows + WSL2, x86_64 | `100.121.141.69` / `fd7a:115c:a1e0::233:8d47` | alias user `micha`; sessions land as Linux user `surface` | n/a | not recorded | 2026-10-02 → 2026-10-09 | mc §2; fleet.yaml:95-102 |
| **server-factory-immich** | Immich photo server; Claude is not expected to run here | Linux | `100.127.97.75` | `deploy` | not recorded | not recorded | 2026-10-07 [MC approved its use] | mc §2; fleet.yaml:144-156 |
| **spectre** | Android 12 phone (SOYES XS19Pro); console-renamed from `a25` (P4) | Android | `100.116.32.124` | `u0_a144`, over SimpleSSHD on port 2222 (not Tailscale SSH) | n/a: the Android app has no CLI | not recorded | 2026-09-09 → 2026-09-25 [observed] | mc §2 |

Client versions on record (they matter for the ACL drop counter, which needs v1.78.0 or later
[metrics L9]): pi5 1.104.1 (2026-10-10); nomad-b 1.102.3 (2026-09-09); albini daemon 1.104.1 with a
Homebrew CLI at 1.96.4 (2026-10-09); spectre 1.98.8, held there on purpose (P5). spec5,
claude-factory and pi3: not recorded (mc §2).

**Names that are not tailnet nodes, as recorded** (mc §2): `elmer` (fleet.yaml says it never
appeared; a later record calls that note stale, mc C2); `seedbox` (a public host reached over the
internet); `kraken` (a future Pi 4B that will join as a new node with a new 100.x, because
`100.126.132.9` belongs to pi5's node key); the GL.iNet travel router (its built-in Tailscale was
disabled 2026-10-02); the M5Stack Atom (cannot run Tailscale).

## 4. The 2026-10-25 change

What the earlier session's tool output shows, run from the droplet (critic F3; sigint pages
re-read 2026-10-26):

| Time (UTC) | Observation | Source |
|---|---|---|
| 2026-10-25T23:05:34Z | nomad-b, spec5 and pi5 show `tags= None`; port 22 on `100.90.68.20`, `100.108.20.20` and `100.126.132.9` "blocked" | sigint p3:1-7 [observed] |
| 2026-10-25T23:27:40Z | All three show `tags= ['tag:fleet']`; `nc -z -w5` to port 22 on `100.90.68.20`, `100.108.20.20` and `100.126.132.9` all "blocked" | sigint p3:136-144 [observed] |
| 2026-10-25T23:30:30Z | `nc` to `100.90.68.20` port 22 "timed out"; the MagicDNS name did not resolve | sigint p2:9-15 [observed] |

What is claimed but not in tool output:

- That MC applied the tags in the admin console's Machines page (sigint p3:49, p3:134, assistant
  prose). The output proves only that the tags were present at 23:27:40Z.
- That ping and port 443 from the droplet succeed (sigint p2:6, p2:21, assistant prose)
  **[unverified]**. `tailnet diagnose` re-measures reachability.
- That the droplet carries `tag:dev` **[unverified]** (critic F3.5).

What the docs say follows, not yet measured on these hosts:

- **The user owner is gone.** "Applying a tag to a device previously authenticated with a user
  account removes the user account" [TAGS L72]. Removing tags cannot undo it: "You cannot remove all
  tags from a device" [TAGS L33]; only re-authenticating as a user does [TAGS L72].
- **Key expiry did not change.** "If you change the tags on the device from the admin console,
  Tailscale CLI, or the Tailscale API, the device's key expiry will not change unless you
  re-authenticate" [TAGS L84]. If the three still carry their user-era expiry, they drop off the
  tailnet when it lapses, which breaks P9 (critic F3.2). Check: `tailnet device list --json`, flag
  `TAGGED_KEY_EXPIRY_ON`.
- **MC's own devices lost their implicit path to spec5's Tailscale SSH.** `autogroup:self` "only
  applies to user-owned devices" [policy-file L230], so the default rule (`autogroup:member` →
  `autogroup:self`, check mode) no longer reaches spec5 [SSH L258-271]. MC's phone and albini now
  need an explicit user → `tag:fleet` `ssh` rule [inference; critic F3.3, R13]. Check:
  `tailnet diagnose spec5 --from iphone192 --ssh-user spec5`.
- **A tagged droplet cannot use a check-mode rule.** "An SSH access rule from a tagged device cannot
  be in check mode" [SSH L218].
- `tag:fleet` should already be a `tagOwners` key, because the console applies only tags that exist
  in the policy file [TAGS L262] [inference]. `tailnet doctor` step S6 confirms it.

## 5. Decisions that bind

| # | Date | Decision | Who | What it means for an agent | Source |
|---|---|---|---|---|---|
| P1 | 2026-09-01 | Reach the Elmer console through `tailscale serve` on a loopback bind; `serve`, never `funnel`. MC: "locked to Tailscale, open to the tailnet" | MC | Never propose Funnel for spec5 | mc §4 |
| P2 | 2026-09-02 | Serve and HTTPS enabled; `sudo tailscale set --operator=spec5` on spec5; console at `https://spec5.taild02cf8.ts.net`, tailnet-only | session (deploy) | Renaming spec5 breaks this URL [spec L504] | mc §4 |
| P3 | 2026-09-02 | Over Serve, "the tailnet is the auth boundary"; no per-user auth on a single-person tailnet | MC | A policy change that widens access to spec5 also widens access to the console | mc §4 |
| P5 | 2026-09-09 | Leave spectre's "out-of-date client" banner; sideloading would re-register the node and undo the rename | MC | Never suggest sideloading Tailscale on spectre | mc §4 |
| P7 | 2026-09-20 → 2026-09-28 | Tailscale SSH on spec5 stays on, in check mode. MC: "never take anything off the tailnet, and the phone may rely on it." Check mode still in effect 2026-10-10 | MC | Never turn off Tailscale SSH on spec5 or drop check mode for people. An `accept` rule for the tagged droplet is open question MC6 | mc §4 |
| P9 | standing; restated 2026-09-28 | **Never take a lab host off the tailnet** | MC | The CLI has no delete, expire, deauthorize, rename, re-address or key-expiry re-enable; never ask for one or improvise it | mc §4 |
| P11 | 2026-10-03 | Key-only SSH mesh between pi5, albini, raptop, surface and cybrpwrpc; every inbound key `from=`-pinned to the source's tailnet v4 and v6; Windows hosts get a non-admin `mesh` account; admin SSH only from albini | MC approved | Re-addressing a device breaks its pins; never do it | mc §4 |
| P12 | 2026-10-03 | Host firewalls admit port 22 only from the tailnet ranges; on Windows, Block rules override tailscaled's allow-all `Tailscale-In` rules | MC approved per change | A host firewall is a live hypothesis when the policy allows port 22 and it still times out | mc §4 |
| P13 | date not recorded | The MESH-15 policy draft was superseded and deliberately not committed | — | Policy drafts never go into a repository | mc §4 |
| P14 | about 2026-10-09 | MC's one-line console edit: iphone192 replaced iphone182 for port 22. Verified on the claude-factory and pi5 netmaps: iphone192 v4 and v6 present, iphone182 absent, 46 port-22 sources | MC (console) | The live policy has a port-22 rule that names phone addresses; read it before drafting | mc §4 |
| P15 | 2026-10-09 | MESH-39 was already applied; rule 3 had 9 sources, and an earlier "outstanding" claim came from a truncated read | session | Never truncate a listing | mc §4 |
| P18 | standing (2026-10-06) | Fleet audit: only `login_path`, `time_machine` and `backblaze` drift is auto-fixed; everything else is a written proposal, never an action. For check mode the proposal is re-authenticate, or "make an additive ACL change only" | audit design | Policy changes are proposals MC applies, and additive | mc §4 |
| A1 | 2026-10-26 | Two OAuth clients: a read client and a write client tagged `tag:fleet` | MC | See `credentials.md` | DESIGN.md Amendment A1 |

## 6. The open blocker

- **Symptom.** From the droplet, TCP 22 to spec5, nomad-b and pi5 times out
  (2026-10-25T23:27:40Z and 23:30:30Z [observed]).
- **The earlier session contradicted itself** (critic X13). At 23:27Z it wrote "Policy rule is in"
  into its plan (sigint p3:128). At 23:32Z it told MC "the `acls` section … is the piece still
  missing" (sigint p2:21). Neither claim was checked against the policy. It stays unresolved until
  `tailnet policy get`, or `tailnet doctor` step S6, reads the live policy.
- **spec5 differs from the other two.** It runs Tailscale SSH, so a network rule on port 22 is
  necessary but the `ssh` section decides admission (critic X1, X10). nomad-b and pi5 run plain
  OpenSSH, where only the network rule matters.
- MC deferred Tailscale work at 2026-10-25T23:34:12Z (sigint p2:44).
- Work it with `tailnet diagnose spec5 nomad-b pi5 --ssh-user spec5`, then `diagnose-port.md`.

## 7. Unknowns

| # | Unknown | Why it matters | Settled by |
|---|---|---|---|
| Q15 | Key-expiry state of spec5, nomad-b and pi5 after the retag | P9: a lapsed key takes a host off the tailnet | `tailnet device list --json` (`TAGGED_KEY_EXPIRY_ON`); `tailnet doctor` S4 |
| Q21 | What the live policy holds: `acls` or `grants`, the `ssh` rules, any `tag:dev` → `tag:fleet` port-22 rule | The blocker; every draft | `tailnet policy get`; `tailnet doctor` S6 |
| F3.5 | Whether the droplet is `tag:dev` | It is the source identity in every policy test | `tailnet doctor` S4 (self's tags) |
| — | The droplet's 100.x address | Self detection joins on it | `tailnet doctor` L3 and S4 |
| — | MC's login email as the policy spells it | Drafts and tests name it | `tailnet policy get` |
| Q20 | Whether `autogroup:member` as a source matches tagged devices | Whether the droplet is already covered by a member rule | `tailnet doctor` S7b |
| Q13 | Whether the tailnet requires device approval | Reading it needs `feature_settings:read`, which neither client holds | MC, in the console |

## 8. Sources

Read on 2026-10-26.

- `mc`: `docs/research/mc-tailnet.md` (compiled 2026-10-26). It cites MC's records in
  `tailnet-ssh` at `2cab922` and `elmer` at `c6d9404` (both 2026-10-10), with file and line for
  each fact.
- `critic`: `docs/research/critic.md` (2026-10-26).
- `sigint pN:L`: the earlier session's transcript extract, events 2026-10-25T23:05Z-23:58Z. It is
  a working file and is not committed (DESIGN.md Amendment A2). Lines in `[TOOL_RESULT …]` blocks
  count as observed; assistant prose counts as a claim. Pages p2:1-52 and p3:1-12, 45-52, 124-146
  were re-read for this file.
- `fleet.yaml`: `/home/user/tailnet-ssh/fleet/fleet.yaml` at `2cab922` (2026-10-10).
- Tailscale docs, fetched as Markdown with curl on 2026-10-26; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| SSH | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| HTTPS | https://tailscale.com/docs/how-to/set-up-https-certificates | Dec 10, 2025 |
| metrics | https://tailscale.com/docs/reference/tailscale-client-metrics | Jul 28, 2026 |

- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`,
  equal to the live `https://api.tailscale.com/api/v2?outputOpenapiSchema=true` at
  2026-10-26T12:54Z. Installed at `~/.local/share/tailnet/spec/tailscale-openapi.yaml`.
- `DESIGN`: `DESIGN.md` in this repo.
