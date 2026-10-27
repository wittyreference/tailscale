# MC's tailnet: what the records say

Compiled 2026-10-26 from MC's own records in `/home/user/tailnet-ssh` and `/home/user/elmer`,
then checked against Tailscale's first-party docs and the OpenAPI spec.

**Staleness.** Everything below was recorded between 2026-08-23 and 2026-10-10. The latest
commit in either repo is 2026-10-10: tailnet-ssh `2cab922`, elmer `c6d9404`. So every fact here
is **at least 16 days old**. Treat each one as a claim about the past. Re-check it against live
state (`tailscale status --json`, or the API with `devices:core:read`) before acting on it. The
date on each fact is when it was recorded, not when it was last true.

**Tags used in this file.** `[measured]` means the record says it was observed on the real
host. `[MC]` means MC decided or reported it. `[record]` means the file says it with no stated
evidence. `[derived]` is my inference and is marked so it can be checked. `[unverified]` means
no record or doc settles it.

The local tailnet-ssh clone is shallow: one commit, `2cab922`, dated 2026-10-10. Its history
cannot date individual lines, so dates come from the text itself.

---

## 1. The tailnet

| Fact | Value | Source |
|---|---|---|
| Tailnet DNS name | `taild02cf8.ts.net` | elmer `HANDOFF.md:143`, `DESIGN_DECISIONS.md:336`, `.claude/learnings.md:611,965` (2026-09-02 → 09-25) |
| Name format | The default `tail<ID>.ts.net` form, not a randomised "fun" name `[derived]` | https://tailscale.com/docs/concepts/tailnet-name (Last validated Jan 5, 2026) |
| Tailnet ID (for API paths) | **Not recorded** `[unverified]`. The DNS name is not the tailnet ID. Use `-` (the token's default tailnet). | OpenAPI `components.parameters.tailnet` |
| MagicDNS | On. Serve URLs and `spectre.taild02cf8.ts.net:2222` resolve. | `learnings.md:611`; `DESIGN_DECISIONS.md:336` |
| HTTPS Certificates | **Enabled for the tailnet, 2026-09-02**, along with Serve. Who clicked it is not recorded. | `DESIGN_DECISIONS.md:336` |
| Consequence of HTTPS | Machine names that get a cert (at least `spec5`) are published in the public Certificate Transparency ledger | https://tailscale.com/docs/how-to/set-up-https-certificates (Last validated Dec 10, 2025) |
| Account / identity provider / owner email | **Not recorded anywhere** `[unverified]` | — |
| Address ranges the hosts' own firewalls trust | `100.64.0.0/10` and `fd7a:115c:a1e0::/48`. Both match the docs. | tailnet-ssh `albini/pf.anchors/tailnet-ssh:15-16`, `raptop/p05c_ssh_mesh_layout.ps1:131`; https://tailscale.com/docs/reference/reserved-ip-addresses (Last validated Jan 12, 2026) |

---

## 2. Hosts

These are tailnet nodes as recorded. **SSH user** is the account a plain `ssh <alias>` lands
as. On several hosts that differs from the user in the key comment (tailnet-ssh
`docs/FINDINGS.md` §12 and §17). **Owner** is MC for every host. The records never name the
tailnet user that owns each node.

| Host | Role | OS / arch | Tailnet IPv4 / IPv6 | SSH user | Tailscale SSH | Tags | Recorded | Source |
|---|---|---|---|---|---|---|---|---|
| **albini** | Hub. MacBook Pro M4 Max, travelling laptop. Holds the admin keys for the Windows hosts. | macOS 27, arm64 | `100.126.116.15` / `fd7a:115c:a1e0::7c33:740f` | `michael` | **Off.** It cannot run: the GUI build (standalone `macsys`) has no Tailscale SSH server. Key-based Remote Login is used instead. | not recorded | 2026-10-01 → 10-09 `[measured]` | tailnet-ssh `README.md:42-50`, `fleet/fleet.yaml:47-63`, `docs/FINDINGS.md:113-128` |
| **claude-factory** | MC's DigitalOcean dev droplet | Linux, x86_64 | **not recorded** `[unverified]` | `mc` | not recorded | Recorded only as "(tagged-devices)". **The tag name `tag:dev` is not in any of MC's records** `[unverified]`. | 2026-10-06 → 10-09 | `fleet/fleet.yaml:65-73`; `TODO.md:124-126`; `docs/STATUS.md:39-43` |
| **pi5** | MC's daily driver. Raspberry Pi 5 16 GB, the ex-`kraken` board. | Debian 12 Bookworm, aarch64 | `100.126.132.9` / `fd7a:115c:a1e0::5b33:840b` | `mc` | **Off.** Prefs show `RunSSH: false`, as of the 2026-09-27 backup. | **None.** `AdvertiseTags: null` (2026-09-27), so the node is user-owned `[derived]`. | 2026-09-27 → 10-10 `[measured]` | elmer `.claude/references/hardware/onboarding-ledger.md:55`; `analysis/host-migration-2026-09/kraken-config/MANIFEST.txt:3,63-77`; tailnet-ssh `raptop/p05c_ssh_mesh_layout.ps1:31` |
| **spec5** | The OG Nomad (Pi 4, green case). Runs the Elmer console. | Debian 12, arm64 | `100.90.68.20` / not recorded | `spec5` | **On, in check mode.** MC keeps it on (2026-09-28). | not recorded | 2026-09-20 → 10-10 | `onboarding-ledger.md:53`; `analysis/sessions/2026-09-28-host-migration-pi5.md:55-57`; `analysis/sessions/2026-10-10-updates-arrivals.md:13`; `fleet/fleet.yaml:85-93` |
| **nomad-b** | The second Nomad (Pi 4, blue-grey case). OS hostname `spec5b`. | Linux, aarch64 | `100.108.20.20` / not recorded | `spec5` | **Off.** `tailscale set --ssh=false` (2026-09-09); the ledger says "Keep `--ssh=false`". | not recorded | 2026-09-09 → 10-10 | `todo.md:559-562`; `onboarding-ledger.md:56`; `fleet/fleet.yaml:134-142` |
| **pi3** | Raspberry Pi 3B. Second machine, not part of the Elmer runtime. | Debian 13 Trixie, aarch64 | `100.79.56.86` / not recorded | `mc` | not recorded `[unverified]`. Key SSH works via the `pi3` alias. | not recorded | 2026-09-20 → 10-09 | `onboarding-ledger.md:57`; `analysis/sessions/2026-09-30-pi3-card-swap.md:17`; `albini/ssh/config-block:33-35` |
| **raptop** | ASUS ROG laptop | Windows 11 Pro, x86_64 | `100.100.253.41` / `fd7a:115c:a1e0::f833:fd2a` | `mesh` (standard user). Admin is `micha`, reachable from albini only, via the `raptop-admin` alias. | n/a. sshd is inbox OpenSSH 9.5p2. | not recorded | 2026-10-03 → 10-07 | `raptop/README.md:1-17`; `albini/ssh/config-block:5-10`; `fleet/fleet.yaml:104-112` |
| **cybrpwrpc** | Windows desktop, always on | Windows 11 Pro, x86_64 | `100.108.249.110` / `fd7a:115c:a1e0::9233:f96f` | `mesh`. Admin is `michael`, from albini only, via `cybrpwrpc-admin`. See contradiction C3. | n/a. sshd is the OpenSSH 10.0p2 MSI. | not recorded | 2026-10-03 → 10-08 | `cybrpwrpc/README.md:1-17`; `TODO.md:92-93`; `fleet/fleet.yaml:114-122` |
| **surface** | Windows laptop. Its sshd routes into WSL2. | Windows + WSL2, x86_64 | `100.121.141.69` / `fd7a:115c:a1e0::233:8d47` | Alias user `micha`. Sessions land as Linux user `surface`. | n/a | not recorded | 2026-10-02 → 10-09 | `albini/ssh/config-block:11-13`; `fleet/fleet.yaml:95-102`; `docs/FINDINGS.md:196` |
| **server-factory-immich** | Immich photo server (server-factory Ansible role `08_immich`). Claude is not expected to run here. | Linux | `100.127.97.75` | `deploy` | not recorded | not recorded | 2026-10-07 `[MC]` approved its use | `fleet/fleet.yaml:144-156` |
| **spectre** | Android 12 phone (SOYES XS19Pro). Renamed from `a25`. | Android | `100.116.32.124` | `u0_a144`, over SimpleSSHD on **port 2222** (not Tailscale SSH) | n/a. The Android app has no Tailscale CLI. | not recorded | 2026-09-09 → 09-25 `[measured]` | elmer `.claude/references/hardware/spectre-pro.md:279-302`; `onboarding-ledger.md:59` |
| **iphone192** | iPhone 18 Pro, MC's current phone (identified by MC 2026-10-09). Runs Termius. | iOS | `100.92.107.24` / `fd7a:115c:a1e0::a533:6b19` | client only | n/a | not recorded | 2026-10-09 | `fleet/fleet.yaml:162-165`; `TODO.md:140-146`; `docs/STATUS.md:47` |
| **iphone182** | iPhone, the previous phone. Removed from the port-22 policy. | iOS | not recorded | client only | n/a | not recorded | 2026-10-09 | `fleet/fleet.yaml:157-160`; `docs/STATUS.md:57` |

**Nodes that are not on the tailnet, or not yet:**

- **elmer.** Named by MC on 2026-08-23. fleet.yaml says it "has never appeared on the tailnet".
  The record is stale; see C2. Sources: `fleet/fleet.yaml:172-174`, `TODO.md:166`.
- **seedbox.** A public host at `62.212.89.185`, reached over the internet and outside the
  tailnet. Source: `fleet/fleet.yaml:176-178`.
- **kraken.** A future Pi 4B. It will join as a **new node with a new 100.x**, because
  `100.126.132.9` belongs to the Pi 5's node key. Sources: `MANIFEST.txt:34-36`,
  `todo.md:255`.
- **GL.iNet AXT1800 travel router.** Its built-in Tailscale was **disabled 2026-10-02**. It had
  been enabled, logged out, and listening on 41641. Source: elmer
  `.claude/references/hardware/gl-inet-firmware.md:139`.
- **M5Stack Atom.** It cannot run Tailscale, so its server lives on pi5's home LAN.
  Sources: `analysis/sessions/2026-10-05-m5stack-atoms-pi5-tools.md:73-74`,
  `m5stack-atoms3r.md:166`.

**Per-host Tailscale client facts:**

- **albini.**
  - Standalone `macsys` build, system extension `io.tailscale.ipn.macsys.network-extension`
    (`README.md:50`).
  - `TailscaleStartOnLogin = 1`, set 2026-10-07 and verified by a real reboot 2026-10-09
    (`docs/STATUS.md:95-109`).
  - Daemon 1.104.1 vs Homebrew CLI 1.96.4 on 2026-10-09 (`docs/STATUS.md:122-125`).
  - A root LaunchDaemon, `tailnet-route-keeper`, calls `/opt/homebrew/bin/tailscale` every 10 s
    (`docs/FINDINGS.md:110-111`; `TODO.md:168-170`).
  - FileVault means albini cannot rejoin the tailnet after a reboot until someone types the
    password (`docs/STATUS.md:117-120`).
- **raptop.** "Unattended (`ForceDaemon: true`); came back up by itself after the 10-07
  reboot", per raptop-goofin, 2026-10-07 (`raptop/README.md:17`).
- **pi5.**
  - Tailscale 1.104.1 after a full-upgrade, 2026-10-10
    (`analysis/sessions/2026-10-10-updates-arrivals.md:21`).
  - Prefs as of 2026-09-27: `CorpDNS: true`, `RouteAll: false`, `ExitNodeID: ""`,
    `ShieldsUp: false`, `AutoUpdate {Check: true, Apply: true}` (`MANIFEST.txt:63-77`).
  - The `Hostname` pref is pinned in tailscaled state, not read from `/etc/hostname`
    (`MANIFEST.txt:34`).
- **nomad-b.** Tailscale 1.102.3, 2026-09-09 (`todo.md:560`).
- **spectre.**
  - Tailscale from Play, version 1.98.8. MC is holding it there; see policy decision P5.
  - Android **Always-on VPN** set for Tailscale, proven by a hands-off reboot 2026-09-25
    (`spectre-pro.md:296-300`).
  - Battery optimisation exempted: `dumpsys deviceidle whitelist +com.tailscale.ipn`
    (`todo.md:568-569`).
- **cybrpwrpc and raptop.** `tailscale status` run as `mesh` returned 401 or "already in use
  by" (tailscaled is owned by the desktop user), 2026-10-09 (`TODO.md:167`;
  `fleet/lib/checks.ps1:27`).

**Public-key fingerprints on record** (fingerprints only, safe to keep):

| Key | Fingerprint | Source |
|---|---|---|
| albini `id_ed25519` | `SHA256:ioTzrVuBijyhLrV9xjG3PkCLRWt+DZZQ73n+3oMx5W4` | `TODO.md:40` |
| surface (`micha@surface`) | `SHA256:Y9BY+HusTUgISrnqJ69BuF9tCvOQmlWs7o5XCfHHYsY` | `docs/FINDINGS.md:401` |
| Termius `mc-termius` | `SHA256:bwy2/PEb…` (recorded truncated) | `TODO.md:135`; `docs/STATUS.md:39` |

The `cyFp+qNe…` key is a per-host key Termius generated on albini. It is not authorised
anywhere, and its origin was never identified (`TODO.md:153-154`).

### claude-factory, everything recorded

| Fact | Recorded | Source |
|---|---|---|
| DigitalOcean dev droplet, "(tagged-devices)", x86_64 Linux, SSH alias `claude-factory`, user `mc`, Linux firewall expected, `login_path` expected | 2026-10-06 | `fleet/fleet.yaml:65-73` |
| **Ownership confirmed by MC directly, patching and reboots included** | 2026-10-09 `[MC]` | `TODO.md:124-126`; `docs/STATUS.md:43` |
| Patched and rebooted: kernel 6.8.0-71 → 6.8.0-146, 66 upgradable → 0, reboot-required cleared, 0 failed units | 2026-10-09 `[measured]` | `TODO.md:125-126`; `docs/STATUS.md:42` |
| Kernel fixes had sat installed and inert for about four months before that | 2026-10-10 | elmer `.claude/learnings.md:7` |
| Its netmap shows iphone192 v4+v6 present, iphone182 absent, port-22 source count 46 | 2026-10-09 `[measured]` | `docs/STATUS.md:57` |
| It accepted `mc-termius` from `100.92.107.24` (iphone192) | 2026-10-09 15:56:19Z `[measured]` | `docs/STATUS.md:28,54`; `TODO.md:173-174` |
| The dead `@mc-iphone-terminus` key was removed from it. A backup file exists. | 2026-10-09 | `docs/STATUS.md:56` |
| It hosts a `dotfiles` repo with a Termius skill at `dotfiles/claude/skills/termius.md` (247 lines). **The local `/home/user/dotfiles` checkout (2026-09-25, `eba5d68`) does not contain it.** | 2026-10-09 | `docs/STATUS.md:46`; `TODO.md:139` |
| Tailnet IPv4, tag name, Tailscale SSH state, key expiry | **Not recorded** `[unverified]` | — |

---

## 3. Tags in use

**No `tag:` string appears in any of MC's records.** I grepped both repos in full for
`tag:[a-z]`; every hit was this session's own command log. The only tag-related records are:

- claude-factory's role text, "(tagged-devices)" (`fleet/fleet.yaml:66`). It names neither
  the tag nor whether "tagged-devices" is a tag at all.
- pi5's prefs show `AdvertiseTags: null` as of 2026-09-27 (`MANIFEST.txt:71`).

`tag:dev` on claude-factory comes from this task's context, not from MC's files
`[unverified]`. Confirm it with `GET /tailnet/-/devices` (each device's `tags`) or with the
policy file's `tagOwners` (`policy_file:read`).

The docs facts that matter for MC's hosts are below. They come from
https://tailscale.com/docs/features/tags (Last validated Dec 4, 2025) and
https://tailscale.com/docs/features/tailscale-ssh (Last validated Jan 5, 2026).

- **Tagging a user device changes who owns it.** The tags page says: "Applying a tag to a
  device previously authenticated with a user account removes the user account" (tags
  `:72`). It also says you "cannot remove all tags from a device" (tags `:33`).
- **Tailscale SSH is narrow about tagged devices.** Only these connections are allowed: user →
  own device; user → tagged device; user → shared tagged device; tagged → tagged. "An SSH
  access rule from a tagged device cannot be in check mode" (tailscale-ssh `:213-218`).
  - So if claude-factory is tagged and spec5 is user-owned, claude-factory **cannot** reach
    spec5 over Tailscale SSH `[derived]`.
  - spec5's Tailscale SSH claims port 22 on its tailnet IP (tailscale-ssh `:40,410`). That is
    consistent with pi5 reaching spec5 "over the bench wire and WiFi" instead
    (`2026-09-28-host-migration-pi5.md:56-57`).

---

## 4. Recorded policy decisions

| # | Date | Decision | Who | Source |
|---|---|---|---|---|
| P1 | 2026-09-01 | Reach the Elmer console through **`tailscale serve`** on a loopback bind. Use `serve`, never `funnel`. MC's words: "locked to Tailscale, open to the tailnet". | MC | elmer `DESIGN_DECISIONS.md:335`; `scripts/expose-console-tailscale.sh:9` |
| P2 | 2026-09-02 | **Serve + HTTPS Certificates enabled for the tailnet.** `sudo tailscale set --operator=spec5` on spec5. Console live at `https://spec5.taild02cf8.ts.net`, tailnet-only. The record does not say who enabled the tailnet settings. | session (deploy) | `DESIGN_DECISIONS.md:336` |
| P3 | 2026-09-02 | Over Serve, "the tailnet is the auth boundary". MC does not want per-user auth on a single-person tailnet. | MC | `DESIGN_DECISIONS.md:318`; `todo.md:923` |
| P4 | 2026-09-09 | **Admin-console rename `a25` → `spectre`** | MC | `todo.md:564-565`; `.claude/learnings.md:609-612` |
| P5 | 2026-09-09 | Leave spectre's "out-of-date client" banner. Sideloading the newer APK would force a re-login and re-register the node, undoing the rename. | MC | `.claude/learnings.md:595-601`; `todo.md:569-571` |
| P6 | 2026-09-09 | Turn **Tailscale SSH off on nomad-b** (`tailscale set --ssh=false`) so plain key SSH works over the tailnet. Restated 2026-09-25 as "Keep `--ssh=false`". | session; ledger | `todo.md:561-562`; `onboarding-ledger.md:56` |
| P7 | 2026-09-20 → 09-28 | The open question was whether to accept check mode on the hop to spec5 or drop `checkMode` for that host. **Outcome: Tailscale SSH on spec5 stays on.** MC: "never take anything off the tailnet, and the phone may rely on it." Check mode was still in effect on 2026-10-10. | MC | `analysis/workbench-ergonomics/2026-09-20-workbench-ergonomics-report.md:341,531`; `analysis/sessions/2026-09-28-host-migration-pi5.md:55-57`; `analysis/host-migration-2026-09/hub-move-plan.md:50-51`; `2026-10-10-updates-arrivals.md:13` |
| P8 | 2026-09-28 | Tailnet rename **`kraken` → `pi5`** with `sudo tailscale set --hostname=pi5`. Same node key and 100.x. The admin console showed no manual override. | MC (decided 09-27) | `analysis/host-migration-2026-09/runbook.md:26,85-87,190-193`; `onboarding-ledger.md:55` |
| P9 | standing | **Never take a lab host off the tailnet.** It is a memory rule, and MC said it again on 2026-09-28. | MC | `gl-inet-axt1800.md:152`; `2026-09-28-host-migration-pi5.md:55` |
| P10 | 2026-10-02 | **Disable the router's built-in Tailscale.** GL.iNet advises against it alongside a VPN client. | session, backup first | `gl-inet-firmware.md:139`; `travel-vpn.md:141-147` |
| P11 | 2026-10-03 | **Key-only SSH mesh** between pi5, albini, raptop, surface and cybrpwrpc. Every inbound key is `from=`-pinned to the source's tailnet v4 + v6. Each Windows box gets a non-admin `mesh` account; admin SSH comes only from albini. | MC approved | `analysis/sessions/2026-10-03-machines-mesh-proxmark-icopy.md:29-36`; tailnet-ssh `docs/FINDINGS.md:298-317` |
| P12 | 2026-10-03 | Host firewalls admit port 22 only from the tailnet ranges. On Windows, Block rules override tailscaled's allow-everything `Tailscale-In` rules. | MC approved per-change | `cybrpwrpc/README.md:17,36`; `raptop/README.md:16` |
| P13 | unknown date | **MESH-15** policy draft `tailnet-policy-draft.hujson` was **superseded**. It was deliberately not committed. | — | `raptop/README.md:32` |
| P14 | ~2026-10-09 | **MC's one-line console edit to the tailnet policy:** iphone192 replaced iphone182 for port 22. Verified on the claude-factory and pi5 netmaps: iphone192 v4+v6 present, iphone182 absent, port-22 source count unchanged at 46. | MC (console) | `docs/STATUS.md:57` |
| P15 | 2026-10-09 | **MESH-39** was already applied. In albini's `tailscale debug netmap`, rule 3 admits `100.92.107.24/32` and rule 4 admits `fd7a:115c:a1e0::a533:6b19/128`, both port 22. Rule 3 has **9** sources. An earlier "outstanding" claim came from a truncated read. | verified by session | `TODO.md:140-143`; `docs/STATUS.md:47,127-136` |
| P16 | 2026-10-09 | MESH-16: the `mc-termius` key is pinned to albini + iphone192, with forwarding disabled. The phone connects **directly** to each Pi, never by ProxyJump. | MC request via pi5 | `analysis/sessions/2026-10-10-updates-arrivals.md:9-14`; `albini/ssh/config-block:26-41` |
| P17 | open (2026-10-09) | Turning on "Run unattended" for raptop and cybrpwrpc is "a security change, MC's call". | pending MC | `TODO.md:167` |
| P18 | standing (2026-10-06) | Fleet audit: drift in `login_path`, `time_machine` and `backblaze` is auto-fixed. **Everything else becomes a written proposal, never an action.** For Tailscale SSH check mode, the proposal is to re-authenticate interactively or "make an additive ACL change only". | audit design | `fleet/fleet.yaml:15-20`; `fleet/audit.sh:252` |
| P19 | 2026-10-09 | The M5Stack voice server listens on pi5's home-WiFi address only, **not the tailnet** | MC (LAB-68) | `m5stack-atoms3r.md:166` |

Two notes on P15. The netmap "rule 3 / rule 4" numbers are packet-filter entries from
`tailscale debug netmap`. They are not rule indices in the HuJSON policy `[derived]`. And
`tailscale debug` is absent from the CLI reference
(https://tailscale.com/docs/reference/tailscale-cli, Last validated Jul 30, 2026), so it is an
undocumented surface. With `policy_file:read` the CLI can read the policy itself instead.

---

## 5. Gotchas learned the hard way

### Tailscale SSH

- **Check mode blocks unattended logins.** A BatchMode hop stalls on a `login.tailscale.com`
  link, so spec5 cannot be reached unattended over the tailnet.
  - Sources: `workbench-ergonomics-report.md:341` (2026-09-20); `2026-09-28-host-migration-pi5.md:56`;
    `fleet/fleet.yaml:86`.
  - Docs: check mode needs a browser re-authentication, default period 12 h, configurable from
    1 minute to 168 h (tailscale-ssh `:178-183,473-481`).
- **`tailscale up --ssh` takes over port 22 on the tailnet IP.** On nomad-b it had to be undone
  with `set --ssh=false` before key SSH would work (`todo.md:561`, 2026-09-09). The docs agree:
  Tailscale SSH "claims port 22 for the Tailscale IP address" (tailscale-ssh `:40,410`).
- **The macOS GUI builds cannot run a Tailscale SSH server.** That covers both the App Store and
  standalone `macsys` builds. Don't swap in the open-source `tailscaled` to get it: the
  Homebrew copy is behind and would contend for the tunnel (`docs/FINDINGS.md:113-128`).
  The docs agree: macOS Tailscale SSH "Requires use of open source `tailscaled` variant"
  (tailscale-ssh `:49`).
- **One-time check URLs are login links.** Redact them from committed reports
  (`fleet/audit.sh:246-247`, 2026-10-09).

### Serve and HTTPS (all found on spec5, 2026-09-02)

- **`tailscale serve` hangs instead of failing when Serve is not enabled.** It prints "Serve is
  not enabled… visit <url>" and waits, so wrap it in `timeout` (`.claude/learnings.md:943-946`;
  `scripts/expose-console-tailscale.sh:41-45`). The docs say only that it "presents a login
  server URL"; the hang is observed behaviour, not documented (tailscale-serve, Last validated
  Jan 20, 2026, `:29-39`).
- **`tailscale serve` needs root or a designated operator.** The error is "Access denied: serve
  config denied". Fix once with `sudo tailscale set --operator=$USER` (`learnings.md:947-950`).
  The docs don't mention operator for Serve `[unverified]`. The CLI reference documents
  `--operator` (tailscale-cli `set`).
- **`tailscale status --json` prints `"DNSName": "…"` with a space after the colon.** Parse it as
  JSON. Take the served URL from `tailscale serve status`. A raw-IP URL throws a cert warning,
  because certs are issued for the MagicDNS name (`learnings.md:951-955`).
- **Serve combined with uvicorn's `proxy_headers=True` rewrote the client to the tailnet peer.**
  Serve sets `X-Forwarded-For`, so loopback-trust auth refused every tailnet write. The fix is
  `proxy_headers=False` (`learnings.md:893-899`).
- **`serve --bg` persists across reboots.** The record says it is stored in tailscaled state
  (`expose-console-tailscale.sh:40`). Not checked against the docs `[unverified]`.
- **Stubs hid all three bugs.** The stubbed `tailscale` returned instantly, used compact JSON and
  modelled no permissions (`learnings.md:956-962`).

### Names, renames and identity

- **A rename keeps the node key and 100.x; a re-auth does not** (`runbook.md:26`).
- **The `Hostname` pref is pinned in tailscaled state**, not taken from `/etc/hostname`
  (`MANIFEST.txt:34`). `tailscale set --hostname` changes it.
- **A manually set console name overrides the advertised hostname.** After the `a25` →
  `spectre` rename, the advertised hostname did not override it (`learnings.md:611-612`;
  `runbook.md:85-87`). The docs agree: unchecking "Auto-generate from OS hostname" stops
  automatic renames (https://tailscale.com/docs/concepts/machine-names, Last validated Jan 5,
  2026).
- **MagicDNS kept the old name until the rename landed.** The preflight refused with
  "Permission denied" because MagicDNS still called the Pi 5 `kraken` (`runbook.md:186-189`,
  2026-09-28).
- **Renaming breaks names that depend on it.** The docs say a device-name change breaks existing
  MagicDNS URLs (OpenAPI `setDeviceName`). Renaming `spec5` would break
  `https://spec5.taild02cf8.ts.net` `[derived]`.
- **A cloned SD card carries the same Tailscale node key.** Never boot the clone beside the
  original (`todo.md:134-136`; `2026-09-30-pi3-card-swap.md:18`, 2026-09-30). nomad-b's
  machine-id is identical to spec5's (cloned image), so identify a Nomad by SoC serial
  (`onboarding-ledger.md:56`).
- **Sideloading Tailscale on Android re-registers the node as a new machine.** The signing key
  differs from Play's, which forces an uninstall and re-login, and the new node loses any
  console rename (`learnings.md:595-601`, 2026-09-09).
- **Renaming a phone node.** The record says it is "admin-console-only" and that "device rename
  is not in the Tailscale API". **This is contradicted** by the current API; see C1
  (`learnings.md:609-612`).

### Health and status

- **`tailscale health` is not a subcommand in 1.102.3.** Read `Health` from
  `tailscale status --json` instead; `[]` means clean (`learnings.md:606-607`). The CLI
  reference, Last validated Jul 30, 2026, lists no `health` command either.
- **The two health warnings live in different places.** "Out-of-date client" is tailnet-wide in
  the admin console. "Tailscale may stop working in the background" is the Android app's own
  battery warning (`learnings.md:603-606`).
- **A stopped backend still reports a stale peer list.** Gate on `BackendState == "Running"`,
  `Self.Online` and a non-empty peer list before concluding anything about peers
  (`fleet/audit.sh:63`; `fleet/lib/tailnet_health.jq:3-6`).
- **On the macsys build, the missing `/var/run/tailscaled.socket` is a red herring.** It is
  absent even while Tailscale runs. The real "down" signal is `tailscale ip -4` failing
  (`docs/STATUS.md:111-115`, 2026-10-09; it corrects `FINDINGS.md:357`).
- **A listing whose length equals your print limit is truncated.** MESH-39 was misreported from
  `srcs[:8]` when rule 3 held 9 entries (`docs/STATUS.md:127-136`; tailnet-ssh `CLAUDE.md:53-56`).

### Boot and unattended operation

- **albini left the mesh on every reboot** while `TailscaleStartOnLogin = 0`. pf blocked
  everything except the tailnet, and there was no tailnet, so albini was "reachable by
  nothing" (`docs/FINDINGS.md:348-371`, 2026-10-06). Fixed 2026-10-07; verified by a reboot
  2026-10-09 (`docs/STATUS.md:95-109`).
- **macsys registers via SMAppService**, so it is absent from the System Events login-item list,
  and that absence proves nothing (`TODO.md:26-28`).
- **Android did not reconnect at boot until Always-on VPN was set** (`spectre-pro.md:296-300`,
  2026-09-25).
- **Windows: a non-desktop account cannot use the CLI.** tailscaled is owned by the desktop
  user, so `tailscale status` as `mesh` returns 401 or "already in use by"
  (`fleet/lib/checks.ps1:27`; `TODO.md:167`, 2026-10-09).
- **Windows: tailscaled re-creates its allow-everything `Tailscale-In` firewall rules on every
  start.** Edits don't stick; use Block rules (`cybrpwrpc/README.md:36`, 2026-10-03/04).
- **WSL's `tailscale.exe` eats stdin.** Run it with `</dev/null` inside piped scripts
  (`fleet/lib/checks.sh:38`).
- **Homebrew's `tailscale` lags the GUI daemon.** Prefer
  `/Applications/Tailscale.app/Contents/MacOS/Tailscale` (`fleet/lib/checks.sh:26-33`).
  Homebrew binaries are also off the SSH `PATH` on albini (`docs/FINDINGS.md:100-111`).
- **Raspberry Pi OS: run `full-upgrade` detached** (`systemd-run`) over the bench wire when
  Tailscale is in the batch (`learnings.md:12`, 2026-10-10).

### Paths and pins

- **A fingerprint validates the key, never its `from=` pin.** Verify every pin address against
  `tailscale status --json` on the installing host. Exercise each pin after installing it
  (`docs/FINDINGS.md:191-211`).
- **A jump host breaks pinned phone keys.** `no-port-forwarding` blocks the ProxyJump channel,
  and the far host sees the jump host's address (`learnings.md:17-19`, 2026-10-10).
- **Tailscale's direct path can ride a LAN link.** spec5 → pi5 ran over the bench wire, so a
  live LAN-address change could cut the session making it (`runbook.md:190-192`, 2026-09-28).
- **The tailnet address does not change with the network.** If SSH broke after a network
  change, the cause is Tailscale connectivity (`docs/TROUBLESHOOTING.md:37-40`).
- **Tailscale on client devices survives the travel router's Nord tunnel.** albini stayed
  reachable from pi5 via DERP, with no direct path (`travel-vpn.md:173-174`, 2026-10-02).
- **One uvicorn socket cannot bind both loopback and the tailnet IP.** That limit decided Serve
  over a direct bind (`learnings.md:934-942`; `DESIGN_DECISIONS.md:316`).

---

## 6. Contradictions and stale records

- **C1. Device rename via the API.**
  - elmer `.claude/learnings.md:609-610` (2026-09-09): "device rename is not in the Tailscale
    API — the console UI … is the only path."
  - The current OpenAPI spec has **`POST /device/{deviceId}/name`** (`setDeviceName`, OAuth
    scope `devices:core`).
  - The machine-names doc (Jan 5, 2026) mentions only the console and the CLI.
  - The learning is stale, or was wrong when written. Whether the endpoint existed on
    2026-09-09 is `[unverified]`.
- **C2. elmer's tailnet status.** `fleet/fleet.yaml:172-174` says elmer "has never appeared on
  the tailnet and its identity is unknown". `TODO.md:166` (2026-10-09) calls that note stale:
  `elmer goofin` sessions exist, and MESH-23 names elmer as the pi-provision target.
- **C3. cybrpwrpc's SSH user.** The committed `albini/ssh/config-block:14-16` has
  `Host cybrpwrpc … User michael` and no `cybrpwrpc-admin`. But `TODO.md:92-93` (2026-10-08)
  and `fleet/fleet.yaml:119` say `ssh cybrpwrpc` lands as `cybrpwrpc\mesh`, with admin via
  `cybrpwrpc-admin`. The FINDINGS §12 table (`docs/FINDINGS.md:167-172`) predates the split.
  The committed config block is probably stale `[derived]`.
- **C4. raptop key-only.** `raptop/README.md:13` (posture per raptop-goofin, 2026-10-07) says
  "Key-only". `TODO.md:103` (file dated "as of 2026-10-03") still has "raptop: key-only step is
  staged, waiting on a UAC approval" open.
- **C5. Would "Run unattended" fix the `mesh` 401?**
  - `raptop/README.md:17` (2026-10-07) says raptop is already unattended (`ForceDaemon: true`).
  - `TODO.md:167` (2026-10-09) lists raptop's `mesh` 401 and says "'Run unattended' would fix
    it".
  - The docs say: "When unattended mode is enabled, the Windows account that activated it owns
    the Tailscale configuration on that device"
    (https://tailscale.com/docs/how-to/run-unattended, Last validated Sep 25, 2026, `:63`).
  - So unattended mode does not obviously give `mesh` CLI access `[unverified]`.
- **C6. The "Hosts covered" row in tailnet-ssh `CLAUDE.md:14`.** It lists "raptop and surface
  (Windows, `micha`)". The current alias is `raptop` → `mesh` (`albini/ssh/config-block:7`;
  `fleet/fleet.yaml:109`). Sessions into surface land as Linux user `surface`
  (`fleet/fleet.yaml:100`).
- **C7. Version skew in older text.** `docs/FINDINGS.md:125-126` (≤ 2026-10-01) and
  `TODO.md:111-114` say daemon 1.102.4 vs Homebrew 1.96.4. `docs/STATUS.md:122-125`
  (2026-10-09) says the daemon is now 1.104.1.
- **C8. The socket as a "down" signal.** `docs/FINDINGS.md:357` and `TODO.md:29-31` cite the
  missing `tailscaled.socket` as evidence Tailscale was down. `docs/STATUS.md:111-115`
  (2026-10-09) withdraws that.
- **C9. How the hub reaches pi3 and nomad-b.** `fleet/fleet.yaml:125,135` say "reached via
  ProxyJump pi5". The phone aliases (`albini/ssh/config-block:30-41`) and HANDOFF
  (`HANDOFF.md:147`, "`ssh pi3` (Tailscale)") reach them directly over the tailnet. That is not
  necessarily a conflict, but whether albini reaches them directly is unrecorded.
- **C10. A docs-internal tension on check mode.** tailscale-ssh `:258-268` shows the
  default-policy SSH rule using `"action": "check"`. The same page at `:483` says "Check mode
  is optional and not enabled by default." spec5's check mode may come from that default rule
  rather than a deliberate edit `[unverified]`.

---

## 7. Credentials seen (locations only, no values)

No Tailscale auth key, API key or OAuth client secret is in either repo. I grepped for
`tskey-`, `TS_AUTHKEY`, `TS_API_KEY`, `TS_OAUTH` and `client_secret`; nothing matched.

Other credentials the records point to:

- **albini, Claude token.** `~/.claude/headless-token` holds a Claude OAuth token. It is
  gitignored (tailnet-ssh `README.md:73-76`).
- **raptop, Claude token.** `raptop/p05d_mesh_claude_token.ps1` prompts for a Claude
  setup-token and stores it for the `mesh` account. The script contains no token
  (`raptop/README.md:26`).
- **albini, SSH key.** A private key at `~/.ssh/server-factory_ed25519`, used for
  server-factory-immich (`fleet/fleet.yaml:150`).
- **spec5, SSH key.** A private key at `~/.ssh/claude-factory_ed25519`. Its public half is
  installed on spectre (`spectre-pro.md:284`).
- **pi5, API key.** `pi5:~/.config/lab/anthropic.env` holds an Anthropic API key, mode 600
  (`m5stack-atoms3r.md:165`).
- **spec5, switch login.** `~/.config/lab/ms305e.env` holds the MS305E web login
  (`onboarding-ledger.md:58`).

---

## Sources

**MC's records.** Line numbers are as read on 2026-10-26.

- tailnet-ssh `2cab922` (2026-10-10; shallow clone):
  - Top-level: `README.md`, `CLAUDE.md`, `TODO.md`.
  - `docs/`: `STATUS.md` ("Last updated 2026-10-09 16:05 PDT"), `FINDINGS.md`,
    `TROUBLESHOOTING.md`.
  - `fleet/`: `fleet.yaml`, `lib/tailnet_health.jq`, `lib/checks.sh`, `lib/checks.ps1`,
    `audit.sh`.
  - Host folders: `albini/ssh/config-block`, `albini/pf.anchors/tailnet-ssh`,
    `cybrpwrpc/README.md`, `raptop/README.md`, `raptop/p05b_ssh_stageA.ps1`,
    `raptop/p05b_ssh_stageB.ps1`, `raptop/p05c_ssh_mesh_layout.ps1`.
- elmer `c6d9404` (2026-10-10):
  - Top-level: `HANDOFF.md` (2026-09-25), `todo.md`, `DESIGN_DECISIONS.md` (D12),
    `.claude/learnings.md`, `scripts/expose-console-tailscale.sh` (last changed 2026-09-29).
  - `.claude/references/hardware/`: `onboarding-ledger.md`, `spectre-pro.md`, `travel-vpn.md`,
    `gl-inet-axt1800.md`, `gl-inet-firmware.md`, `m5stack-atoms3r.md`.
  - `analysis/sessions/`: `2026-09-28-host-migration-pi5.md`, `2026-09-30-pi3-card-swap.md`,
    `2026-10-02-pi5-voice-usb-router.md`, `2026-10-03-machines-mesh-proxmark-icopy.md`,
    `2026-10-05-m5stack-atoms-pi5-tools.md`, `2026-10-10-updates-arrivals.md`.
  - `analysis/host-migration-2026-09/`: `runbook.md`, `hub-move-plan.md`,
    `kraken-config/MANIFEST.txt`.
  - `analysis/workbench-ergonomics/2026-09-20-workbench-ergonomics-report.md`. This is outside
    the listed sources; it was found by a content grep.

**Tailscale first-party docs.** Fetched as `.md` with curl on 2026-10-26. Copies are in
`research/mc-tailnet-docs/`.

| Page | Last validated |
|---|---|
| https://tailscale.com/docs/concepts/machine-names | Jan 5, 2026 |
| https://tailscale.com/docs/concepts/tailnet-name | Jan 5, 2026 |
| https://tailscale.com/docs/concepts/macos-variants | Jan 5, 2026 |
| https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| https://tailscale.com/docs/features/magicdns | Jan 5, 2026 |
| https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| https://tailscale.com/docs/features/tailscale-serve | Jan 20, 2026 |
| https://tailscale.com/docs/how-to/set-up-https-certificates | Dec 10, 2025 |
| https://tailscale.com/docs/how-to/run-unattended | Sep 25, 2026 |
| https://tailscale.com/docs/concepts/tailscale-ip-addresses | Jan 12, 2026 |
| https://tailscale.com/docs/reference/reserved-ip-addresses | Jan 12, 2026 |
| https://tailscale.com/docs/reference/tailscale-cli | Jul 30, 2026 |

**OpenAPI spec.** `scratchpad/tsdocs/openapi.json` (YAML, "Tailscale API" v2). Operations used:

| Operation | Path | Scope |
|---|---|---|
| `setDeviceName` | `POST /device/{deviceId}/name` | `devices:core` |
| `setDeviceIp` | `POST /device/{deviceId}/ip` | `devices:core` |
| `setDeviceTags` | `POST /device/{deviceId}/tags` | `devices:core` |
| `deleteDevice` | `DELETE /device/{deviceId}` | `devices:core` |
| `expireDeviceKey` | `POST /device/{deviceId}/expire` | `devices:core` |
| `updateDeviceKey` | `POST /device/{deviceId}/key` | `devices:core` |
| `authorizeDevice` | `POST /device/{deviceId}/authorized` | `devices:core` |
| `listTailnetDevices` | `GET /tailnet/{tailnet}/devices` | `devices:core:read` |
| `getPolicyFile` | `GET /tailnet/{tailnet}/acl` | `policy_file:read` |

The `tailnet` path parameter is described under `components.parameters.tailnet`.
