# Diagnosing "can't reach a host on a port"

How `tailnet diagnose` works, how to read what it prints, and what each verdict proves. Facts about
MC's hosts are dated records: confirm them with `tailnet device list --json` before acting.

## Contents

1. [The command](#1-the-command)
2. [The ladder, step by step](#2-the-ladder-step-by-step)
3. [Reading the output](#3-reading-the-output)
4. [Verdicts and what each proves](#4-verdicts-and-what-each-proves)
5. [The on-host block](#5-the-on-host-block)
6. [Ping types](#6-ping-types)
7. [Per-host notes: spec5, nomad-b, pi5](#7-per-host-notes-spec5-nomad-b-pi5)
8. [What does not discriminate](#8-what-does-not-discriminate)
9. [`tailscale debug netmap`](#9-tailscale-debug-netmap)
10. [Unverified](#10-unverified)
11. [Sources](#11-sources)

Tags: **[unverified]**, **[inference]** and **[source-code]** (Tailscale's client at `de16943c`,
undocumented, liable to change). Keys resolve in [Sources](#11-sources).

## 1. The command

```
tailnet diagnose DEVICE... [--port N] [--ssh-user USER] [--from DEVICE]
```

- Read-only. `--port` defaults to 22 and must be 1-65535. Add `--json` when you will act on the
  result.
- Exit codes: **0** when every destination is `OPEN`, `ADMITTED_CHECK_MODE` or `ALLOWED`; **8** when
  any is blocked or inconclusive; **3** when a local precondition fails (for example
  `TAILSCALE_CLI_MISSING`); **4** when an API read fails (DESIGN §5.2, §5.3).
- **Self mode** (the default): the source is this host, the droplet. All three local probes run in
  production posture.
- **`--from DEVICE`**: the source is that device's identity, and only the API checks run. It
  answers "can MC's phone or albini reach spec5?" without touching either.
- `--ssh-user` matters only for a destination that runs Tailscale SSH. spec5's recorded SSH user is
  `spec5` (`tailnet-facts.md`).
- MC's live blocker, as DESIGN §26 step 5 runs it:
  `tailnet diagnose spec5 nomad-b pi5 --ssh-user spec5`, then
  `tailnet diagnose spec5 --from iphone192 --ssh-user spec5`.

## 2. The ladder, step by step

Destinations are always addressed by IPv4 100.x, because MagicDNS failed on the droplet
(2026-10-25T23:30:30Z; critic F3.6). Every step is a read.

0. **Source health** (self mode, production only). The local `tailscale status --json` must show
   `BackendState == "Running"` and `Self.Online` with Tailscale IPs. A stopped backend still reports
   a stale peer list (mc §5), so anything else makes every destination `SOURCE_DOWN`, and no API
   call is made. An empty `Peer` map is not a failure: the netmap holds only devices the policy lets
   this host reach or be reached by [visibility L37-42], so it raises the warning `NO_PEERS_VISIBLE`
   and the ladder goes on to the API (DESIGN A52).
1. **Inventory.** `GET /tailnet/-/devices?fields=all` resolves the source and each `DEVICE`, and
   records `nodeId`, IPv4, `tags`, `user`, `sshEnabled`, `connectedToControl`, `lastSeen`,
   `keyExpiryDisabled`, `expires`, `blocksIncomingConnections` and `clientVersion`. `sshEnabled`
   arrives only with `fields=all` (api §5.1); when absent it is unknown, never false.
2. **Source identities.** Each of the source's tags if it is tagged (a tagged identity is the union
   of its tags [TAGS L66]), otherwise its `user` email. Never a raw 100.x: the documented test
   `src` types are user, group, tag and host [spec L2533-2540; policy-file L879].
3. **Gates**, first match final: not found or ambiguous; `KEY_EXPIRED` (`expires` in the past and
   expiry not disabled); `DEST_OFFLINE` (`connectedToControl == false`, with `lastSeen` reported as
   given, because it is omitted while connected [spec L4548]); `SHIELDS_UP`
   (`blocksIncomingConnections`).
4. **Local probes** (self mode; 5 s each). TSMP ping, ICMP ping, and a real TCP connect to
   `<ipv4>:<port>` (section 6 explains the pings). In test posture the pings are recorded
   `not-run: test posture` and the TCP probe still runs against loopback. Beside the pings,
   `probes.in_netmap` records whether the local status lists the destination as a peer: TSMP can
   reach only a listed peer (DESIGN A52).
5. **Network policy.** For each source identity S, one `POST /tailnet/-/acl/validate` with the array
   `[{"src": S, "proto": "tcp", "accept": ["<dst-ipv4>:<port>"]}]`, run against the **live** policy
   [spec L2508-2512]. A Tailscale IP is a documented `accept` host [policy-file L907]. Allowed if any
   S passes; `want: Accept, got: Drop` is kept verbatim.
6. **Tailscale SSH layer**, only when `sshEnabled == true` and the port is 22. The network rule is
   necessary; the `ssh` section decides admission [policy-file L542-545].
   - No `--ssh-user` gives `TS_SSH_UNVERIFIED`, unless a self-mode probe timed out: then the
     verdict is `TS_SSH_TIMEOUT_UNEXPLAINED` (DESIGN A50).
   - Otherwise the CLI reads the live policy as JSON, copies it in memory, **deletes its `tests` and
     `sshTests`** so only the probe runs, adds a host alias `tailnet-diag-dst` for the destination
     (`sshTests.dst` takes aliases, not raw IPs [policy-file L963]), sets one `sshTests` entry with
     `accept: [<user>]`, and posts it to `/acl/validate` as a candidate policy. Validate never
     modifies the policy [spec L2518]. The candidate is never saved.
   - If no S passes with `accept`, it repeats with `check`. A pass only under `check` means
     admission needs a check-mode re-authentication.
7. **Verdict**, first match wins (section 4).
8. **On-host block.** For any host-side verdict the CLI prints a block for MC to run *on the
   destination* (section 5). The droplet cannot reach the host; that is the problem.

## 3. Reading the output

Per destination: `{dest, resolved, gates, probes, network_test[], ssh_test[], verdict,
explanation, next[]}`. Plus `source {mode, nodeId, hostname, identities, self_source}` and the API
calls made. Human output gives one verdict line per host, then the evidence, each with
`measured_at` (DESIGN §15.2).

| Field | Read it as |
|---|---|
| `gates` | Which gate stopped the ladder, if any. A gate verdict means no probe or policy result follows |
| `probes.tsmp` → `path_ok` | Connectivity only. TSMP stops before the policy check [manage L29] |
| `probes.icmp` → `icmp_ok` | True whenever *any* port is open between the pair. **Never port evidence** |
| `probes.tcp` | `open` (raw banner bytes follow), `refused` (an RST came from the host's stack), `timeout`, or `error:<errno>` |
| `network_test[]` | One per source identity; `want/got` per address, verbatim |
| `ssh_test[]` | The `accept` probe, then the `check` probe if the first failed |
| `next[]` | `who: agent` runs it; `who: mc` names what MC's hands are needed for (`needs: terminal`, `browser`, `console`); `who: ask_mc` is one question |

## 4. Verdicts and what each proves

| Verdict | Condition | Proves | Does not prove | Next |
|---|---|---|---|---|
| `SOURCE_DOWN` | Self mode; step 0 failed | The droplet is not on the tailnet right now: not Running, not online, or no Tailscale IPs | Anything about the destinations; an empty peer list alone never gives it (DESIGN A52) | `tailscale status` on the droplet |
| `NOT_FOUND` / `AMBIGUOUS` / `SAME_DEVICE` | Step 1 | The argument did not name exactly one other device | — | List the candidates; never pick one |
| `KEY_EXPIRED` | Gate | The destination's key has lapsed: it is off the tailnet (P9) | — | User-owned: MC re-authenticates at the host; then `tailnet device disable-key-expiry`. Tagged: a plain re-auth makes it user-owned and drops its tags [TAGS L72], so MC uses **Temporarily extend key** in the console and `disable-key-expiry` runs within its 30 minutes [key-expiry L49-54], or else MC runs `sudo tailscale up --advertise-tags=<its tags> --force-reauth`, which turns expiry off itself [TAGS L84, L297-300] (DESIGN A70) |
| `DEST_OFFLINE` | Gate | Not connected to control now | That the host is powered off | Report `lastSeen` as given |
| `SHIELDS_UP` | Gate | The device refuses all incoming tailnet connections | — | On the host: `tailscale get shields-up` |
| `PATH_DOWN` | Self mode; TSMP failed; the destination is in this host's netmap; the network test named no drop (DESIGN A52) | A connectivity fault, not policy [manage L41] | — | `tailscale netcheck`, `tailscale status`; the official skill's `connectivity.md` |
| `OPEN` | TCP `open`, and Tailscale SSH off or admitted with `accept` | The port is reachable through both policy and host | That `ssh` will log in: a wrong user and a missing key look alike (tailnet-ssh FINDINGS §12) | `ssh -v <user>@<ipv4>` |
| `ADMITTED_CHECK_MODE` | User source; admitted only by a `check` rule; and the path holds: TCP `open` in self mode, network allowed in `--from` mode (DESIGN A31) | Reachable after a browser check each period | Unattended access | MC's case for the phone (P7) |
| `TS_SSH_CHECK_FOR_TAGGED` | Tagged source; only a `check` rule matches; and TCP `open` in self mode, or `--from` mode, or the network dropped (DESIGN A50) | It can never work: "An SSH access rule from a tagged device cannot be in check mode" [SSH L218] | — | An `accept` rule `tag:dev` → `tag:fleet` needs MC's answer to MC6 |
| `TS_SSH_POLICY` | Tailscale SSH on; network allowed; `ssh` denies both ways; TCP `open` in self mode, or `--from` mode (DESIGN A50) | The `ssh` section has no rule from S to this host for that user | — | `policy-workflow.md`, the `ssh` rule shape |
| `TS_SSH_UNVERIFIED` | Tailscale SSH on; network allowed; no `--ssh-user`; TCP `open` in self mode, or `--from` mode (DESIGN A50) | Nothing about SSH admission yet | — | Rerun with `--ssh-user` |
| `POLICY_DROP` | `network_allowed == false`; in self mode, the probe neither reset nor connected (DESIGN A53) | The live policy drops it. That matches a timeout: a dropped SYN gets a TSMP reject and no RST (`wrap.go:1234-1252` [source-code]). A failed TSMP ping beside it is the same policy when it lets neither device reach the other, which trims each from the other's netmap [visibility L77-80] | — | `tailnet policy draft` with the recipe grant; MC applies; rerun. A Tailscale SSH host also needs an `ssh` rule |
| `ALLOWED` | `--from` mode; network allowed; Tailscale SSH off or admitted with `accept` | The policy permits it | That the host answers: no probe runs from here | — |
| `REFUSED_BY_HOST` | Self mode; TCP `refused`; network allowed | The SYN passed Tailscale's filter and the host reset it: nothing listening on that address | — | On-host block |
| `HOST_SIDE_DROP` | Self mode; TCP `timeout`; network allowed; Tailscale SSH off | The policy allows it; the host firewall or sshd's bind is the suspect | — | On-host block. If the policy changed within the last minute, rerun once first (propagation timing [unverified]) |
| `TS_SSH_TIMEOUT_UNEXPLAINED` | Self mode; TCP `timeout`; network allowed; Tailscale SSH on, whatever its `ssh` section said (DESIGN A50) | Not the `ssh` section: tailscaled completes the handshake on port 22 and asks the `ssh` section only at login [SSH L61, L118], so it cannot cause a timeout. The SYN was dropped before tailscaled took it, or Tailscale SSH is not running there | Which of those; while Tailscale SSH runs, a host firewall is probably not in the path [inference] | On-host block. The `ssh` section's answer is in the explanation as a second blocker: a denial, or check mode for a tagged source (MC6), still needs fixing once the port opens |
| `INCONCLUSIVE` | Anything else: probe or API errors, `sshEnabled` unknown on port 22 with the network allowed (DESIGN A31), a destination this host's netmap does not list with no drop named (DESIGN A52), or in self mode a reset or an open port beside a named drop (DESIGN A53) | — | — | Every fact is reported and both Tailscale SSH hypotheses listed; a peer's `sshHostKeys` is a weak hint only [unverified]. A probe that got through beside a named drop means the identity test does not represent this host's traffic (an address, host alias, CIDR or posture rule), the policy changed, or for a reset this host's own firewall; a reset also gets the on-host block |

## 5. The on-host block

The CLI prints this for the three host-side verdicts (`REFUSED_BY_HOST`, `HOST_SIDE_DROP`,
`TS_SSH_TIMEOUT_UNEXPLAINED`), and for an `INCONCLUSIVE` reset beside a named drop (DESIGN A53),
as `next: who=mc needs=terminal`, filled in with the destination,
this host's name and address, and the port (DESIGN A32), each name reduced to letters, digits,
`.`, `_` and `-` (DESIGN A54); the template below shows port 22. It runs
**on the destination**, from a session that can reach it: MC's phone through Termius, or albini →
pi5 → spec5 over the bench wire (fleet.yaml:86). Hand MC the block in one paste, and say what it
proves. Beside it the CLI suggests `tailnet diagnose <dest> --from <nodeId>` for each of MC's
user-owned devices; run those to see which device can reach it.

```sh
# On <dest>, while the agent retries from claude-factory:
tailscale metrics print | grep -E 'inbound_dropped_packets_total'        # reason="acl" rising → Tailscale policy drop (client ≥ 1.78)
sudo journalctl -u tailscaled --since '-10min' | grep -E 'Drop: TCP\{[^}]*:22\}'   # "no rules matched"
sudo timeout 20 tcpdump -ni tailscale0 -c 5 'tcp port 22 and src host <droplet-100.x>'   # SYN seen → passed Tailscale's filter
sudo ufw status verbose ; tailscale get ssh ; tailscale get shields-up ; tailscale get netfilter-mode
```

For `TS_SSH_TIMEOUT_UNEXPLAINED` the block leaves out the `tcpdump` and `ufw` lines and ends with
`tailscale get ssh ; tailscale get shields-up` (DESIGN A51): while Tailscale SSH takes port 22,
tailscaled's netstack consumes the SYN after the filter [SSH L63, L118] (`netstack.go:1294-1296,
:1497-1504` [source-code]), so neither `tailscale0` nor the host firewall ever sees it, and an empty
capture there proves nothing.

| Line | What it proves |
|---|---|
| `tailscale metrics print` | `tailscaled_inbound_dropped_packets_total` with `reason="acl"` counts "packets dropped by Tailscale access control" [metrics L132-144]. Rising across a retry means the policy dropped them. Needs client v1.78.0 or later [metrics L9]. How `print` renders the label is [unverified], hence the grep |
| `journalctl … 'Drop: TCP{…:22}'` | The receiving filter logs a policy drop as `Drop: TCP{<src>:<sport> > <dst>:22} <len> no rules matched` (`filter.go:364, :559`, `packet.go:82-98` [source-code]). Drop logging is rate-limited (`filter.go:338-366`) |
| `tcpdump -ni tailscale0` | Tailscale's inbound filter runs before the packet is written to the TUN device (`wrap.go:1306, :1325` [source-code]), so a SYN seen on `tailscale0` already passed the policy [inference]. A SYN with no SYN-ACK means host firewall or sshd. General Linux, not Tailscale docs. Kernel-TUN mode only: userspace networking has no `tailscale0`. Blind on a Tailscale SSH host's port 22, where netstack takes the SYN first, so the block leaves it out there |
| `ufw status verbose` | Look for `Anywhere on tailscale0 ALLOW IN`; Tailscale's own ufw guide adds it with `sudo ufw allow in on tailscale0` [ufw L129-139] |
| `tailscale get ssh` | Whether Tailscale SSH is on, which claims port 22 [SSH L40]. `tailscale get` takes the same names as `tailscale set` [cli L409-428] |
| `tailscale get shields-up` | Shields-up blocks incoming tailnet connections. It would also block 443, so it is unlikely when 443 works [inference] |
| `tailscale get netfilter-mode` | Context for whether a host firewall can still drop `tailscale0` traffic, which the docs do not settle [unverified] |

Client versions on record: pi5 1.104.1 (2026-10-10), nomad-b 1.102.3 (2026-09-09); spec5 not
recorded (mc §2). All are at least 1.78 where recorded.

## 6. Ping types

| Ping | Command | Tests | Source |
|---|---|---|---|
| DISCO (the default) | `tailscale ping <ip>` | Path discovery: DERP, peer relay or direct. Not policy | [ping-types L20-30] |
| TSMP | `tailscale ping --tsmp <ip>` | Connectivity, stopping "before the access control policy check"; bypasses the OS IP stack | [manage L29; ping-types L56] |
| ICMP | `tailscale ping --icmp <ip>` | End-to-end, "including access control policies". Passes whenever *any* port is allowed between the pair | [manage L35; policy-file L109] |

- TSMP succeeds and ICMP fails: policy is likely blocking. TSMP fails: the devices cannot connect
  at all, or the policy lets neither reach the other and has trimmed the peer from the netmap
  [visibility L77-80], which `probes.in_netmap` tells apart. Both succeed and the connection still fails: "check the port numbers in your access
  control policies and services" [manage L41]. **MC's droplet case is the last one, so ping says
  nothing about port 22.**
- Flags: `--c` (default 10), `--timeout` (default `5s`); `--tsmp` and `--icmp` default to false
  [cli L639-644].
- The exit code of `tailscale ping` on a timeout is [unverified]; e2e test E9 settles it, and until
  then an unknown result is `INCONCLUSIVE`.
- Upstream says the default ping is TSMP (`references/cli.md:124`); it is DISCO
  (`upstream-corrections.md` C3).

## 7. Per-host notes: spec5, nomad-b, pi5

All three were tagged `tag:fleet` at 2026-10-25T23:27:40Z [observed]; port 22 from the droplet
timed out then (`tailnet-facts.md` §4).

- **spec5.** Tailscale SSH **on, in check mode** (P7, recorded 2026-09-28 and 2026-10-10). SSH user
  `spec5`.
  - The network rule on port 22 is necessary; the `ssh` section decides (critic X1, X10).
  - From the droplet (`tag:dev`, unconfirmed): a check rule can never admit a tagged source
    [SSH L218], so with `--from claude-factory`, or once port 22 opens, expect
    `TS_SSH_CHECK_FOR_TAGGED` or `TS_SSH_POLICY`. The only fix is an `accept` rule, which is open
    question MC6. Drafts never include it until MC says yes.
  - A self-mode timeout to spec5 is never the `ssh` section's doing: it is
    `TS_SSH_TIMEOUT_UNEXPLAINED`, and the `ssh` answer rides along as a second blocker (DESIGN A50).
  - From MC's phone or albini: user → tagged device is allowed [SSH L216], but since the retag
    `autogroup:self` no longer covers spec5 [policy-file L230], so an explicit user → `tag:fleet`
    `ssh` rule is needed [inference; critic F3.3, R13]. Check mode is fine for people (P7).
  - tailscaled claims port 22 on the Tailscale IP [SSH L410], so a host firewall is probably not in
    the path [inference].
- **nomad-b.** Plain OpenSSH: Tailscale SSH turned off 2026-09-09, "Keep `--ssh=false`" 2026-09-25
  (P6). SSH user `spec5`; OS hostname `spec5b`. The `ssh` section and `sshTests` play no part; the
  network rule decides, then the host firewall and sshd (P12: host firewalls admit port 22 only from
  the tailnet ranges). Cloned from spec5's image: same machine-id (mc §5).
- **pi5.** Plain OpenSSH: `RunSSH: false` in the 2026-09-27 backup. SSH user `mc`. Client 1.104.1
  (2026-10-10). As for nomad-b, the network rule decides, then the host.
- Whether the droplet's SSH key is authorised on nomad-b or pi5 is not recorded [unverified]. The
  recorded key mesh (P11) covers pi5, albini, raptop, surface and cybrpwrpc, not the droplet. So
  `OPEN` followed by a failed login points at keys or the username.

## 8. What does not discriminate

- **Ping, and `tailscale ping --icmp`.** Both pass whenever any port is allowed [policy-file L109].
- **Network flow logs.** "Tailscale only logs successful connects. If a connection attempt results
  in denied access, the attempt isn't logged" [flowlogs L480]; Premium and Enterprise only
  [flowlogs L11].
- **The `ssh` section and `sshTests`, for a plain OpenSSH host** (nomad-b, pi5). They govern only
  Tailscale's own SSH server [policy-access (a), inference].
- **A peer listed in `tailscale status`.** The netmap includes devices "even if you aren't permitted
  to connect to them" [visibility L42].
- **A timeout on its own.** A policy drop and a host-side drop both look like a timeout.
- **`sshHostKeys` in local status**, as a marker of Tailscale SSH [unverified] (policy-access
  unverified 13).

## 9. `tailscale debug netmap`

- `tailscale debug` is hidden and "not a stable interface" (`cmd/tailscale/cli/debug.go:69`
  [source-code]). The netmap shape "is an internal type and may change without notice"
  (`ipn/localapi/debug.go:252-264` [source-code]).
- The docs do suggest it for checking effective rules: "Run `tailscale debug netmap` and examine the
  `PacketFilter` section to check effective rules" [route-injection L119].
- MC used it on albini to verify MESH-39 (P15). Its "rule 3" numbers are packet-filter entries, not
  rule indices in the HuJSON policy [inference] (mc §4).
- Use it for a human's confirmation, never in automation (DESIGN §23).

## 10. Unverified

Each is reported as unknown when it matters, never filled in.

- How `tailscale metrics print` renders `reason="acl"` (policy-access unverified 9).
- Whether `[v1]` accept lines appear at default verbosity (unverified 10).
- Whether the sender sees the TSMP reject anywhere (unverified 11).
- Whether ufw or nftables can drop `tailscale0` traffic despite netfilter mode `on` (unverified 12).
- Whether `sshHostKeys` reliably marks a Tailscale SSH peer (unverified 13).
- `tailscale ping` exit codes on a timeout (DESIGN §24; e2e E9).
- Whether the live policy's JSON form is accepted as a validate body. If not, every `TS_SSH_*`
  verdict degrades to `INCONCLUSIVE`; the network verdict is unaffected (DESIGN §24; e2e E7).
- Whether a Tailscale SSH banner is recognisable in the TCP probe's bytes (DESIGN §15.2).
- How long a policy change takes to reach a host.
- Whether a host firewall affects Tailscale SSH at all (DESIGN §24).
- How a tag destination such as `tag:fleet:22` behaves in a test when several devices, or none,
  carry the tag (policy-access unverified 5). `diagnose` avoids it by using 100.x and a host alias.

## 11. Sources

Read or fetched 2026-10-26.

- `DESIGN`: `DESIGN.md` §5.2, §5.3, §15, §24, §26 and Amendments A31, A32, A50-A54 and A70 in this
  repo.
- `mc`, `critic`, `api`, `policy-access`: `docs/research/mc-tailnet.md`, `critic.md`,
  `api-surface.md`, `policy-access.md` (all 2026-10-26).
- `fleet.yaml`: `/home/user/tailnet-ssh/fleet/fleet.yaml` at `2cab922` (2026-10-10).
- `spec`: the OpenAPI spec, sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`
  (live copy identical at 2026-10-26T12:54Z).
- `[source-code]`: `github.com/tailscale/tailscale` at `de16943cbf034d2c8238052dae4b2380837fe765`,
  as read by policy-access.
- Tailscale docs, fetched as Markdown with curl; line numbers are lines of that copy:

| Key | URL | Last validated |
|---|---|---|
| SSH | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| TAGS | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| key-expiry | https://tailscale.com/docs/features/access-control/key-expiry (fetched 2026-10-27) | Jan 5, 2026 |
| policy-file | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| manage | https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies | Mar 13, 2026 |
| ping-types | https://tailscale.com/docs/reference/ping-types | Jan 13, 2026 |
| cli | https://tailscale.com/docs/reference/tailscale-cli | Jul 30, 2026 |
| metrics | https://tailscale.com/docs/reference/tailscale-client-metrics | Jul 28, 2026 |
| ufw | https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw | Jan 5, 2026 |
| flowlogs | https://tailscale.com/docs/features/logging/network-flow-logs | Jan 23, 2026 |
| visibility | https://tailscale.com/docs/concepts/device-visibility | Jan 5, 2026 |
| route-injection | https://tailscale.com/docs/reference/route-injection | Sep 29, 2026 |
