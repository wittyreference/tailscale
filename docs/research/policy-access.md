# Policy and access: grants, ACLs, tags, tests, and diagnosing a :22 timeout

Research date: 2026-10-26. Topic: `policy-access`.

**How sources are cited.** Each fact names its source: a docs URL with the page's "Last validated" date, an OpenAPI spec path, or a `repo/path:line` at a pinned commit. The Sources section at the end gives the full list.

**Tags used here:**
- **[unverified]** means no confirmed source states it. Settle it by testing before relying on it.
- **[source-code]** means the fact comes from reading Tailscale's open-source client at commit `de16943c`. It is not documented, and behaviour can change.
- **[inference]** means a reasoned conclusion from the cited facts. No source says it outright.

**MC's situation, as given (not re-observed in this session):**
- The droplet is tagged `tag:dev`. It can ping spec5, nomad-b and pi5 (all tagged `tag:fleet`) and reach them on port 443, but TCP 22 times out.
- The hosts run plain OpenSSH. Tailscale SSH was deliberately turned off on nomad-b.
- The last session suspected there is no `acls` or `grants` rule that lets `tag:dev` reach `tag:fleet` on port 22. **This session did not read MC's policy file**, so that is still a hypothesis.

---

## TL;DR for the droplet to fleet :22 problem

1. **Ping working proves nothing about port 22.**
   - The ACL reference says: "If traffic is allowed for a given pair of IP addresses, then ICMP will also be allowed." ([syntax/policy-file], `proto` note)
   - The client's packet filter accepts an inbound ICMP echo "If any port is open to an IP" [source-code `wgengine/filter/filter.go:520`].
   - So a rule that allows only port 443 also makes ping work.
2. **`ssh` rules grant no network access.** With plain OpenSSH, the `ssh` section is not involved at all. Port 22 must be opened by an `acls` or `grants` rule. See (a).
3. **Fastest read-only check (needs only `policy_file:read`):** run a policy test against the current policy using `POST /tailnet/-/acl/validate` with this body:
   ```json
   [{"src":"tag:dev","proto":"tcp","accept":["<spec5-100.x>:22"]}]
   ```
   A response carrying `want: Accept, got: Drop` means the policy is the blocker. A passing response means look at the host. See (c) and (d).
4. **On-host check (documented):** run `tailscale metrics print` on the destination before and after an SSH attempt. If `tailscaled_inbound_dropped_packets_total` with `reason="acl"` goes up, Tailscale's packet filter dropped the packet. If it does not, look at the host firewall or sshd. See (d).
5. **The fix needs a write scope MC's credential lacks.** Setting the policy (`POST /tailnet/{tailnet}/acl`) requires OAuth scope `policy_file`, and MC's credential has only `policy_file:read` (OpenAPI `setPolicyFile`). The fix goes in through the admin console, or through a credential that has `policy_file`. See (e) for the grant text.

---

## (a) How network access is granted

### Two rule syntaxes for the same network layer

The policy file has two access-control sections that work at the network layer:
- `acls`: network-level rules.
- `grants`: network-level and application-level rules. The syntax reference says to "Prefer grants for access control policies." ([syntax/policy-file], section table)

Both deny by default ([grants-vs-acls]). The docs say grants are "feature complete with ACLs", and that grants will keep getting new features while ACLs will not ([grants-vs-acls]). ACLs stay supported indefinitely ([grants-vs-acls]; [migrate-acls-grants]). The two can sit in the same file: "Grants and legacy ACLs can coexist in the same tailnet policy file" ([features/access-control/grants], Limitations).

**ACL rule shape** ([syntax/policy-file] §ACLs):
```json
{ "action": "accept", "src": [ ... ], "proto": "tcp", "dst": [ "<host>:<ports>" ] }
```
- `action`: the only possible value is `accept`.
- `dst`: each entry is `<host>:<ports>`. Ports can be `*`, a single port (`22`), a list (`80,443`) or a range (`1000-2000`).
- `proto`: optional. Without it, "the access rule applies to all TCP and UDP traffic."
- "If traffic is allowed for a given pair of IP addresses, then ICMP will also be allowed."
- Only TCP, UDP and SCTP take ports. Other protocols take only `*`.
- The legacy fields `users` and `ports` still work; `src` and `dst` are the best practice.

**Grant shape** ([syntax/grants] §Syntax, §Network layer capabilities):
```json
{ "src": [ ... ], "dst": [ ... ], "ip": [ ... ], "app": { ... }, "srcPosture": [ ... ], "via": [ ... ] }
```
- Every grant needs `src`, `dst`, and either `ip` or `app`. Each grant implies `accept`.
- Every property is an array, except `app`, which is a map.
- Forms allowed in `ip`:

  | `ip` value | Meaning |
  |---|---|
  | `*` | All ports. Implies TCP, UDP and ICMP. |
  | `<port>` or `<port>-<port>` | Implies TCP, UDP and ICMP on those ports. |
  | `<proto>:*` | All ports of that protocol, for example `icmp:*`. |
  | `<proto>:<port>` | One protocol on one port or range, for example `tcp:22` or `tcp:80-443`. |

- "If multiple grants match a connection, the Tailscale policy engine applies the union of all granted capabilities. More specific grants do not override less specific ones; they add to them." ([syntax/grants] §Core concepts)
- Whether a `tcp:22`-only grant also allows ICMP is not stated in the grants docs. The client filter allows ICMP echo whenever any port is open to that IP pair [source-code `wgengine/filter/filter.go:520`].

**Converting ACLs to grants** ([migrate-acls-grants] §Structural mapping):
- Drop `action`.
- Move the port out of `dst` into `ip`, and move `proto` in as a prefix (`"proto":"tcp"` with `tag:x:443` becomes `"ip":["tcp:443"]`).
- An ACL with no `proto` converts to a grant with no protocol prefix.
- If an ACL's `dst` names two tags with different ports, it must become two grants. Merging them would give both tags both ports.
- The admin console's **Convert to grants** button rewrites the whole `acls` section in the editor straight away, with no confirmation dialog.

**Union of `acls` and `grants`:** the docs say the two coexist, and that "Tailscale automatically translates all ACLs to lower-level rules" ([syntax/policy-file] §ACLs). That rules from both sections combine as a union is **[unverified]**, though it is the natural reading.

### Do `ssh` rules grant network-layer access? No.

The docs require two separate permissions for **Tailscale SSH**, and say what each one is for:
- "To allow a connection, the tailnet policy file must contain rules permitting both network access and SSH access:
  1. An access rule to allow connections from the source to the destination on port 22.
  2. An SSH access rule to allow connections from the source to the destination and the given SSH users. Tailscale SSH uses this to distribute keys to authenticating SSH connections." ([syntax/policy-file] §Tailscale SSH)
- The same split appears in [tailscale-ssh] §Ensure Tailscale SSH is permitted: rule 1 "is used to allow any connections in Tailscale (including SSH connections), to distribute keys for WireGuard"; rule 2 "is used for Tailscale SSH". The prerequisites there say: "Ensure an access control policy exists that grants the source with access to the destination on port `22`."
- On disabling Tailscale SSH: "You do not need to remove or modify other access rules if you still want users to be able to access the specified devices, but not using Tailscale SSH." ([tailscale-ssh] §Disable Tailscale SSH from your tailnet)
- "You can use check mode only on Tailscale SSH connections, not for plain SSH or other TCP connections running over Tailscale." ([tailscale-ssh] §Limitations)
- SSH rules live "in a separate section … separate from both ACLs and grants" ([migrate-acls-grants] §SSH rules).

**What this means for plain OpenSSH [inference from the above]:**
- The `ssh` section configures only Tailscale's own SSH server. It does not open port 22 in the packet filter.
- Plain sshd over Tailscale needs only an `acls` or `grants` rule allowing TCP 22.
- `tailscale set --ssh` "configures `tailscaled` to intercept all traffic from your tailnet that is routed to port `22`" ([tailscale-ssh] §Advertise SSH on the host). With it off (`tailscale set --ssh=false`, as on nomad-b), tailnet traffic to port 22 reaches the host's own sshd.

**Checking which mode a host is in:**
- `tailscale get ssh` reads the current value of the `--ssh` setting. `tailscale get` takes the same setting names as `tailscale set` ([tailscale-cli] §get and §set).
- `tailscale debug prefs` prints prefs that include `RunSSH` [source-code `ipn/prefs.go:137-140`]. `tailscale debug` is hidden and "not a stable interface" [source-code `cmd/tailscale/cli/debug.go:69`].

### Which tagged and user combinations Tailscale SSH allows (for completeness)

From [syntax/policy-file] §Order of evaluation:
- User to their own devices.
- User to a tagged device.
- Tagged device to tagged device. This cannot use check mode.
- User to a tagged device shared with them.

[targets-and-selectors] §Restrictions adds: "Devices with a tag-based identity can only SSH into other tagged devices." Under the docs' wording these limits apply to Tailscale SSH. Whether they touch plain SSH is not stated. Plain SSH is ordinary TCP under acls/grants [inference].

---

## (b) What changes when a user-owned device is tagged

**Identity and ownership** ([tags], key characteristics, §Tag vs. user authentication, §Ownership):
- "Applying a tag to a device removes any user-based authentication."
- "it's impossible for a user account identity and a tag identity to exist on the same device. Applying a tag to a device previously authenticated with a user account removes the user account. Similarly, authenticating a device with a user account removes all tags from the device."
- "A tagged device's identity is the combination of all its tags (not the intersection)." A rule for any one of the device's tags applies to it.
- A tag-based device must keep at least one tag. You cannot remove every tag from it in the admin console. Either assign a new tag or re-authenticate the device as a user ([tags] §Limitations and §Apply a tag in the admin console).
- In the API Device object, `tags` is described as: "Once a device is tagged, the tag is the owner of that device." `user` is "The user who registered the node. For untagged nodes, this user is the device owner." ([openapi] `components.schemas.Device`). For a tagged device, `user` still names whoever registered it, but that user is not the owner.
- "removing a user also removes all their devices", but removing a user "won't affect the device if you use tags" ([tags] §Use cases).
- Tagging during re-authentication "generates a new node key for the device. The Tailscale IP address for the device does not change." ([tags] §Apply a tag to a device)

**Key expiry** ([tags] §Key expiry; [key-expiry] §Using key expiry with tagged devices):
- "When you apply a tag to a device for the first time and authenticate it, the tagged device's key expiry is disabled by default."
- "If you change the tags on the device from the admin console, Tailscale CLI, or the Tailscale API, the device's key expiry will not change unless you re-authenticate."

So a droplet tagged from the console or API without re-authenticating may still have key expiry on. Check the device's `keyExpiryDisabled` field ([openapi] `Device.keyExpiryDisabled`). `POST /device/{deviceId}/key` with `{"keyExpiryDisabled": true}` turns expiry off and needs scope `devices:core` ([openapi] `updateDeviceKey`).

**Implicit access the owner loses:**
- `autogroup:self` "only applies to user-owned devices. It does not apply to tagged devices." ([syntax/policy-file] §Autogroups). So any `src: autogroup:member` → `dst: autogroup:self` rule, network or SSH, stops covering the tagged device.
- The default SSH policy is the rule `check`, `autogroup:member` → `autogroup:self`, as `autogroup:nonroot` or `root` ([tailscale-ssh] §SSH access rules in default access control policy). It no longer reaches the device.
- Netmap visibility: a device's network map includes "All devices authenticated with the same user identity as your current device, even if the tailnet policy file doesn't permit you to connect to them" ([device-visibility] §Device visibility principles). A tagged device no longer shares the user's identity, so it loses that implicit visibility [inference].
- Taildrop: "Taildrop permits you to share files between devices you're logged in to, even if you use ACLs to restrict access" ([syntax/policy-file] §Taildrop precedence). A tagged device is not logged in as the user [inference].
- Tailscale SSH from the tagged device can now reach only other tagged devices ([tags] §Limitations).
- **As a source, the tagged device probably no longer matches the user's email or `autogroup:member`.** The docs describe `autogroup:member` as selecting users "who [are] direct member[s]" ([syntax/policy-file] §Autogroups), and tagging removes the user. But no page says outright that `autogroup:member` excludes tagged devices. **[unverified]**
  - Settle it with a validate test (see (c)): `{"src":"tag:dev","accept":["<dst>:<port>"]}` against a policy whose only matching rule has `src: autogroup:member`.
  - Practical result: the droplet needs its own `tag:dev` rule (see (e)).

---

## (c) Policy tests (`tests`, `sshTests`) and the validate endpoint

### `tests`: network-level assertions for ACLs and network-level grants

From [syntax/policy-file] §Tests:
```json
"tests": [
  {
    "src": "dave@example.com",
    "srcPostureAttrs": { "node:os": "windows" },
    "proto": "tcp",
    "accept": ["example-host-1:22", "vega:80"],
    "deny": ["192.0.2.3:443"],
  },
],
```
- **`src`:** a user email, a group, a tag, or a host alias that maps to an IP. "The test case runs from the perspective of a device authenticated with the provided identity."
- **`proto`:** optional. "When omitted, the test checks for either TCP or UDP access."
  - To test ICMP, use `"proto": "icmp"` with port `0`, for example `"accept": ["tag:production:0"]`.
- **`accept` and `deny`:** each entry is `host:port` with a single numeric port. The host can be:
  - a Tailscale IP (IPv6 written as `[1:2:3::4]:80`)
  - a host alias
  - a user
  - a group
  - a tag ("the Tailscale IP addresses of devices tagged with the provided tag")
  - a service (`svc:`)
- **Not allowed:** CIDR in `accept` or `deny`, and `*` wildcards in `src`, `accept` or `deny` (for example, no `tags:*`).
- **Legacy:** `allow` still works in place of `accept`, but `accept` is the best practice.
- **When tests run:** "each time the tailnet policy file changes. If an assertion fails, Tailscale rejects the updated tailnet policy file with an error."
- **Tag tests in the docs** ([tags] §ACLs): `{"src": "group:sre", "accept": ["tag:prod:1234"]}`.

**Example: assert tag:dev to tag:fleet** (illustration; the deny entry is meant to show directionality, and should be kept only if it matches MC's intent):
```json
"tests": [
  { "src": "tag:dev",   "proto": "tcp", "accept": ["tag:fleet:22", "tag:fleet:443"] },
  { "src": "tag:fleet", "proto": "tcp", "deny":   ["tag:dev:22"] },
],
```
Adding the first test to the *current* policy before the fix would make the save fail, because tests run on every change. Run it through the validate endpoint first.

### `sshTests`: Tailscale SSH assertions only

From [syntax/policy-file] §SSH Tests:
```json
"sshTests": [
  { "src": "dave@example.com", "dst": ["example-host-1"],
    "accept": ["dave"], "check": ["admin"], "deny": ["root"],
    "srcPostureAttrs": { "node:os": "windows" } },
],
```
- `src` takes a user, group, tag or host alias. `dst` takes users, groups, tags or host aliases.
- `accept`, `check` and `deny` are lists of **host usernames**. The reference text calls `accept` and `check` "usernames to disallow", which is a wording error (see contradictions). The example's prose ("If the user is `dave`, it accepts the connection") gives the real meaning.
- `sshTests` say nothing about whether plain OpenSSH works, because they test only the `ssh` section [inference from (a)]. For MC's fleet, use `tests`.

### How the validate endpoint runs tests

`POST /tailnet/{tailnet}/acl/validate`, operationId `validateAndTestPolicyFile`, OAuth scope `policy_file:read` ([openapi]). It has two modes, and "neither of which modifies your current tailnet policy file":

1. **Body is a JSON array of tests.** "Tailscale runs ACL tests against the tailnet's current policy file." Each item takes `src` (required), `srcPostureAttrs`, `proto`, `accept` and `deny`.
2. **Body is a policy file**, sent as a JSON object or as `Content-Type: application/hujson`. "Tailscale interprets the body as a hypothetical new tailnet policy file with new ACLs, including any new rules and tests. It validates that the policy file is parsable and runs tests to validate the existing rules."
   - The spec's wording about *which* tests run in this mode is ambiguous. That the posted file's own `tests` run is the reasonable reading **[unverified]**.

**Responses:**
- Pass: HTTP 200 with an empty body ("An empty response body implies passing") or `{}` (the `testsOrValidationSuccess` example).
- Fail: **also HTTP 200**, for example:
  ```json
  {"message":"test(s) failed","data":[{"user":"user1@example.com","errors":["address \"2.2.2.2:22\": want: Drop, got: Accept"]}]}
  ```
- Warnings use `"message":"warning(s) found"` with `data[].warnings`.
- So a client must read the body. HTTP 200 does not mean pass.
- Other statuses: 400, 403, 404 and 500, with an `Error` schema.

The policy can also be saved from the admin console, GitOps, Terraform or the API. All of them validate syntax on save and refuse a file that references an undefined target such as a group ([troubleshooting/grants] §Diagnosing grant issues).

---

## (d) Telling a policy drop from a host-firewall drop when ping works but :22 times out

### What each layer does to the SYN

- **Where the policy is enforced.** Access policy is "enforced on the server side" ([tailscale-ssh] §OS user authentication on the client). "Each time a device attempts a connection, the receiving device logs whether it allowed or denied the connection." ([connect-device-failure] step 5)
- **The receive path [source-code].** Inbound WireGuard packets go through `filterPacketInboundFromWireGuard`, which runs `filt.RunIn`. Only accepted packets are then written to the TUN device (`net/tstun/wrap.go:1306`, `:1215`, `:1325`).
- **When the policy drops a TCP SYN [source-code].**
  - For an IPv4 TCP SYN the filter drops, the receiver sends a TSMP "rejected" message back to the sender with reason `RejectedDueToACLs`.
  - It sends **no TCP RST**. The code carries the comment `// TODO(bradfitz): also send a TCP RST, after the TSMP message.` (`net/tstun/wrap.go:1234-1252`).
  - So the sender's `ssh` sees a timeout, not "connection refused". That matches MC's symptom [inference].
- **Non-SYN packets** are accepted ("tcp non-syn"), so return traffic for connections the host starts works (`wgengine/filter/filter.go:533`) [source-code].
- **Netfilter `on` mode (the default)** inserts jump rules "at the start of the built-in chains (`INPUT` and `FORWARD` …)", and its rules include "Traffic arriving through the `tailscale0` interface is accepted" ([netfilter-modes] §on).
  - "Packet filtering for traffic in and out of Tailscale is always performed by packet filtering internal to Tailscale itself" ([firewall-mode] §Firewall mode heuristic).
  - Whether a host firewall such as ufw, nftables or firewalld can still drop tailscale0 traffic depends on firewall mode, netfilter mode and rule order. **[unverified]**: the docs don't cover how these interact.
  - Tailscale's ufw guide adds `sudo ufw allow in on tailscale0` explicitly ([ufw how-to] Step 5).

### Diagnostic steps (run in this order)

Each step gives the command, what it tells you, and its source.

**1. TSMP vs ICMP ping, run from the droplet** ([manage-tailnet-policies] §Debug access control policies; [ping-types]):
- `tailscale ping --tsmp spec5` checks "whether two devices can establish a network connection but stop[s] before the access control policy check."
- `tailscale ping --icmp spec5`, or the OS `ping`, checks "end-to-end connectivity between devices, including access control policies."
- "If both TSMP and ICMP pings succeed, but connections still fail, check the port numbers in your access control policies and services you are trying to connect to."
- **MC is in this branch:** ICMP passes because port 443 is open, so ping cannot tell you anything about port 22.
- The default `tailscale ping` with no flag uses **DISCO** ([ping-types] §DISCO). It shows the path (DERP, peer relay or direct), not policy.

**2. Validate test against the live policy, through the API** (read-only, `policy_file:read`). See (c):
```
POST https://api.tailscale.com/api/v2/tailnet/-/acl/validate
Content-Type: application/json
[{"src":"tag:dev","proto":"tcp","accept":["<spec5-ip>:22","<nomad-b-ip>:22","<pi5-ip>:22"]}]
```
- `want: Accept, got: Drop` in `data[].errors` means the policy drops port 22.
- An empty body or `{}` means the policy permits it, so go to the host-side steps.
- `tag:fleet:22` also works as a destination.

**3. Preview rules for the destination port, through the API.** `POST /tailnet/{tailnet}/acl/preview?type=ipport&previewFor=<spec5-ip>:22`, operationId `previewRuleMatches` ([openapi]).
- The request body is a policy file (JSON or HuJSON). Send the current file, fetched first with `GET /tailnet/-/acl`.
- The response is `{"matches":[{"users":[...],"ports":[...],"lineNumber":N}],"type":"ipport","previewFor":"..."}`. It lists "the tailnet policy rules that apply to that resource, without saving the policy file."
- `type=user` takes a **user's email** "of a valid user with registered machines". It cannot preview a tag as the source.
- The names `user` and `ipport` "remain in the API for compatibility"; policy files now use `src` and `dst`.
- How a tagged source appears in `matches[].users` (as `tag:dev` or as an IP) is **[unverified]**.
- The admin-console equivalent is the **Preview rules** tab at `https://console.tailscale.com/admin/acls/preview` ([manage-tailnet-policies] §Preview changes; [connect-device-failure] step 5).

**4. On the destination: the ACL drop counter** ([tailscale-client-metrics] §Dropped packets and §Command line):
- Run `tailscale metrics print` and note `tailscaled_inbound_dropped_packets_total{reason="acl"}`.
- Retry `ssh` from the droplet, then run it again.
- If the counter rose, Tailscale access control dropped the packets. If it did not, look at the host.
- The counter is documented as "packets dropped by Tailscale access control". It needs client v1.78.0 or later.
- The exact rendering of the label in the `print` output is **[unverified]**. Grep for `inbound_dropped_packets_total` and `acl`.

**5. On the destination: tailscaled's own log**:
- Commands: `journalctl -u tailscaled --since="10 min ago"`, or a live stream with `tailscale debug daemon-logs` ([tailscaled] §Getting logs from tailscaled).
- A policy drop logs a line shaped like `Drop: TCP{<droplet-100.x>:<sport> > <spec5-100.x>:22} <len> no rules matched` [source-code: format `"%s: %s %d %s"` at `wgengine/filter/filter.go:364`, packet string `PROTO{src > dst}` at `net/packet/packet.go:82-98`, reason at `filter.go:559`].
- Drop logging is rate-limited, and accept lines are prefixed `[v1]` [source-code `filter.go:338-366`]. Whether `[v1]` lines appear without extra verbosity is **[unverified]**.

**6. On the destination: does the SYN reach the OS?** Run `sudo tcpdump -ni tailscale0 tcp port 22` while retrying.
- Tailscale's inbound filter runs *before* the packet is written to the TUN device [source-code `net/tstun/wrap.go:1306`, `:1325`]. So a SYN seen on `tailscale0` has already passed the Tailscale policy [inference].
- If SYNs arrive with no SYN-ACK back, the cause is local: host firewall, sshd not listening on that address, and so on.
- tcpdump and Linux firewall behaviour are general Linux knowledge, not Tailscale docs.
- This applies to kernel-TUN mode. A node in userspace-networking mode has no `tailscale0` ([tailscaled] §Flags, `--tun=userspace-networking`).

**7. On the destination: host firewall and Tailscale prefs:**
- `sudo ufw status verbose`: look for `Anywhere on tailscale0 ALLOW IN` ([ufw how-to] Step 5).
- `tailscale get shields-up` and `tailscale get netfilter-mode` ([tailscale-cli] §get and §set).
- Shields-up "Block[s] incoming connections from other devices on your Tailscale network" ([tailscale-cli] §set). It would also block 443, so it is unlikely here [inference].

**8. Effective packet filter on the destination** ([route-injection] §Traffic blocked despite route existing):
- "Run `tailscale debug netmap` and examine the `PacketFilter` section to check effective rules."
- The netmap JSON has the fields `PacketFilter` and `PacketFilterRules` [source-code `types/netmap/netmap.go:42-43`].
- The JSON shape is internal: "the netmap.NetworkMap shape is an internal type and may change without notice" [source-code `ipn/localapi/debug.go:252-264`].
- `tailscale debug` is hidden and unstable [source-code `cmd/tailscale/cli/debug.go:69`].
- Use this for confirmation, not for automation.

**9. Identity checks:**
- `tailscale status --json` on the droplet: `Self.Tags` should contain `tag:dev`, and each fleet peer's `Tags` should show `tag:fleet` [source-code `ipn/ipnstate/ipnstate.go:259-261`].
- A peer's `sshHostKeys` is "the node's SSH host keys, if known" [source-code `ipnstate.go:315-316`]. That it is set only when Tailscale SSH is advertised is **[unverified]**.
- `tailscale whois <droplet-ip>` on the destination shows the source's tags and capabilities ([tailscale-cli] §whois; [troubleshooting/grants] §Inspect capabilities with whois).
- **Caution:** `tailscale status` listing a peer does not prove you can connect to it. A netmap also includes "All devices that can connect to your device, even if you aren't permitted to connect to them" ([device-visibility]).

### Things that do not discriminate

- **Ping and `tailscale ping --icmp`:** they pass whenever any port is allowed. See step 1.
- **Network flow logs:** Premium and Enterprise only, and "Tailscale only logs successful connects. If a connection attempt results in denied access, the attempt isn't logged." ([network-flow-logs])
- **The `ssh` section and `sshTests`:** irrelevant to plain OpenSSH. See (a).

---

## (e) Grants for MC's two rules

Both rules follow the official guidance to prefer grants ([syntax/policy-file], section table; [grants-vs-acls]). Shown in HuJSON:

```jsonc
{
  "grants": [
    // The droplet (tag:dev) may open SSH to the fleet hosts. They run plain OpenSSH,
    // so this network rule alone is enough; the "ssh" section is not involved.
    { "src": ["tag:dev"], "dst": ["tag:fleet"], "ip": ["tcp:22"] },

    // Human members of the tailnet may reach the fleet on every port and protocol.
    { "src": ["autogroup:member"], "dst": ["tag:fleet"], "ip": ["*"] },
  ],
  "tests": [
    { "src": "tag:dev", "proto": "tcp", "accept": ["tag:fleet:22", "tag:fleet:443"] },
    { "src": "<mc-login-email>",        "accept": ["tag:fleet:22", "tag:fleet:443"] },
  ],
}
```

Notes, with sources:
- **`ip` forms.** `"tcp:22"` is the `<proto>:<port>` form. `"*"` is "all ports … (implies TCP, UDP, and ICMP access)" ([syntax/grants] §Network layer capabilities). `"22"` with no protocol would also allow UDP 22.
- **What `autogroup:member` covers.** It means "any user who is a direct member (including all invited users) of the tailnet. Does not include users from shared devices." ([syntax/policy-file] §Autogroups). Using MC's own email instead is narrower.
  - An SSH-section warning notes that granting `autogroup:member` also reaches external invited users when a device is shared with them ([syntax/policy-file] §Tailscale SSH `src`). Whether that applies to grants too is **[unverified]**.
- **Why tag:dev needs its own rule.** The droplet as a tagged source is probably *not* matched by `autogroup:member` (see (b), **[unverified]**). The first test settles it.
- **Tags must already exist.** `tag:dev` and `tag:fleet` must be defined in `tagOwners` ([syntax/policy-file] §Tags: "You must define the tag in the `tagOwners` section … before using it in an ACL"). Both are already applied to devices, so presumably they exist. Saving checks this anyway ([troubleshooting/grants]).
- **Tests must use specific identities.** Wildcards are not allowed in tests. Whether `autogroup:member` is accepted as a test `src` is **[unverified]**: the documented `src` types are user, group, tag and host. So use MC's login email.
- **The equivalent legacy ACL** ([migrate-acls-grants] §Basic migration patterns):
  ```json
  {"action":"accept","src":["tag:dev"],"proto":"tcp","dst":["tag:fleet:22"]}
  {"action":"accept","src":["autogroup:member"],"dst":["tag:fleet:*"]}
  ```
- **Applying the change.**
  1. Fetch the file with `GET /acl`, which returns an `ETag`.
  2. Validate the edited file with `POST /acl/validate`, using the policy-file body mode.
  3. Save with `POST /acl` plus `If-Match: "<etag>"` ([openapi] `setPolicyFile`; 412 on an ETag mismatch). This needs scope `policy_file`, which MC's credential does not have.
- **Reverting.** Admin-console changes can be reverted from Configuration logs ([manage-tailnet-policies] §Revert changes), but not under GitOps.

---

## (f) HuJSON notes

- **What it is.** The policy file is "human JSON (HuJSON)" ([tailnet-policy-file]; [syntax/policy-file]). HuJSON is JWCC: it allows "C-style line comments and block comments intermixed with whitespace" and "trailing commas after the last member/element in an object/array." "All JSON is valid JWCC." ([hujson README] lines 9-14)
- **Formatter.** `hujsonfmt` formats HuJSON: `go install github.com/tailscale/hujson/cmd/hujsonfmt@latest` ([hujson README] lines 20-26).
- **Over the API** ([openapi] `getPolicyFile`, `setPolicyFile`, `validateAndTestPolicyFile`, `previewRuleMatches`):
  - GET returns JSON if `Accept: application/json` is sent; "otherwise HuJSON will be returned."
  - POST, validate and preview accept `application/json` or `application/hujson`.
  - `GET ?details=true` returns `{acl: <base64 HuJSON>, warnings: [...], errors: [...]}`. Don't send an `Accept` header with it.
  - That a JSON-format GET drops the comments is **[unverified]**, but it follows from what JSON can hold [inference].
- **Python.** The stdlib `json` module cannot parse HuJSON with comments or trailing commas [general Python fact]. Re-serialising through `json` throws away MC's comments [inference].
- **Tag case.** "Tailscale ignores tag name case and parses all tags in the tailnet policy file as lowercase." ([tags] §Define a tag)
- **Group and tag prefixes.** "Forgetting to prefix group names with `group:` or tag names with `tag:` … will be caught automatically unless there's also a host with the same name as the group or tag." ([troubleshooting/grants] §Selector matching issues)
- **Doc code blocks.** Many doc snippets are labelled ` ```json ` but contain `//` comments and trailing commas. They are HuJSON.
- **`If-Match: "ts-default"`** replaces the policy "only if the current policy file is still the untouched default" ([openapi] `setPolicyFile` `If-Match`).

---

## Discrepancies: upstream official skill vs first-party docs

The upstream skill is `tailscale-skill` at commit `4f05d353` (2026-07-09). Paths are relative to `skills/tailscale/`.

| # | Upstream claim (file:line) | First-party source says | Severity for us |
|---|---|---|---|
| U1 | `references/access-control.md:88`: `"ip": ["*:*"]` | The grants `ip` forms are `*`, `<port>`, `<proto>:*` and `<proto>:<port>` ([syntax/grants]). The same upstream file says `"ip": ["*"]` at line 37. Whether `*:*` parses is **[unverified]**. | Medium: an agent may copy it. |
| U2 | `access-control.md:141`: "Actions: `accept` (allow), `check` (require re-authentication), `deny`." | The SSH `action` is "`accept` or `check`" ([syntax/policy-file] §Tailscale SSH; [tailscale-ssh] §action). `deny` exists only as an `sshTests` username list. | Medium |
| U3 | `access-control.md:163`: "`autogroup:self` (same device)" | It selects "all devices owned by the same user" ([targets-and-selectors] §autogroup:self). | Medium |
| U4 | `access-control.md:163`: lists `autogroup:nonroot` among grant/ACL sources and destinations | Allowed only "As an SSH user" ([syntax/policy-file] §Autogroups). | Low to medium |
| U5 | `access-control.md:168`: the default "lets SSH to all devices as non-root users" | The default SSH rule is `check`, `autogroup:member` → `autogroup:self`, users `autogroup:nonroot` and `root`: a user's *own* devices ([tailscale-ssh] §SSH access rules in default access control policy). | Medium |
| U6 | `access-control.md:75`: "Tagged devices have key expiry disabled by default." (also `common-tasks.md:118`) | True only when the tag is first applied *and the device authenticates*. Retagging from the console, CLI or API leaves expiry unchanged until re-auth ([tags] §Key expiry). | High for MC: the droplet may have been tagged without re-auth. |
| U7 | `access-control.md:41`: "The policy file is JSON" | HuJSON ([tailnet-policy-file]). Upstream's own examples use `//` comments. | Low |
| U8 | `access-control.md:102`: SSH rules are in a separate `ssh` section (correct) | It omits the documented requirement for a *separate* network rule on port 22 ([syntax/policy-file] §Tailscale SSH), and that `ssh` rules do nothing for plain sshd. | **High: this is exactly MC's failure mode.** |
| U9 | `access-control.md:11`: grants-vs-acls is the place for "the most up-to-date list of capability schemas" | grants-vs-acls has no capability schemas. They are at `/docs/features/access-control/grants/grants-app-capabilities`. | Low |
| U10 | `access-control.md:94-96`: drive capability `{"shares": [...]}` | The docs example also carries `"access": "rw"`/`"ro"` ([grants-app-capabilities]). Whether `access` is required is **[unverified]**. | Low (off topic) |
| U11 | `references/cli.md:124`: `tailscale ping <hostname>  # Ping via Tailscale (TSMP)` | The default is DISCO; TSMP needs `--tsmp` ([ping-types] §DISCO). | Medium: diagnostic misread. |
| U12 | `references/api.md:99-103`: preview body `{"src":"alice@example.com","dst":"tag:server"}` | Preview takes query params `type=user\|ipport` and `previewFor=<email\|ip:port>`, with a **policy file** as the body ([openapi] `previewRuleMatches`). | High if copied: wrong request shape. |
| U13 | `access-control.md` (whole file) | No coverage of `tests`/`sshTests`, `/acl/validate`, `/acl/preview`, `tailscale ping --tsmp` vs `--icmp`, or the ACL drop metric. | Gap, not error. Our skill should fill it. |

## Discrepancies inside first-party sources

| # | Where | Inconsistency | Which to trust |
|---|---|---|---|
| D1 | [tailnet-policy-file] sections table | Names the section `nodeAttr` | [syntax/policy-file] uses `nodeAttrs` in its table and its code. Trust `nodeAttrs`. |
| D2 | [tags] §Apply a tag from another tag | Example key `"TagOwners"` (capital T) | Everywhere else uses `tagOwners`. Whether keys are case-insensitive is **[unverified]**. Use `tagOwners`. |
| D3 | [migrate-acls-grants] §IP address ranges | ACL example `"proto": ["tcp"]` (an array) | [syntax/policy-file] shows `"proto": "tcp"` (a string). Use the string. |
| D4 | [syntax/policy-file] §SSH Tests | `accept` and `check` described as "usernames to disallow" | The example prose says they accept or check. A wording error. |
| D5 | [manage-tailnet-policies] §Debug access control policies | The text says to use `tailscale ping --icmp` or regular `ping`, but the code block shows bare `tailscale ping`, which is DISCO. The TSMP block omits the host. | Use `tailscale ping --icmp <host>` and `tailscale ping --tsmp <host>`. |
| D6 | [openapi] `validateAndTestPolicyFile` example `aclValidateJSON` | `"tests", [` (a comma where a colon belongs), plus legacy `allow` | Invalid JSON in the spec example. Don't copy it. |
| D7 | [syntax/policy-file] §Tailscale SSH `src` | The `src` subsection talks about restricting the `dst` field | Editorial. The `dst` rules are under `dst` and in [tailscale-ssh]. |
| D8 | [tailscale-ssh] §Prerequisites vs §SSH access rules in default policy | One says the default SSH rules "grant SSH access to all devices"; the other shows `autogroup:member` → `autogroup:self` | Trust the rule text: own devices, check mode. |
| D9 | [trust-credentials] `policy_file:read` | "devices:posture_attributes:read and devices:core:read are required when using this scope." | Not a contradiction but a **constraint**: MC's chosen scope set (`devices:core`, `policy_file:read`, `dns:read`) has no `devices:posture_attributes:read`. `devices:core` includes the `devices:core:read` endpoints ([trust-credentials] §devices:core). Whether the admin console enforces or auto-adds the posture scope is **[unverified]**. |

---

## Unverified / open

1. That `autogroup:member` as a source excludes tagged devices. Inferred; not stated. Settle with a validate test.
2. That `acls` and `grants` combine as a union when both are present.
3. That a `tcp:22`-only grant allows ICMP. Implied by the filter source; not stated in the grants docs.
4. How `matches[].users` in `/acl/preview?type=ipport` represents tagged sources, and whether `previewFor` accepts anything but IP:port or email.
5. In tests, how a tag destination (`tag:fleet:22`) behaves when several, or zero, devices carry the tag.
6. Which tests run in the validate endpoint's policy-file mode.
7. Whether `GET /acl` with `Accept: application/json` strips comments.
8. Whether `"ip": ["*:*"]` parses.
9. The exact `tailscale metrics print` rendering of `tailscaled_inbound_dropped_packets_total{reason="acl"}`.
10. Whether `[v1] Accept:` filter lines show at default verbosity, and the scope of `logIPs` that gates filter logging.
11. Whether the TSMP "rejected" message is shown anywhere on the *sender*. A source comment says the "GUI or tailscale CLI can show them a rejection history", but no command was found.
12. Whether ufw or nftables rules can drop tailscale0 traffic despite Tailscale's netfilter `on` accept rules, per firewall mode. Also ufw's default ICMP handling, which is ufw behaviour and not in Tailscale docs.
13. That `sshHostKeys` in `tailscale status --json` reliably marks a peer running Tailscale SSH.
14. Which client version introduced `tailscale get`. The hosts' client versions are not known.
15. Whether `autogroup:member` is accepted as a test `src`.
16. **MC's actual policy file, and the three hosts' firewall, netfilter-mode and RunSSH state.** None of it was observed this session. That port 22 is missing from the policy is still the previous session's hypothesis.

---

## Design implications for the CLI and skill

1. **`policy test`.** Wrap `POST /acl/validate` in array mode. It is read-only, needs only `policy_file:read`, and is the quickest way to prove or rule out a policy drop. Parse the body: HTTP 200 with `message`/`data[].errors` is a **failure**. Report `want/got` per address.
2. **`policy preview --dst <ip:port>` and `--user <email>`.** Wrap `POST /acl/preview`, sending the live policy (from `GET /acl`) as the body. State in the help text that `type=user` needs an email: tags cannot be previewed as a source, so use `policy test` for tag sources.
3. **`policy get`.** Ask for HuJSON by default (no `Accept: application/json`) so MC's comments survive display and editing. Ask for JSON only when parsing. Never write a policy re-serialised by `json.dumps`. Record the `ETag`.
4. **No `policy set` with the chosen credential.** `POST /acl` needs `policy_file`. Two options:
   - the skill emits a reviewed HuJSON diff, already run through `policy test`/validate, for MC to apply in the admin console; or
   - a future credential adds `policy_file`. That write must go through the write guard with validate first and `If-Match`, and be logged.
5. **Check the credential's scope set at setup.** [trust-credentials] says `policy_file:read` requires `devices:posture_attributes:read`. Have the CLI's `whoami`/`doctor` call `GET /acl` and `/acl/validate` once and report a 403 clearly.
6. **A diagnose recipe in the skill (not CLI code).** The ladder in (d), split by where each step runs:
   - From the API: `policy test`, `policy preview`.
   - From the source: `tailscale ping --tsmp`/`--icmp`.
   - On the destination: `tailscale metrics print` (acl counter), `journalctl -u tailscaled` (the `Drop: … no rules matched` line), `tcpdump -i tailscale0 port 22`, `ufw status verbose`, `tailscale get ssh|shields-up|netfilter-mode`.
   Prefer documented commands. Flag `tailscale debug …` as hidden and unstable.
7. **The skill must state plainly** that `ssh` rules and `sshTests` do not open network access, and do not apply to plain OpenSSH. Port 22 needs an `acls` or `grants` rule. This corrects upstream U8.
8. **Device facts for tag effects.** Expose `tags`, `user` and `keyExpiryDisabled` from `GET /device/{id}` (scope `devices:core`) so the skill can flag a tagged device whose key expiry was never disabled (U6).
9. **Audit log.** Validate and preview are read-only, but they are autonomous actions that feed decisions. Append them to the audit log (request summary, verdict), never the policy text in full.
10. **Override upstream where it is wrong.** The skill defers general knowledge to the official upstream skill, but must explicitly override U1–U6, U8, U11 and U12. Cite the docs URLs above rather than restating, so drift is easy to recheck.

---

## Sources

All docs were fetched on 2026-10-26 as Markdown, using `curl` with `.md` appended to the URL. Dates are each page's "Last validated" line.

| Key | URL | Last validated |
|---|---|---|
| [tailnet-policy-file] | https://tailscale.com/docs/features/tailnet-policy-file | May 21, 2025 |
| [syntax/policy-file] | https://tailscale.com/docs/reference/syntax/policy-file | Apr 8, 2026 |
| [syntax/grants] | https://tailscale.com/docs/reference/syntax/grants | Jan 5, 2026 |
| [grants-vs-acls] | https://tailscale.com/docs/reference/grants-vs-acls | Aug 1, 2025 |
| [migrate-acls-grants] | https://tailscale.com/docs/reference/migrate-acls-grants | Mar 13, 2026 |
| [features/access-control/grants] | https://tailscale.com/docs/features/access-control/grants | Jul 24, 2026 |
| [grants-app-capabilities] | https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities | Dec 1, 2025 |
| [examples/grants] | https://tailscale.com/docs/reference/examples/grants | Jan 5, 2026 |
| [targets-and-selectors] | https://tailscale.com/docs/reference/targets-and-selectors | Jan 5, 2026 |
| [tags] | https://tailscale.com/docs/features/tags | Dec 4, 2025 |
| [key-expiry] | https://tailscale.com/docs/features/access-control/key-expiry | Jan 5, 2026 |
| [tailscale-ssh] | https://tailscale.com/docs/features/tailscale-ssh | Jan 5, 2026 |
| [ssh-over-tailscale] | https://tailscale.com/docs/reference/ssh-over-tailscale | Jan 12, 2026 |
| [ufw how-to] | https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw | Jan 5, 2026 |
| [manage-tailnet-policies] | https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies | Mar 13, 2026 |
| [troubleshooting/grants] | https://tailscale.com/docs/reference/troubleshooting/grants | Jan 12, 2026 |
| [connect-device-failure] | https://tailscale.com/docs/reference/troubleshooting/connectivity/connect-device-failure | Nov 14, 2025 |
| [tailscale-cli] | https://tailscale.com/docs/reference/tailscale-cli | Jul 30, 2026 |
| [ping-types] | https://tailscale.com/docs/reference/ping-types | Jan 13, 2026 |
| [route-injection] | https://tailscale.com/docs/reference/route-injection | Sep 29, 2026 |
| [tailscaled] | https://tailscale.com/docs/reference/tailscaled | Jan 5, 2026 |
| [tailscale-client-metrics] | https://tailscale.com/docs/reference/tailscale-client-metrics | Jul 28, 2026 |
| [netfilter-modes] | https://tailscale.com/docs/reference/netfilter-modes | Dec 29, 2025 |
| [firewall-mode] | https://tailscale.com/docs/features/firewall-mode | Dec 29, 2025 |
| [device-visibility] | https://tailscale.com/docs/concepts/device-visibility | Jan 5, 2026 |
| [network-flow-logs] | https://tailscale.com/docs/features/logging/network-flow-logs | Jan 23, 2026 |
| [trust-credentials] | https://tailscale.com/docs/reference/trust-credentials | Jan 30, 2026 |

**OpenAPI spec [openapi].** Local file `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/tsdocs/openapi.json`. It is YAML despite the name: OpenAPI 3.1.0, `info.version: v2`, server `https://api.tailscale.com/api/v2`, sha256 prefix `b3532da71b7bc5f3`. Paths used:
- `paths./tailnet/{tailnet}/acl.get` (`getPolicyFile`, scope `policy_file:read`; `Accept` header; `details` query)
- `paths./tailnet/{tailnet}/acl.post` (`setPolicyFile`, scope `policy_file`; `If-Match`; 412)
- `paths./tailnet/{tailnet}/acl/validate.post` (`validateAndTestPolicyFile`, scope `policy_file:read`)
- `paths./tailnet/{tailnet}/acl/preview` (path-level params `type` and `previewFor`; scope `policy_file:read`) and `.post` (`previewRuleMatches`)
- `components.schemas.Device` (`tags`, `user`, `keyExpiryDisabled`, `expires`)
- `paths./device/{deviceId}/key.post` (`updateDeviceKey`, scope `devices:core`)
- `paths./device/{deviceId}/tags.post` (`setDeviceTags`, scope `devices:core`)

**Tailscale client source [source-code].** `github.com/tailscale/tailscale` at commit `de16943cbf034d2c8238052dae4b2380837fe765`, the `main` head on 2026-10-26, read through raw.githubusercontent.com:
- `cmd/tailscale/cli/debug.go:69` (hidden, "not a stable interface"); `:103` daemon-logs; `:257` prefs; `:291` netmap; `:721-732` runNetmap
- `ipn/localapi/debug.go:252-264` (`current-netmap`, internal shape)
- `types/netmap/netmap.go:42-43` (`PacketFilter`, `PacketFilterRules`)
- `net/tstun/wrap.go:1150` (`filterPacketInboundFromWireGuard`); `:1215` (`RunIn`); `:1234-1252` (TSMP reject `RejectedDueToACLs`, no RST); `:1306`, `:1325` (filter before TUN write)
- `wgengine/filter/filter.go:338-366` (rate-limited log format); `:443-472` (`RunIn`); `:520` (ICMP if any port open); `:533` (tcp non-syn accepted); `:552` (tsmp ok); `:559` ("no rules matched")
- `net/packet/packet.go:82-98` (`PROTO{src > dst}` string)
- `ipn/ipnstate/ipnstate.go:259-261` (`Tags`); `:315-316` (`sshHostKeys`)
- `ipn/prefs.go:81` (`RouteAll`); `:137-140` (`RunSSH`); `:164` (`ShieldsUp`); `:246` (`NetfilterMode`)

**HuJSON [hujson README].** `github.com/tailscale/hujson` `README.md` at commit `b80ff77dac4f3b606c8bf0a28a84b33e68d07f60` (HEAD on 2026-10-26), lines 1-26.

**Upstream official skill (compared, not trusted).** `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/upstream/tailscale-skill`, commit `4f05d353efc56962546aa26ccc59bb08ca699ad1` (2026-07-09). Files: `skills/tailscale/references/access-control.md` (lines cited above), `references/cli.md:124`, `references/api.md:99-103`, `references/common-tasks.md:118`.

**Local copies of every fetched page:** `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/docs-policy/` (doc Markdown) and `/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/ts-src/` (source files).
