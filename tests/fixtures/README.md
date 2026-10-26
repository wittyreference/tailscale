# Test fixtures

Every fixture names its source. A file under `api/` is a body the spec documents, with the spec
lines it came from; a file under `scenario/` or `status/` is shaped like MC's tailnet but made up,
and says so.
JSON fixtures carry the same statement in a top-level `"_source"` key, which the loopback seam
strips before it serves a body (the real API never sends it). `[spec NNNN]` is a line of
`spec/tailscale-openapi.yaml`.

| Fixture | Source |
|---|---|
| `api/device.json` | The Device schema's per-field examples [spec 4461-4822], gathered into one object. They are not one coherent device: `connectedToControl` is true beside a `lastSeen` the spec says is then omitted [spec 4543-4548] |
| `api/dns-nameservers.json` | `GET /tailnet/{tailnet}/dns/nameservers`'s 200 body, its `dns` example [spec 1531-1557] |
| `api/dns-preferences.json` | `DnsPreferences`, its `magicDNS` example [spec 5613-5622] |
| `api/dns-searchpaths.json` | `DnsSearchPaths`, its `searchPaths` example [spec 5623-5636] |
| `api/dns-split.json` | `SplitDns`, its example map of domain to nameservers [spec 5637-5653] |
| `api/dns-configuration.json` | `DnsConfiguration`'s `nameservers`, `splitDNS` and `searchPaths` examples [spec 5680-5724] with the `DnsConfigurationPreferences` field examples [spec 5667-5679]. Whether `dns:read` covers this endpoint is unverified [critic Q23] |
| `api/policy.hujson` | `ExampleHuJSONPolicyFile` [spec 6757-6778], the value's text with the YAML block's indentation removed: the policy file as `GET /tailnet/{tailnet}/acl` serves it as HuJSON, comments and trailing commas included [spec 2260-2265]. HuJSON has no `_source` key, so this row is its citation |
| `api/policy.json` | `ExampleJSONPolicyFile` [spec 6742-6756]: the same endpoint's `application/json` form [spec 2244-2251] |
| `api/validate-tests-failed.json` | `POST /tailnet/{tailnet}/acl/validate`'s 200 example `testsOrValidationFailed` [spec 2660-2667]: a failed test is still HTTP 200 (critic R2) |
| `api/validate-scim-warnings.json` | The same endpoint's 200 example `validateSCIMGroupsNotSynced` [spec 2668-2675]: warnings only |
| `api/validate-success.json` | The same endpoint's 200 example `testsOrValidationSuccess`, an empty object [spec 2676-2678]; an empty body also passes [spec 2642] |
| `scenario/devices.json` | Synthetic, from the Device schema [spec 4461-4822]: six MC-shaped devices (the droplet on `tag:dev`, three fleet boxes on `tag:fleet` with key expiry on, MC's laptop and phone). Names, IDs and addresses are made up; expiry dates are in 2099 so the calendar never changes a test |
| `scenario/policy.json` | Synthetic, in the JSON form of a policy file [spec 6742]: MC-shaped `tagOwners` and rules for the write tests. `tag:fleet` owns itself, `tag:lab` and `tag:ci`, so a write client tagged `tag:fleet` may assign those (TAGS L324); `tag:dev` is owned by admins only |
| `status/self-running.json` | Synthetic `tailscale status --json` for the droplet: the real field names of `ipnstate.Status` and `PeerStatus` [ipnstate:43-50, 239-316], indented with a space after each colon as the real binary prints it [mc §5]. Values match `scenario/devices.json`. Used only by the `selfnode` parser tests; e2e E2 checks the parser against the real binary |
