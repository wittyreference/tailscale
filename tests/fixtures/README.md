# Test fixtures

Every fixture names its source. A file under `api/` is a body the spec documents, with the spec
lines it came from; a file under `scenario/` is shaped like MC's tailnet but made up, and says so.
JSON fixtures carry the same statement in a top-level `"_source"` key, which the loopback seam
strips before it serves a body (the real API never sends it). `[spec NNNN]` is a line of
`spec/tailscale-openapi.yaml`.

| Fixture | Source |
|---|---|
| `api/device.json` | The Device schema's per-field examples [spec 4461-4822], gathered into one object. They are not one coherent device: `connectedToControl` is true beside a `lastSeen` the spec says is then omitted [spec 4543-4548] |
| `scenario/devices.json` | Synthetic, from the Device schema [spec 4461-4822]: six MC-shaped devices (the droplet on `tag:dev`, three fleet boxes on `tag:fleet` with key expiry on, MC's laptop and phone). Names, IDs and addresses are made up; expiry dates are in 2099 so the calendar never changes a test |
