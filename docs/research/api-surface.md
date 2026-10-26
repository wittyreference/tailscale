# Tailscale API surface for the `wittyreference/tailscale` CLI

Reference for every Tailscale REST endpoint the CLI will call, plus the OAuth token
exchange, error format, pagination, rate limiting, tailnet shorthand and device IDs.
Researched 2026-10-26.

**How to read the citations**

- `spec:NNNN` is a line in the OpenAPI document. The local copy is
  `scratchpad/tsdocs/openapi.json` (it is YAML despite the extension). Its sha256 is
  `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`. On 2026-10-26 it was
  byte-identical to the live document at
  `https://api.tailscale.com/api/v2?outputOpenapiSchema=true` (same sha256; served as
  `application/yaml`). The spec carries no date, only `version: v2` (spec:51). It also warns
  about itself: *"The API endpoints documented here are stable unless otherwise noted. However,
  the OpenAPI spec used to generate this documentation is unstable. It may change or break
  without notice."* (spec:7)
- `[TC]`, `[OC]` and the other bracketed tags are docs pages. The Sources section gives each
  one's URL and "Last validated" date.
- `[GO]` is Tailscale's own Go client, `tailscale/tailscale-client-go-v2` at commit
  `9412c90d30928a9d496f3b30a1dde0d67913b3e9`. It is cited as observed behaviour of
  first-party code, not as documentation.
- `[LIVE]` is a request made on 2026-10-26 without valid credentials. It changed nothing.
- **[unverified]** marks a gap that no confirmed source closes. Nothing below fills a gap by
  inference.

---

## 1. Base URL and authentication

| Item | Value | Source |
|---|---|---|
| Base URL | `https://api.tailscale.com/api/v2` | spec:13, spec:56 |
| Auth (bearer) | `Authorization: Bearer <access token>` | spec:21-28, spec:48-50 (`securitySchemes.bearerAuth`) |
| Auth (basic) | access token as the Basic username, blank password (`curl -u "$TOKEN:"`) | spec:20-25 |
| OAuth client secret prefix | `tskey-client-` | spec:33; `[KP]` table |
| User API access token prefix | `tskey-api-`, 1 to 90 day expiry | spec:31; `[API]` line 16 |
| Prefix of an OAuth-derived access token | **[unverified]**. `[OC]`'s example response shows `"access_token":"tskey-0123456789ABCDEF..."`, and `[KP]` lists no prefix for it | `[OC]` line 132 |
| Trust credential = OAuth client **or** federated identity | "Trust credentials come in two forms: OAuth clients and federated OIDC workload identities" | `[TC]` line 9; spec:33 |
| Who can create an OAuth client with `devices:core` | Owners and Admins can grant any scope or tag; "a Network admin cannot grant the `devices:core` scope, but an IT admin can" | `[OC]` line 30 |
| Revocation | "When you revoke a trust credential, any active API access tokens that the credential created are also revoked." | `[TC]` line 388 |
| Audit of token minting | Each token creation is written to the configuration audit log, with the trust credential's Client ID as the actor | `[TC]` line 392 |

---

## 2. OAuth token endpoint (client credentials)

The OpenAPI spec does **not** contain this endpoint (`grep -c oauth/token` on the spec returns 0).
The only documentation is `[OC]`.

| Item | Value | Source |
|---|---|---|
| Method and path | `POST https://api.tailscale.com/api/v2/oauth/token` | `[OC]` line 60; `[GO]` oauth.go:33 |
| Standard | "accepts requests that conform to the OAuth 2.0 client credentials grant request format [RFC 6749 §4.4.2], and returns responses that conform to … [§4.4.3]" | `[OC]` line 62 |
| Encoding | form-encoded (`curl -d`) | `[OC]` lines 122-125 |
| `client_id` | the client ID | `[OC]` line 123 |
| `client_secret` | the `tskey-client-…` secret | `[OC]` line 123 |
| `grant_type` | `client_credentials`. RFC 6749 §4.4.2 marks it REQUIRED, and the docs claim RFC conformance, but the docs' own curl example leaves it out. Whether the server needs it is **[unverified]**. Send it anyway: that is what the RFC says and what the Go `clientcredentials` library sends | `[OC]` lines 62, 123 |
| `scope` (optional) | a space-delimited list of requested scopes. "The OAuth client must have permission to grant the requested scopes and tags." | `[OC]` line 64 |
| `tags` (optional, not part of the OAuth standard) | a space-delimited list of tags. "Tags are only relevant for tokens with the `devices:core`, `auth_keys`, or `all` scopes. The OAuth client ignores tags if none of these scopes are present." | `[OC]` lines 64-66 |
| Client auth in an HTTP Basic header | **[unverified]**. The docs show only form parameters. `[GO]` uses `golang.org/x/oauth2/clientcredentials` with its default auto-detected auth style, which does not show which style the server accepts | `[GO]` oauth.go:29-34 |
| Response fields | `access_token` (string), `token_type` (`"Bearer"`), `expires_in` (integer seconds; the example is `3600`), `scope` (string; the example is `"devices"`, a **legacy** scope name) | `[OC]` line 132 |
| Token lifetime | "An API access token expires after one hour." "This time cannot be modified." | `[OC]` lines 20, 272 |
| Format of the returned `scope` string with several scopes | **[unverified]**. Probably space-delimited, as in RFC 6749 §3.3, but no Tailscale source shows a multi-scope example | — |
| Error body for bad credentials | `401`, `{"message":"API token invalid"}`, `content-type: application/json`. This is the Tailscale error shape, **not** the RFC 6749 §5.2 `{"error":"invalid_client"}` shape | `[LIVE]` 2026-10-26 01:35:30Z, request id `REQ-202610260135300d1f3025a3e59fde` |
| Can a client with `devices:core` mint a token scoped only to `devices:core:read`? | **[unverified]**. The docs show only that a client with `all` can request `devices:core` plus a tag (`[OC]` line 64) | — |
| Tags on a `devices:core` token when no `tags` parameter is sent | **[unverified]** | — |

---

## 3. Conventions shared by every endpoint

### 3.1 Tailnet path parameter and the `-` shorthand
- `{tailnet}` takes either `-` ("reference the default tailnet of the access token being
  used … the best option for most users") or the **tailnet ID** shown on the admin console's
  General Settings page (example `T1234CNTRL`). spec:4052-4083.
- "Tailnets created before Oct 2025 can still use the legacy ID, but the Tailnet ID is the
  preferred identifier." spec:4058. In October 2025 the admin console renamed the
  **Organization** field to **Legacy ID**, and tailnets created after that do not show it.
  `[TN]` lines 73-83.
- Using `-` is "equivalent … as long as the access token is owned by the `example.com`
  tailnet". `[OC]` lines 161-177.
- The spec's example value for the parameter is still `example.com`, the legacy form
  (spec:4083).

### 3.2 `deviceId`: `nodeId` versus `id`
- Path parameter: "ID of the device. Using the device's `nodeId` is preferred, but its numeric
  `id` value can also be used." spec:4125-4132.
- `Device.id` is "the legacy identifier … although "id" is still accepted, "nodeId" is
  preferred" (example `'92960230385'`). `Device.nodeId` is "the preferred identifier", for
  example `n292kg92CNTRL`. spec:4482-4495.
- `[GO]` devices.go agrees: "Using the device `NodeID` is preferred, but its numeric `ID` value
  can also be used."

### 3.3 Error response body
- Schema `Error`: `{ "message": string }` with `message` required. spec:4823-4829. The overview
  says errors "may include additional information in the response body" in that shape
  (spec:37-45).
- Shared response components (all `Error`-shaped): `400` bad request, `402` payment required
  ("The `message` field says which change"), `403`, `404`, `409`, `429`, `500`, `501`, `502`,
  `504`. spec:6657-6740.
- Policy validation failures add a `data` array, `[{ "user": string, "errors": [string] }]`,
  or `warnings: [string]` in place of `errors` (spec:2648-2675). `[GO]` client.go:72-82
  decodes errors into exactly `{message, data[{user, errors}]}`.
- **`401` is not documented anywhere in the spec** (`grep -c "'401'"` returns 0). Live, a
  missing or invalid token returns `401` with `{"message":"API token invalid"}`. `[LIVE]`
  2026-10-26 01:35:29Z on `GET /tailnet/-/devices`, request id
  `REQ-202610260135297edf4d030be8b167`.
- Every live response carried an `x-tailscale-request-id: REQ-…` header. The spec does not
  document it. `[LIVE]`
- The status a valid token gets when it lacks the needed **scope** (403? 404?) is
  **[unverified]**. The spec lists `403` only on the ACL endpoints, the key-delete endpoint and
  a few others, and never on the device endpoints.

### 3.4 Pagination
- The overview says: "The Tailscale API does not currently support pagination. All results are
  returned at once." spec:47-49.
- **The same spec contradicts this.** `GET /organizations/{organization}/tailnets` (Alpha) takes
  `limit` (1-100, default 100) and an opaque `cursor`, and returns `cursor` and `totalCount`.
  spec:3951-4001, spec:6587-6602.
- None of the endpoints the CLI uses declares a paging parameter or a paging response field.
  For our surface, one call returns everything.

### 3.5 Rate limiting, 429, Retry-After
- No first-party doc found states rate limits for the management API. A site-restricted search
  of tailscale.com on 2026-10-26 found only Aperture's 429 behaviour, which belongs to a
  different product. **[unverified]** whether limits exist or what they are.
- The spec defines a `429` component ("Too Many Requests", `{"message":"too many requests"}`,
  spec:6701-6708). Only the device posture-attribute POST and DELETE reference it
  (spec:747, spec:770). None of our endpoints lists `429`.
- The only stated rate limit in the spec is "Invite resends are rate limited to one per minute"
  (spec:1040, spec:1105).
- **`Retry-After` is not documented anywhere in the spec.** No response in the spec declares any
  header at all (`grep "headers:"` finds nothing). Whether a 429 carries `Retry-After` is
  **[unverified]**. The live 401 responses carried no rate-limit headers.
- `[GO]` client.go:345-392 has no retry or back-off logic.

### 3.6 Media types
- Bodies and responses are JSON "typically" (spec:9). The policy-file endpoints also accept and
  return `application/hujson` (§6).

---

## 4. OAuth scopes: the map that matters for MC's credential

The chosen credential has `devices:core` (write), `policy_file:read` and `dns:read`. Here is
what the docs say each scope reaches. `[TC]` lines 37-374 hold the current scope table.

| Scope | Endpoints it reaches | Source |
|---|---|---|
| (any scope) | `GET /tailnet/:tailnet/keys/:keyID` "for the key in use" | `[TC]` line 45 |
| `devices:core:read` | `GET /tailnet/:tailnet/devices`, `GET /device/:deviceID` | `[TC]` lines 135-141 |
| `devices:core` | everything in `devices:core:read`, plus `DELETE /device/:id`, `POST /device/:id/authorized`, `/expire`, `/ip`, `/name`, `/key`, `/tags`. "You must select one or more tags when you create a credential with the devices:core scope." | `[TC]` lines 143-163; spec:2154 "Mandatory if the scopes include "devices:core" or "auth_keys"" |
| `devices:routes:read` | `GET /device/:id/routes` | `[TC]` lines 183-187 |
| `devices:routes` | everything in `devices:routes:read`, plus `POST /device/:id/routes` | `[TC]` lines 189-195 |
| `policy_file:read` | `GET /tailnet/:tailnet/acl`, `POST …/acl/preview`, `POST …/acl/validate`. **"devices:posture_attributes:read and devices:core:read are required when using this scope."** | `[TC]` lines 91-100 |
| `policy_file` | everything in `policy_file:read`, plus `POST /tailnet/:tailnet/acl` (requires `devices:posture_attributes` and `devices:core:read`) | `[TC]` lines 102-109 |
| `dns:read` | `GET …/dns/nameservers`, `/preferences`, `/searchpaths`, `/split-dns`. **`/dns/configuration` is not listed.** | `[TC]` lines 65-75 |
| `feature_settings:read` | `GET /tailnet/:tailnet/settings` (and the posture integration GETs) | `[TC]` lines 354-362 |
| `logs:network:read` | `GET …/logging/network` and `GET …/settings` | `[TC]` lines 322-328 |
| `api_access_tokens:read`, `auth_keys:read`, `oauth_keys:read`, `federated_keys:read` | `GET …/keys` and `GET …/keys/:keyID`, each limited to its own kind of key | `[TC]` lines 215-267 |
| `all:read` / `all` | "The all and all:read scopes are the only scopes which can get a list of all access tokens which exist in the tailnet." | `[TC]` lines 53-63 |

**`devices:core` reaches every device, not only tagged ones.** That is already confirmed: it
can "read the list of all devices in the tailnet, authorize or remove machines, and manipulate
tags" (`[TC]` lines 145-147). The client's tags constrain auth keys it mints.

**There is one nuance on tag writes.** `[TAGS]` line 324 says: *"When an OAuth client or auth
key assigns tags to a device, the requested tags must either exactly match the full set of
tags on the OAuth client or auth key, or each requested tag must be owned by one of the
authenticating entity's tags as defined in the `tagOwners` section."* So the client's tags
**do** constrain which tags `set tags` may apply. They do not constrain which devices can be
deleted, expired, renamed or re-addressed. What happens when you set an empty list (strip all
tags) under this rule is **[unverified]**.

---

## 5. Device endpoints

All device paths are `/device/{deviceId}`, with no tailnet segment, except the list endpoint.

### 5.1 List devices: `GET /tailnet/{tailnet}/devices`
- **Scope:** `devices:core:read` (spec:151). `devices:core` includes it (`[TC]` line 149).
- **Path parameter:** `tailnet`.
- **Query `fields`:** `all` or `default`; leaving it out means `default` (spec:4084-4124).
- **Query `<field>=<value>` filters (server-side):**
  - The field must be a top-level device property. Matching is exact. Simple types and lists
    are supported; complex objects such as `clientConnectivity` are not.
  - Several parameters are ANDed. For a list field, repeat the key:
    `isEphemeral=true&tags=tag:prod&tags=tag:subnetrouter` means the device must carry both
    tags.
  - spec:130-145.
- **Response 200:** `{ "devices": [Device] }` (spec:156-166).
- **Status codes:** 200, 404 (tailnet not found), 500, 504 ("Request took too long to process,
  please try again later"). spec:155-174.
- **Pagination:** none (§3.4).

**What `fields=default` returns** (spec:4092-4116), 23 fields:
`addresses`, `id`, `nodeId`, `user`, `name`, `hostname`, `clientVersion`, `updateAvailable`,
`os`, `created`, `connectedToControl`, `lastSeen`, `keyExpiryDisabled`, `expires`, `authorized`,
`isExternal`, `machineKey`, `nodeKey`, `blocksIncomingConnections`, `tailnetLockKey`,
`tailnetLockError`, `tags`, `isEphemeral`.

**What `fields=all` adds** (the Device schema minus the default list, computed from
spec:4461-4822):
`multipleConnections`, `enabledRoutes`, `advertisedRoutes`, `clientConnectivity`, `sshEnabled`,
`postureIdentity`, `postureStatus`, `distro`. `[GO]` devices.go:107-113 agrees ("only included
in listings when querying `all` fields").

Whether `fields=all` with a token that lacks `devices:routes:read` still includes
`enabledRoutes` and `advertisedRoutes` is **[unverified]**.

**Device fields worth displaying** (spec:4461-4822):

| Field | Type | Meaning and caveat |
|---|---|---|
| `nodeId` | string | preferred ID, e.g. `n292kg92CNTRL` |
| `id` | string | legacy numeric ID, still accepted |
| `name` | string | MagicDNS FQDN, e.g. `pangolin.tailfe8c.ts.net` |
| `hostname` | string | "The machine name in the admin console" |
| `addresses` | string[] | Tailscale IPv4 (100.x.y.z) and IPv6 (fd7a:115c:a1e0:…) |
| `user` | string | the user who registered it; for untagged nodes, the owner |
| `tags` | string[] | empty for external devices |
| `os`, `clientVersion` | string | `clientVersion` is empty for external devices |
| `updateAvailable` | boolean | |
| `created` | date-time | empty for external devices |
| `connectedToControl` | boolean | recently held a TCP connection to control |
| `lastSeen` | date-time | **"Omitted if the device has never been online or `connectedToControl` is true."** (spec:4548) |
| `expires` | date-time | key expiry |
| `keyExpiryDisabled` | boolean | |
| `authorized` | boolean | device approval state |
| `isExternal` | boolean | shared into the tailnet, not a member |
| `isEphemeral` | boolean | |
| `blocksIncomingConnections` | boolean | |
| `multipleConnections` | boolean (`all` only) | several devices are using one node key, "usually a sign of node state being copied". The field is omitted when it is not true, and it does not stick (spec:4575-4581) |
| `enabledRoutes`, `advertisedRoutes` | string[] (`all` only) | |
| `sshEnabled` | boolean (`all` only) | |
| `distro` | object `{name, version, codeName}` (`all` only) | |

### 5.2 Get device: `GET /device/{deviceId}`
- **Scope:** `devices:core:read` (spec:303).
- **Parameters:** path `deviceId`; query `fields` (`all`/`default`) (spec:307-308).
- **Response 200:** a `Device` (spec:310-315).
- **Status codes:** 200, 400 ("Invalid ID supplied."), 404, 500, 504 (spec:309-325).
- `[GO]` devices.go:127-156 sends `fields=all` only from `GetWithAllFields`. Its plain `Get`
  returns default fields.

### 5.3 Delete device: `DELETE /device/{deviceId}`
- **Scope:** `devices:core` (spec:333).
- **Rules:** "The device must belong to the requesting user's tailnet. Deleting devices shared
  with the tailnet is not supported." (spec:329-331)
- **Request body:** none.
- **Response 200:** no body schema.
- **Status codes:** 200, 400 ("Invalid device value."), 500, 501 ("Device not owned by
  tailnet."), 504 (spec:337-349).
- **404 is not listed.** What deleting a nonexistent ID returns is **[unverified]**.

### 5.4 Authorize or deauthorize: `POST /device/{deviceId}/authorized`
- **Scope:** `devices:core` (spec:462).
- **Body:** `{ "authorized": boolean }`, required. `true` authorizes or re-authorizes; `false`
  deauthorizes (spec:466-478). It only matters "for tailnets where device authorization is
  required" (spec:459).
- **Response 200:** no body.
- **Status codes:**
  - 200
  - 400: "The `authorized` field is missing from the request body, or is not a boolean."
  - 402: "The tailnet's plan or billing state does not allow authorizing more devices."
  - 404, 500, 504
  - spec:479-494.

### 5.5 Expire device key: `POST /device/{deviceId}/expire`
- **Scope:** `devices:core` (spec:360).
- **Body:** none.
- **Effect:** "Mark a device's node key as expired. This will require the device to
  re-authenticate in order to connect to the tailnet." (spec:356-358)
- **Status codes:** 200, 404, 500, 504 (spec:364-373).

### 5.6 Set device name: `POST /device/{deviceId}/name`
- **Scope:** `devices:core` (spec:506).
- **Body:** `{ "name": string }`, required.
  - Either the FQDN (`nodename.your-domain.ts.net`) or the base name is accepted.
  - "If `name` is unset or provided empty, the device's name is reset to be generated from its
    OS hostname."
  - spec:510-528.
- **Caution:** "Device name changes immediately get propogated through your tailnet … any
  existing Magic DNS URLs using the old name will no longer work." (spec:504)
- **Status codes:** 200, 404, 500, 504 (spec:529-538).

### 5.7 Set device tags: `POST /device/{deviceId}/tags`
- **Scope:** `devices:core` (spec:555).
- **Body:** `{ "tags": [string] }`, "The new list of tags for the device". The list **replaces**
  the old one (spec:559-573). The schema does not mark `tags` as required.
- **Constraints:**
  - Tags must be defined in the policy file with an owner (spec:548).
  - The OAuth tag-ownership rule in §4 applies (`[TAGS]` line 324).
  - Changing tags through the API does not change key expiry until the device re-authenticates
    (`[TAGS]` line 84).
- **Status codes:** 200, 400, 500, 504 (spec:574-582). **404 is not listed.**

### 5.8 Set key expiry: `POST /device/{deviceId}/key`
- **Scope:** `devices:core` (spec:592).
- **Body:** `{ "keyExpiryDisabled": boolean }`, required (spec:596-609).
  - `true` disables expiry. "The original key expiry time is still maintained. Upon
    re-enabling, the key will expire at that original time."
  - `false` re-enables it, back to the original time. "The key may already have expired. In
    that case, the device must be re-authenticated."
  - spec:606-607.
- **Status codes:** 200, 404, 500, 504 (spec:610-619).

### 5.9 Set device IPv4: `POST /device/{deviceId}/ip`
- **Scope:** `devices:core` (spec:634).
- **Body:** `{ "ipv4": string }`, required, e.g. `100.80.0.1` (spec:638-650). The address must
  come from the CGNAT range or the tailnet's IP pool (spec:626-628).
- **Caution:** "This action will break any existing connections to this machine." Clients may
  need a DNS cache flush (spec:630-632).
- **Status codes:** 200, 404, 500, 504 (spec:651-660).
- Which status a conflicting or out-of-pool address returns is **[unverified]**.

### 5.10 Routes: `GET` and `POST /device/{deviceId}/routes`
- **GET**
  - **Scope:** `devices:routes:read` (spec:389).
  - **Response 200:** `DeviceRoutes` = `{ "advertisedRoutes": [string], "enabledRoutes":
    [string] }` (spec:4830-4850).
  - **Status codes:** 200, 404, 500, 504.
- **POST**
  - **Scope:** `devices:routes` (spec:419).
  - **Body:** `{ "routes": [string] }`, required. It **replaces** the set of *enabled* routes.
    "Advertised routes cannot be set through the API" (spec:410-438).
  - **Response 200:** `DeviceRoutes`.
  - **Status codes:** 200, 404, 500, 504 (spec:439-452).
- Routes work only when both advertised and enabled (spec:383-385).
- **MC's credential does not include `devices:routes:read` or `devices:routes`.** `devices:core`
  does not list `/routes` (`[TC]` lines 143-163). As specified, both routes commands would be
  refused. See the design implications.

---

## 6. Policy file endpoints

### 6.1 Get policy file: `GET /tailnet/{tailnet}/acl`
- **Scope:** `policy_file:read` (spec:2222).
- **Header `Accept`:** `application/json` gets JSON; "otherwise HuJSON will be returned"
  (spec:4387-4393, spec:2217). Sending no `Accept` header therefore gets HuJSON. `[GO]` sets
  `Accept: application/hujson` for raw HuJSON (policyfile.go:215; client.go:295-300 sets `Accept` only on body-less requests and `Content-Type` otherwise).
- **Query `details`:** boolean. `details=true` returns JSON `{ "acl": <base64 HuJSON>,
  "warnings": [string], "errors": [string] | null }`. Any other value counts as false. "If using
  this, do not supply an `Accept` parameter in the header." (spec:2227-2240, example
  spec:2252-2259)
- **ETag:** "The response also includes an `ETag` header, which can be optionally included when
  setting the policy file to avoid missed updates." (spec:2218) This is prose only; no response
  header is declared. `[GO]` reads it as `header.Get("Etag")` (policyfile.go:209, 228).
- **Response 200:** `application/json` (a free-form object) or `application/hujson` (string).
- **Status codes:** 200, 400, 403, 404, 500 (spec:2241-2274).
- Whether the ETag value itself contains double quotes is **[unverified]**. `[GO]` strips quotes
  and re-adds them before sending `If-Match` (policyfile.go:237).

### 6.2 Set policy file: `POST /tailnet/{tailnet}/acl`
This is recorded for completeness. **MC's credential is read-only on policy; setting it needs
`policy_file`.**
- **Scope:** `policy_file` (spec:2286).
- **Body:** a JSON object (`application/json`) or HuJSON (`application/hujson`) (spec:2304-2317).
- **Header `If-Match`** (optional):
  - The `ETag` from a GET. The file is replaced only if it still matches.
  - Or `ts-default`, which replaces the file only if it is still the untouched default.
  - Examples: `-H "If-Match: \"e0b2816b418\""` and `-H "If-Match: \"ts-default\""`.
  - spec:2291-2303.
- **Response 200:** the updated policy as JSON or HuJSON, depending on `Accept` (spec:2281,
  spec:2319-2333).
- **Status codes:**
  - 200
  - 400: "ACL validation or test error."
  - 403, 404
  - **412**: "If-Match hash mismatch.", body `{"message": "precondition failed, invalid old
    hash"}`
  - 500
  - spec:2334-2351.

### 6.3 Validate and test: `POST /tailnet/{tailnet}/acl/validate`
- **Scope:** `policy_file:read` (spec:2520). It "does not modify the tailnet policy file in any
  way" (spec:2518).
- **Body form A, tests only:** a JSON **array** of tests, run "against the tailnet's current
  policy file". Each test object (spec:2529-2590):
  - `src` (string, required): a user, group, tag or host
  - `srcPostureAttrs` (object of string, number or boolean)
  - `proto` (string; when omitted, the test covers TCP or UDP)
  - `accept` ([string] of `host:port`)
  - `deny` ([string] of `host:port`)
  - no `*` wildcards in `src`, `accept` or `deny`
- **Body form B, a full candidate policy:** a JSON **object** (or `application/hujson`). It is
  treated as "a hypothetical new tailnet policy file". The server checks that it parses and runs
  its tests (spec:2513-2516, spec:2614-2639).
  - The spec's own schema types this branch as `type: string` ("The JSON representation of the
    policy file", spec:2591-2593), which contradicts "When the request body is a JSON object".
- **Response on pass:** `200` with an **empty body** ("An empty response body implies passing
  validation or tests", spec:2642). The spec's example shows `{}` (spec:2676-2678). `[GO]` treats
  status 200 with a zero-length body as a pass (policyfile.go:313-316). Treat both an empty body
  and `{}` as a pass.
- **Response on fail: still `200`**, with
  `{ "message": "test(s) failed", "data": [ { "user": "...", "errors": ["address \"2.2.2.2:22\": want: Drop, got: Accept"] } ] }`
  (spec:2659-2667).
- **Warnings: also `200`**, with `{ "message": "warning(s) found", "data": [ { "user": "...",
  "warnings": [...] } ] }` (spec:2668-2675).
- **Status codes:** 200, 400, 403, 404, 500 (spec:2640-2687).
- **The spec's example contains errors:**
  - `aclValidateJSON` has a syntax error, `"tests", [` (spec:2610).
  - It uses the legacy test key `allow` (spec:2611). `[POL]` line 922: "The legacy `allow`
    (instead of `accept`) continues to work … best practice to use `accept`."

### 6.4 Preview rule matches: `POST /tailnet/{tailnet}/acl/preview`
- **Scope:** `policy_file:read`. The spec states this inside the `type` parameter's description
  (spec:2390); `[TC]` line 98 agrees.
- **Query `type`** (required): `user` or `ipport`.
  - `user`: `previewFor` is a user's email. "`user` remains in the API for compatibility … has
    been replaced by `src`".
  - `ipport`: `previewFor` is `IP:port`. "has been replaced by `dst`".
  - spec:2384-2406.
- **Query `previewFor`** (required): an email "of a valid user with registered machines", or
  `10.0.0.1:80` (spec:2407-2417).
- **Body:** **a policy file** (JSON object or HuJSON) to query, "without saving the policy file
  to the server" (spec:2421-2440).
  - It is not a `{src, dst}` object.
  - Whether the body can be left out to preview the *current* policy is **[unverified]**.
- **Response 200:** `{ "matches": [ { "users": [string], "ports": [string], "lineNumber":
  integer } ], "type": string, "previewFor": string }`, all required (spec:2442-2492).
- **Status codes:** 200, 400, 403, 404, 500 (spec:2493-2501).

---

## 7. DNS endpoints (GET only; the credential has `dns:read`)

The spec states **no** OAuth scope for any DNS endpoint. The scope coverage comes from `[TC]`
lines 65-75.

| Endpoint | 200 response | Codes | Scope coverage |
|---|---|---|---|
| `GET /tailnet/{tailnet}/dns/nameservers` | `{ "dns": [string] }` (spec:1546-1557) | 200, 404, 500 | `dns:read` (`[TC]` line 69) |
| `GET /tailnet/{tailnet}/dns/preferences` | `DnsPreferences` = `{ "magicDNS": boolean }`, required (spec:5613-5622) | 200, 404, 500 | `dns:read` (`[TC]` line 71) |
| `GET /tailnet/{tailnet}/dns/searchpaths` | `DnsSearchPaths` = `{ "searchPaths": [string] }`, required (spec:5623-5636) | 200, 404, 500 | `dns:read` (`[TC]` line 73) |
| `GET /tailnet/{tailnet}/dns/split-dns` | `SplitDns` = a map from domain to `[string]` or `null` (spec:5637-5653) | 200, 404, 500 | `dns:read` (`[TC]` line 75). `[OC]` lines 11-16 leave split-dns out of the `dns:read` example list |
| `GET /tailnet/{tailnet}/dns/configuration` | `DnsConfiguration` = `{ "nameservers": [{address, useWithExitNode}], "splitDNS": {domain: [{address, useWithExitNode}] \| null}, "searchPaths": [string], "preferences": {overrideLocalDNS, magicDNS} }` (spec:5654-5724) | 200, 404, 500 | **[unverified]**. `[TC]`'s `dns:read` list does not include it |

Notes:
- `useWithExitNode` keeps a resolver in use while an exit node is active. It needs client
  v1.88.1 or later (spec:5665).
- `overrideLocalDNS: true` makes `nameservers` override the OS resolver; `false` uses them as
  fallback. Both preferences default to false on set (spec:5670-5674, spec:1816-1820).

---

## 8. Tailnet settings: `GET /tailnet/{tailnet}/settings`

- **Scopes**, per the spec (spec:3473-3479):
  - `feature_settings:read` for "all settings except those governed by the below scopes"
  - `logs:network:read` for `networkFlowLoggingOn`
  - `networking_settings:read` for "`httpsCertificates`"
  - `policy_file:read` for `aclsExternallyManagedOn` and `aclsExternalLink`
- **Response 200:** `TailnetSettings` (spec:6234-6344):

| Field | Type |
|---|---|
| `aclsExternallyManagedOn` | boolean or null |
| `aclsExternalLink` | uri |
| `adminConsoleSessionTimeoutMinutes` | int, 0-43200 |
| `devicesApprovalOn` | boolean or null |
| `devicesAutoUpdatesOn` | boolean or null |
| `devicesKeyDurationDays` | int, 1-180 |
| `usersApprovalOn` | boolean or null |
| `usersRoleAllowedToJoinExternalTailnets` | `none`, `admin` or `member` |
| `networkFlowLoggingOn` | boolean or null |
| `regionalRoutingOn` | boolean or null, readOnly |
| `routeSelection` | `active-passive-failover`, `regional-routing`, `regional-routing-failover` or `magicroute` |
| `postureIdentityCollectionOn` | boolean or null |
| `httpsEnabled` | boolean or null |

- **Status codes:** 200, 400, 404, 500 (spec:3483-3496).
- **MC's credential has only `policy_file:read` from that list.** The response for a token
  without `feature_settings:read` is **[unverified]**: an object with only the two `acls*`
  fields, or a refusal.
- **The spec contradicts itself:** the scope text names a `httpsCertificates` setting
  (spec:3477), but the schema field is `httpsEnabled` (spec:6338). Also, `[TC]` has no
  `networking_settings` entry, and it lists `GET /settings` under `logs:network:read` and
  `feature_settings:read` only (`[TC]` lines 328, 362).

---

## 9. Keys

### 9.1 List keys: `GET /tailnet/{tailnet}/keys`
- **Scopes:** each grants one kind of key (spec:1854-1860):
  - `api_access_tokens:read`: personal API access tokens
  - `auth_keys:read`: auth keys
  - `oauth_keys:read`: OAuth clients
  - `federated_keys:read`: federated identities
- **Query `all`:** boolean. "If set to true, this will return all auth keys, API access tokens
  and OAuth clients for the tailnet."
  - The parameter is declared `required: true` (spec:4369-4376).
  - The endpoint text contradicts that: "If the parameter {all} was not specified, the set of
    keys returned depends on the access token". With an OAuth-derived token, "this returns all
    OAuth clients for the tailnet." (spec:1849-1852)
- **Response 200:** `{ "keys": [Key] }` (spec:1867-1910).
- **Status codes:** 200, 404, 500.
- `[TC]` lines 54 and 60: only `all` and `all:read` can list *all* access tokens.

### 9.2 Get key: `GET /tailnet/{tailnet}/keys/{keyId}`
- **Scopes:** as for the list (spec:2059-2065).
- **Self-lookup:** any scope may read "the key in use" (`[TC]` line 45), "for itself only"
  (`[OC]` line 16). Whether `keyId` here means the OAuth client's ID or the minted token's ID is
  **[unverified]**.
- **Response 200:** a `Key`. Revoked or expired keys have `invalid: true` (spec:2070-2078).
- **Status codes:** 200, 404 ("Tailnet or key not found."), 500.

### 9.3 `Key` schema (spec:5773-5898)
- `id` (string, e.g. `k123456CNTRL`)
- `key` (string; secret material, "only populated at creation time")
- `keyType` (`auth`, `client`, `api` or `federated`)
  - `api` covers personal tokens **and** tokens generated from an OAuth client or federated
    identity.
- `expirySeconds` (int64; auth keys only)
- `created`, `updated`, `expires`, `revoked` (date-time)
- `capabilities` (`KeyCapabilities`, `devices.create.{reusable, ephemeral, preauthorized,
  tags}`; auth keys only)
- `scopes` ([string]; OAuth clients, API tokens and federated identities)
- `tags` ([string]; trust credentials)
- `description` (string)
- `invalid` (boolean)
- `userId` (string; "empty for keys created by trust credentials")
- federated only: `audience`, `issuer`, `subject`, `customClaimRules`

**MC's credential holds none of the four `*_keys:read` / `api_access_tokens:read` scopes.**
Listing keys would be refused (the exact status is **[unverified]**). Only the self-lookup in
§9.2 is documented as reachable.

---

## 10. Stale or wrong claims in the upstream skill

File: `upstream/tailscale-skill/skills/tailscale/references/api.md`, at commit
`4f05d353efc56962546aa26ccc59bb08ca699ad1` (2026-07-09).

| Line | Upstream claim | What the sources say |
|---|---|---|
| 13 | OAuth scopes are "`devices:read`, `devices:write`, `dns:read`, others" | `devices:read` is a **legacy** scope (`[TC]` lines 482-500; new trust credentials have used the new scopes since 2024-11-14, `[TC]` line 400). `devices:write` does not exist in either scope set. Current names: `devices:core`, `devices:core:read`, `devices:routes`, `devices:routes:read`, `devices:posture_attributes`, `auth_keys` (`[TC]` lines 135-247, legacy map at lines 556-564) |
| 11-14 | three auth options: API tokens, OAuth clients, and "Trust credentials … attribute-based limits … key/value claims" as a separate third kind | OAuth clients **are** trust credentials. The two kinds of trust credential are OAuth clients and federated identities (`[TC]` line 9; spec:33). So there are two credential families, and "attribute-based limits" has no source |
| 15 | "HuJSON … for the ACL endpoint" | Partly true. GET returns JSON when `Accept: application/json` is sent and HuJSON otherwise. POST, validate and preview accept either (spec:4393, spec:2304-2317) |
| 16 | "**No pagination** today — list endpoints return everything" | Matches the spec overview (spec:47-49) and holds for the tailnet-scoped lists, but the spec contradicts itself: `/organizations/{organization}/tailnets` paginates with `limit`/`cursor` (spec:3969-3983, spec:6595-6598) |
| 17 | "No published rate limits … back off on 429s" | No management-API limits found (**[unverified]** that none exist). But the spec does publish one ("Invite resends are rate limited to one per minute", spec:1040, spec:1105) and defines a 429 component (spec:6701). No `Retry-After` is documented |
| 63, 108 | `lastSeen` is "the standard field for 'is this device still active?' filtering", so bulk-delete stale devices by `lastSeen` | `lastSeen` is "**Omitted** if the device has never been online or `connectedToControl` is true" (spec:4548). A naive filter treats online and never-seen devices as missing data. Also, `id` is the legacy ID; `nodeId` is preferred (spec:4482-4495) |
| 91 | "GET returns HuJSON + an ETag" | It returns HuJSON only when `Accept` is not `application/json` (spec:4393). The ETag is in prose only (spec:2218) |
| 96 | `-H "If-Match: \"$ETAG\""` | If the ETag header already carries quotes, this double-quotes it (**[unverified]** which form the server sends; `[GO]` trims quotes before re-adding them, policyfile.go:237). Not documented: `ts-default` (spec:2302-2303) and 412 on mismatch (spec:2342-2349) |
| 100-103 | "Preview / validate before applying" with body `{"src":"alice@example.com","dst":"tag:server"}` sent to `/acl/preview` | **Wrong shape.** Preview needs the query parameters `type=user\|ipport` and `previewFor=...`, and its body is a **policy file** (spec:2384-2440). Validate is a separate endpoint (`/acl/validate`) that takes a tests array or a full policy (spec:2508-2516) |
| 108 | "Throttle to avoid 429s" | Sensible, but no source states a limit for device delete; DELETE does not list 429 (spec:337-349) |
| 117, 131 | for "endpoints, fields, query parameters", fetch `https://tailscale.com/docs/reference/tailscale-api` | That page (Last validated Jun 24, 2026) holds only auth and OAuth-app node-attribute notes and links out to the interactive `/api` docs. It has **no** endpoint reference (`[API]` lines 1-41). The machine-readable source is `https://api.tailscale.com/api/v2?outputOpenapiSchema=true` |
| 118, 133 | "For OAuth scope names … fetch the OAuth clients page" | Scopes "moved to the trust credentials topic" (`[OC]` lines 261-263). Use `https://tailscale.com/docs/reference/trust-credentials#scopes` |
| 31-34 | token request includes `grant_type=client_credentials` | Not stale. It is RFC-correct; the official docs example leaves it out (`[OC]` line 123) |

The same theme recurs in a related file,
`upstream/.../references/enterprise.md:97`: "Scopes are tag-restricted (the client can only
operate on tags it owns)." That contradicts `[TC]` lines 145-147. `devices:core` reaches every
device; tags constrain auth keys and tag assignment (`[TAGS]` line 324), not which devices can
be deleted or expired.

---

## 11. Inconsistencies inside first-party sources (for the record)

1. **Pagination.** The spec says there is none (spec:49), but `listOrganizationTailnets`
   paginates (spec:3969-3983).
2. **`all` on list keys.** The parameter is declared `required: true` (spec:4373), but the
   endpoint text describes the behaviour when it is "not specified" (spec:1849).
3. **Settings field name.** The scope text names `httpsCertificates` (spec:3477, 3506); the
   schema field is `httpsEnabled` (spec:6338).
4. **Validate body type.** The schema's alternative is `type: string` (spec:2591), but the prose
   says a JSON object (spec:2513). The JSON example is syntactically invalid (spec:2610).
5. **Validate pass body.** The prose says an empty body (spec:2642); the example shows `{}`
   (spec:2678).
6. **`dns:read` coverage.** `[TC]` lists four GETs including split-dns; `[OC]` lists three
   without split-dns (`[OC]` lines 11-16). Neither lists `/dns/configuration`.
7. **Token response example.** It uses the legacy scope string `"devices"` (`[OC]` line 132).
8. **Typos and path mismatches in `[TC]`:**
   - `devices_invites:read` versus `device_invites:read` (lines 197, 209)
   - "Endpoints from user:read" (line 123)
   - `logstreaming:read` (line 312)
   - `[TC]` writes `/api/v2/user/:userID`, but the spec's path is `/users/{userId}`
     (spec:2956)
   - `[TC]` lists `GET …/logging/:logType/status`, but the spec's path is
     `…/logging/{logType}/stream/status` (spec:1343)
9. **Undocumented status.** The spec documents no `401`, yet the live API returns it for an
   invalid token (`[LIVE]`).
10. **Console host.** The docs link `console.tailscale.com/admin/...`; the spec still links
    `login.tailscale.com/admin/...` (spec:31, spec:4070).

---

## 12. Design implications for the CLI and skill

1. **The chosen credential cannot reach `routes get` or `routes set`.** They need
   `devices:routes:read` and `devices:routes` (spec:389, spec:419; `[TC]` lines 183-195). Either
   add those scopes to the OAuth client, or drop the routes commands. A read-only alternative is
   showing `enabledRoutes`/`advertisedRoutes` from `devices list --fields=all`, but whether that
   needs the routes scope is **[unverified]**.
2. **`policy_file:read` "requires" `devices:posture_attributes:read` and `devices:core:read`**
   (`[TC]` line 94). The credential as specified (`devices:core`, `policy_file:read`,
   `dns:read`) lacks `devices:posture_attributes:read`. Add it when creating the client. Whether
   the admin console enforces this or adds it automatically is **[unverified]**.
3. **`settings get` needs `feature_settings:read`** for almost every field (spec:3473). Add it,
   or have the CLI display only `aclsExternallyManagedOn` and `aclsExternalLink`. Test what the
   API returns without it before shipping (**[unverified]**).
4. **`dns configuration`** is not in the documented `dns:read` list. Implement it as optional
   and handle a refusal gracefully; the four granular DNS GETs are documented.
5. **`keys list` is out of reach.** It needs one of the `*_keys:read` /
   `api_access_tokens:read` scopes. The documented self-lookup
   (`GET /tailnet/-/keys/{keyId}` "for the key in use") makes a good `whoami` that reports
   `scopes` and `tags`, once it is confirmed which ID it accepts.
6. **Mint least-privilege tokens per command.** The token endpoint takes a `scope` parameter that
   can narrow the request (`[OC]` line 64). Read commands can request only read scopes; the
   write guard can mint a `devices:core` token only after its confirmation step. Whether
   narrowing `devices:core` to `devices:core:read` is accepted is **[unverified]**; test it
   live.
7. **Token handling:**
   - Cache the token in memory, or 0600 on disk, until about `expires_in - 60s`.
   - `expires_in` is 3600 seconds and cannot be changed (`[OC]` line 272).
   - Send `grant_type=client_credentials` with the form parameters.
   - Parse token errors as `{message}`, not RFC `{error}` (`[LIVE]`).
8. **Error handling:**
   - Expect `{message}` on every non-2xx response.
   - Surface `x-tailscale-request-id` in errors and in the audit log. Every live response
     carried it, and it is the handle support will ask for.
   - Treat 401 (undocumented) as "token invalid or expired: re-mint once, then fail".
   - Do not assume that 403 means a missing scope.
9. **No retry on 429 by default.** Nothing documents 429 or `Retry-After` for our endpoints.
   - If the CLI retries at all, honour a numeric `Retry-After` when one is present, cap the
     attempts, and **never retry a non-idempotent write** silently: delete, expire, IP, name and
     tags are all POST or DELETE.
   - Retrying a 504 on a write is also unsafe (spec:172-174), because the write may have
     landed.
10. **Use `nodeId` throughout.**
    - Accept a numeric `id` as input, because the path accepts both (spec:4129).
    - The write guard's confirmation should echo `nodeId`, `name` and `hostname`.
    - Resolving a hostname to a `nodeId` can use the server-side `hostname=<value>` filter,
      which matches exactly (spec:130-145).
11. **Device listing:**
    - Default to `fields=default`, and request `fields=all` only when routes, SSH, distro or
      `multipleConnections` are needed.
    - **Never** infer "offline" or "stale" from a missing `lastSeen`; check `connectedToControl`
      first (spec:4548).
    - Surface `multipleConnections` (all-fields only) as a security warning: it means node state
      may have been cloned.
12. **Validate parsing:** HTTP 200 alone does **not** mean success.
    - An empty body or `{}` is a pass.
    - A body with `message` is a failure or a warning; show `data[].user` with its
      `errors`/`warnings`.
    - Send the tests-only form as a JSON array (`Content-Type: application/json`).
    - Send a full policy as a JSON object, or HuJSON with `Content-Type: application/hujson`.
13. **Preview needs a policy body.** It is a POST with the query parameters `type` and
    `previewFor`, and the body is a policy file. To preview the live policy, the CLI should GET
    it (HuJSON) and post it back as the body; whether an empty body is accepted is
    **[unverified]**.
14. **Policy GET:**
    - Default to HuJSON (no `Accept` header, or `application/hujson`) so comments survive.
    - Use `Accept: application/json` for machine parsing.
    - Capture the `ETag` and store it in the audit log, so any later out-of-band `set` can send
      `If-Match`.
    - `set` is out of scope for this credential. The skill should say so plainly and point at
      412 and `ts-default` for whoever holds `policy_file`.
15. **Tag writes are constrained by the client's tags** (`[TAGS]` line 324). The CLI should
    pre-check a requested tag set against the client's own tags, from the self-lookup's
    `tags`, plus the `tagOwners` in the policy file it can read, and explain refusals rather
    than relaying a bare 400.
16. **Treat replace semantics as destructive.** `set tags` and `set routes` replace the whole
    list. The write guard should show the before and after diff and log both.
17. **Name and IP changes break live connections** (spec:504, spec:630-632). The write guard
    should state that consequence in its confirmation prompt, and the audit log should record
    the old value.
18. **Use `-` as the default tailnet.** Allow an explicit tailnet ID. The legacy ID is still
    accepted for tailnets created before October 2025 (spec:4058).
19. **Pin the spec.** Commit the spec's sha256 (above) to the repo, and add a check that warns
    when the live `?outputOpenapiSchema=true` document changes. The spec calls itself unstable
    (spec:7).
20. **In the skill, correct the upstream errors rather than deferring to them** on scope names,
    preview shape, `lastSeen`, and where the endpoint reference lives (§10). Defer to the
    official skill for general concepts only.

---

## Sources

**First-party docs** (fetched as Markdown with curl on 2026-10-26)

- `[API]` https://tailscale.com/docs/reference/tailscale-api.md. Last validated Jun 24, 2026.
- `[TC]` https://tailscale.com/docs/reference/trust-credentials.md. Last validated Jan 30, 2026.
  `https://tailscale.com/kb/1623/trust-credentials` 308-redirects here.
- `[OC]` https://tailscale.com/docs/features/oauth-clients.md. Last validated Jun 30, 2026.
- `[TAGS]` https://tailscale.com/docs/features/tags.md. Last validated Dec 4, 2025.
- `[TN]` https://tailscale.com/docs/concepts/tailnet-name.md. Last validated Jan 5, 2026.
- `[KP]` https://tailscale.com/docs/reference/key-prefixes.md. Last validated Aug 1, 2025.
- `[POL]` https://tailscale.com/docs/reference/syntax/policy-file.md. Last validated Apr 8, 2026.
- Docs index: https://tailscale.com/docs/llms.txt (local copy `scratchpad/tsdocs/docs-llms.txt`).
  It has no rate-limit page.

**OpenAPI spec**

- `scratchpad/tsdocs/openapi.json` (YAML). sha256
  `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38`.
- Identical to https://api.tailscale.com/api/v2?outputOpenapiSchema=true as fetched
  2026-10-26. `openapi: 3.1.0`, `info.version: v2`.

**First-party code** (observed)

- `[GO]` https://github.com/tailscale/tailscale-client-go-v2 at
  `9412c90d30928a9d496f3b30a1dde0d67913b3e9`:
  - `client.go:72-82` (APIError), `client.go:345-392` (response handling, no retry)
  - `oauth.go:29-34` (TokenURL)
  - `devices.go:107-156` (fields)
  - `policyfile.go:199-330` (ETag, If-Match, Validate)

**Live observation** `[LIVE]` (2026-10-26, no valid credentials, nothing modified)

- `GET https://api.tailscale.com/api/v2/tailnet/-/devices` returned `401`,
  `{"message":"API token invalid"}`, and the headers `x-tailscale-request-id`, `x-tailscale-s`.
- `POST https://api.tailscale.com/api/v2/oauth/token` with dummy `client_id`/`client_secret`
  and `grant_type=client_credentials` returned `401`, `{"message":"API token invalid"}`.

**Upstream skill audited**

- `scratchpad/upstream/tailscale-skill/skills/tailscale/references/api.md` (137 lines) and
  `references/enterprise.md:97`, at commit `4f05d353efc56962546aa26ccc59bb08ca699ad1`.

**Search with no first-party result**

- WebSearch "Tailscale API rate limit 429 Retry-After", limited to tailscale.com, 2026-10-26.
  It returned only Aperture docs (https://tailscale.com/docs/aperture/configuration), which
  cover a different product.
