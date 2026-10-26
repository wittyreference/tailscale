# Tailscale credentials: OAuth clients (trust credentials)

Reference notes for the `wittyreference/tailscale` CLI and skill. They cover the
credential MC chose: an OAuth client with `devices:core` (write), `policy_file:read` and
`dns:read`.

Gathered 2026-10-26. Every fact carries a source tag that points into the
[Sources](#sources) table: `[TC]` is the trust credentials page, `[OC]` the OAuth clients
page, `[SPEC]` the OpenAPI spec, and so on. A line number such as `[TC L94]` is the line in
the Markdown copy of that page fetched on 2026-10-26 (copies saved under
`scratchpad/cred-docs/`). **[unverified]** marks a gap that no first-party source closes. It
was left open on purpose and not filled by inference. **Inference:** marks a conclusion
drawn from two or more sourced statements that no single source states outright.

---

## 0. Findings that change the plan

1. **`policy_file:read` needs two more scopes.** The trust credentials page says:
   "devices:posture\_attributes:read and devices:core:read are required when using this
   scope." `[TC L94]` The chosen set already has `devices:core` (write), and the doc lists
   that scope as "Endpoints from devices:core:read" plus the write endpoints `[TC L149]`.
   **`devices:posture_attributes:read` is missing.** Add it, or expect policy reads to fail.
   The GitHub GitOps page points readers at the same dependency: "For information about
   other scopes that are required when using the `policy_file:read` … refer to the trust
   credentials scopes documentation" `[GHGITOPS L21]`. Whether the console enforces the
   dependency or adds it automatically is **[unverified]**.
2. **No document says tags limit what `devices:core` can delete, expire or authorize.**
   Details in §3. The write guard is the only limit on that power.
3. **The tag must be defined in `tagOwners` before the client is created.** Details in §4.
4. **The chosen scopes cannot read Tailscale's own configuration audit log.** That needs
   `logs:configuration:read` `[TC L316-320]` `[SPEC L1268]`. Without it, the CLI cannot
   check its local append-only log against Tailscale's record. Details in §9.

---

## 1. What a trust credential is

- Trust credentials "provide a framework for delegated and scoped access to the Tailscale
  API". They mint scoped access tokens, unlike a fully-permitted API access token, which
  expires after 90 days or less `[TC L5]`.
- There are two forms: **OAuth clients** and **federated OIDC workload identities** `[TC L9]`.
  The admin console page that manages both is
  `https://console.tailscale.com/admin/settings/trust-credentials` `[OC L34]` `[TC L382]`.
- OAuth clients use the OAuth 2.0 **client credentials** flow (RFC 6749 §4.4) `[OC L5]`.
- An OAuth client is not an OAuth *app*. OAuth apps use the authorization code flow and act
  as the consenting user. OAuth clients "create tag-owned resources tied to a service
  identity" `[OAUTH L7-8]` `[OAPPS L9-11]`.
- An OAuth client must be "owned by the tailnet, and not by an individual user" `[OC L271]`.
  It keeps working even after the user who created it loses tailnet access `[OC L56]`.
  Trust credentials and their tokens "are not tied to an individual Tailscale user"
  `[SPEC L33]`. A key created by a trust credential has an empty `userId` `[SPEC L5857]`.
- OAuth client vs federated identity: an OAuth client needs "a long-lived client secret …
  [that] can be used to generate access tokens indefinitely until it is revoked". A
  federated identity stores no long-lived secret, but needs an OIDC-capable third party to
  issue JWTs `[TC L19-33]`.

## 2. Full scope list (current, post-2024-11-14)

New credentials created since 2024-11-14 use these scopes. Older credentials keep their
legacy scopes `[TC L398-400]`. The table follows the trust credentials page `[TC L37-376]`.
Every scope also allows `GET /api/v2/tailnet/:tailnet/keys/:keyID` "for the key in use"
`[TC L45]`.

| Scope | Grants (doc wording, condensed) | Endpoints `[TC]` |
|---|---|---|
| `all:read` | Read-only access to the whole tailnet, including APIs added later. With `all`, the only scope that can list every access token | All `*:read` endpoints; `GET keys/:keyID` for any key `[TC L53-57]` |
| `all` | Complete access, including APIs added later | All endpoints; `GET, DELETE keys/:keyID` for any key `[TC L59-63]` |
| `dns:read` | Read DNS settings | `GET dns/nameservers`, `dns/preferences`, `dns/searchpaths`, `dns/split-dns` `[TC L65-75]` |
| `dns` | Read and change DNS settings | dns:read plus `POST nameservers`, `preferences`, `searchpaths`; `PATCH, PUT split-dns` `[TC L77-89]` |
| `policy_file:read` | Read and validate the policy file. **Requires `devices:posture_attributes:read` and `devices:core:read`** | `GET acl`; `POST acl/preview`; `POST acl/validate` `[TC L91-100]` |
| `policy_file` | Read, validate and change the policy file. Requires `devices:posture_attributes` and `devices:core:read` | policy_file:read plus `POST acl` `[TC L102-109]` |
| `users:read` | Read user information | `GET tailnet/:tailnet/users`, `GET user/:userID` `[TC L111-117]` |
| `users` | Also change roles, and approve, suspend, delete and restore users | `POST user/:userID/{role,approve,suspend,restore,delete}` `[TC L119-133]` |
| `devices:core:read` | Read devices | `GET tailnet/:tailnet/devices`, `GET device/:deviceID` `[TC L135-141]` |
| `devices:core` | "read the list of all devices in the tailnet, authorize or remove machines, and manipulate tags on devices". **One or more tags must be chosen at creation** | devices:core:read plus `DELETE device/:id`; `POST device/:id/{authorized,expire,ip,name,key,tags}` `[TC L143-163]` |
| `devices:posture_attributes:read` | Read device posture attributes | `GET device/:id/attributes[/:key]` `[TC L165-171]` |
| `devices:posture_attributes` | Also write them | `POST, DELETE device/:id/attributes[/:key]` `[TC L173-181]` |
| `devices:routes:read` | Read subnet-router and exit-node settings | `GET device/:id/routes` `[TC L183-187]` |
| `devices:routes` | Also approve or revoke routes and exit nodes | `POST device/:id/routes` `[TC L189-195]` |
| `device_invites:read` | Read device invites. The doc spells it `devices_invites`; the spec spells it `device_invites` | `GET device/:id/device-invites`, `GET device-invites/:id` `[TC L197-203]` |
| `device_invites` | Also change them | adds `DELETE device-invites/:id` `[TC L205-213]` |
| `api_access_tokens:read` / `api_access_tokens` | Read, or also delete, API access tokens | `GET keys`, `GET keys/:id`; `DELETE keys/:id` (API access tokens only) `[TC L215-229]` |
| `auth_keys:read` / `auth_keys` | Read, or also create and delete, auth keys | `GET keys`, `GET keys/:id`; `POST keys`, `DELETE keys/:id` (auth keys only) `[TC L231-247]` |
| `oauth_keys:read` / `oauth_keys` | Read, or also delete, OAuth credentials and OAuth keys | `GET keys/:id`; `DELETE keys/:id` (OAuth only) `[TC L249-261]` |
| `federated_keys:read` / `federated_keys` | Same, for federated identities | `[TC L263-275]` |
| `webhooks:read` / `webhooks` | Read webhooks; also create, change, test and rotate their secrets | `[TC L277-297]` |
| `log_streaming:read` / `log_streaming` | Read, or also change, log-streaming configuration. A private endpoint also needs `device_invites` and `policy_file` | `[TC L299-314]` |
| `logs:configuration:read` | Read configuration audit logs | `GET tailnet/:tailnet/logging/configuration` `[TC L316-320]` |
| `logs:network:read` / `logs:network` | Read network flow logs and settings; also change network-logging settings | `[TC L322-336]` |
| `account_settings:read` / `account_settings` | Read, or also change, tailnet contacts; resend verification email | `[TC L338-352]` |
| `feature_settings:read` / `feature_settings` | Read, or also change, posture integrations and tailnet feature settings | `[TC L354-374]` |

The spec names scopes that the doc's list does not: `networking_settings[:read]` `[SPEC L3477, L3506]`,
`services[:read]` `[SPEC L3540]`, `oauth_apps[:read]` `[SPEC L3782, L3814]` and
`tailnets[:read]` (`tailnets` is also in `[TAILNETS L27]`). The doc's list is therefore
incomplete; see Contradictions.

Scopes grow over time. "When new Tailscale functionality is provided, we will add it to
existing scopes where applicable" `[TC L376]`.

Legacy scopes map to new ones like this: `devices` → `auth_keys`, `devices:posture_attributes`
or `devices:core`; `routes` → `devices:routes`; `acl` → `policy_file`; `logs` →
`logs:configuration`; `network-logs` → `logs:network` `[TC L552-564]`.

### What MC's credential can reach

Scopes: `devices:core` + `policy_file:read` + `dns:read` + the required
`devices:posture_attributes:read`. Endpoints, by scope:

- **Reads:** `GET /tailnet/-/devices` and `GET /device/{id}` (devices:core:read, `[SPEC L151, L303]`);
  `GET /tailnet/-/acl` and `POST /tailnet/-/acl/{preview,validate}`, which are POST but
  read-only (`[SPEC L2222, L2390, L2520]`); `GET /device/{id}/attributes[/{key}]`; the four
  `GET /tailnet/-/dns/*` endpoints listed above.
- **Writes (devices:core only):** `DELETE /device/{id}` `[SPEC L333]`; `POST /device/{id}/expire`
  `[SPEC L360]`; `/authorized` `[SPEC L462]`; `/name` `[SPEC L506]`; `/tags` `[SPEC L555]`;
  `/key` `[SPEC L592]`; `/ip` `[SPEC L634]`.
- **Out of reach:** routes (needs `devices:routes:read`), users, keys, the audit log, and
  any DNS or policy write.
- **[unverified]:** whether `dns:read` covers `GET /tailnet/{tailnet}/dns/configuration`.
  The spec defines that endpoint `[SPEC L1789]` but gives no scope for any DNS endpoint, and
  the doc's `dns:read` list leaves it out.

## 3. Tags, and what they do and do not limit

- **Which scopes require tags at creation:** `devices:core` and `auth_keys`. "Mandatory if
  the scopes include "devices:core" or "auth_keys"" `[SPEC L1991, L2154, L5839]`. The doc
  says the same for devices:core `[TC L146]` and for auth_keys `[OC L139]`. Tags matter
  only for tokens with `devices:core`, `auth_keys` or `all`. "The OAuth client ignores tags
  if none of these scopes are present" `[OC L66]`.
- **What the tags limit, per the docs:**
  - Auth keys. "Auth keys created with this credential must have those exact tags, or tags
    owned by the credential's tags" `[TC L146-147]` `[SPEC L1990]`.
  - Tag assignment by an OAuth client. "When an OAuth client or auth key assigns tags to a
    device, the requested tags must either exactly match the full set of tags on the OAuth
    client or auth key, or each requested tag must be owned by one of the authenticating
    entity's tags as defined in the `tagOwners` section." `[TAGS L324]`
    Whether this rule also governs `POST /device/{id}/tags` called with an OAuth token is
    **[unverified]**. The note sits in the section about tagging at authentication time.
- **Delete, expire and authorize. Quotes, as asked:**
  - Trust credentials page: "The credential has access to read the list of all devices in
    the tailnet, authorize or remove machines, and manipulate tags on devices. You must
    select one or more tags when you create a credential with the devices:core scope. Auth
    keys created with this credential must have those exact tags, or tags owned by the
    credential's tags" `[TC L145-147]`.
  - OAuth clients page: "the `devices:core` scope, which grants access to read and write
    the list of devices in the tailnet, authorize or remove machines, and manipulate tags
    on devices." `[OC L9]`
  - Spec, delete and expire: "The device must belong to the requesting user's tailnet."
    For delete it adds: "Deleting devices shared with the tailnet is not supported."
    `[SPEC L330-331, L358]`
  - **None of these texts limits delete, expire or authorize to tagged devices or to the
    client's own tags.** The only constraint the docs give the tags is on auth keys (and,
    possibly, on tag assignment). No sentence says outright that `devices:core` *can*
    delete or expire an untagged, user-owned device either. "All devices" in the doc
    attaches to *read the list*. **Inference:** the tags put no limit on which devices can
    be deleted, expired or deauthorized. Design for the worst case: one token can delete
    or expire any device the tailnet owns.
- **Retagging a user-owned device:** "Applying a tag to a device removes any user-based
  authentication" `[TAGS L17]`. "Adding a tag to a previously user-authenticated device
  removes the user's identity" `[TAGS L177]`. "You cannot remove all tags from a device"
  `[TAGS L33]`, so the change cannot be reversed by untagging. Whether an OAuth token with
  `devices:core` may tag a user-owned device is **[unverified]**. If it may, a single `tags`
  call permanently converts the device to tag ownership.
- **Narrower tags at token time:** see §5.

## 4. Must the tag exist in `tagOwners` first?

**Yes. Inference from several sources; no page says it in one sentence:**

- "Owners and Admins can create an OAuth client with any scope and any tag **that is in the
  tailnet**" `[OC L30]`. Auth_keys clients take "any tag or set of tags **in your tailnet**"
  `[OC L139]`.
- A tag comes into existence only through `tagOwners`: "Tags are defined in the tailnet
  policy file in the `tagOwners` section" `[TAGS L19]`. "There's no 'tag' section … you
  define tags by their owners in the `tagOwners` section" `[TAGS L64]`. "The `tagOwners`
  section … defines the tags assignable to devices" `[POLICY L464]`.
- Tailscale's own walkthroughs create the tag before the client. The GitHub Action page:
  "1. Create at least one tag … 2. Set up a Tailscale OAuth client" `[GHA L71-72]`, then
  "These tags must already exist in your tailnet" `[GHA L86]`. The Kubernetes operator
  page adds tags under `tagOwners` in step 1 and creates the client in step 2
  `[K8S L19-43]`.
- What the console does when given an undefined tag (hides it, or rejects it) is
  **[unverified]**.

Notes for defining the tag:

- Defining a tag needs the Owner, Admin or Network admin role `[TAGS L26]`.
- `"tag:x": []` is valid. `[]` is shorthand for `autogroup:admin`, and admins and network
  admins can assign every tag anyway `[POLICY L490-500]` `[TAGS L230]`.

## 5. Token endpoint, request and lifetime

- **Endpoint:** `POST https://api.tailscale.com/api/v2/oauth/token` `[OC L60]`. It accepts
  RFC 6749 §4.4.2 client-credentials requests and returns §4.4.3 responses `[OC L62]`. The
  spec does not define this endpoint (no `oauth/token` path in `[SPEC]`).
- **Documented request:**
  `curl -d "client_id=${OAUTH_CLIENT_ID}" -d "client_secret=${OAUTH_CLIENT_SECRET}" https://api.tailscale.com/api/v2/oauth/token`
  `[OC L122-125]`, sent as a form body. The doc example leaves out `grant_type`. RFC 6749
  §4.4.2 requires `grant_type=client_credentials`, and the upstream skill sends it
  `[UPSTREAM api.md L31-34]`. Sending it conforms to the format the doc names. Whether
  HTTP Basic client authentication also works is **[unverified]**.
- **Documented response:** `{"access_token":"tskey-…","token_type":"Bearer","expires_in":3600,"scope":"devices"}`
  `[OC L132]`. The scope value in the example is a legacy name.
- **Lifetime:** "An API access token expires after one hour" `[OC L20]`. "This time cannot
  be modified." `[OC L272]` To keep access, request a new token "shortly before" expiry
  `[OC L20]`.
- **Requesting a narrower scope or tags at token time:** requests "can include `scope` and
  `tags` request parameters, which specify space-delimited lists of requested scopes and
  tags … The OAuth client must have permission to grant the requested scopes and tags"
  `[OC L64]`. The `tags` parameter is not part of OAuth 2.0 `[OC L66]`.
  - Whether a client holding `devices:core` may request only `devices:core:read` is
    **[unverified]**. The doc's only example is `all` → `devices:core` + `tag:server`
    `[OC L64]`. Test it and check the `scope` field in the response.
- A `tailnet` body parameter exists for API-only tailnets. It needs the `all` scope, works
  only for OAuth-client exchange, and is irrelevant to MC `[TAILNETS L43-45]`.
- **Using the token:** `Authorization: Bearer <token>`, or HTTP Basic with the token as
  username and an empty password `[SPEC L19-29]` `[OC L168-182]`.
- **Federated (comparison only):** `POST https://api.tailscale.com/api/v2/oauth/token-exchange`
  with `client_id` and `jwt` returns a "short-lived" token `[WIF L231-247]`. Its lifetime
  is **[unverified]**.

## 6. Does the client secret expire? Revoking

- **No expiry.** "Trust credentials don't expire, and can therefore be used to provide
  ongoing access" `[SPEC L33]`. The secret "can be used to generate access tokens
  indefinitely until it is revoked" `[TC L21-22]`. Trust credentials "do not expire"
  `[TF L31]`. One page disagrees; see Contradictions (`[KSM L83]`).
- **Revoking in the console:** open Trust credentials → find the credential → **Revoke** →
  confirm **Revoke**. "When you revoke a trust credential, any active API access tokens
  that the credential created are also revoked." `[TC L380-388]`
- **Revoking through the API:** `DELETE /tailnet/{tailnet}/keys/{keyId}` with `oauth_keys`
  "grants access to OAuth clients and OAuth tokens" `[SPEC L2085-2095]` `[TC L255-261]`. The
  audit log has a "Revoke OAuth access token" event `[AUDIT L330]`. **MC's client has no
  `oauth_keys` scope, so it cannot revoke itself or its tokens.** Revocation is a console
  action for MC.
- **If compromised:** revoke, create a new credential, and review the configuration audit
  log for the exposure window `[TC L394]`.
- Rotating a secret in place is not documented **[unverified]**. The documented route is a
  new credential plus revoking the old one. A client's scopes, tags and description can be
  edited after creation, which leaves an "Update API key" event `[AUDIT L324]`
  `[SPEC L2113-2154]`.
- Best practice: "Regularly remove OAuth clients that are no longer needed" `[SEC L134-138]`.

## 7. Prefixes and identifiers inside keys

- **Client secret:** `tskey-client-` `[KP L15]` `[SPEC L33]`. Case-sensitive `[OC L54]` `[KP L19]`.
- Other prefixes: `tskey-api` (API access token), `tskey-auth`, `tskey-scim`, `tskey-webhook`
  `[KP L11-17]`. Example key ID form: `tskey-api-` + a key ID + `-` + the secret part `[KP L7]` (example elided so the secret scan stays quiet).
- "The identity of the key is embedded in the key itself" `[SPEC L1926]`. Tokens minted
  from an OAuth client have `keyType` `"api"` `[SPEC L5797]`. The client itself is
  `"client"` `[SPEC L5795]`.
- The prefix of an OAuth-derived access token is **[unverified]**: the doc example shows a
  placeholder, `tskey-0123…` `[OC L132]`. How to parse the key ID out of a secret or token
  is also **[unverified]**.

## 8. Operations an OAuth-derived token cannot perform

- **Create, resend or accept device invites:** "cannot be created using an API access token
  generated from an OAuth client as the shared device is scoped to a user" `[SPEC L831]`;
  resend `[SPEC L1107]`; accept `[SPEC L1125]`.
- **Create, delete or resend user invites:** "Only permitted for user-owned keys, because
  invites require an inviting user" `[SPEC L938, L1018, L1042]`.
- **Change the token lifetime:** fixed at one hour `[OC L272]`.
- **Mint long-lived auth keys:** auth keys expire after 90 days or on first use
  `[OC L137]`. MC's client lacks `auth_keys` anyway.
- **Act on another tailnet:** a federated token cannot `[TAILNETS L45]`. Cross-tailnet OAuth
  needs `all` `[TAILNETS L43]`.
- Limits that apply to every token, not only OAuth ones: advertised routes cannot be set
  through the API `[SPEC L411]`; shared-in devices cannot be deleted `[SPEC L331]`.
- Listing keys with an OAuth-derived token returns all OAuth clients when the `all` flag is
  absent `[SPEC L1851]`. That needs `oauth_keys:read`.

## 9. Configuration audit log and OAuth clients

- The log records "actions that modify a tailnet's configuration, including the type of
  action, the actor, the target resource, and the time" `[AUDIT L5]`. It is "always enabled
  … and cannot be disabled" `[AUDIT L31]`. It keeps 90 days and the period cannot be
  changed `[AUDIT L409]`. Read-only actions are not recorded `[AUDIT L404]`.
- **Token creation is recorded with the client as actor:** "creating an access token
  records the action in your audit log. The log entry shows the trust credential's Client
  ID as the actor." `[TC L390-392]` The event is "Create OAuth access token" `[AUDIT L329]`.
- Client lifecycle events: OAuth client "Create API key", "Update API key" (scopes, tags or
  description changed) and "Revoke API key" `[AUDIT L323-325]`.
- **Calls refused for missing scope are recorded:** event "API: Failed request — API call
  attempted with insufficient permission" `[AUDIT L316]`.
- **Actor for writes made with the token** (for example "Delete node"): the actor schema's
  `type` enum includes `OAUTH_CLIENT` `[SPEC L5111]`. The OAuth apps page contrasts its
  per-user audit entries with "a shared service identity" `[OAPPS L7]`. No page says that a
  device deletion done with an OAuth token shows actor type `OAUTH_CLIENT` with the client
  ID **[unverified]**.
- Reading the log through the API needs `logs:configuration:read`
  (`GET /tailnet/{tailnet}/logging/configuration`, with `start`/`end` in RFC 3339 and
  optional `actor`/`target`/`event` filters) `[SPEC L1255-1268]` `[AUDIT L67-104]`. MC's
  scopes do not include it.

## 10. Tailnet identifiers in API paths

- **`-` (dash):** "reference the default tailnet of the access token being used … This is
  the best option for most users." `[SPEC L4062]` `[OC L161-177]` `[TF L33]`. **Use this
  form.**
- **Tailnet ID:** "the string used with the Tailscale API" `[TN L9]`. It is shown on the
  General settings page `[TN L53-55]`. Example form: `T1234CNTRL` `[SPEC L4076]`.
- **Legacy ID (formerly "Organization"):** renamed in October 2025, and visible only on
  tailnets created before then. "If you previously used the **Organization** field for the
  Tailscale API, update your settings to use the **Tailnet ID** field instead." `[TN L73-83]`
  Pre-October-2025 tailnets "can still use the legacy ID, but the Tailnet ID is the
  preferred identifier" `[SPEC L4058]`.
- **Organization path parameter:** a separate `{organization}` parameter exists, used only
  by the alpha `/organizations/{organization}/tailnets`. Here `-` means "the organization of
  the access token" `[SPEC L4455]`.
- The tailnet DNS name (`tail<ID>.ts.net`) and the display name are not API identifiers
  `[TN L7-15, L57-71]`.

## 11. Tailscale's recommendations for storing client secrets

- Secrets are shown once. Copy them "into a password manager as soon as they are generated"
  `[KSM L11]`. The client secret cannot be copied again after the Credential created page
  closes `[OC L44]`. "Store the client secret securely." `[OC L48]`
- "We strongly recommend that you use a secrets manager … **Do not store sensitive
  information such as an OAuth client or API access token in source control.**" `[KSM L15]`
  The Terraform page says to use "an environment variable or a secrets manager" `[TF L37]`.
- Secret scanning covers OAuth clients `[SCAN L15-17]`. GitHub scans public repos, and
  private ones where enabled. **An active secret it finds is revoked**, and the security
  contact gets an email `[SCAN L36-38]`. TruffleHog findings are not revoked automatically
  `[SCAN L52]`.
- Who can create clients: Owner, Admin, Network admin or IT admin `[OC L28]` `[ROLES L252-259]`.
  A Network admin cannot grant `devices:core`; an IT admin can `[OC L30]`.

## 12. Procedure: MC creates the credential

Each step is one action, with the hazard named first. Step text is sourced; the scope and
tag *labels* in the console are known only where a doc shows them.

**Before you start.** MC must be an **Owner or Admin**. Only those roles can create a client
with any scope and any tag `[OC L30]`, and the Network admin role cannot grant
`devices:core` `[OC L30]`.

1. **Define the tag** that `devices:core` requires.
   *Hazard:* the client can probably apply this tag to devices `[TAGS L324]`, and tagging
   a device strips its user identity `[TAGS L17]`.
   *Check:* pick a tag that no device and no ACL rule uses today.
   *Action:* open Access controls (`https://console.tailscale.com/admin/acls/file`)
   `[K8S L16, L23]` and add, under `tagOwners`, `"tag:<name>": []` `[POLICY L496-500]`.
   Save. Defining a tag needs Owner, Admin or Network admin `[TAGS L26]`. The name itself
   is MC's choice; nothing in the docs prescribes one.
2. Open the **Trust credentials** page: `https://console.tailscale.com/admin/settings/trust-credentials`
   `[OC L34]`.
3. Select the **Credential** button `[OC L36]`.
4. Select **OAuth** `[OC L38]`.
5. For each operation, select **Read** or **Write** `[OC L40]`:
   - **Devices → Core: Write**, then choose `tag:<name>` as its tag. The label "`Devices/Core`
     (with `tag:…`)" is the one the Kubernetes operator guide shows `[K8S L42]`. The tag is
     mandatory `[TC L146]` `[SPEC L1991]`. The exact tag-picker control is **[unverified]**.
   - **Policy file: Read** (`policy_file:read`) `[TC L91]`. Console label **[unverified]**.
   - **DNS: Read** (`dns:read`) `[TC L65]`. Console label **[unverified]**.
   - **Device posture attributes: Read** (`devices:posture_attributes:read`). The doc says
     `policy_file:read` requires it `[TC L94]`. Console label **[unverified]**.
   - Select nothing else. Least privilege `[TC L7]`.
6. Select **Generate credential** `[OC L42]`.
7. *Hazard:* the secret is shown only once `[OC L44]` `[KSM L11]`.
   *Action:* copy both the **client ID** and the **client secret** straight into a password
   manager or secrets manager `[KSM L11, L15]`. The secret is case-sensitive `[OC L54]` and
   should start with `tskey-client-` `[KP L15]`. Never paste it into a file inside a
   repository `[KSM L15]`.
8. Select **Done** `[OC L52]`.
9. **Verify.** Mint one token with the documented request `[OC L118-127]`, passing the
   values from environment variables. Confirm `expires_in` is `3600` and that `scope` lists
   the four scopes `[OC L132]`.
10. **Verify the audit trail.** On the Logs page (`https://console.tailscale.com/admin/logs`)
    `[AUDIT L13]`, look for the OAuth client "Create API key" event `[AUDIT L323]` and the
    "Create OAuth access token" event with the client ID as actor `[TC L392]` `[AUDIT L329]`.
11. **To revoke later:** Trust credentials → **Revoke** → **Revoke** `[TC L380-388]`.

## 13. Contradictions and stale claims

| Claim | Where | Counter-evidence |
|---|---|---|
| OAuth scopes are "`devices:read`, `devices:write`, `dns:read`" | Upstream official skill `references/api.md:13` (commit `4f05d353`, 2026-07-09) | Current scopes are `devices:core[:read]` and so on `[TC L135-163]`. `devices:read` is legacy `[TC L482]`. `devices:write` appears in neither list |
| Trust credentials are a third auth option, distinct from OAuth clients, "with attribute-based limits … key/value claims" | Upstream skill `references/api.md:14` | OAuth clients are one of the two forms of trust credential `[TC L9]` |
| "API access tokens, auth keys, and **OAuth keys** are generated with an expiry that you can adjust" | `[KSM L83]` (validated 2026-01-05) | Token lifetime "cannot be modified" `[OC L272]`; trust credentials "don't expire" `[SPEC L33]` `[TC L22]` |
| `dns:read` reaches nameservers, preferences, searchpaths, and keys/:keyID "for itself only" | `[OC L13-16]` (validated 2026-06-30) | `[TC L65-75]` also lists `split-dns`; `[TC L45]` says "for the key in use" |
| Example token response has `"scope":"devices"` | `[OC L132]` | `devices` is a legacy scope `[TC L456, L558-560]` |
| devices:core says "Auth keys created with this credential must have those exact tags" | `[TC L146-147]` | Creating auth keys is an `auth_keys` endpoint `[TC L239-247]` `[SPEC L1929]`; the sentence is carried over from legacy `devices` `[TC L458-460]` |
| Chosen credential: devices:core + policy_file:read + dns:read | Computed task | `policy_file:read` also requires `devices:posture_attributes:read` `[TC L94]` |
| "devices:core reaches every device … tags constrain auth keys, not which devices it can delete or expire" was "confirmed" | Computed task, citing kb/1623 | The page says "read the list of **all** devices" and leaves delete, expire and authorize unqualified `[TC L145]`. The claim rests on a missing restriction, not a positive statement. The tags page also suggests tags limit *tag assignment* `[TAGS L324]` |
| "tailnet organization name" | `[TF L39]` | The Organization field became Legacy ID in October 2025; use Tailnet ID `[TN L73-81]` |
| Scope list is complete | `[TC L47-374]` (validated 2026-01-30) | The spec also names `networking_settings`, `services`, `oauth_apps` and `tailnets` scopes `[SPEC L3477, L3540, L3782]` `[TAILNETS L27]` |
| `devices_invites` | `[TC L205]` | The spec uses `device_invites` `[SPEC L784, L1083]` |
| User endpoints are `/api/v2/user/:userID/...` | `[TC L117-133]` | Spec paths are `/users/{userId}/...` `[SPEC L2956-3117]` |
| `Key` schema: "An API access token or Auth Key" | `[SPEC L5776]` | The same schema's `keyType` also covers `client` and `federated` `[SPEC L5786-5797]` |

## 14. Design implications for the CLI and skill

- **Credential:** add `devices:posture_attributes:read`. Optionally add
  `logs:configuration:read` (read-only) so the CLI can check its local audit log against
  Tailscale's. Optionally add `devices:routes:read` if device views should show routes. All
  three are reads.
- **Write guard:** `devices:core` is tailnet-wide destructive power. Tags do not limit
  delete, expire or authorize. Classify by endpoint meaning, not HTTP method:
  `POST acl/validate` and `POST acl/preview` are reads. Put `POST /device/{id}/tags` in the
  highest-risk class, because it can permanently strip a user-owned device's identity
  `[TAGS L17, L33, L177]`.
- **Least privilege per call:** read commands request
  `scope=devices:core:read policy_file:read dns:read devices:posture_attributes:read`; only
  write commands request `devices:core`. Whether the server accepts this downscoping is
  **[unverified]**: test it in integration and assert on the response's `scope` field.
- **Tokens:** form-POST `client_id`, `client_secret` and `grant_type=client_credentials`.
  Refresh shortly before the 3600 s expiry. Keep tokens in memory, or in a 0600 cache
  outside any repo. Never log the token or the secret; redact anything matching `tskey-`.
- **Paths:** always use `/tailnet/-/…`.
- **Secrets:** read the client ID and secret from env vars, or from a 0600 file outside the
  repo. Add a pre-commit regex for `tskey-(client|api|auth)-`. GitHub secret scanning would
  revoke a leaked secret in a scanned repo `[SCAN L36-38]`.
- **Revocation:** the CLI cannot revoke its own credential (no `oauth_keys`). The skill must
  send MC to the console steps `[TC L380-388]`.
- **Audit:** Tailscale records every configuration write and every scope-denied call, but no
  reads `[AUDIT L316, L404]`. The CLI's append-only log must record reads itself.
- **Not offered:** no device or user invite commands (refused for OAuth tokens), no
  route-setting, no lifetime option.
- **Skill vs official skill:** our skill must override the upstream skill's stale scope
  names, and say that OAuth clients *are* trust credentials.

## Sources

All fetched 2026-10-26 with `curl -L`, as Markdown (`.md` suffix). Local copies are in
`/tmp/claude-0/-home-user-elmer/2efec2c0-071d-5291-9372-65e893474c78/scratchpad/cred-docs/`.

| Tag | URL | Last validated |
|---|---|---|
| TC | https://tailscale.com/docs/reference/trust-credentials.md (https://tailscale.com/kb/1623/trust-credentials returns 308 to `/docs/reference/trust-credentials`) | Jan 30, 2026 |
| OC | https://tailscale.com/docs/features/oauth-clients.md | Jun 30, 2026 |
| KSM | https://tailscale.com/docs/reference/key-secret-management.md | Jan 5, 2026 |
| KP | https://tailscale.com/docs/reference/key-prefixes.md | Aug 1, 2025 |
| TN | https://tailscale.com/docs/concepts/tailnet-name.md | Jan 5, 2026 |
| WIF | https://tailscale.com/docs/features/workload-identity-federation.md | Jan 30, 2026 |
| AUDIT | https://tailscale.com/docs/features/logging/audit-logging.md | Jan 5, 2026 |
| TAGS | https://tailscale.com/docs/features/tags.md | Dec 4, 2025 |
| POLICY | https://tailscale.com/docs/reference/syntax/policy-file.md | Apr 8, 2026 |
| ROLES | https://tailscale.com/docs/reference/user-roles.md (columns: Owner, Admin, Network admin, IT admin, Billing admin, Auditor, Member; L115-133) | Dec 4, 2025 |
| SEC | https://tailscale.com/docs/reference/best-practices/security.md | Jan 20, 2026 |
| SCAN | https://tailscale.com/docs/integrations/secret-scanning.md | Jan 5, 2026 |
| TF | https://tailscale.com/docs/integrations/terraform-provider.md | Jan 30, 2026 |
| GHA | https://tailscale.com/docs/integrations/github/github-action.md | Jan 30, 2026 |
| GHGITOPS | https://tailscale.com/docs/integrations/github/gitops.md | Dec 5, 2025 |
| K8S | https://tailscale.com/docs/kubernetes-operator/install-operator.md | Jun 5, 2026 |
| TAILNETS | https://tailscale.com/docs/features/tailnets-api.md | Oct 20, 2026 |
| OAUTH | https://tailscale.com/docs/oauth.md | Jun 30, 2026 |
| OAPPS | https://tailscale.com/docs/features/oauth-apps.md | Jun 30, 2026 |
| API | https://tailscale.com/docs/reference/tailscale-api.md | Jun 24, 2026 |
| SPEC | `scratchpad/tsdocs/openapi.json` (OpenAPI 3.1.0 in YAML, `info.version: v2`, sha256 `b3532da7…ac38`). Line numbers are file lines. The spec warns that it "is unstable. It may change or break without notice" (L7) | n/a |
| UPSTREAM | `scratchpad/upstream/tailscale-skill/skills/tailscale/references/api.md`, commit `4f05d353efc56962546aa26ccc59bb08ca699ad1` (2026-07-09) | n/a |
| Index | https://tailscale.com/docs/llms.txt | n/a |
