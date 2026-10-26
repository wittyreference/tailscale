# `tailnet`: design

The final, buildable design for the private repo `wittyreference/tailscale`. It contains:

- a stdlib-only Python CLI named `tailnet`;
- a Claude Code skill named `tailnet`;
- an idempotent installer;
- a full test suite.

Everything runs on MC's droplet `claude-factory`. Written 2026-10-26. The spec is written so that
someone who reads only this file and the research files can build the repo test-first without
making any further design decisions.

## How to read this spec

**Provenance.** This spec synthesises three candidate designs: `safety-first` (SF), `minimal`
(MIN) and `agent-ergonomics` (AE). Two judges scored them:

- **J1** used a safety-and-correctness lens. Winner: SF (8), then AE (6.5), then MIN (5.5).
- **J2** used a maintainability-and-fit lens. Winner: MIN (7.5), then AE (6.5), then SF (5.5).

The totals are SF 13.5, MIN 13 and AE 13. The judges split, and **the tie is broken on safety, so
SF is the base.** Every J1 and J2 `must_graft` item is grafted and every `must_fix` item is fixed.
Where the judges conflict, §1 resolves it in one line. §27 maps each judge item to the section
that answers it.

**Citation keys.** Bracketed keys point into the research files and the saved first-party copies.

| Key | Points to |
|---|---|
| `[critic F4]`, `[critic Q14]`, `[critic R2]`, `[critic §6]` | `research/critic.md` |
| `[api §5.7]` | `research/api-surface.md` |
| `[cred §3]` | `research/credentials.md` |
| `[pol (d)]` | `research/policy-access.md` |
| `[mc §5]`, `[mc P9]` | `research/mc-tailnet.md` |
| `[up §4a A3]` | `research/upstream-skill.md` |
| `[pkg §5.1]` | `research/skill-packaging.md` |
| `[spec NNNN]` | A line of `tsdocs/openapi.json` (YAML), sha256 `b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38` |
| `[PM Lnn]` | `design-src/permission-modes.md` (code.claude.com, fetched 2026-10-26) |
| `[PERM Lnn]` | `critic-src/cc-permissions.md` |
| `[SK Lnn]` | `skilldocs/skills.md` |
| `[tsssh Lnn]` | `docs-policy/features_tailscale-ssh.md` |
| `[cliref Lnn]` | `dl-upstream-audit/reference_tailscale-cli.md` |
| `[ipnstate:N]` | `ts-src/ipnstate.go` at `tailscale/tailscale@de16943c` |
| `[TC]`, `[OC]`, `[TAGS]`, `[AUDIT]` | Tailscale docs pages as keyed in the research files |
| `[Corrections]` | The "Corrections" section of `/home/user/tailnet-ssh/CLAUDE.md` |
| `[sigint pN:L]` | `sigint/pageN.txt`, the earlier session's transcript |

**Tags.** **[unverified]** marks a fact the design tolerates but does not depend on.
**[inference]** marks a conclusion that no source states outright.

**Pronouns.** MC is "they/them" throughout.

---

## Amendments recorded after synthesis

Amendments win over the text they amend. Each names its date and who decided.

**A1. MC answered the credential questions (2026-10-26, MC).** After being told the corrected
reach ("a devices:core client can apply its own tag to any device, and tagging albini or your
phone would permanently remove your user from it"), MC chose **Two clients**. The option read:
"Read client (devices:core:read, policy_file:read, devices:posture_attributes:read, dns:read;
needs no tag) does all day-to-day work. Separate write client (devices:core, tagged tag:fleet)
in its own 0600 file, loaded only by --apply writes, each of which also prompts you via a Claude
Code ask rule, even in auto mode." That answers MC1 (yes, a write client), MC2 (exactly the four
read scopes), MC3 (two clients) and MC4 (`tag:fleet`). Consequences:

- `doctor` never emits `write-client-consent`. `scope-set` still fires when the read client's
  granted scope differs from the four.
- `references/credentials.md` records the answer and its date instead of asking again, and
  keeps the consent text as the record of what MC accepted.
- SKILL.md item 3's first bullet states what MC accepted on 2026-10-26; it is no longer a
  question.
- §28 rows MC1-MC4 are answered; MC5-MC12 stay open with their safe defaults.

**A2. Where the cited files live (2026-10-26).** The research files are committed under
`docs/research/`, so `research/<file>` in a citation means `docs/research/<file>`. The saved
first-party copies (`design-src/`, `critic-src/`, `skilldocs/`, `docs-policy/`,
`dl-upstream-audit/`, `ts-src/`, `tsdocs/`) were working files and are not committed; each
research file's Sources section gives their URLs and fetch dates. The pinned OpenAPI spec is
committed at `spec/tailscale-openapi.yaml` (§4).

**A3. Questions also go out as a numbered list (2026-10-26, MC's standing rule).** MC's
user-scope CLAUDE.md: "When you use the question picker, also list the same options as a plain
numbered list in the message text, so I can answer '2' from the phone if the picker gets
dismissed. Recommend one and say why in a clause." The skill's one-question-per-turn rule
(§19.2 item 2) carries this.

**A4. (build, 2026-10-26)** §4 said `pyproject.toml` holds `[tool.pytest.ini_options]` only; it
was built with a `[tool.ruff]` table as well (`target-version = "py310"`), and still no build
backend; because lint has to hold code to the 3.10 floor (critic Q26), and a linter tuned to the
newest Python would pass 3.11-only syntax that the droplet may not run.

**A5. (build, 2026-10-26)** §21.6 said the pre-commit hook refuses any staged line matching
`tskey-(client|api|auth|scim|webhook)-[A-Za-z0-9]`; it was built to let through a match whose key
part is nothing but runs of lowercase `x` joined by hyphens, and to refuse every other match in
every file; because the spec that §29 item 4 pins byte-for-byte carries four such documentation
placeholders (spec 25, 28, 5784, 6626), so the hook as written would block the pin. A content
rule keeps that file scanned, where a path exemption would wave a real key pasted into it
through, and a real key cannot be all `x`: its key ID is `k123456CNTRL`-shaped [spec 5780, 6623].

**A6. (build, 2026-10-26)** §21.1 said netguard raises on a `socket.connect` off loopback and on
running a `tailscale` executable; it was built to refuse as well a connect by host name (only
literal loopback addresses pass), a `sendto`/`sendmsg` off loopback, a name lookup a resolver
would answer over the network (anything but `localhost` and address literals, and a reverse
lookup of any non-loopback literal), socket families other than IPv4, IPv6 and Unix, and
`tailscale` anywhere in argv (`env tailscale`, `sh -c "… tailscale …"`) unless that word is a
path to a directory; because each of these leaves the box, or runs the binary, without raising
either event the spec named. The loopback seam skips `HTTPServer`'s reverse lookup of its own
address for the same reason.

**A7. (build, 2026-10-26)** §10.4 said registered values are matched exactly, the JSON field
pattern is `"(access_token|client_secret)"\s*:\s*"[^"]*"`, and the excepthook is `sys.excepthook`;
it was built to register each value's JSON-escaped and URL-encoded spellings as well, to let the
JSON field pattern step over escaped quotes (`"(?:[^"\\]|\\.)*"`), and to install a redacting
`threading.excepthook` beside `sys.excepthook`; because redaction runs on serialised text, where a
value with a quote, backslash or non-ASCII character no longer appears as itself, `[^"]*` stops
at an escaped quote and leaves the rest of the secret showing, and a crash on another thread is
printed by its own hook, unredacted, which invariant 2 forbids.

**A8. (build, 2026-10-26)** §5.4 listed `error.kind` as
`refused|usage|local|api|internal|unconfirmed|rejected`, with no kind for exit 8, although §5.5
gives exit 8 stable codes of its own, and §5.5 lists no code for exit 1; it was built with
`kind: "negative"` for exit 8, so `DOCTOR_FAIL` and its siblings reach the envelope's `error`
object (`ok` stays false and `outcome` stays `negative`), and with `INTERNAL`, the §5.3 name, as
exit 1's only code; because agents branch on codes, and a negative answer whose code had nowhere
to go would drop the reason it was negative.

**A9. (build, 2026-10-26)** §21.1 said netguard allows a connect whose address is loopback; it
was built to refuse a loopback connect to the port of any proxy named in a `*_proxy` environment
variable (either case) that listens on loopback; because a proxy on 127.0.0.1 forwards what it is
sent off the box, so reaching it leaves loopback in all but address, and the build machine has
exactly that (`HTTPS_PROXY=http://127.0.0.1:<port>`, observed 2026-10-26). Production posture
honours environment proxies by design (§7.1), so without this an in-process test that reached
production posture would go out through the proxy unseen. Integration CLI processes run with a
minimal environment (§21.1) and are unaffected.

**A10. (build, 2026-10-26)** §7.2 said `TAILNET_API_BASE` is parsed with `urllib.parse` and
`TAILNET_HOME`'s paths are `$TAILNET_HOME/config` and `/state`; it was built to check the raw text
as well, which must be exactly `http://127.0.0.1:PORT` or `http://localhost:PORT` (lowercase, port
1-65535, at most a bare trailing `/`), to count a variable that is present but empty as set, and
to build every test path from the `realpath` of `TAILNET_HOME` that rule 3 checked; because
`urllib.parse` strips tabs, newlines and leading spaces and lowercases scheme and host, so a value
can parse clean when the text is not what the rule names, port 0 cannot be connected to, an
exported-but-empty override silently becoming production is the fallback rule 4 forbids, and a
symlink re-pointed after the check must not steer test reads into the real directories.

**A11. (build, 2026-10-26)** §8.5 said `write_private_atomic` writes through a temp file and a
rename, and §13.1 said the audit log is opened `O_APPEND` with mode 0600 and locked; it was built
so that `write_private_atomic` first refuses a directory that group or other can write, and
`append_locked` runs the §8.2 file checks (regular file, owned by the euid, no group or other bit,
one link) on the opened log and refuses with `AUDIT_UNWRITABLE` otherwise; each function takes the
refusal code from its caller, and a missing file raises `FileNotFoundError` for the caller to
judge; because invariant 2 keeps credential files out of directories others can write, which a
write must hold as well as a read, and a log that is a hard link or belongs to someone else would
send the narrative into another file or let it be swapped, while absence means different things
to different callers (no credential, an unanswered protected list, a token to mint).

**A12. (build, 2026-10-26)** §6 lists the audit surface as `append(event)`, `last(event_name)` and
`count_lines()`, and the credentials surface likewise without the posture they act under; §13.1
said the CLI never opens the log in any other mode than append, while §16.3 reads it back with
`audit.last`; it was built so that every module function that touches the posture's files takes
the `Posture` as its first argument (`audit.append(posture, event, *, argv=None)`,
`credentials.load_read(posture)`, and so on), the log is opened for writing only with `O_APPEND`
and for read-back only read-only, `append` refuses an event name §13.2 does not list or an event
that sets a common field, and a log that fails the §8.2 file checks is refused on read-back with
`AUDIT_UNWRITABLE`; because every path comes from the posture (§7.1) and a module-level current
posture would be hidden global state, doctor must be able to read its settled answers back (D3),
a mistyped event would be written where no reader looks, a forged `ts` or `posture` would make
the narrative lie, and a log that cannot be read safely is one the same checks stop being written.

**A13. (build, 2026-10-26)** §8 left five points of the credentials module open or overlapping;
it was built as follows. (1) §8.1 said a `file:` target must be an absolute path inside the
config directory; it must be exactly `<config dir>/<role>.secret`, else `CREDENTIAL_UNSAFE`,
because a `read.json` naming `write.secret` would have every read open the write secret
(invariant 4). (2) §8.3's rows overlap when `read.json` alone has a granted scope that is not
read-only (both "read-only" and "single-client" match); it is `single-client`, as
`test_a_read_client_granted_write_scope_means_single_client` says, because that client's read
tokens can write, so reads must be minted narrowed and L2 is absent. (3) §9.2's `cacheable` rule
lives in `credentials` and `tokens` re-exports it, because `mode()` needs it and §6 orders
credentials before tokens. (4) §8.2 item 9 registers a secret immediately; a value shorter than 8
characters (the shortest valid secret in either posture) is refused as malformed without being
registered, because registering it would blank that string out of all later output; a
`write.secret` gone missing by the time `load_write_secret` runs refuses with
`WRITE_CREDENTIAL_MISSING` (exit 5), nothing sent. (5) §5.2 gives `credentials forget` exit 0
only; it removes the files first and logs after, a log that cannot be written is reported rather
than fatal, the log line adds `removed`, and a file that cannot be removed raises
`CREDENTIAL_UNSAFE` (exit 3), because the disarm must never wait on the log, and reporting a
disarm that did not happen would be worse than failing. `.gitignore`'s `credentials.*` backstop
gains an exception for `src/tailnet/credentials.py`, which it would otherwise hide from git.

**A14. (build, 2026-10-26)** §6 gives `Transport(posture).request(…, idempotent)`, §10.2 gives a
write column of exits 6 and 7, a 403 message naming the scope "from a small table in `api.py`",
and a validate 400 that is a verdict rather than an error; it was built as `Transport(posture, *,
sleep, timeout)` with two more keywords on `request`: `needs_scope`, which `api.py` fills from its
table, and `expect`, the statuses a caller takes as an answer. A write (`idempotent=False`) gets
every status back as a `Response` for `writes` to judge after its re-read, and `http.NoResponse`
(exit 4, `NETWORK` or `API_BAD_RESPONSE`) carries `sent`, false only when urllib failed while
connecting or sending. A 401 on a read whose token cannot be renewed is `TOKEN_REJECTED` at once;
because §6 orders `http` before `api`, so it cannot read api's table; §10.2's write outcomes
depend on the post-read that only `writes` performs; a failure inside urllib's send step means
the API never received a whole request, while one after it may have landed, as may a write whose
reply was too large to read; and a freshly minted token that is refused is §5.3's "token
rejected after re-minting" with nothing left to re-mint.

**A15. (build, 2026-10-26)** §6 gives `tokens.read_token() -> str` and `mint(cred, *, scope=None)`,
§9.1 says every mint appends a `token.mint` line, and §9.3 says an unsafe cache is unlinked "never
read" with a warning naming its `expires_at`; it was built as `mint(posture, transport, cred, *,
scope=None)` and a `tokens.ReadToken(posture, transport)` source, which the transport asks for
`bearer()` and, after a 401 on a read, for `renew()` once, re-minting only a token that came from
the cache. Every mint attempt leaves its line, failures included (`http_status` says which); a
line that cannot be written stops a write-role mint (`AUDIT_UNWRITABLE`) and only warns for a
read. The unsafe cache's expiry is its mtime plus the token's fixed hour, and a grant that cannot
be cached also removes any older cache; because a function returning a string cannot tell the
transport that its token came from the cache, the only case §9.3 re-mints; §13.3's `http_status`
field only means something if failed attempts are recorded; a write whose token mint cannot be
recorded must not be sent (C9), while a read changes nothing and the console keeps its own record
of the mint (L5); a file that is never read cannot supply its `expires_at`; and a token on disk
that nothing will use is exposure with no benefit.

**A16. (build, 2026-10-26)** §6 lists the `api` functions with no session argument
(`list_devices()`, …, `set_device_tags(node_id, tags, write_token)`) and leaves what reads return;
it was built so that every function takes an `api.Session` first (the transport and a lazy
`tokens.ReadToken`; `api.session(posture)` builds one); reads return `api.Reply(data, response)`;
the two validate calls return the 200 or 400 `Response` for `policy.parse_verdict`; the writes
take a `tokens.Token` minted from the write client and refuse anything else; `set_device_tags`
refuses an empty or non-string tag list before sending; and a key ID gets the same
letters-and-digits check as a device ID, refused as `CREDENTIAL_MALFORMED` because it comes from a
credential file; because a module-level session would be the hidden global state A12 rules out;
the envelope's `request_ids` and the policy ETag need the response; the verdict parser takes the
status and the body; a single-client read token can write, so a bug that passed it to a write
must fail loudly; an empty list would strip every tag, with results the spec marks unverified;
and either ID ends up in a request path.

**A17. (build, 2026-10-26)** §5.1 refuses "the literal placeholder `<why>`"; §5.4 says `--json`
prints exactly one envelope "error or not" and names no posture for a run whose override was
refused; and §5.3 has exit 1 print a redacted message; it was built so that a `--reason`
containing `<why>` anywhere, in any case, is `REASON_PLACEHOLDER`, a blank one is
`REASON_REQUIRED`, and one over 200 characters is `USAGE`, checked whenever `--reason` is given.
Every argparse error raises `UsageError` (`USAGE`, with `next` pointing at that command's
`--help`) instead of printing and exiting, and `--json` is read from argv before parsing. A
refused override gives an envelope with `"posture": "unknown"`, and `main` turns any other
exception into an `INTERNAL` envelope, printing the redacted traceback only with
`TAILNET_DEBUG=1`; because a reason that still carries the placeholder was pasted unedited,
whatever surrounds it; argparse's own error path prints usage and exits before any envelope
exists; a refused override has decided neither posture and must not be reported as either; and
the excepthook alone cannot keep the one-envelope rule.

**A18. (build, 2026-10-26)** §11.2 listed the normalised Device's fields, gave `last_seen_kind`
as `"online"|"never"|"at"` and the owner as `{kind, value}`, and left unsaid what a malformed
device does; it was built (1) with `addresses`, every Tailscale address, beside `ipv4` and
`ipv6`; (2) with `online` and `last_seen_kind` both `null` when `connectedToControl` is absent;
(3) with a tagged owner's `value` the tags joined by commas; (4) refusing as `API_BAD_RESPONSE` a
device whose `nodeId` is missing or not a string, or whose `addresses` or `tags` is not a list of
strings, while display fields are read leniently; (5) with `request_ids` holding the device
list's request ID, the mint's being in its `token.mint` line; and (6) with `self` and `protected`
`null` until self detection and the protected file are wired in (§29 item 16); because self is
joined on every address and a write's audit target records them all (§11.3, §13.3); a missing
`lastSeen` beside a missing `connectedToControl` says nothing, and reading it as "never" is the
inference §11.2 forbids; a string keeps `owner.value` one type; a tag list of the wrong shape
would make a tagged device look user-owned to the guard; the envelope reports the calls that
produced its data; and the list never guesses self or protection.

**A19. (build, 2026-10-26)** §11.4 said the protected file must pass §8.2, and §5.5 has
`PROTECTED_MALFORMED` but no code for an unsafe protected file; §11.4's grammar did not say what a
line naming two devices means, nor whether `protects` covers self; it was built to refuse an
unsafe protected file (a symlink, a hard link, any group or other bit, another owner, over 64 KiB,
not UTF-8) as `PROTECTED_MALFORMED`, exit 3, with a message naming the problem and MC's fix; to
refuse a line that names two things; to word every refusal by line number, never quoting the
file; and to have `protects` name the self line's device as protected; because
`CREDENTIAL_UNSAFE` would point the reader at the credentials when the protected file is the one
in the way, a line holding two names is a typo the CLI must not settle by guessing, the file sits
behind a deny rule so its text should not reach a transcript through an error, and §11.4 says
self is always protected against tag writes, listed or not.

**A20. (build, 2026-10-26)** §6 gave `localts` as `status_json(timeout)`, `ping(ip, kind,
timeout)`, `get_pref(name)` and `version()`, and `selfnode` as `SelfNode(known, device, source,
id_agrees, reason)` from `resolve_self`; it was built with the posture first on every `localts`
call (A12) and a timeout on all four; with `localts.Failed(reason)` for a run that gives no answer
(a timeout, a binary that cannot start, a non-zero exit where one means no answer) and
`localts.NotInTestPosture`, a `RuntimeError`, for any call in test posture; with `ping` taking
an IP address only, sent as `ping --<kind> --c=1 --timeout=<N>s <ip>`; and with `SelfNode`
carrying a sixth field, `refusal` (`SELF_UNKNOWN` or `SELF_LINE_DISAGREES`), beside the pure
`decide(local, devices, protected)` and `from_line(devices, protected)` that `resolve_self` calls;
because a hung daemon must not stall a command; §5.5 has no code for a local run that failed, and
an unknown self is the fail-closed answer; a test-posture call is a bug, never a user error, so
it ends as exit 1 rather than as a code an agent might act on; the probe ladder addresses hosts by
IP (§3.1); the guard must know which of its two self codes applies; and the production join must
be testable without running tailscale, which no test may do.

**A21. (build, 2026-10-26)** §6 gave `gate.missing_rules(settings_path)` while §20.4 said it
compares against `rules_for(claude_dir)`'s output, and neither said where `claude_dir` comes
from; it was built as `missing_rules(settings_path, claude_dir=None)` beside
`gate.claude_dir(posture, environ)`, which gives the test home's Claude directory in test
posture and `CLAUDE_CONFIG_DIR`, made absolute, or `None` in production; `rules_for` refuses a
relative directory; a settings file that is not a regular file, or is over 1 MiB, is not read and
counts every rule missing; and `rules()` raises on a `rules.json` that is not v1 with its gate
among its ask rules; because the comparison must use the directory the installer used and only
the environment says whether `CLAUDE_CONFIG_DIR` is set, `~/.claude` cannot name a test home, a
`//` rule is meaningful only for an absolute path [PERM L370], `status` must always answer and a
FIFO put in place of the settings file would hang a blocking read, and rules that cannot be read
cannot vouch for a gate, so `--apply` must not go ahead on them.

---

## 0. The design on one page

1. **Two OAuth clients; the write client is optional.**
   - The **read client** (`devices:core:read`, `policy_file:read`, `devices:posture_attributes:read`,
     `dns:read`; no tag) serves every read [critic F4, R6; TC L94].
   - The **write client** (`devices:core`, tagged) is loaded only by a write command carrying
     `--apply`, after every guard check has passed.
   - A single all-scope client also works. In that mode its tokens are cached only if the server
     honours a narrowed read scope, and the separate-secret lever is absent (§8.3).
2. **Hazards are removed by structure, not guarded.**
   - The CLI can send exactly two write requests: `POST /device/{id}/tags` and
     `POST /device/{id}/key` with the constant body `{"keyExpiryDisabled": true}`.
   - It cannot delete, expire, deauthorize, rename, re-address or re-enable key expiry. So MC's P9
     ("never take a lab host off the tailnet") and critic F5 hold by construction [mc P9;
     critic F5].
3. **The human gate is a Claude Code `ask` rule that prompts in every interactive mode.** That
   includes `bypassPermissions` and auto. In headless `-p` runs the same calls are **denied**
   [PM L34-36, L56, L327, L650; PERM L83]. The separate write secret is the only boundary against
   a determined agent. The CLI guard stops accidents. Elmer's rule applies: this is **one
   enforced surface, not the whole surface** (§2).
4. **The server is the only parser.**
   - There is no HuJSON parser. Drafts are text, edited as text.
   - `/acl/validate` parses each draft and runs its own tests [critic R1, Q18 option (a)].
   - MC applies policy changes in the console.
5. **One read token per hour.** The read token is cached for its 3600 s life, mode 0600. A token
   is cached only when every granted scope ends in `:read`. A write token is never cached
   [critic F6; OC L20, L272].
6. **Fail closed throughout.**
   - An unknown self refuses every `--apply`.
   - A missing protected list refuses every tag write.
   - A missing `ask` gate in `~/.claude/settings.json` refuses every `--apply`.
   - A loopback test override never sends a real secret.
   - A write that was sent but not confirmed gets its own exit code (6), and the agent is told
     never to re-apply.

---

## 1. Decisions and conflicts resolved

Each row is a conflict between the designs or the judges, resolved in one line.

| # | Question | Resolution | One-line reason |
|---|---|---|---|
| D1 | Base design | SF | The judges split (J1 picked SF, J2 picked MIN), so the tie is broken on safety |
| D2 | SF's PreToolUse write-gate hook (J1: re-decide it; J2: drop it) | **Dropped**, together with its tests and SF's `test_e2e_bypass_mode_hook_denies_apply` | Its premise was false: ask rules prompt in bypass too [PM L34-36]. Its bypass branch would deny writes MC can approve. A hook's own answer cannot beat a matching ask rule [PERM L631] |
| D3 | Settled-facts store (J1: graft it; J2: no TTL store) | **No separate store file.** Doctor writes its settled answers into its `doctor.run` audit line. Probes that cost audit events re-run on `--settle`, on the first run, or when the newest answer is more than 30 days old (§16.3) | Keeps J1's 30-day re-measure and stops a deliberate "Failed request" being fired on every run, without a second state file (J2) |
| D4 | AskUserQuestion payloads in CLI output (J1: graft; J2: don't) | Doctor emits generic `questions[]` (`id`, `priority`, `text`, `options[{label, description}]`, `safe_default`). The skill asks one per turn, using AskUserQuestion | Delivers J1's priority order and one question per turn without tying CLI output to a Claude Code tool schema (J2) |
| D5 | `doctor --check-write` (J1: an ask rule on it; J2: doctor only stats the write file) | **No `--check-write`.** `credentials set write`, which needs a TTY and so runs in MC's hands, does the verification mint and the self-lookup, and records the client's tags | Settles Q16 without any command an agent can run loading the write secret |
| D6 | Self detection (J1: fail closed, join on IPs; J2: a required `self` line and no fake `tailscale`) | **Production:** a live IP join is required, and it must agree with the `self` line when one is present. **Test posture:** `tailscale` is never run, and self comes from the `self` line (§11.3) | Production fails closed and catches a credential for a foreign tailnet. Tests need no fake executable |
| D7 | `disable-key-expiry` while the protected list is unanswered (J1: allow it; J2: refuse every write without the `self` line) | **Allowed.** Tag writes still require the protected file and its `self` line | The outcome does not depend on which devices are protected or which is self, and this is the P9-protective write that must not wait on MC [critic F3.2] |
| D8 | `device rename` (MIN had it; J1 says don't carry it) | **Not offered** (§23) | The only need is one past console rename (P4). A rename breaks MagicDNS and Serve URLs [spec 504]. Which field changes first is unverified |
| D9 | Tag grammar: full set (MIN, AE) or delta (SF) | **`--add` / `--remove` delta** | The new set is computed from the fresh pre-read at apply time, so a concurrent console change is never silently reverted |
| D10 | SF's `--expect` fingerprint | **Dropped** | The delta grammar, a fresh re-evaluation at apply time and a `verb:hostname` confirm bound to a `nodeId` target together catch a stale plan. The hash only lengthens MC's phone prompt (AE §16) |
| D11 | Typed confirms | **Every R2 and R3 write takes `--confirm <verb>:<hostname>`**: `retag:`, `strip-owner:`, `no-expiry:` | J2 grafted the verb so the prompt reads as the risk. J1 flagged MIN's unconfirmed R2. The dry run prints the token |
| D12 | SF's `--strip-owner` flag | **Dropped.** The `strip-owner:` verb carries the intent | One fewer flag, same gate |
| D13 | Hash chain, write budget, arming TTL, install-manifest hash gate, `FS_IOC_GETFLAGS` probe | **All dropped** (J2) | Each one costs code and tests for accident-level gain. Disarming is `tailnet credentials forget write`, which makes J1's L2 timing correction moot |
| D14 | SF's write lock | **Kept**, as `apply.lock`, taken **before** the pre-reads | Two concurrent applies on one device would race the delta. About 10 lines |
| D15 | Audit outcome for a sent but unconfirmed write (J1: keep exit 6; J2: `failed` with `confirmed:false`) | **Exit 6**, CLI `outcome: "unconfirmed"`, audit `outcome: "failed"` with `confirmed: false` and the reason | The agent acts on the exit code. The audit keeps the decided outcome set (dry-run, refused, applied, failed) |
| D16 | No-ops | **Exit 0.** Audit `dry-run` without `--apply`, or `applied` with `sent: false, noop: true` | J2: dry runs and no-ops exit 0. Nothing is sent and the requested state already holds |
| D17 | `policy preview` | **No command.** The flow is documented in §14.5 | J2: `policy test` answers accept or drop, and `type=user` cannot take a tag source [pol (d) step 3] |
| D18 | `device show` | **Dropped.** `device list --json` carries every field, plus `self` and `protected` | One way to inventory (MIN). The exit-6 step is `tailnet device list --json` (J2) |
| D19 | Spec-drift and upstream-pin checks (J1: in doctor; J2: in e2e) | **Both.** Doctor reports them as INFO, and e2e asserts the spec sha | Drift is a doctor-visible fact, and e2e makes it a test |
| D20 | What "doctor only stats `write.json`" means once the secret sits in its own file | `write.json` **must** use the `file:` form, so it holds no secret. Doctor, status and the guard read its metadata, and only **stat** `write.secret` | Keeps the purpose of MIN's invariant 4: only `--apply` (or MC's `credentials set write`) opens the write secret |
| D21 | Settings tampering (J1, lever failure (a)) | Ask `Edit(~/.claude/settings.json)`; ask tripwire `Bash(*.claude/settings.json*)`; `status` and `doctor` check every rule on every run; the guard refuses `--apply` when the gate rule is missing | In bypass mode, writes to `~/.claude` are allowed without a prompt [PM L720-731]. An explicit ask rule still prompts in every mode |
| D22 | Deny `Bash(*.config/tailnet*)` | **Added** | Deny holds in every mode [PM L30]. It stops `cat`, `cp`, `printf >` and the like on the secret and protected files at the command-text level |
| D23 | SF's `TAILNET_TAILSCALE_BIN` | **Dropped** | J2: a runtime binary override is a mock seam. Test posture never runs `tailscale` at all |
| D24 | `--tailnet`, `--timeout` and `--version` flags | **Dropped.** The tailnet is always `-` | One tailnet [cred §10]. `status` prints the version |
| D25 | AE's opt-in allow rules | **Not installed** | An installer an agent runs must never loosen MC's permissions. The skill's `allowed-tools` covers reads during its turn |
| D26 | Policy draft shape | SF's draft directory: `base.hujson`, `candidate.hujson`, `meta.json`. `diff` reports readiness | Grafted per J2 |
| D27 | Exit-code table | SF's table, with exit 5 used only for refusals | 1 is a bug, 8 is a negative answer, and 6 versus 7 separates "may have landed" from "rejected" |
| D28 | Naming the disarm command (J2 wrote `tailnet forget write`) | `tailnet credentials forget write` | Grouped with `credentials set` for a regular grammar. Same behaviour |
| D29 | Installer ask tripwire | **Kept:** `Bash(*install-tailnet*)` | A reinstall replaces the guard code that every write runs through |
| D30 | Doctor's reachability probe (MIN S7a; SF has a WARN-versus-FAIL choice) | **WARN, not FAIL** | Doctor reports the tool's health and `diagnose` reports reachability. A healthy tool on today's tailnet exits 0 |

---

## 2. The levers, and which protection rests on which

This answers critic F4 and Elmer's "one enforced surface, not the whole surface". The Claude
Code facts were checked against the saved first-party pages.

| # | Lever | What it is | Holds when | Fails when |
|---|---|---|---|---|
| L1 | **CLI guard** | `guard.py` and `writes.py` checks (§12) | The agent goes through the CLI | An agent calls the API another way, or edits the installed code. It stops accidents, not a determined agent [critic F4, X8] |
| L2 | **Separate write secret** | The read client cannot write [critic R6]. `write.secret` exists only between MC's `credentials set write` and `credentials forget write`. Nothing expires it automatically | No write secret on disk: nothing on the droplet can write to the tailnet | While it is present, any process running as `mc` can read it by a route the deny rules do not match, such as a Python script that opens the file itself [PERM L356]. **Absent in single-client mode** |
| L3 | **Claude Code `ask` rule** `Bash(*tailnet*--apply*)` | Merged into `~/.claude/settings.json` | **Every interactive mode, including `bypassPermissions`.** Explicit ask rules are "actions no mode auto-approves" [PM L34-36, L650; PERM L83]. In auto mode, ask rules "still force a prompt" [PM L327]. Ask rules match inside `&&`, `;`, `$(…)` and after leading assignments [PERM L223, L233]. Headless `-p` runs **deny** the call instead [PM L56]. Remote Control from the app cannot select Bypass [PM L254]. Rules are checked deny, then ask, then allow [PERM L58] | (a) Command text that lacks `tailnet` or `--apply`, such as a wrapper script or `$(printf -- --ap""ply)`. A Bash rule "isn't a security boundary around the program" [PERM L252-260]. (b) An agent editing `~/.claude/settings.json`: bypass allows protected-path writes [PM L720-731]. Mitigated by D21 (an ask rule on `Edit(~/.claude/settings.json)`, a Bash tripwire, a check on every run, and the guard refusing `--apply` when the gate is missing). (c) **A mod that handles `tool.check` can approve an ask-matched call without prompting** when the machine has no managed settings and the session has no Team or Enterprise login [PERM L633-643]. MC's personal setup is in that case **[inference]**; doctor states it |
| L4 | **Deny rules** | `Read`/`Edit(~/.config/tailnet/**)`, `Bash(*.config/tailnet*)`, `Edit(~/.local/state/tailnet/audit.jsonl)` | Every mode, including bypass [PM L30]. They cover Read, Edit and Write, the Bash file commands Claude Code recognises (`cat`, `head`, `sed`, `tee`) and redirect targets [PERM L352, L356] | A script that opens files itself [PERM L356]. A `tool.check` mod in the setup named in L3 (c) [PERM L641] |
| L5 | **Tailscale's configuration audit log** | Always on, cannot be disabled, kept 90 days. Records every write, every token mint (with the Client ID as actor) and every scope-refused call [AUDIT L31, L316, L329, L409; TC L390-392] | Always. It is the tamper-resistant record | Reads are not logged [AUDIT L404] |
| L6 | **Local JSONL audit log** | `~/.local/state/tailnet/audit.jsonl`, written with `O_APPEND` and `flock` (§13) | Accidents; correlating with transcripts | A deliberate rewrite through a script |
| L7 | **Server-side rules** | Tags must be in `tagOwners` [spec 548]. The OAuth tag rule [TAGS L324] (whether it applies on the API path is **[unverified]**, critic Q8). Shared-in devices cannot be deleted [spec 331] | Always | They do not limit which devices `devices:core` can change [critic F1; cred §3] |
| L8 | **Console revocation** | MC revokes a client. Its live tokens die with it [TC L388] | Everything | Neither client holds `oauth_keys`, so only MC can do it [cred §6] |

**Postures MC can choose** (judge 2's last `must_fix`):

- **Standing.** Leave `write.json` and `write.secret` in place. This is safe against accidents in
  every interactive mode, because L3 prompts for every `--apply`, bypass included.
- **Session-scoped.** Run `tailnet credentials forget write` after each write session. This is
  the posture that holds against a determined agent (L2).

The skill offers the second posture once, after a write session ends. It never runs it
unprompted.

---

## 3. Scope, assumptions, and needs traced to commands

### 3.1 Assumptions

- **One host.**
  - The droplet `claude-factory` runs Ubuntu on x86_64, as user `mc`, and is on the tailnet
    [critic Q25; mc §2].
  - Cloud and Cowork sessions do not read `~/.claude/skills/` and would have no secret, so they
    are out of scope [pkg §5.1].
- **Python 3.10 or later, stdlib only at runtime.**
  - There is no `tomllib` and no `datetime.UTC`; use `datetime.timezone.utc`.
  - pytest is a development-only dependency.
  - The droplet's Python version is unknown [critic Q26], so doctor reports it.
- **The tailnet is always `-`** [cred §10; api §3.1].
- **Addresses.**
  - Hosts are addressed by their 100.x address or `nodeId`, never by MagicDNS name. MagicDNS
    failed on the droplet at 2026-10-25T23:30Z [critic F3.6].
  - Real paths come from `pwd.getpwuid(os.geteuid()).pw_dir`, not `$HOME`, so an environment
    change cannot move them. On the droplet these are the same directory.

### 3.2 Needs → commands (the command set is exactly these 14)

| MC's recorded need or constraint | Source | Command |
|---|---|---|
| "Is there no API for Tailscale why do I need to do this in the console" (about tagging three hosts) | [sigint p3:84] | `device tag` |
| Inventory the tailnet without console work | Task; [sigint p3:84] | `device list` |
| The retagged hosts may still carry key expiry and drop off when it lapses | [critic F3.2; TAGS L84; mc P9] | `device list` flags it; `device disable-key-expiry` fixes it |
| The live blocker: droplet → spec5, nomad-b and pi5 on TCP 22 times out, while ping and 443 work | [sigint p3:138-144; critic F3] | `diagnose` |
| Did tagging cut MC's phone or albini off spec5? | [critic F3.3, R13] | `diagnose --from` |
| Fix the policy without the agent holding policy write power | Decided; [pol (e)] | `policy get`, `policy draft`, `policy validate`, `policy diff` |
| Ask "can X reach Y:22" of the live policy | [pol TL;DR 3] | `policy test` |
| DNS visibility (`dns:read` is in the scope set; MagicDNS failed on the droplet) | Decided; [critic F3.6] | `dns` |
| A first run with the real credential settles Q1-Q23; it doubles as the end-to-end check | [critic §6] | `doctor` |
| Live state when the skill loads; gate rules checked on every run | [SK L772-793]; J1 `must_fix` | `status` |
| The secret never passes through chat, argv or the environment | Decided | `credentials set` (TTY only) |
| Disarming writes stays easy, and the agent can do it | J2 `must_graft` | `credentials forget` |

`tests/unit/test_cli_args.py::test_the_command_set_is_exactly_the_designed_fourteen` is the
tripwire against scope creep (grafted from MIN §15.2).

---

## 4. Repository layout (every file)

Every file of executable code starts with two `# ABOUTME:` lines. That covers `*.py`, `*.sh`,
`githooks/pre-commit`, `Makefile` and the generated launcher. Data files (`*.json`, `*.yaml`,
`*.hujson`) and Markdown are exempt. Comments explain the domain and the decision, never syntax.

```
wittyreference/tailscale/
├── README.md                     For MC: what it is; the 3 things MC may not realise (§19.2 item 3);
│                                 first-run sequence (§26); levers (§2); postures; uninstall; revoke
├── CLAUDE.md                     Repo working rules and the maintainer invariants (§22)
├── DESIGN.md                     This spec, committed, plus a change log; every guard change records
│                                 MC's approval and date
├── Makefile                      test | e2e | install | install-dry-run | uninstall | venv
├── pyproject.toml                [tool.pytest.ini_options] only (§21.1); no build backend
├── .gitignore                    (exists) + drafts/ + captures/
├── install-tailnet.sh            Thin bash wrapper: python3 ≥ 3.10, not root, then
│                                 `python3 -I installer/install.py "$@"`
├── githooks/pre-commit           (exists) identity guard + NEW staged-diff secret scan (§21.6)
├── installer/
│   ├── install.py                install, --uninstall, --dry-run / DRY_RUN=1, --no-upstream, --no-mcp
│   ├── settings_merge.py         pure merge/remove of rules into settings.json (§20.4)
│   └── upstream.py               pinned clone + verify of tailscale/tailscale-skill@4f05d35
├── spec/
│   ├── tailscale-openapi.yaml    pinned copy of api/v2?outputOpenapiSchema=true (from tsdocs/openapi.json)
│   └── SHA256SUMS                b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38  tailscale-openapi.yaml
├── src/tailnet/
│   ├── __init__.py               __version__ = "0.1.0"
│   ├── __main__.py               python -m tailnet → cli.main()
│   ├── rules.json                single source of every ask/deny string and the gate rule (§20.4)
│   ├── cli.py                    argparse (allow_abbrev=False everywhere), dispatch, exit mapping
│   ├── errors.py                 TailnetError hierarchy → exit codes (§5.3)
│   ├── output.py                 the tailnet.v1 envelope, human renderers, emit(), warn(), now_utc()
│   ├── posture.py                production vs test posture; base URL rule; TAILNET_HOME rule; paths
│   ├── secure_files.py           ssh-style checks; atomic 0600 writes; O_APPEND+flock appends
│   ├── redact.py                 value + pattern redaction; redacting excepthook
│   ├── credentials.py            read/write credential loading, modes, set (TTY), forget
│   ├── http.py                   urllib transport: no redirects, proxies, status mapping, 429 rule
│   ├── tokens.py                 mint, cacheable(), 0600 read-token cache
│   ├── api.py                    one function per endpoint; exactly two write functions
│   ├── localts.py                the ONLY module that runs the tailscale binary; refuses in test posture
│   ├── selfnode.py               parse `tailscale status --json` (pure), IP join (pure), resolve self
│   ├── devices.py                normalise, resolve a DEVICE argument, derivations, table
│   ├── protected.py              parse/load MC's protected file (pure parser)
│   ├── gate.py                   reads rules.json and Claude settings; is the gate present?
│   ├── guard.py                  pure planning: classes, checks, confirm tokens, tag rules
│   ├── writes.py                 apply orchestration: lock, write mint, single POST, post-read, audit
│   ├── audit.py                  JSONL append and read-back (doctor's settled answers)
│   ├── policy.py                 get/draft/validate/diff/test; verdict parser (pure)
│   ├── diagnose.py               probes, API checks, ssh candidate (pure), verdict (pure)
│   ├── doctor.py                 local checks + critic §6 steps 1-8, settle logic, questions
│   └── status.py                 offline status; --brief for skill injection
├── skill/tailnet/
│   ├── SKILL.md                  §19.2
│   └── references/
│       ├── tailnet-facts.md      §19.3
│       ├── gotchas.md
│       ├── diagnose-port.md
│       ├── policy-workflow.md
│       ├── credentials.md
│       └── upstream-corrections.md
└── tests/
    ├── conftest.py               installs netguard in-process; shared fixtures (§21.1)
    ├── netguard.py               sys.addaudithook: refuse non-loopback connect and any `tailscale` exec
    ├── loopback.py               ThreadingHTTPServer seam: route table + request recorder
    ├── run_cli.py                integration launcher: netguard.install(), then tailnet.cli.main()
    ├── test_pre_commit.py        (exists) + secret-scan cases
    ├── unit/                     §21.2
    ├── integration/              §21.3
    ├── e2e/                      §21.4: conftest.py fails loudly; run_live.py refuses --apply
    └── fixtures/
        ├── README.md             maps every fixture to its spec line or its "synthetic, from schema" label
        ├── api/*.json            spec-example bodies, each with a "_source" key (stripped before serving)
        ├── api/policy.hujson     ExampleHuJSONPolicyFile [spec 6757-6778]
        ├── api/policy.json       ExampleJSONPolicyFile [spec 6742]
        ├── scenario/*.json       MC-shaped bodies built from spec shapes, labelled synthetic
        └── status/self-running.json  synthetic `tailscale status --json`, indented with real field
                                      names [ipnstate:43-50, 239-280]; parser unit tests only
```

---

## 5. CLI grammar

### 5.1 Global rules

- **Abbreviations.** Every argparse parser and sub-parser is built with `allow_abbrev=False`.
  Otherwise `--appl` would mean `--apply` and slip past the ask pattern `*--apply*` (L3).
  Test: `test_abbreviated_flags_are_usage_errors`.
- **`--apply`** is `store_true`. `--apply=yes` is a usage error.
- **`--json`** is accepted before or after the subcommand, through a shared parent parser. With
  `--json`, stdout holds exactly one envelope, error or not (§5.4).
- **No flag** takes a secret, a base URL, a tailnet ID, a credential path or `--force`. A guard
  refusal is final for the CLI; MC can still use the console.
- **`DEVICE`** matches exactly one device on any of these:
  - `nodeId`;
  - the numeric `id`;
  - `hostname` (ignoring case);
  - the full `name` (with or without its trailing dot);
  - the first label of `name` (ignoring case);
  - a Tailscale IPv4 or IPv6 address.

  It never matches by substring or prefix. Zero matches gives `DEVICE_NOT_FOUND`. Two or more
  give `DEVICE_AMBIGUOUS`, with each candidate's `nodeId`, `hostname` and IPv4. "Ambiguity is
  absence's twin" (Elmer invariant 2) [api §12.10].
- **Write paths** use only the `nodeId` the API returned. It is checked against
  `^[A-Za-z0-9]+$`, then URL-quoted.
- **Listings are never truncated.** Each ends with `N of N devices (the API does not
  paginate)` [spec 47-49; critic X6; Corrections, MESH-39].
- **Every output carries `measured_at`** (UTC, ISO 8601, `Z`) [Corrections, "report the
  measurement time"].
- **`--reason TEXT`** is **required with `--apply`**.
  - It is 1-200 characters, redacted, and stored in the audit record.
  - Because it is part of the command line, MC sees it in the permission prompt (J2 graft).
  - The literal placeholder `<why>` is refused.

### 5.2 Commands

**R** is a read and **W** a write. A dry run counts as a read.

| Command | Arguments and flags | Does | Exit codes |
|---|---|---|---|
| `tailnet status` | `[--brief]` | Local only: no API call and no network. It reads the credential metadata, the token cache, the protected file, the gate rules, the newest `doctor.run` line, the audit line count and the local `tailscale status --json` (3 s timeout; production only). `--brief` prints at most 6 lines. R | Always 0 |
| `tailnet doctor` | `[--settle]` | Local checks plus critic §6 steps 1-8 (§16). R | 0 when nothing FAILs; 8 on a FAIL; 3 when the read credential is missing or unsafe |
| `tailnet device list` | — | `GET /tailnet/-/devices?fields=all` plus the derivations in §11.2. R | 0 / 3 / 4 |
| `tailnet device tag` | `DEVICE (--add TAG \| --remove TAG)... [--confirm TOKEN] [--apply --reason TEXT]` | Plans or applies a new full tag set (§12). Exactly one `DEVICE`. At least one `--add` or `--remove`. W | 0, 2, 3, 4, 5, 6, 7 |
| `tailnet device disable-key-expiry` | `DEVICE... [--confirm TOKEN] [--apply --reason TEXT]` | Plans or applies `{"keyExpiryDisabled": true}`. Several devices are allowed only when every target is R1 (§12.5). W | 0, 2, 3, 4, 5, 6, 7 |
| `tailnet policy get` | `[--format hujson\|json] [--out FILE]` | `GET /tailnet/-/acl`. The bytes go to stdout (or `--out`) exactly as served; metadata goes to stderr. R | 0 / 3 / 4 |
| `tailnet policy draft` | `[--name NAME]` | Fetches the live HuJSON into a new draft directory (§14.2). R | 0 / 3 / 4 |
| `tailnet policy validate` | `TARGET` (a draft directory or a file) | `POST /acl/validate`, sending the candidate bytes as HuJSON. Records the verdict in the draft's `meta.json`. R | 0 pass (with or without warnings) / 8 fail / 2 array-shaped file / 3 / 4 |
| `tailnet policy diff` | `DRAFT` | Diff of base → candidate, a drift check and a readiness line, ending with the console steps (§14.4). R | 0 READY / 8 NOT READY / 3 / 4 |
| `tailnet policy test` | `--src SRC (--accept HOST:PORT)... (--deny HOST:PORT)... [--proto PROTO]` | `POST /acl/validate` with a one-test array, run against the **live** policy. R | 0 pass / 8 fail / 2 / 3 / 4 |
| `tailnet dns` | — | The four documented `dns:read` GETs, plus `/dns/configuration` best-effort, plus local `tailscale get accept-dns` and a `getaddrinfo` of self's MagicDNS name (§18). R | 0 / 3 / 4 |
| `tailnet diagnose` | `DEVICE... [--port N] [--ssh-user USER] [--from DEVICE]` | The ladder in §15. `--port` defaults to 22. R | 0 when all are reachable / 8 when any is blocked or inconclusive / 3 / 4 |
| `tailnet credentials set` | `{read\|write}` | **TTY only.** Prompts for the client ID and the secret, writes the 0600 files, mints once to verify, and for `write` also runs the self-lookup and records the tags (§8.4) | 0 / 2 / 3 / 4 |
| `tailnet credentials forget` | `{read\|write\|token}` | Unlinks that role's files (or the token cache) and logs it. No prompt; any agent may run it. `forget write` is **disarm** | 0 |

That is 14 leaf commands. Two of them can write, and only with `--apply`.

**Validation done before any API call** (failures exit 2):

- **Tags.** Each `TAG` is lowercased [pol (f)] and must match `^tag:[a-z0-9][a-z0-9-]*$`. A tag
  may not appear in both `--add` and `--remove`.
- **`policy test`.**
  - `SRC` must be a user email, `group:…`, `tag:…`, or a bare host-alias name.
  - A raw IP as `SRC` is refused. The documented `src` types are user, group, tag and host alias
    [spec 2533-2540]. The spec's only IP-as-`src` example is its syntactically invalid
    `aclValidateJSON` [spec 2606-2612].
  - `*` is refused anywhere [spec 2574, 2585; pol (c)].
  - Ports must be a single number from 0 to 65535. Port 0 is for `--proto icmp` [pol (c)].
    IPv6 targets are written `[addr]:port`.
- **`policy validate`.** After skipping leading whitespace and leading `//` or `/* */` comments
  (a scan of the start only, not a parser), refuse a body whose first character is `[`. Message:
  "a tests array runs against the live policy: use `tailnet policy test`". The server picks its
  mode from the body's shape [api §6.3] (MIN §3.3, J1 graft).
- **`--name`** must match `^[a-z0-9-]{1,40}$`.
- **`--port`** must be 1-65535.

### 5.3 Exit codes (stable and tested)

| Code | Name | Meaning | Was anything sent? |
|---|---|---|---|
| 0 | OK | Success. Covers a check that passed, a dry run planned, a no-op, and an applied write confirmed by a re-read | — |
| 1 | INTERNAL | A bug. The message is redacted. The traceback, also redacted, is shown only with `TAILNET_DEBUG=1` | unknown |
| 2 | USAGE | Bad arguments, `--apply` without `--reason`, an array-shaped validate file, a wildcard | no |
| 3 | LOCAL | A local precondition failed: a credential or protected file that is missing, unsafe or malformed; an unsafe override; a real secret in test posture; the tailscale CLI missing; no TTY; the audit log unwritable; a token rejected after re-minting | no |
| 4 | API | A read failed: an API error status, a malformed body, a redirect, or a network failure | no write |
| 5 | REFUSED | The write guard declined. The reason code and message are printed | **no** |
| 6 | UNCONFIRMED | A write was sent and its outcome is not confirmed: a 5xx, timeout or reset after sending with no re-read showing the change; a re-read that failed; or a 2xx whose re-read does not match. **Never re-apply** | **yes, it may have landed** |
| 7 | REJECTED | A write was sent and the API rejected it (3xx, 4xx or 429). The re-read is reported | yes, and it was not applied |
| 8 | NEGATIVE | The command ran fine and the answer is "no": a policy test or validate failed, `diff` is not ready, `diagnose` found a block, or `doctor` has a FAIL | — |

With several targets, the exit code is that of the first target that did not end in OK.

### 5.4 Output

**Human output (the default).**

- The first line is the verdict and ends with `(as of <UTC>)`.
- Next comes a compact block.
- Then `Next:` lines, each naming who acts (`agent`, `MC`).
- Warnings go to stderr, prefixed `tailnet: `.
- In test posture, every run starts with this stderr banner:
  `TEST POSTURE: API http://127.0.0.1:N, home <dir>. Nothing here touches the real tailnet.`

**JSON (`--json`).** Exactly one object on stdout:

```json
{
  "schema": "tailnet.v1",
  "command": "device tag",
  "cli_version": "0.1.0",
  "posture": "production",
  "measured_at": "2026-10-27T01:02:03Z",
  "ok": true,
  "exit": 0,
  "outcome": "dry-run",
  "data": {},
  "warnings": [{"code": "TAGGED_KEY_EXPIRY_ON", "message": "…", "source": "TAGS L84"}],
  "error": null,
  "next": [{"who": "agent", "run": "tailnet device tag nAbc… --remove tag:lab --confirm retag:pi5 --apply --reason \"<why>\"", "why": "applies this plan; MC is prompted"}],
  "request_ids": ["REQ-…"]
}
```

**Fields.**

- **`outcome`** is one of: `ok`, `negative`, `dry-run`, `noop`, `refused`, `applied`,
  `rejected`, `unconfirmed`, `error`.
- **`ok`** is `exit == 0`. Agents branch on `outcome`.
- **`error`** has the shape
  `{"code": "CONFIRM_MISMATCH", "kind": "refused|usage|local|api|internal|unconfirmed|rejected", "message": "…", "http_status": 403, "request_id": "REQ-…"}`.
- **`next[]`** entries come in three shapes (grafted from AE §3.1):
  - `{"who": "agent", "run": "…", "why": "…"}`
  - `{"who": "mc", "do": "…", "why": "…", "needs": "terminal|browser|console|sudo"}`
  - `{"who": "ask_mc", "question": {"id", "text", "options": [{"label", "description"}], "safe_default"}}`
- Every string passes through `redact()` before `emit()` writes it (§10.4).

### 5.5 Stable error and refusal codes

These are the strings tests assert on. Messages may change; codes may not.

- **Exit 2:** `USAGE`, `REASON_REQUIRED`, `REASON_PLACEHOLDER`, `TAG_MALFORMED`,
  `TAG_ADD_AND_REMOVE`, `TEST_WILDCARD`, `TEST_SRC_IS_IP`, `TEST_PORT`, `VALIDATE_ARRAY_BODY`.
- **Exit 3:** `CREDENTIAL_MISSING`, `CREDENTIAL_UNSAFE`, `CREDENTIAL_MALFORMED`,
  `WRITE_SECRET_INLINE`, `TEST_POSTURE_REAL_SECRET`, `ENV_UNSAFE_OVERRIDE`, `HOME_WITHOUT_BASE`,
  `TAILSCALE_CLI_MISSING`, `NOT_A_TTY`, `RUN_AS_ROOT`, `TOKEN_REJECTED`, `AUDIT_UNWRITABLE`,
  `PROTECTED_MALFORMED`.
- **Exit 4:** `API_BAD_REQUEST`, `API_FORBIDDEN`, `API_NOT_FOUND`, `API_PAYMENT`,
  `API_RATE_LIMITED`, `API_SERVER`, `API_REDIRECT`, `API_BAD_RESPONSE`, `NETWORK`.
- **Exit 5:**
  - targeting: `DEVICE_NOT_FOUND`, `DEVICE_AMBIGUOUS`, `SHARED_IN`;
  - self: `SELF_UNKNOWN`, `SELF_LINE_DISAGREES`, `SELF_DEVICE`;
  - protected list: `PROTECTED_UNANSWERED`, `PROTECTED_DEVICE`;
  - gate and confirm: `GATE_MISSING`, `CONFIRM_MISSING`, `CONFIRM_MISMATCH`;
  - tags: `TAG_UNDEFINED`, `TAG_NOT_PRESENT`, `TAG_SET_EMPTY`, `CLIENT_CANNOT_ASSIGN`,
    `WRITE_CLIENT_TAGS_UNRECORDED`, `POLICY_UNREADABLE`;
  - write client: `WRITE_CREDENTIAL_MISSING`, `WRITE_SCOPE_MISSING`;
  - batch and concurrency: `MULTI_TARGET_NOT_R1`, `APPLY_IN_PROGRESS`.
- **Exit 6:** `WRITE_UNCONFIRMED`.
- **Exit 7:** `WRITE_REJECTED`.
- **Exit 8:** `POLICY_TEST_FAILED`, `POLICY_INVALID`, `DRAFT_NOT_READY`, `DIAGNOSE_BLOCKED`,
  `DOCTOR_FAIL`.

---

## 6. Module structure

Dependencies run one way, with no cycles: `errors → redact → posture → secure_files → output →
audit → credentials → http → tokens → api → localts → selfnode, devices, protected, gate → guard
→ writes → policy, diagnose, doctor, status → cli`.

| Module | Responsibility | Public surface (the contract the tests use) |
|---|---|---|
| `errors` | One exception class per exit code, each carrying a stable `code` | `TailnetError(exit, code, message, *, http_status=None, request_id=None, next=None)`; subclasses `UsageError`(2), `LocalError`(3), `ApiError`(4), `Refused`(5), `Unconfirmed`(6), `Rejected`(7), `Negative`(8) |
| `redact` | Strips secrets from all outbound text | `REDACTOR.add_secret(value)`; `REDACTOR.redact(text) -> str`; `install_excepthook()` |
| `posture` | Decides production or test; validates overrides; owns every path | `Posture.from_env(environ, real_home) -> Posture` with `.kind`, `.api_base`, `.config_dir`, `.state_dir`, `.drafts_dir`, `.claude_settings`, `.runs_tailscale`, `.proxies` |
| `secure_files` | The only code that opens credential, protected, token or audit files | `check_private_stat(st, euid) -> list[str]` (pure); `check_parent(path, euid)`; `read_private(path, max_bytes) -> bytes`; `write_private_atomic(path, data)`; `append_locked(path, line: bytes)` |
| `output` | The single exit point for text | `Envelope`; `emit(env, json_mode)`; `warn(code, msg, source=None)`; `now_utc()` |
| `audit` | The JSONL log | `append(event: dict)`; `last(event_name) -> dict \| None`; `count_lines() -> int` |
| `credentials` | Role files and modes | `load_read() -> Credential`; `load_write_meta() -> WriteMeta \| None`; `load_write_secret(meta) -> Credential`; `mode() -> "two-client" \| "single-client" \| "read-only" \| "none"`; `set_interactive(role, io)`; `forget(role)` |
| `http` | Transport | `Transport(posture).request(method, path, *, token=None, accept=None, content_type=None, body=None, query=None, idempotent) -> Response(status, headers, body, request_id, etag_raw, date)` |
| `tokens` | Tokens | `cacheable(scope: str \| None) -> bool` (pure); `read_token() -> str`; `mint(cred, *, scope=None) -> Token` |
| `api` | Endpoint wrappers. **The only two write functions are here** | `list_devices()`, `get_device(node_id)`, `get_key(key_id)`, `get_routes(node_id)`, `get_policy(accept)`, `validate_tests(tests)`, `validate_policy(body, content_type)`, `dns_nameservers()`, `dns_preferences()`, `dns_searchpaths()`, `dns_split()`, `dns_configuration()`, **`set_device_tags(node_id, tags, write_token)`**, **`disable_key_expiry(node_id, write_token)`** |
| `localts` | Runs `tailscale`. Raises `LocalError(TAILSCALE_CLI_MISSING)` when absent, and refuses to run in test posture | `status_json(timeout) -> str`; `ping(ip, kind: "tsmp"\|"icmp", timeout) -> PingResult(exit, output)`; `get_pref(name) -> str`; `version() -> str` |
| `selfnode` | Who am I | `parse_status(text) -> LocalStatus` (pure); `join(local, devices) -> Device \| None` (pure); `resolve_self(posture, devices, protected) -> SelfNode(known, device, source, id_agrees, reason)` |
| `devices` | Answers from the device list | `normalise(dict) -> Device`; `resolve(arg, devices) -> Device`; `owner()`, `key_expiry(now)`, `control()`, `tailscale_ssh()`, `flags()`; `render_table(devices, now)` |
| `protected` | MC's protected file | `parse(text) -> Protected(self_node_id, entries)` (pure); `load(posture) -> Protected \| None`; `Protected.protects(device) -> str \| None` (why) |
| `gate` | The ask gate | `rules() -> dict` (from the package `rules.json`); `rules_for(claude_dir) -> dict` (pure; substitutes the settings path when `CLAUDE_CONFIG_DIR` is set; the installer uses it too); `missing_rules(settings_path) -> list[str]`; `gate_present(settings_path) -> bool` |
| `guard` | **Pure** planning. No I/O, so every rule is unit-testable | `plan_tag(device, add, remove, ctx) -> Plan`; `plan_disable_key_expiry(devices, ctx) -> list[Plan]`; `client_may_assign(new, client_tags, tag_owners) -> bool`; `rule_references(policy_json, tags) -> list[str]`; `check_apply(plans, ctx, confirm, reason) -> list[Refusal]` |
| `writes` | Side-effecting apply | `run(command, args) -> Envelope`: dry run or apply, lock, write mint, one POST per target, post-read, audit |
| `policy` | Policy flows | `get()`, `draft(name)`, `validate(target)`, `diff(draft)`, `test(src, accept, deny, proto)`; `parse_verdict(status, body) -> Verdict` (pure); `parse_want_got(errors) -> list` (pure) |
| `diagnose` | The reachability ladder | `tcp_probe(ip, port, timeout) -> str`; `ssh_candidate(live_json, dst_ip, src, user, mode) -> dict` (pure); `verdict(facts) -> Verdict` (pure); `run(args) -> Envelope` |
| `doctor` | First-run settlement and health | one function per check returning `Check(id, title, status, settles, finding, evidence, measured_at, next)`; `questions(state) -> list[Question]` (pure); `run(args) -> Envelope` |
| `status` | Offline status | `run(brief) -> Envelope` (always exits 0) |
| `cli` | Grammar and exit mapping | `build_parser()`; `main(argv=None) -> int` |

`Plan` is a dataclass with these fields: `op`, `cls` (`"R1"|"R2"|"R3"`), `target` (normalised
device), `before`, `after`, `checks[]`, `refusal` (`code`, `message` or `None`),
`confirm_required` (token or `None`), `warnings[]`, `consequences[]`, `noop`, `apply_argv`.

---

## 7. Posture and paths

### 7.1 Two postures, decided once at start-up

| | Production (default) | Test |
|---|---|---|
| Entered when | `TAILNET_API_BASE` and `TAILNET_HOME` both unset | both set and both pass §7.2 |
| API base | `https://api.tailscale.com/api/v2` [spec 13, 56] | `TAILNET_API_BASE` + `/api/v2` |
| TLS | `ssl.create_default_context()`, full verification, no way to disable it | plain HTTP to loopback |
| Proxies | environment proxies honoured (`HTTPS_PROXY`) | `ProxyHandler({})`: environment proxies ignored, so test traffic and fixture secrets cannot leave the box [AE §7.1] |
| Config dir | `<pw_dir>/.config/tailnet` (0700) | `$TAILNET_HOME/config` |
| State dir | `<pw_dir>/.local/state/tailnet` (0700); drafts in `drafts/` | `$TAILNET_HOME/state` |
| Claude settings (gate check) | `$CLAUDE_CONFIG_DIR/settings.json`, else `<pw_dir>/.claude/settings.json` | `$TAILNET_HOME/claude/settings.json` |
| Secrets accepted | `^tskey-client-[A-Za-z0-9_-]+$`; `tskey-api-` refused by name [cred §7; KP L15] | **anything beginning `tskey-` is refused** (`TEST_POSTURE_REAL_SECRET`); fixtures match `^[A-Za-z0-9_-]{8,256}$` |
| Runs `tailscale` | yes, through `localts` | **never**: `localts` raises; self comes from the protected file's `self` line (§11.3); pings are recorded `not-run: test posture` |
| Banner | none | stderr banner on every run; `"posture": "test"` in JSON |
| Doctor network extras (spec drift, `git ls-remote`) | run (INFO) | skipped |

### 7.2 Override rules (checked before any file is read; MIN, SF §7.1, AE §7.4, J2 `must_fix`)

1. Either both `TAILNET_API_BASE` and `TAILNET_HOME` are set, or neither. Exactly one set → exit 3
   `HOME_WITHOUT_BASE` / `ENV_UNSAFE_OVERRIDE`.
2. `TAILNET_API_BASE` parsed with `urllib.parse`: scheme `http`; hostname exactly `127.0.0.1` or
   `localhost`; a port is required; no userinfo, query or fragment; path empty or `/`. For
   `localhost`, every address `socket.getaddrinfo` returns must satisfy
   `ipaddress.ip_address(a).is_loopback`. Refused: `127.0.0.1.example.com`, `localhost.evil`,
   `127.1`, `0x7f000001`, `[::1]`, `http://user@127.0.0.1:9`, `https://127.0.0.1:9`, any port-less
   form.
3. `TAILNET_HOME` must be absolute, and its `realpath` must not be inside (or equal to) the real
   `<pw_dir>/.config/tailnet` or `<pw_dir>/.local/state/tailnet`, and neither real directory may be
   inside it (this rejects `TAILNET_HOME=~`). So the real credential files are never read in a test
   run.
4. Any failure → exit 3 `ENV_UNSAFE_OVERRIDE`, contacting nothing, never falling back to production.

Why both rules: the loopback rule alone removes remote exfiltration but leaves a local listener on
127.0.0.1 able to harvest a real secret; the separate home means the real files are never read, and
the `tskey-` refusal means a real secret copied into the test home is still never sent.

---

## 8. Credentials

### 8.1 Files (test posture: the same names under `$TAILNET_HOME/config`)

| Path | Mode | Contents | Written by |
|---|---|---|---|
| `~/.config/tailnet/` | 0700 | — | installer, `credentials set` |
| `~/.config/tailnet/read.json` | 0600 | `{"v":1,"role":"read","client_id":"k…","client_secret":"file:/home/mc/.config/tailnet/read.secret","set_at":"…","granted_scope":"…"}` | `credentials set read` |
| `~/.config/tailnet/read.secret` | 0600 | the read client's secret and a newline, nothing else | `credentials set read` |
| `~/.config/tailnet/write.json` | 0600 | `{"v":1,"role":"write","client_id":"k…","client_secret":"file:/home/mc/.config/tailnet/write.secret","tags":["tag:fleet"],"tags_source":"self-lookup\|typed","granted_scope":"…","set_at":"…"}` | `credentials set write` |
| `~/.config/tailnet/write.secret` | 0600 | the write client's secret | `credentials set write` |
| `~/.config/tailnet/read-token.json` | 0600 | cached read token (§9) | `tokens` |
| `~/.config/tailnet/protected` | 0600 | MC's protected list (§11.4) | **MC by hand**; never the CLI or an agent |

- `client_secret` follows the Terraform provider: "If the value starts with 'file:' then it is
  treated as a path to a file on disk that contains the client secret" [critic R12]. `read.json`
  may hold the secret inline (`tskey-client-…`) or as `file:`. **`write.json` must use `file:`**
  (inline → exit 3 `WRITE_SECRET_INLINE`), so status, doctor and the guard read `client_id` and
  `tags` without the write secret ever being opened (D20). A `file:` target must be an absolute path
  inside the config directory; anything else is refused.
- All files sit under one directory so one pair of deny rules (`Read`/`Edit(~/.config/tailnet/**)`)
  plus `Bash(*.config/tailnet*)` keeps every secret, the token and the protected list out of the
  transcript and in MC's hands only (MIN §8.2, J2).

### 8.2 Loading rules (ssh `StrictModes` style; every failure exits 3)

`secure_files.read_private` applies these to every credential, `file:` target, token cache and the
protected file (SF §5.2, MIN §5.3, J2 graft on the parent directory):

1. `lstat`: must be a regular file. Symlinks are refused.
2. `os.open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)`, then `fstat` on the descriptor; every check
   below runs on the opened file, closing the check-to-read race.
3. `st_uid == os.geteuid()`, else "owned by uid N, not you".
4. `st_mode & 0o077 == 0`: any group or other bit refuses it, not only read bits, because a
   group-writable file can be swapped. Message: `refusing to read …/read.json: mode 0644 lets
   group/other access it; MC runs: chmod 600 …/read.json` with `next: who=mc needs=terminal`
   (unsafe modes may mean exposure, so MC should know, AE §5).
5. `st_nlink == 1`. Hard links are refused.
6. Parent directory: owned by the euid and `mode & 0o022 == 0` (J2 graft).
7. Size ≤ 4 KiB (credential, secret), 16 KiB (token cache), 64 KiB (protected).
8. JSON parse; required keys present; `v == 1`; `role` equals the file stem. Messages never
   include file contents.
9. Secret format per §7.1. The secret is registered with `REDACTOR` immediately, before any use.
10. **No environment variable and no argv path ever supplies a secret.** There is no code that reads
    one. Doctor scans `os.environ` values for `tskey-` and warns `SECRET_IN_ENVIRONMENT` naming only
    the variable (AE §5).

### 8.3 Modes (the CLI works in each; MC's answer to C1 changes nothing in code)

| Mode | Detected when | Reads | Writes | L2 |
|---|---|---|---|---|
| `none` | no `read.json` | exit 3 with the console steps (`next: who=mc`) | refused | — |
| `read-only` | `read.json` only | read token, cached | `WRITE_CREDENTIAL_MISSING` (exit 5) | holds trivially |
| `two-client` | both, different `client_id`, `read.json.granted_scope` cacheable | read token, cached | write token per command | **holds** |
| `single-client` | same `client_id` in both, **or** `read.json.granted_scope` not cacheable | mint **with** `scope=devices:core:read policy_file:read devices:posture_attributes:read dns:read`; cache only if the granted scope is cacheable (§9) | write token from `write.secret` | **absent**: `status` and `doctor` say so |

### 8.4 `credentials set {read|write}` (MC's hands, one command)

1. Refuse unless stdin and stdout are both TTYs (`NOT_A_TTY`, exit 3). The agent's Bash tool has no
   TTY, so this is MC's command, run over SSH from Termius or albini (Corrections: hand MC one
   command, say what it proves).
2. In production posture refuse to run as root (`RUN_AS_ROOT`): the files would land in `/root`.
3. Create or tighten the config directory to 0700. If the role file exists, ask `replace? [y/N]`.
4. Prompt `Client ID:` (echo on) and `Client secret:` via `getpass`. Check the prefix (§7.1).
5. Write `<role>.secret` then `<role>.json` atomically (§8.5).
6. Verification mint (§9.1), no `scope` unless single-client is detected.
   - `read`: record `granted_scope` in `read.json`; cache the token if cacheable; if the granted
     scope holds write power, warn `READ_CLIENT_CAN_WRITE` ("this is single-client mode; L2 is
     absent").
   - `write`: refuse to keep the files (delete them, exit 3) unless `granted_scope` contains
     `devices:core`, the legacy `devices`, or `all` [OC L132 uses a legacy name]. Then
     `GET /tailnet/-/keys/<client_id>` with that token: on 200 with `tags`, record them
     (`tags_source: "self-lookup"`); otherwise prompt `Tags on this write client, comma-separated,
     as the console shows them:` and record them (`tags_source: "typed"`). Record the lookup's
     outcome either way (settles Q3 for the write client). The write token is discarded, never
     cached.
7. Log `credential.set` (role, `client_id`, granted scope, tags, `tags_source`). Print the
   reminder: "each mint is one 'Create OAuth access token' event in your Tailscale audit log"
   [critic F6].

### 8.5 Atomic 0600 writes (`write_private_atomic`)

`os.open(tmp, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600)` in the same directory → `fchmod(0o600)`
(a permissive umask cannot widen it) → write → `fsync` → `os.replace(tmp, path)` → `fsync` the
directory. On any error the temp file is removed.

### 8.6 `credentials forget {read|write|token}`

Unlinks `write.secret` then `write.json` (`write`); `read.secret`, `read.json` and the token cache
(`read`); or the cache only (`token`). Logs `credential.forget`. Never prompts: it only removes
power. Prints: "this is not revocation. The client still exists in Tailscale; MC revokes it in the
console: Trust credentials → Revoke → Revoke" [TC L380-388; cred §6].

---

## 9. Token cache

### 9.1 Minting (`tokens.mint`)

- `POST {api_base}/oauth/token`, `Content-Type: application/x-www-form-urlencoded`, body
  `client_id`, `client_secret`, `grant_type=client_credentials` [OC L60-64, L122-125; critic Q6,
  R4]. No `Authorization` header. No `tags` parameter [critic Q2].
- `scope` is sent only for a read mint in single-client mode (the four read scopes). If that mint
  gets a 400, retry **once** with no `scope` and classify whatever is granted (doctor S2 settles Q1,
  §16.2).
- Response must be `{access_token, token_type: "Bearer", expires_in: int, scope}`;
  `expires_at = local_now + expires_in` (always 3600 [OC L20, L272]).
- A token error is the `{"message": …}` shape [api §2]. A 401 is never retried: exit 3
  `TOKEN_REJECTED`, `next: who=mc needs=console` "the client may be revoked or mistyped: Trust
  credentials".
- Every mint of either role appends a `token.mint` audit line (role, `client_id`, scope requested,
  scope granted, `cacheable`, `expires_at`, `request_id`), so MC can match each to the console's
  "Create OAuth access token" event [AUDIT L329] (J2 graft).

### 9.2 What may be cached (`tokens.cacheable`, MIN §6, J1 graft)

- Split `scope` on whitespace and commas (the multi-scope format is unverified [critic Q5]).
- **Cacheable only if** the result is non-empty and **every** item ends in `:read`.
- A missing `scope` field, an empty string, a legacy name such as `devices` (OC L132's own example)
  or `all` counts as write power: **not cached**.
- **Write tokens are never cached**: minted after every guard check passes, held in memory for the
  one command, then deleted.

### 9.3 The cache file

- `~/.config/tailnet/read-token.json`, 0600, atomic write (§8.5):
  `{"v":1,"client_id":"k…","access_token":"…","scope":"…","minted_at":"…","expires_at":"…"}`.
- Used only if: it passes §8.2; `client_id` equals the current `read.json`; `scope` is still
  cacheable; and `now < expires_at − 300 s` (a long `diagnose` or `doctor` must not watch its token
  expire mid-command; OC L20: renew "shortly before" expiry). Otherwise mint and overwrite.
- A cache that fails §8.2 is unlinked, never read, with the warning "token cache had unsafe
  permissions and may have been exposed; it expires by `<expires_at>`".
- A 401 on a read with a cached token: delete the cache, re-mint once, retry that read once. A
  second 401 → exit 3 `TOKEN_REJECTED`. No loop.

With the cache, an hour of reads costs one audit event in MC's console [critic F6].

---

## 10. HTTP layer

### 10.1 Request construction (`http.Transport`)

- `urllib.request.build_opener(...)` with: a redirect handler that **refuses every 3xx**
  (`API_REDIRECT`), because a redirect could carry the bearer token elsewhere; `ProxyHandler({})`
  in test posture.
- `Authorization: Bearer <token>` added with `add_unredirected_header` (second layer; J2 graft).
- `User-Agent: tailnet/<version> (+wittyreference/tailscale)`.
- `Accept: application/json`, except the HuJSON policy GET, which sends
  `Accept: application/hujson` [spec 4387-4393; api §6.1].
- `Content-Type`: `application/json`, `application/hujson` or
  `application/x-www-form-urlencoded`, as the body requires.
- Timeout 20 s per request; response bodies capped at 8 MiB (`API_BAD_RESPONSE` beyond).
- Every response records `status`, `x-tailscale-request-id` (seen on every live response,
  undocumented [api §3.3]), raw `ETag`, and `Date` (doctor's clock-skew check).
- `http.py` never logs a request body; errors show method, path (query values redacted), status,
  request ID and the redacted server `message`.

### 10.2 Status mapping

Every non-2xx body is decoded as `{"message": …}` [spec 4823-4829]; a non-JSON body is shown as its
first 200 characters, redacted.

| Status | Read | Write (sent exactly once) | Message |
|---|---|---|---|
| 2xx | parse | post-read (§12.6) | — |
| 200 on `/acl/validate` | §14.3 verdict parser (a `message` in a 200 is a failure, not an API error [critic R2]) | — | — |
| 3xx | exit 4 `API_REDIRECT` | exit 7, post-read | "redirect refused (would carry the token)" |
| 400 | exit 4 `API_BAD_REQUEST` (validate: parse failure, §14.3) | exit 7 | `bad request: <message>`; for a tag write add the TAGS L324 rule, the `tagOwners` check and the client's recorded tags |
| 401 | cached token: delete, re-mint once, retry once, then exit 3 `TOKEN_REJECTED` | exit 7, not retried (fresh token: the client is likely revoked) | "token rejected: the client may be revoked; console → Trust credentials" |
| 402 | exit 4 `API_PAYMENT` | exit 7 | "plan or billing refuses this" [spec 479-494] |
| 403 | exit 4 `API_FORBIDDEN` | exit 7 | "forbidden: possibly a missing scope (unconfirmed, critic Q4); refused calls show in the console as 'Failed request'" [AUDIT L316]. Names the scope that call needs from a small table in `api.py` |
| 404 | exit 4 `API_NOT_FOUND` | exit 7 | "not found: wrong ID, or possibly a missing scope (unconfirmed)" |
| 429 | **retry once**: numeric `Retry-After` or HTTP-date, capped at 30 s; 5 s when absent; then exit 4 [critic X7] | **never retried**: exit 7 | "rate limited; nothing was retried" |
| 500, 502, 503, 504 | exit 4 `API_SERVER`, no retry [spec 172-174] | **exit 6 unless the post-read shows the change** (then applied, confirmed) | "the write may have landed; do not re-apply" [api §12.9] |
| timeout / reset after send | exit 4 `NETWORK` | as 5xx | — |
| connect failure before send (DNS, refused) | exit 4 `NETWORK` | exit 7 (not sent), `sent: false` | — |

`Transport.request(idempotent=False)` contains **no retry branch at all**; a test asserts that a
write path makes exactly one request whatever the status.

### 10.3 Body parsing

JSON through `json.loads`; bad JSON → `API_BAD_RESPONSE` with a redacted 200-character excerpt. The
policy HuJSON GET returns raw bytes, never parsed.

### 10.4 Redaction (`redact.py`)

Applied to the final serialised text in `output.emit` and `output.warn` (so JSON-escaped forms are
covered), to every audit record before it is written, to the redacting `sys.excepthook`, and to
captured subprocess output from `localts`.

- **By value:** every loaded secret and every token (exact match). This does not depend on the
  OAuth token's prefix, which is unverified [api §2; cred §7].
- **By pattern** (replaced by a marker that keeps only the kind):
  - `tskey-[A-Za-z0-9_-]+` → `tskey-…[REDACTED]`;
  - `(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+` → `Bearer …[REDACTED]`;
  - `client_secret=[^&\s"]+` → `client_secret=…[REDACTED]`;
  - `"(access_token|client_secret)"\s*:\s*"[^"]*"` → `"\1": "…[REDACTED]"`;
  - `https://login\.tailscale\.com/a/[A-Za-z0-9]+` → `https://login.tailscale.com/a/…[REDACTED]`
    (one-time Tailscale SSH check-mode links are login links [mc §5]; J2 graft).

---

## 11. Devices, self, protected list, gate

### 11.1 Resolution

As §5.1. Pre-reads always use `GET /tailnet/-/devices?fields=all` with the read token
(`fields=all` is needed for `sshEnabled` and `multipleConnections` [api §5.1; spec 4753]). There is
no pagination [spec 47-49].

### 11.2 Derived fields (`devices.normalise`)

Normalised `Device`:

```
nodeId, id, hostname, name, ipv4, ipv6, user, tags[], owner {kind: "tag"|"user", value},
os, client_version, online (from connectedToControl), last_seen, last_seen_kind ("online"|"never"|"at"),
key_expiry {disabled, expires, days_left, expired}, tailscale_ssh (true|false|null),
authorized, external, ephemeral, blocks_incoming, multiple_connections, update_available,
self (bool|null), protected (why|null)
```

- Owner: tagged if `tags` is non-empty, otherwise user-owned by `user` [spec Device.tags,
  Device.user].
- Online comes from `connectedToControl`. A missing `lastSeen` **never** means stale (it is omitted
  while connected) [spec 4548; api §12.11].
- `tailscale_ssh`: `sshEnabled` true/false; absent → `null`, shown `?`, never false [critic Q12].
- Warnings raised by `device list`, each with its source:
  `TAGGED_KEY_EXPIRY_ON` (with days left) [TAGS L84; critic F3.2]; `KEY_EXPIRES_SOON` (< 30 days);
  `KEY_EXPIRED`; `MULTIPLE_CONNECTIONS` ("node key in use twice: cloned node state; identify the
  box by SoC serial") [spec 4575-4581; mc §5]; `BLOCKS_INCOMING` [spec 4594].
- Human table: `HOSTNAME  NODE ID  IPV4  OWNER/TAGS  ONLINE  KEY EXPIRY  TS-SSH  FLAGS`, flags
  `self protected external multi-conn blocks-in update`; ends `N of N devices (the API does not
  paginate) (as of …)`.
- JSON: `data.devices[]` (normalised, plus `raw` with the untouched API object), `count`,
  `self_node_id`.

### 11.3 Self detection (fail closed; SF §8.1 + AE §8.2 + J1 + J2, resolved as D6)

**Production posture:**

1. `localts.status_json(timeout=10)`. Binary: `/usr/bin/tailscale` if it exists and is executable,
   else `shutil.which("tailscale")`; doctor reports which. A planted `tailscale` earlier on `PATH` is
   not preferred. Missing → self unknown, reason `TAILSCALE_CLI_MISSING`.
2. `selfnode.parse_status`: require `BackendState == "Running"` [ipnstate:43] and `Self.Online ==
   true` [ipnstate:280]; take `Self.TailscaleIPs` [ipnstate:255], `Self.ID` [ipnstate:239],
   `Self.HostName`, `Self.DNSName`. A stopped backend still reports a stale peer list [mc §5], so
   anything else → unknown.
3. `selfnode.join`: the self device is the one API device whose `addresses` intersect
   `Self.TailscaleIPs`. Exactly one must match; zero means the credential belongs to another tailnet,
   two or more means unknown. Record `id_agrees = (device.nodeId == Self.ID)`; that the two are the
   same string is **[inference]**, so it is recorded, never required (J1 `must_fix`).
4. If the protected file has a `self` line, it must equal the joined `nodeId`, else refuse
   `SELF_LINE_DISAGREES` ("MC re-records the self line").

**Test posture:** `tailscale` is never run; self is the protected file's `self` line, which must
resolve to exactly one API device. No line → unknown. Consequence: in test posture a missing
protected file leaves self unknown, so every `--apply` refuses there; D7 (key-expiry disable while
the list is unanswered) is therefore exercised by the pure guard tests and observed in production by
e2e E13's plan, never by an integration apply. That is acceptable because test posture can never
reach the real tailnet anyway.

**An unknown self refuses every `--apply`** (`SELF_UNKNOWN`, exit 5); dry-runs still print the plan
with "apply would be refused: self unknown (<reason>)".

### 11.4 The protected file (`~/.config/tailnet/protected`)

Written by MC by hand. No CLI command writes it, and the agent cannot: `Edit` and `Read` of it and
any Bash command naming the directory are denied (MIN §8.4, J2 `must_fix`).

```
# MC's protected list. Written by MC, never by an agent. One entry per line.
self nXyz123CNTRL            # claude-factory (required: exactly one self line)
spec5                        # Elmer console; Tailscale SSH host; Serve URL (P1, P2, P7)
nAbc456CNTRL                 # pi5 (a nodeId survives a rename)
albini
iphone192
```

- Grammar: blank lines and `#` comments are ignored; `self <nodeId>`; otherwise `<entry>` with an
  optional `# why`. An `<entry>` matches a device when it equals its `nodeId` exactly, or its
  `hostname` or the first label of its `name` ignoring case. Matching more devices means more
  protection, the safe direction.
- Exactly one `self` line is required; none or several → exit 3 `PROTECTED_MALFORMED`.
- The file must pass §8.2 (0600, owned, not a symlink).

**Semantics (fail closed; critic Q14 "never inferred"):**

| State | Tag writes (`device tag`) | `disable-key-expiry` |
|---|---|---|
| file missing (**unanswered**) | refused, `PROTECTED_UNANSWERED` | allowed (D7) |
| present, only the `self` line | allowed on unlisted devices; doctor warns "nothing but self is protected" | allowed |
| present with entries | refused on listed devices (`PROTECTED_DEVICE`) and on self (`SELF_DEVICE`) | allowed on every device |

**Self is always protected** against tag writes, listed or not.

**How MC writes it.** Doctor builds a proposal from live inventory: the `self` line plus **every**
device, with its `nodeId` and a hostname comment ("protect everything" is the safe default; MC
deletes the lines for devices they want the CLI to be able to tag). Doctor prints it as **one shell
block for MC to run over SSH** (`next: who=mc needs=terminal`), for example a single
`umask 077; cat > ~/.config/tailnet/protected` here-document. The agent proposes it with one
question; MC runs it (Corrections: one command, say what it proves). The agent itself running the
block is refused by the deny rule `Bash(*.config/tailnet*)`.

### 11.5 Gate check (`gate.py`)

- `rules()` reads `src/tailnet/rules.json` (§20.4), shipped with the package.
- `missing_rules(path)`: every ask and deny string from `rules.json` that is absent from
  `permissions.ask` / `permissions.deny` in the settings file. A missing or unparseable file counts
  every rule as missing.
- `gate_present(path)`: `rules()["gate"]` (`Bash(*tailnet*--apply*)`) is in `permissions.ask`.
- Used by: the guard (every `--apply` is refused with `GATE_MISSING` when absent: "the ask rule
  that puts this write in front of MC is missing from <path>; re-run the installer"); `status` and
  `doctor`, which report every missing rule on every run (D21).

---

## 12. The write guard

### 12.1 Risk classes

| Class | Meaning | Offered? |
|---|---|---|
| R1 | Keeps the device on the tailnet; reversible in the console | Yes; `--apply --reason` |
| R2 | Reversible, but changes reachability or security posture now | Yes; plus `--confirm <verb>:<hostname>` |
| R3 | **Irreversible from the API**; recovery needs hands at the device (re-authenticate) | Yes; plus `--confirm strip-owner:<hostname>`; never on protected devices or self |
| R4 | Takes a device off the tailnet now or later, or admits an unknown device | **No**: no code path exists |

### 12.2 Common checks (computed by the dry run; enforced by `--apply`; in this order)

Each refusal under `--apply` exits 5 and leaves an audit line. In a **dry run** the checks split
two ways:

- **Operation refusals** make the dry run itself exit 5, because the operation cannot happen
  whatever MC does: C1, C2, C6, `PROTECTED_DEVICE`, `SELF_DEVICE`, `MULTI_TARGET_NOT_R1`.
- **Apply-time preconditions** are printed as `apply would be refused: <code>` warnings, and the
  dry run still exits 0, so the plan can be shown to MC first: C3, C4, C5, C7, C8.

Both kinds are recorded in the audit line's `checks`. Every write command, dry or not, needs the
audit log to open (C9); otherwise it exits 3 `AUDIT_UNWRITABLE`.

| # | Check | Refusal code | Lever |
|---|---|---|---|
| C0 | `--apply` only: take `~/.local/state/tailnet/apply.lock` with `fcntl.flock(LOCK_EX \| LOCK_NB)` **before** the pre-reads (D14) | `APPLY_IN_PROGRESS` | L1 |
| C1 | Every target resolves to exactly one device in a fresh `GET /tailnet/-/devices?fields=all` (read token) | `DEVICE_NOT_FOUND`, `DEVICE_AMBIGUOUS` | L1 |
| C2 | No target has `isExternal` (shared-in devices are not ours to change [spec 329-331]) | `SHARED_IN` | L1, L7 |
| C3 | Self is known (§11.3) | `SELF_UNKNOWN`, `SELF_LINE_DISAGREES` | L1 |
| C4 | Tag writes only: the protected file is answered (§11.4) | `PROTECTED_UNANSWERED` | L1 |
| C5 | The gate rule is present in Claude settings (§11.5) | `GATE_MISSING` | L1 backing L3 |
| C6 | Op-specific checks (§12.3) | see §12.3 | L1, L7 |
| C7 | `--confirm` equals the plan's `confirm_required` exactly (case-sensitive; printed by the dry run) | `CONFIRM_MISSING`, `CONFIRM_MISMATCH` | L1 (the prompt text serves L3) |
| C8 | `write.json` present and passes §8.2 (metadata only) | `WRITE_CREDENTIAL_MISSING` | L2 |
| C9 | The audit log opens for append; a write that cannot be recorded is not sent | `AUDIT_UNWRITABLE` (exit 3) | L6 |
| C10 | **Only now**: load `write.secret`, mint the write token; its granted scope must contain `devices:core`, `devices` or `all` | `WRITE_SCOPE_MISSING` | L2 |

`--reason` is enforced by argparse before C0 (exit 2). Pre-read and post-read always use the
**read** token (J2 `must_fix`).

### 12.3 Guard table

| Operation | Endpoint (write token) | Class | Extra pre-read (read token) | Refused when (exit 5) | `--confirm` | Protected device | Self | Levers |
|---|---|---|---|---|---|---|---|---|
| `disable-key-expiry`, **tagged** device | `POST /device/{nodeId}/key` `{"keyExpiryDisabled": true}` [spec 592-609] | R1 | — | C1-C3, C5, C7-C10. **Already disabled → noop** (exit 0, nothing sent) | none | **allowed** (it protects P9) | **allowed** (keeps self on the tailnet) | L1-L3, L5, L6 |
| `disable-key-expiry`, **user-owned** device | same | R2 (a stolen device's key would never expire) | — | as above; more than one target (`MULTI_TARGET_NOT_R1`) | `no-expiry:<hostname>` | allowed with confirm | allowed with confirm | same |
| either, `expires` already past | same | — | — | **not refused**; warning `KEY_ALREADY_EXPIRED`: "disabling may not reconnect it **[unverified]**; re-authentication at the device may be needed" [spec 606-607] | as above | as above | as above | — |
| `tag` (`--add`/`--remove`), **tagged** device | `POST /device/{nodeId}/tags` `{"tags": [full new set]}` [spec 541-582] | R2 (changes which policy rules match it) | `GET /tailnet/-/acl` `Accept: application/json` (`tagOwners`, rule references) | C1-C10, plus: policy JSON unreadable (`POLICY_UNREADABLE`); a tag in the new set not a key of `tagOwners` (`TAG_UNDEFINED`) [spec 548]; `--remove` of a tag the device lacks (`TAG_NOT_PRESENT`, typo guard); empty new set (`TAG_SET_EMPTY`) [critic Q10; TAGS L33]; client tags not recorded (`WRITE_CLIENT_TAGS_UNRECORDED`); the client could not assign the set (`CLIENT_CANNOT_ASSIGN`, §12.4). **Unchanged set → noop** | `retag:<hostname>` | **refused** (`PROTECTED_DEVICE`) | **refused** (`SELF_DEVICE`) | L1-L3, L5-L7 |
| `tag`, **user-owned** device (strip owner) | same | **R3** [TAGS L72, L33; critic F1, Q9 designed for "yes, the API can"] | same, plus the device's `user` | all of the above | `strip-owner:<hostname>` | **refused** | **refused** | same |
| re-enable key expiry | `POST /device/{id}/key` `{"keyExpiryDisabled": false}` | R4 [critic F5; spec 606-607] | — | **not offered**: no code path sends `false` | — | — | — | L2, L5 |
| delete; expire; (de)authorize; set IPv4 | `DELETE /device/{id}`; `POST …/expire`, `…/authorized`, `…/ip` | R4 (off the tailnet, unknown admission, breaks `from=` pins) [spec 326-373, 459-494, 621-660; mc P9, P11; critic Q13, Q17] | — | **not offered** | — | — | — | L2, L5 |
| rename | `POST /device/{id}/name` | R2 (breaks MagicDNS and Serve URLs) [spec 504] | — | **not offered** (D8) | — | — | — | L2, L5 |
| routes, posture attributes, policy set, auth keys, users, invites | various | — | — | **not offered**; scopes absent too [cred §2] | — | — | — | L7, L5 |

"Not offered" is structural: `api.py` defines exactly two write functions,
`set_device_tags(node_id, tags, write_token)` and `disable_key_expiry(node_id, write_token)`, the
second with the literal body `{"keyExpiryDisabled": True}`.
`test_api_module_exposes_only_the_two_writes` and `test_disable_key_expiry_hardcodes_true` enforce
this by parsing `api.py` with `ast`.

### 12.4 Tag pre-checks in detail

- **New set** = `sorted((current ∪ add) − remove)`, computed from the **fresh** pre-read at apply
  time. The full set is sent because the API replaces the list [api §5.7].
- **Client may assign** (`guard.client_may_assign`, with `C = write.json.tags` and `tagOwners` from
  the live policy JSON): pass if `set(new) == set(C)`; pass if every `t ∈ new` has some `c ∈ C` with
  `c ∈ tagOwners[t]`; **otherwise refuse** `CLIENT_CANNOT_ASSIGN`, quoting TAGS L324. Refusing a
  request the server might have accepted is the safe direction while critic Q8 is unverified (J1
  `must_fix`).
- **Rule references** (`guard.rule_references`): every path in the policy JSON whose string value
  contains an added or removed tag (`grants[i].src|dst`, `acls[i].src|dst`, `ssh[i].src|dst`,
  `tests[i].src|accept|deny`, `sshTests[i]…`, `autoApprovers…`, `tagOwners`). Shown in the plan, so
  MC sees what the change touches.
- **Consequence lines for R3**, printed verbatim in the plan: "removes `<user>` as owner; you cannot
  remove all tags afterwards" [TAGS L72, L33]; "`autogroup:self` rules and the default SSH rule stop
  covering it" [critic R13; tsssh L255-268]; "Taildrop and same-user netmap visibility end"
  [pol (b)]; "key expiry is unchanged by tagging: ON, expires <date>; follow up with `tailnet device
  disable-key-expiry <nodeId>`" [TAGS L84]; "recovery: re-authenticate on the device as the user".
- After any applied tag write, `next[]` suggests `disable-key-expiry` when key expiry is on [TAGS
  L84; AE §8.5 step 12].

### 12.5 Several targets (`disable-key-expiry` only; J2 graft)

- Allowed only when **every** target is R1 (tagged). A user-owned target must be the only target
  (`MULTI_TARGET_NOT_R1`).
- The guard is **all-or-nothing**: if any target is refused, nothing is sent. Noop targets are
  reported and skipped; they do not refuse the batch.
- **One** write token is minted for the command. POSTs go in argument order and **stop at the
  first** non-OK result; later targets are reported `not-attempted`.
- Each target gets its own audit line. This serves the three retagged fleet hosts with one approval
  [critic F3.2].

### 12.6 Write flow (`writes.run`)

The same code runs dry-run and apply; `--apply` adds steps 5-10.

1. Parse. Usage errors exit 2.
2. `--apply` only: C0 (apply lock).
3. Pre-reads (read token): device list; for tag ops, the policy JSON; load `protected`; resolve
   self.
4. `guard.plan_*` (pure) → one `Plan` per target, with the confirm token computed from the fresh
   `hostname` and `apply_argv` = the full apply line with the `nodeId` as `DEVICE`, the confirm
   token, `--apply` and `--reason "<why>"`. **Without `--apply`:** print the plan (including any
   `apply would be refused: <code>` warnings) and log `write` `{mode: "dry-run", outcome:
   "dry-run"}`, exit 0; or, when the plan carries an operation refusal (§12.2), log `outcome:
   "refused"` and exit 5.
5. `guard.check_apply`: C3-C9 on the fresh plan (a plan from an earlier dry run is never trusted).
   Refusal → log, exit 5.
6. C10: load `write.secret`, mint the write token (logs `token.mint`), check its scope.
7. `POST` exactly once per target with the write token.
8. Post-read with the **read** token: `GET /device/{nodeId}?fields=all` [spec 303-325]. Compare the
   intended fields (tags sorted and lowercased; or `keyExpiryDisabled == true`).
9. Outcome:

   | Response | Re-read | CLI outcome | Exit | Audit `outcome` / `confirmed` |
   |---|---|---|---|---|
   | 2xx | matches | `applied` | 0 | `applied` / true |
   | 2xx | differs | `unconfirmed` ("server accepted; not yet visible; check `tailnet device list --json` in a minute; do not re-apply") | 6 | `failed` / false |
   | 2xx | re-read failed | `unconfirmed` | 6 | `failed` / false |
   | 3xx / 4xx / 429 | any | `rejected` | 7 | `failed` / true when the re-read shows no change, else false |
   | 5xx / timeout / reset after send | matches | `applied` (confirmed by re-read) | 0 | `applied` / true |
   | 5xx / timeout / reset after send | differs or failed | `unconfirmed` | 6 | `failed` / false |
   | connect failure before send | — | `rejected`, `sent: false` | 7 | `failed` / true |

10. Delete the token, release the lock, append the result line, print, exit.

The skill's rule for exit 6: never re-apply; run `tailnet device list --json` and report what it
shows with its `measured_at` (J2 `must_fix`).

### 12.7 What a plan looks like (human output)

```
DRY RUN: nothing changed (as of 2026-10-27T01:02:03Z)
device tag  pi5  nAbc456CNTRL  100.126.132.9
  class    R2  changes which policy rules match this device; reversible by retagging
  before   tags: tag:fleet, tag:lab        owner: tags (registered by mc@…)
  after    tags: tag:fleet
  checks   ok  resolved once, by hostname
           ok  not self (self = claude-factory nXyz123CNTRL, joined by 100.x; Self.ID agrees)
           ok  not protected (protected file answered, 11 entries)
           ok  tag:fleet defined in tagOwners
           ok  write client [tag:fleet] may assign [tag:fleet]: exact match (TAGS L324)
           ok  gate rule present in ~/.claude/settings.json
  policy   tag:lab appears in grants[2].dst, tests[0].accept
  expiry   unchanged by retagging: ON, expires 2027-03-26 (151 days)  [TAGS L84]
  write    write client present (k…CNTRL); the secret is opened only on --apply
Next (agent): tailnet device tag nAbc456CNTRL --remove tag:lab --confirm retag:pi5 --apply --reason "<why>"
              Replace <why> with one line for MC. MC is asked to approve that exact command.
```

---

## 13. Audit log

### 13.1 Location and append rules

- `~/.local/state/tailnet/audit.jsonl`; directory 0700, file 0600; outside every repository. The
  agent may read it (`tail -n 20`); an `Edit` deny rule covers it (L4).
- Appended by `secure_files.append_locked`: open with
  `O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC`, mode 0600 → `fcntl.flock(LOCK_EX)` (J1:
  every append is locked) → **one** `os.write` of one line → `fsync` → unlock, close.
- The CLI never opens it in any other mode and never rewrites, rotates or truncates it. History is
  not rewritten (Elmer invariant 4). Tailscale's own configuration log is the tamper-resistant
  record (L5); the local file is the narrative.

### 13.2 Events

| `event` | When |
|---|---|
| `write` | Every write attempt: dry-run, refused, applied, failed (refusals before resolution included, with `target: null`) |
| `token.mint` | Every mint, either role |
| `credential.set`, `credential.forget` | Every `credentials set` / `forget` |
| `doctor.run` | Every doctor run: counts, settled answers, mints, audit events caused (§16.4) |

Plain reads are not recorded: they change nothing, and Tailscale does not record them either
[AUDIT L404].

### 13.3 Record schema (v1)

Common fields (every record):

```json
{"v": 1, "ts": "2026-10-27T01:02:03.456Z", "event": "write", "cli_version": "0.1.0",
 "posture": "production", "host": "claude-factory", "user": "mc", "pid": 4242,
 "argv": ["device", "tag", "nAbc456CNTRL", "--remove", "tag:lab", "--confirm", "retag:pi5", "--apply", "--reason", "drop the lab tag"]}
```

`write` adds:

```json
{"op": "device.tag | device.disable-key-expiry",
 "mode": "dry-run | apply",
 "outcome": "dry-run | refused | applied | failed",
 "sent": true, "confirmed": true, "noop": false,
 "failure": null,
 "class": "R1 | R2 | R3",
 "reason": "drop the lab tag",
 "refusal": null,
 "target": {"nodeId": "nAbc456CNTRL", "hostname": "pi5", "addresses": ["100.126.132.9", "fd7a:…"]},
 "before": {"tags": ["tag:fleet", "tag:lab"], "user": "…", "keyExpiryDisabled": false, "expires": "…"},
 "requested": {"tags": ["tag:fleet"]},
 "observed_after": {"tags": ["tag:fleet"]},
 "checks": [{"id": "C3", "result": "pass", "detail": "self joined by 100.x; id_agrees=true"}],
 "confirm": {"required": "retag:pi5", "matched": true},
 "self": {"nodeId": "nXyz123CNTRL", "source": "live | line", "id_agrees": true},
 "write_client": {"client_id": "k…CNTRL", "tags": ["tag:fleet"]},
 "http": [{"method": "POST", "path": "/device/nAbc456CNTRL/tags", "status": 200, "request_id": "REQ-…", "ms": 412}]}
```

`failure` is `null | "rejected" | "unconfirmed" | "not-attempted"`; `refusal` is
`null | {"code", "message"}`.

- `token.mint` adds `role`, `client_id`, `scope_requested`, `scope_granted`, `cacheable`,
  `expires_at`, `http_status`, `request_id`.
- `credential.set` / `credential.forget` add `role`, `client_id`, `granted_scope`, `tags`,
  `tags_source`.
- `doctor.run` adds `counts {pass,warn,fail,info,skip}`, `settled {Qn: {answer, evidence,
  measured_at}}`, `mints_this_run`, `audit_events_caused[]`.
- No record ever holds a secret, a token, a policy body or a request body; the redactor runs over
  the whole serialised line before writing. The client ID is not secret: Tailscale logs it as the
  actor [TC L392], so it is recorded for correlation.

---

## 14. Policy flows (exact API calls)

The CLI never parses HuJSON; the server is the only parser [decided; critic Q18 option (a)].
Comments survive because the bytes are never re-serialised [pol (f)]. Drafts live in
`~/.local/state/tailnet/drafts/<YYYYMMDDTHHMMSSZ>-<name>/` (directory 0700, files 0600), outside
every repository: the policy names MC's people and hosts, and MC kept an earlier draft out of git on
purpose [mc P13].

### 14.1 `policy get`

- `GET /api/v2/tailnet/-/acl` with `Accept: application/hujson` (default) or `application/json`
  (`--format json`) [spec 2217-2274].
- The body goes to stdout (or `--out FILE`, written 0600) **byte for byte**. Stderr carries: the raw
  `ETag` (stored raw, quotes included; displayed with one surrounding pair stripped [critic R3]),
  the body's sha256, line count, `measured_at`. `--format json` warns "comments are not in this form"
  [pol (f), inference].
- `--json` envelope: `data {text, etag_raw, etag, sha256, format, sections}`; `sections` (counts of
  `acls`, `grants`, `ssh`, `tests`, `sshTests`, `hosts`, `groups`, and the `tagOwners` keys) is
  filled only for `--format json`, because HuJSON is never parsed.

### 14.2 `policy draft [--name NAME]`

- `GET …/acl` (HuJSON). Writes `base.hujson` and `candidate.hujson` (identical bytes) and
  `meta.json`:
  `{"v":1,"name":"…","base_etag_raw":"…","base_sha256":"…","fetched_at":"…","request_id":"…","validated":null}`.
- Prints the directory and the loop that follows (§14.7). The agent then edits `candidate.hujson`
  **as text** with the Edit tool (SF §11; J2 graft).

### 14.3 `policy validate TARGET`

- TARGET is a draft directory (body = `candidate.hujson`; the verdict is recorded in `meta.json`) or a
  file path (no meta).
- Refuses an array-shaped body (§5.2, `VALIDATE_ARRAY_BODY`, exit 2).
- `POST /api/v2/tailnet/-/acl/validate`, `Content-Type: application/hujson`, body = the bytes
  [spec 2502-2520, 2620-2639]. Policy-file mode runs **the candidate's own** `tests` and `sshTests`
  [critic R1].
- **Verdict** (`policy.parse_verdict(status, body)`, pure; critic R2; MIN §10):
  - 200 with an empty body or `{}` → `pass`;
  - 200 with any `data[].errors` non-empty → `fail`;
  - 200 with only `data[].warnings` → `pass-with-warnings` (warnings printed);
  - 200 with `message` and no `data` → `fail`;
  - 200 with any other JSON → `fail` (`unknown shape`);
  - 400 → `fail` with the server message (a parse error in the draft);
  - other statuses → `ApiError` (exit 4).
- Failure lines are parsed with `address "([^"]+)": want: (\w+), got: (\w+)` into `{target, want,
  got}`; an unparsed line is kept verbatim [spec 2660-2667].
- On a draft, writes `meta.validated = {"sha256": "<candidate sha>", "verdict": "...", "at": "...",
  "request_id": "...", "messages": [...]}`. Exit 0 on pass (with or without warnings), 8 on fail.

### 14.4 `policy diff DRAFT`

- `GET …/acl` (HuJSON) for the drift check.
- Prints `difflib.unified_diff(base, candidate, n=3)` with line numbers.
- **Readiness** (SF §11, J2 graft): READY only when (a) `meta.validated.sha256` equals the sha256 of
  the current `candidate.hujson` **and** the verdict is `pass` or `pass-with-warnings`, **and** (b)
  the live raw ETag equals `base_etag_raw` **and** the live body's sha256 equals `base_sha256`.
  Otherwise NOT READY with the reason: "candidate changed since validate: re-run `policy validate`",
  "not validated", "validation failed", or "MC's console changed the policy since this draft (ETag
  moved): re-draft" (a concurrent console edit would otherwise show up as a reversal).
- Ends with the console hand-off:

  ```
  READY: candidate sha256:… validated PASS at 2026-10-27T01:05Z; live unchanged since draft (ETag "…").
  MC applies it: https://console.tailscale.com/admin/acls/file → make the edits shown above → Save.
  Saving re-runs the policy's tests; a failing test blocks the save.
  ```

- Exit 0 READY, 8 NOT READY.

### 14.5 Preview: the flow, documented; no command (D17; J2 `must_fix`)

The endpoint is `POST /api/v2/tailnet/-/acl/preview?type=ipport&previewFor=<IP:PORT>` (or
`type=user&previewFor=<email>`), with **a policy file as the body** (JSON object or
`Content-Type: application/hujson`), returning `{matches: [{users, ports, lineNumber}], type,
previewFor}` [spec 2381-2492; api §6.4]. To preview the live policy, GET it first and post it back
(an empty body is unverified, critic Q22). `type=user` takes a user's email and cannot preview a tag
as a source [pol (d) step 3]. **Why `policy test` replaces it:** MC's question is "accept or drop for
this identity and port", which `policy test` answers directly against the live policy, including tag
sources; preview answers "which rule lines mention this destination". Upstream's
`references/api.md:100-103` posts `{"src","dst"}` to preview, which is the wrong shape (A3); the
upstream-corrections reference flags it.

### 14.6 `policy test`

- `POST /api/v2/tailnet/-/acl/validate`, `Content-Type: application/json`, body
  `[{"src": SRC, "proto": PROTO?, "accept": [...], "deny": [...]}]`: array mode, run against the
  **live** policy [spec 2508-2516; api §6.3 form A].
- Output: one line per address, `ACCEPT`/`DROP` with `want`/`got`; `raw_errors` for unparsed text.
  Exit 0 if every assertion passes, 8 otherwise.
- The skill passes `--proto tcp` for SSH questions (omitting `proto` tests "either TCP or UDP"
  [pol (c)]).

### 14.7 The loop the skill teaches (draft → validate → diff → MC → verify)

1. `tailnet policy draft --name <topic> --json`; note `data.path`.
2. Edit `candidate.hujson` as text (Edit tool). Add rules from `references/policy-workflow.md`;
   keep MC's comments; **add `tests` (and `sshTests` for a Tailscale SSH host) asserting the
   intended access**, so validate proves it and future saves are guarded [pol (c)]. Never
   round-trip through `json.dumps` [pol (f)]. Never press or emulate **Convert to grants**
   unprompted (it rewrites the whole section with no confirmation [pol (a)]).
3. `tailnet policy validate <path>` until exit 0.
4. `tailnet policy diff <path>` until READY; relay the hunks to MC in a few lines.
5. One question to MC (applied / not now / change something), with `next: who=mc needs=console`.
6. After MC applies: `tailnet policy test …` with the same assertions against the live policy, then
   `tailnet diagnose …`. Byte equality is not the proof (the console may reformat); the live
   assertions are (AE §10.2).
7. Revert path: console changes can be reverted from Configuration logs [pol (e)].

`If-Match`, `ts-default` and 412 are recorded in `references/policy-workflow.md` for whoever holds
`policy_file` (never this CLI) [spec 2291-2351].

---

## 15. `diagnose` (MC's live blocker)

**Symptom:** from the droplet (`tag:dev`, unconfirmed [critic F3.5]), TCP 22 to spec5, nomad-b and
pi5 (`tag:fleet`) times out while ping and 443 work [critic F3; sigint p3:138-144]. spec5 runs
Tailscale SSH, which claims port 22 on its Tailscale IP [fleet.yaml:86; tsssh L40, L410]; nomad-b
and pi5 run plain OpenSSH (as of 2026-09-09 and 2026-09-27) [mc §2]. Everything below is read-only.
Destinations are addressed by IPv4 100.x, never MagicDNS [critic F3.6].

### 15.1 Modes

- **Self mode (default).** The source is this host. In production posture all three local probes
  run. In test posture self comes from the `self` line, the two `tailscale ping` probes are recorded
  `not-run: test posture` (`path_ok = null`, so the `PATH_DOWN` gate is skipped), and the TCP probe
  still runs for real against the fixture's `127.0.0.x` addresses.
- **`--from DEVICE`** (AE §11, J1 and J2 graft). API-only: the source is that device's identity, and
  no local probe runs. Answers "did tagging spec5 cut MC's phone (iphone192) or albini off it?"
  [critic F3.3, R13]. Also makes the API branch integration-testable without any `tailscale` binary.

### 15.2 Steps

**Step 0, source health (self mode, production).** `localts.status_json`: require `BackendState ==
"Running"`, `Self.Online`, and a non-empty `Peer` map. Otherwise every destination's verdict is
`SOURCE_DOWN` (exit 8), with no API calls. A missing binary → exit 3 `TAILSCALE_CLI_MISSING`.

**Step 1, inventory (API).** `GET /tailnet/-/devices?fields=all`. Resolve the source (self per §11.3,
or `--from`) and each `DEVICE`. Record per destination: `nodeId`, IPv4, `tags`, `user`,
`sshEnabled` (true/false/absent→unknown), `connectedToControl`, `lastSeen`, `keyExpiryDisabled`,
`expires`, `blocksIncomingConnections`, `clientVersion`. A destination that is the source itself →
`SAME_DEVICE`.

**Step 2, source identities** (never a raw 100.x [spec 2533-2540; J1 and J2 `must_fix`]): each of
the source's tags if tagged (a tagged identity is the union of its tags [pol (b)]), else its `user`
email.

**Step 3, gates** (first match is final for that destination): `NOT_FOUND` / `AMBIGUOUS`;
`KEY_EXPIRED` (`expires < now` and not `keyExpiryDisabled`); `DEST_OFFLINE` (`connectedToControl ==
false`; report `lastSeen` as given, never inferring from its absence [spec 4548]); `SHIELDS_UP`
(`blocksIncomingConnections` [spec 4594]).

**Step 4, local probes** (self mode only; the pings in production posture only, the TCP probe in
both; 5 s each):

| Probe | Command | Proves |
|---|---|---|
| TSMP | `tailscale ping --tsmp --c 1 --timeout=5s <ipv4>` [cliref L639-644] | `path_ok`: connectivity, stopping **before** the policy check [pol (d) step 1; ping-types] |
| ICMP | `tailscale ping --icmp --c 1 --timeout=5s <ipv4>` | `icmp_ok`: true whenever *any* port is open between the pair, so it says nothing about the port [pol TL;DR 1; filter.go:520]. **Never counted as port evidence** |
| TCP | `socket.create_connection((ipv4, port), timeout=5)` | `open` (then read up to 255 banner bytes for 3 s, printed raw; whether a Tailscale SSH banner is recognisable is **[unverified]**), `refused` (an RST came from the host's stack), `timeout`, or `error:<errno>`. A policy-dropped SYN gets a TSMP reject and **no RST**, so it looks like a timeout [pol (d); wrap.go:1234-1252] |

Pings use the exit code only, with the raw output kept in `data`; the exit-code meaning on a timeout
is **[unverified]** and settled by e2e E9.

**Step 5, network policy (API).** For each source identity S, one call (attributable verdicts; reads
are not logged server-side, so the extra calls cost nothing in MC's log):
`POST /tailnet/-/acl/validate`, `application/json`,
`[{"src": S, "proto": "tcp", "accept": ["<dst-ipv4>:<port>"]}]` (a Tailscale IP is a documented
`accept` host [pol (c)]). `network_allowed` = any S passes; `want: Accept, got: Drop` is kept
verbatim.

**Step 6, Tailscale SSH layer** (only when `sshEnabled == true` and `port == 22`; critic F3.3-4, X1,
X10). The network rule is necessary; the `ssh` section decides admission.

1. SSH user from `--ssh-user`; none → `TS_SSH_UNVERIFIED` with `next: rerun with --ssh-user <user>`
   (usernames differ per host [mc §2]; spec5's is `spec5` per `references/tailnet-facts.md`).
2. `GET /tailnet/-/acl`, `Accept: application/json` → live policy J.
3. `diagnose.ssh_candidate(J, dst_ipv4, S, user, mode)` (pure; AE §11 step 5, J2 graft): deep-copy J;
   **delete `tests` and `sshTests`** so only the probe runs; add `hosts["tailnet-diag-dst"] =
   "<dst-ipv4>"` (if that key exists, `tailnet-diag-dst-2`, `-3`, …; `sshTests.dst` takes host
   aliases, not raw IPs [pol (c)]); set `sshTests = [{"src": S, "dst": ["tailnet-diag-dst"],
   "<mode>": ["<user>"]}]` with `mode` = `accept`.
4. `POST /tailnet/-/acl/validate`, `application/json`, body = the candidate object (policy-file mode;
   modifies nothing [spec 2518]). One call per S. Admitted if any S passes.
5. If no S passes with `accept`, repeat with `mode` = `check`. A pass there means admission only in
   check mode: for a **tagged** source that is `TS_SSH_CHECK_FOR_TAGGED`, because "An SSH access
   rule from a tagged device cannot be in check mode" [tsssh L218]; for a user source it is
   `ADMITTED_CHECK_MODE` (needs a browser re-auth, MC's case for the phone, P7).
6. The candidate exists only in memory and is never written as a draft. Errors whose test is not
   ours (validation warnings from J itself) are reported separately. That the JSON form of the live
   policy round-trips as a validate body is **[inference]** (gitops-pusher posts standardised JSON
   [critic Q18]); e2e E7 settles it.

**Step 7, verdict** (`diagnose.verdict(facts)`, pure; first match wins):

| Verdict | Condition | Meaning → next step |
|---|---|---|
| `SOURCE_DOWN` | self mode; step 0 failed | This host is not on the tailnet now → `tailscale status` on the droplet |
| `NOT_FOUND` / `AMBIGUOUS` / `SAME_DEVICE` | step 1 | List candidates / pick another source |
| `KEY_EXPIRED` | gate | Off the tailnet (P9) → MC re-authenticates at the host; then `device disable-key-expiry` |
| `DEST_OFFLINE` | gate | Not connected to control; `lastSeen` as given |
| `SHIELDS_UP` | gate | Refuses all tailnet connections → on the host: `tailscale get shields-up` |
| `PATH_DOWN` | self mode, `path_ok == false` | Connectivity, not policy → `tailscale netcheck`, `tailscale status`; the official skill's `connectivity.md` |
| `OPEN` | self mode, TCP `open`, and (not `sshEnabled` **or** ssh admitted with `accept`) | Port reachable; a failing ssh is auth or user (wrong user and missing key look alike [FINDINGS §12]) → `ssh -v <user>@<ipv4>` |
| `ADMITTED_CHECK_MODE` | ssh admitted only with `check`, user source, and (`--from` mode, or self mode with TCP `open`) | Reachable; needs a browser check each period (P7) |
| `TS_SSH_CHECK_FOR_TAGGED` | ssh admitted only with `check`, tagged source | Impossible from a tagged source → draft an `accept` rule `tag:dev → tag:fleet` (MC's decision, open question MC6 (§28)) |
| `TS_SSH_POLICY` | `sshEnabled`, network allowed, ssh denied both ways | The `ssh` section has no rule S → dest for that user → recipe `ssh` rule |
| `TS_SSH_UNVERIFIED` | `sshEnabled`, network allowed, no `--ssh-user` | Rerun with `--ssh-user` |
| `POLICY_DROP` | `network_allowed == false` | The policy drops it (matches a timeout: TSMP reject, no RST) → `policy draft` with the recipe grant; MC applies; re-run. For a Tailscale SSH host the `ssh` section also needs an accept rule |
| `ALLOWED` | `--from` mode, network allowed, and (not `sshEnabled` or ssh admitted with `accept`) | Policy permits it; no probe possible from here |
| `REFUSED_BY_HOST` | self mode, TCP `refused`, network allowed | The policy let the SYN through and the host reset it: sshd not listening on that address → on-host ladder |
| `HOST_SIDE_DROP` | self mode, TCP `timeout`, network allowed, `sshEnabled == false` | Host firewall or sshd bind → on-host ladder. If the policy changed within the last minute, re-run once first (propagation timing **[unverified]**) |
| `TS_SSH_TIMEOUT_UNEXPLAINED` | self mode, TCP `timeout`, network allowed, `sshEnabled == true` (so the ssh section admitted the source, or the rows above would have matched) | tailscaled claims :22 itself, so a host firewall is probably not in the path **[inference]**; the ssh-section result is shown as evidence → on-host ladder |
| `INCONCLUSIVE` | anything else (probe errors, API errors, `sshEnabled` unknown with network allowed and timeout) | Every fact is reported; both TS-SSH hypotheses are listed; the peer's `sshHostKeys` from local status is shown as a weak hint only [ipnstate:316; pol unverified 13] |

Exit 0 if every destination is `OPEN`, `ADMITTED_CHECK_MODE` or `ALLOWED`; 8 otherwise.

**Step 8, the on-host ladder, emitted (never run).** From the droplet the destination is
unreachable, which is the problem, so for any host-side verdict the CLI emits one paste block as
`next: who=mc needs=terminal`, to run on the destination from a session that *can* reach it (MC's
phone via Termius, or albini → pi5 → spec5 over the bench wire [fleet.yaml:86]), plus a suggestion
`tailnet diagnose <dst> --from iphone192` to check which device can:

```sh
# On <dest>, while the agent retries from claude-factory:
tailscale metrics print | grep -E 'inbound_dropped_packets_total'        # reason="acl" rising → Tailscale policy drop (client ≥ 1.78)
sudo journalctl -u tailscaled --since '-10min' | grep -E 'Drop: TCP\{[^}]*:22\}'   # "no rules matched"
sudo timeout 20 tcpdump -ni tailscale0 -c 5 'tcp port 22 and src host <droplet-100.x>'   # SYN seen → passed Tailscale's filter
sudo ufw status verbose ; tailscale get ssh ; tailscale get shields-up ; tailscale get netfilter-mode
```

Sources: [pol (d) steps 4-7; client-metrics; filter.go:364; ufw how-to]. The `print` label
rendering is **[unverified]**, hence the grep; tcpdump and ufw are general Linux, not Tailscale docs.

**Output.** Per destination: `{dest, resolved, gates, probes, network_test[], ssh_test[], verdict,
explanation, next[]}`; plus `source {mode, nodeId, hostname, identities, self_source}` and the API
calls made. Human: one verdict line per host, then the evidence, each with `measured_at`.

---

## 16. `doctor` (read-only; also MC's end-to-end check on the droplet)

### 16.1 Local checks

| ID | Check | PASS when | Otherwise | Settles |
|---|---|---|---|---|
| L1 | Python | ≥ 3.10; version printed | FAIL | critic Q26 |
| L2 | Posture | production | WARN in test posture (so integration runs can still pass) | — |
| L3 | Local tailscale (production) | binary path used, `tailscale version`, `BackendState == Running`, `Self.Online`, `Self.TailscaleIPs`, `Self.Tags`; `tailscale get accept-dns`; `getaddrinfo(Self.DNSName)` | WARN (writes will be refused: self unknown) | §11.3; critic F3.6 |
| L4 | Credentials | `read.json` + target pass §8.2; mode (§8.3); `write.json` read as metadata and `write.secret` **only `stat`ed** (D20); environment scan for `tskey-` values | FAIL if the read credential is missing or unsafe (exit 3; API section skipped); WARN `single-client` ("L2 absent"); WARN `SECRET_IN_ENVIRONMENT` | — |
| L5 | Token cache | absent, or 0600 with `expires_at` and a cacheable scope | WARN (it is unlinked) | §9 |
| L6 | Protected file | present, one `self` line, entry count; after S4: entries resolve, the self line agrees with live self | WARN "tag writes refused until MC writes it" + the proposal block (§11.4); WARN for entries matching no device | critic Q14 |
| L7 | Audit log | opens for append (nothing written) | FAIL ("writes will not be sent") | §13 |
| L8 | Claude Code integration | every `rules.json` string present (§11.5); our skill's `.tailnet-install` marker matches the installed commit; upstream copy marker names pin `4f05d353efc56962546aa26ccc59bb08ca699ad1` and `git -C ~/.local/share/tailnet/upstream/tailscale-skill rev-parse HEAD` equals it; `tailscale-docs` present via `claude mcp get tailscale-docs` (or `~/.claude.json` `mcpServers`); `bash -lc 'command -v tailnet'` resolves | FAIL if the gate rule is missing; WARN for others | D21 |
| L9 | Lever notes | INFO lines: "ask rules prompt in every interactive mode incl. bypass; `-p` runs deny writes"; "an installed mod that handles `tool.check` can approve `--apply` without prompting you when there are no managed settings and no Team/Enterprise login [PERM L641-643]"; current posture (standing / session-scoped) | — | §2 |
| L10 | Clock skew (after S1) | API `Date` vs local ≤ 60 s | WARN | expiry maths |
| L11 | Drift (production; network, no auth; J1 graft, D19) | `GET https://api.tailscale.com/api/v2?outputOpenapiSchema=true` sha256 equals `spec/SHA256SUMS` [api §12.19]; `git ls-remote https://github.com/tailscale/tailscale-skill HEAD` equals the pin | INFO "drifted: re-check fixtures / upstream corrections" | — |

### 16.2 API steps (critic §6 steps 1-8, applied to the read client)

| Step | Call | Records | Settles | Settle-gated? |
|---|---|---|---|---|
| S1 | Reuse the cached read token, else `POST /oauth/token` (no `scope`) | granted `scope` (raw string), `expires_in`, `cacheable`; "reused cache: no audit event" or "minted: 1 event" | critic Q5 | no |
| S2 | Single-client only: `POST /oauth/token` with `scope=` the four read scopes | accepted? granted scope; cacheable? Two-client: `moot: the read client holds only read scopes` | critic Q1 | **yes** |
| S3 | `GET /tailnet/-/keys/<read client_id>` | status; on 200 `keyType`, `scopes`, `tags`, `invalid` | critic Q3 | **yes** |
| S4 | `GET /tailnet/-/devices?fields=all` | count (complete); self join and `id_agrees`; self's tags (F3.5: is it `tag:dev`?); every tagged device with key expiry on, with `expires` (F3.2; spec5, nomad-b, pi5 expected); expired keys; `multipleConnections`; whether `enabledRoutes`/`advertisedRoutes`/`sshEnabled` appear; protected entries resolved | critic Q15, F3.5, Q12, F3.2 | no |
| S5 | `GET /device/<self nodeId>/routes` | the status of an expected refusal. **Leaves one "Failed request" event in MC's console by design** [AUDIT L316]; doctor says so | critic Q4 | **yes** |
| S6 | `GET /tailnet/-/acl` twice: HuJSON, then `Accept: application/json` | raw ETag of each (quotes? equal?); sizes; counts of `acls`, `grants`, `ssh`, `tests`, `sshTests`; `tagOwners` keys include self's tags and `tag:fleet`? | critic Q21, R3, X13 | no |
| S7a | For each self identity S: `POST /acl/validate` array `[{"src": S, "proto": "tcp", "accept": ["<ipv4>:22" for every other tagged device]}]` | pass, or `want/got` per address. A DROP is a **WARN** (D30) with `next` → `tailnet diagnose` | part of critic X13 | no |
| S7b | Only if self is tagged: `POST /acl/validate` object (synthetic, never saved): `{"tagOwners": J.tagOwners, "groups": J.groups?, "hosts": {…J.hosts, "tailnet-diag-dst": "<another tagged device ipv4>"}, "grants": [{"src": ["autogroup:member"], "dst": ["tailnet-diag-dst"], "ip": ["tcp:22"]}], "tests": [{"src": "<self tag>", "proto": "tcp", "accept": ["<that ipv4>:22"]}]}` | pass → `autogroup:member` matches tagged sources; fail → it does not | critic Q20 | **yes** |
| S8 | `GET /tailnet/-/dns/configuration`, then `GET /tailnet/-/dns/nameservers` | status of each; the pair separates "endpoint not covered by `dns:read`" from "scope missing" | critic Q23 | configuration call **yes**, nameservers no |

Critic §6 step 9 (tag semantics through a real write, Q8/Q9) is a write; doctor never runs it.

### 16.3 Settling (D3)

- Settle-gated steps (S2, S3, S5, S7b, S8-configuration) run when: `--settle` is given; or no earlier
  `doctor.run` line holds a settled answer for that question; or the newest one is older than 30
  days (verification-discipline's drift rule). Otherwise doctor reports the stored answer with its
  original `measured_at` and age: "settled 2026-10-27T01:05Z (3 days ago)".
- The answers are read back with `audit.last("doctor.run")` (scanning back for the newest per
  question). No second state file exists.
- Live facts (S1, S4, S6, S7a, S8-nameservers) run every time.

### 16.4 Output, accounting, questions

- One line per check: `PASS | WARN | FAIL | INFO | SKIP`, the value, its `measured_at`, the question
  it settles, and `next[]`.
- Summary (J1 and J2 graft): `mints_this_run` (0, 1 or 2) and `audit_events_caused`, e.g.
  `["Create OAuth access token ×1", "Failed request ×1 (S5)"]`, so MC can match every console event
  [critic F6; AUDIT L316, L329].
- `questions[]` (D4), only those that apply, in this priority order; the skill asks one per turn
  with AskUserQuestion, copying `text` and `options`:

| Priority | `id` | Emitted when | Text (abridged) | Options (`safe_default` first) |
|---|---|---|---|---|
| 1 | `write-client-consent` | no `write.json` | "Before creating a write client: Devices → Core: Write reaches every device in the tailnet, not only tagged ones (TC L145-147). It can apply its own tag to any device, and tagging a user-owned device permanently removes its owner (TAGS L324, L72, L33). The earlier answer 'devices on tag:fleet only' rested on the premise that it could touch only fleet boxes; that premise was wrong. Create one?" | "Read client only for now" (safe default) / "Also a write client tagged tag:fleet" / "One client with every scope (no separate write secret)" |
| 2 | `scope-set` | read client granted scope ≠ the four read scopes | "Confirm the read client's scopes: Devices Core Read, Policy file Read, Device posture attributes Read (required by Policy file Read, TC L94), DNS Read" | "Keep exactly these" (safe default) / "Change them in the console" |
| 3 | `protected-list` | protected file missing | "Which devices must the CLI never retag? Proposed: every device (listed). Delete lines for any you want it able to tag" | "Protect every device" (safe default) / "Use the list minus some (I'll say which)" |
| 4 | `fleet-key-expiry` | S4 found tagged devices with expiry on | "spec5, nomad-b and pi5 still have key expiry ON (earliest <date>). Console tagging keeps it (TAGS L84). Disable it so they cannot drop off (P9)?" | "Leave it for now" (safe default) / "Disable on all of them" / "Only those expiring within 30 days" |
| 5 | `policy-fix` | S7a found a DROP | "The policy drops <self tag> → tag:fleet:22. I can draft and validate the grant; you would apply it in the console. Go ahead?" | "Not now" (safe default) / "Draft it" / "Show me the rule first" |

- Exit 0 when nothing FAILs; 8 on any FAIL; 3 when the read credential is missing or unsafe.
- A `doctor.run` audit line is always appended.

---

## 17. `status`

Local only, no API call, always exits 0 (a non-zero exit would abort the skill invocation
[SK L772-774]). `--brief` is at most six lines, for example:

```
tailnet 0.1.0 · production · as of 2026-10-27T01:02:03Z
credentials: two-client (read k…CNTRL; write k…CNTRL present) · read token cached, 41 min left
protected: answered (12 entries, self nXyz123CNTRL) · gate rules: 10/10 present
self (local view): claude-factory 100.x.y.z BackendState=Running
last doctor: 2026-10-27T00:55Z · 0 FAIL, 2 WARN · 2 questions for MC
audit: ~/.local/state/tailnet/audit.jsonl (143 lines)
```

- Shows no secret or token character beyond the `tskey-client-` prefix; never opens `write.secret`
  or `read.secret`.
- Missing rules print as `gate rules: 9/10 present (MISSING: Edit(~/.claude/settings.json))`, so the
  skill's injected state flags tampering at load time (D21).
- The local `tailscale status --json` call has a 3 s timeout; on failure the line reads
  `self (local view): unknown (<reason>)`. In test posture: `self (local view): not run (test posture)`.
- JSON: `data {version, posture, mode, credentials[], token_cache, protected, gate {present, missing[]}, self_local, last_doctor, open_questions, audit}`.

---

## 18. `dns`

- API (read token): `GET /tailnet/-/dns/nameservers`, `/preferences`, `/searchpaths`, `/split-dns`
  (TC L65-75 is authoritative over OC [critic R8]); best-effort `GET /tailnet/-/dns/configuration`,
  whose refusal is reported and does not fail the command [critic Q23].
- Local (production; J1 graft from AE §3.2): `tailscale get accept-dns` [cliref L409-428, L508] and
  `socket.getaddrinfo(Self.DNSName)`. MagicDNS did not resolve on the droplet at 2026-10-25T23:30Z
  [critic F3.6]; `accept-dns=false` is a documented reason a node ignores the tailnet's DNS, so it
  is reported beside the failure without asserting cause **[inference]**.
- Output: labelled sections; JSON `data {nameservers, magicDNS, searchPaths, splitDns, configuration
  {status, body|null}, local {accept_dns, self_dnsname, resolves, error}}`.

---

## 19. The skill

### 19.1 Name, location, coexistence

- Name and directory **`tailnet`**: `~/.claude/skills/tailnet/`. Upstream owns `tailscale`, its
  directory and `/tailscale` [up §2, §9; pkg §5.2]. Both load; ours carries corrections where upstream
  is wrong and says ours wins.
- The skill calls the CLI by its bare name (`~/.local/bin/tailnet` on PATH). No bundled scripts; no
  `${CLAUDE_SKILL_DIR}` (its behaviour through symlinks and in `references/` is unverified
  [pkg §4.1]). The pinned spec is referenced by absolute install path
  `~/.local/share/tailnet/spec/tailscale-openapi.yaml`.

### 19.2 `SKILL.md`

**Frontmatter** (portable keys only, so a claude.ai upload would accept it [pkg §2.2; SK L434]):

```yaml
---
name: tailnet
description: >-
  Operate MC's own tailnet (taild02cf8.ts.net) from the claude-factory droplet with the `tailnet`
  CLI: inventory devices with tags, owners, key expiry and Tailscale SSH state; diagnose why SSH
  or a TCP port times out between tailnet hosts (policy drop, Tailscale SSH rules, or the host's
  firewall); read, draft, validate, test and diff the tailnet policy for MC to apply in the
  console; and the two guarded writes (change a device's tags, disable key expiry), always as a
  dry run first and only with MC's approval. Use for MC's machines (spec5, nomad-b, pi5, albini,
  the droplet), tag:fleet and tag:dev, OAuth clients for the Tailscale API, or "can't reach
  <host> over Tailscale". For general Tailscale concepts use the official tailscale skill and the
  tailscale-docs MCP server; this skill overrides them where they are wrong.
license: Proprietary; private to MC
compatibility: >-
  Claude Code on claude-factory (Ubuntu): Python 3.10+, the tailscale CLI, `tailnet` on PATH,
  credentials in ~/.config/tailnet. Not for cloud or Cowork sessions.
metadata:
  version: "0.1.0"
  upstream-skill-pin: "4f05d353efc56962546aa26ccc59bb08ca699ad1"
  openapi-sha256: "b3532da71b7bc5f37fd030f324aaaa1e59df72ac025e7d15b4e3d268ea15ac38"
  facts-as-of: "2026-10-26"
allowed-tools:
  - Bash(tailnet status *)
  - Bash(tailnet doctor *)
  - Bash(tailnet device list *)
  - Bash(tailnet policy *)
  - Bash(tailnet dns *)
  - Bash(tailnet diagnose *)
---
```

- Description stays ≤ 1,024 characters (test). `allowed-tools` is a YAML list because entries
  contain spaces; Claude Code accepts the list form, the standard says string [pkg Contradiction 4].
- `allowed-tools` lists reads only. It pre-approves them for the invoking turn and lets the injected
  `status` run in Manual mode [SK L789-793]; a trailing ` *` also matches the bare command
  [PERM L186]. Device writes are deliberately absent; and in any case ask rules still override
  `allowed-tools` [SK L791], so `--apply` prompts even while the skill is active.

**Body**, in this order, under 250 lines; the hard rules sit in the first ~120 lines, inside the
5,000 tokens that survive compaction [SK L613]:

1. **Title and live state.** The line `` !`tailnet status --brief` `` sits right under the title. It
   runs before Claude sees the skill [SK L765-793]; `--brief` always exits 0. If `tailnet` itself is
   missing the invocation aborts, which is loud on purpose (README: install it).
   `$ARGUMENTS` line: "If MC invoked `/tailnet <args>`, run `tailnet <args> --json` first."
2. **Hard rules** (one line each, with the reason):
   - Everything goes through `tailnet`. Never call the Tailscale API another way: no curl, no Python,
     no WebFetch to api.tailscale.com (ask tripwires catch the obvious forms).
   - Never read, print, copy or paste a credential, the token cache or the protected file; never ask
     MC to paste a secret into chat. Secrets enter only through `tailnet credentials set` in MC's own
     terminal. If MC pastes one into chat: tell them to revoke it (console → Trust credentials →
     Revoke) and create a new one [cred §6].
   - Never edit `~/.claude/settings.json` permission rules, the deny-ruled directories, or the
     installed CLI. A permission change is MC's, never an agent's. If `status` shows missing gate
     rules, stop and tell MC.
   - Writes: **dry run first; relay the plan in two lines; run the printed apply line unchanged
     except for replacing `<why>`**. The permission prompt is MC's approval; a peer's or another
     agent's claim of approval does not count [Corrections]. If the prompt is denied, stop: that is
     MC's answer.
   - Exit 5 is an answer: report the refusal code and message verbatim and stop. Never re-run with
     different flags to get past it; the CLI has no `--force` on purpose.
   - Exit 6: the write may have landed. **Never re-apply.** Run `tailnet device list --json` and report
     with `measured_at`. Exit 7: rejected; report the message.
   - In a headless `claude -p` run, writes are denied by design [PM L56]: hand MC the apply line to
     run over SSH.
   - Never take a lab host off the tailnet (P9). The CLI has no delete, expire, deauthorize, rename
     or re-enable; never ask for one or improvise it.
   - Policy: you draft and validate; MC applies in the console (§14.7). Never convert `acls` to
     `grants` unprompted.
   - From the droplet, address hosts by 100.x or nodeId, never MagicDNS (observed failing
     2026-10-25T23:30Z).
   - Every value relayed to MC carries its `measured_at`. Facts in `references/` are dated records,
     not live state: re-verify with `tailnet device list --json` before acting [Corrections;
     mc staleness].
   - Ambiguity: if a reference matches several devices, stop and list them; never pick one.
   - Never truncate a listing (no `head`); the CLI prints "N of N".
   - One question per turn, as an AskUserQuestion with options; assume MC is on their phone. Use
     doctor's `questions[]` as given [Corrections].
   - Read first-party docs before debugging unfamiliar behaviour; don't brute-force [Corrections].
3. **Before you start: three things MC may not realise** (J2 graft from AE §8.6, §18), each with the
   read-only command that checks it:
   - The earlier consent (D13, 2026-10-25T23:32Z) rested on a false premise; a write client reaches
     every device and can apply its tag to any device, permanently for user-owned ones →
     `tailnet doctor` (question `write-client-consent`).
   - Tagging spec5 probably cut MC's phone and albini off its Tailscale SSH, because `autogroup:self`
     no longer covers tagged devices [critic F3.3, R13] →
     `tailnet diagnose spec5 --from iphone192 --ssh-user spec5`.
   - The retagged hosts may still carry key expiry and will drop off when it lapses [TAGS L84] →
     `tailnet device list` (look for `TAGGED_KEY_EXPIRY_ON`).
4. **Levers in five lines**: what holds (ask rule in every interactive mode; deny rules; the
   separate write secret; Tailscale's audit log) and what does not (command text the rule doesn't
   match; a script reading the secret; a `tool.check` mod). Postures: standing vs session-scoped;
   after a write session, offer `tailnet credentials forget write` once.
5. **Command card**: the 14 commands, one line each; the exit-code table; "add `--json` when you
   will act on the result".
6. **Workflows** (a few numbered lines each):
   - (a) First session or "is this working?": `tailnet doctor`, then its questions one per turn.
   - (b) "Can't reach X": `tailnet diagnose X` (add `--ssh-user` for spec5) → branch on the verdict
     → `references/diagnose-port.md`.
   - (c) Inventory and the P9 watch: `tailnet device list --json`; never infer offline from a missing
     `lastSeen`.
   - (d) Keep retagged hosts on the tailnet: `tailnet device disable-key-expiry <hosts…>` (one
     approval for all tagged targets).
   - (e) Change tags: `tailnet device tag`; for new hosts prefer `--advertise-tags` at authentication,
     which also disables key expiry by default [pol (b)].
   - (f) Policy change: the §14.7 loop → `references/policy-workflow.md`.
   - (g) Credentials missing or broken: `tailnet doctor` → `references/credentials.md`; hand MC
     exactly one command and say what it proves.
7. **MC's tailnet in five lines** plus a pointer to `references/tailnet-facts.md` and its staleness
   rule.
8. **Routing: where knowledge comes from.**

   | Need | Go to |
   |---|---|
   | MC's hosts, users, tags, decisions | `references/tailnet-facts.md`, then confirm live with `tailnet device list --json` |
   | A Tailscale concept or how-to | The official `tailscale` skill (`/tailscale` or `~/.claude/skills/tailscale/references/<topic>.md`). **First** check `references/upstream-corrections.md` for that file; it wins |
   | Current doc text | The `tailscale-docs` MCP server's search tool if connected (passages with source URLs). **Privacy rule (SF §14.3, J2 graft): it is a third-party host (kapa.ai), so queries stay generic: no hostnames, 100.x addresses, emails or tailnet name.** For exact wording: `curl -fsSL https://tailscale.com/docs/<path>.md`; not WebFetch, which returns a model summary [up §2] |
   | An endpoint, field or scope | `grep -n -A40 'operationId: <op>' ~/.local/share/tailnet/spec/tailscale-openapi.yaml`; scopes from TC, not the OAuth clients page [critic R8] |
   | Something the CLI cannot do | Say so and name the console page; never improvise API calls |

   Upstream is wrong on these, so trust this skill (one line each; details in
   `references/upstream-corrections.md`): `devices:core` reaches every device, tags do not fence it
   (A6); scope names are `devices:core[:read]` (A1); preview takes `type`/`previewFor` and a policy
   body, `api.md:100-103` is wrong (A3); `tailscale ping` defaults to DISCO (C3); serve/funnel syntax
   changed in 1.52 (C1, C2); `ssh` rules do not open port 22 (U8); `autogroup:self` means the user's
   own devices (P4); retagged devices keep their old key expiry (U6); SSH actions are only
   `accept`/`check` (P3).
9. **Only MC does these**: create, rotate or revoke OAuth clients; run `credentials set`; write the
   protected file; apply policy in the console; delete, expire, (de)authorize, rename or re-IP a
   device; re-enable key expiry; re-authenticate a host; `claude mcp login`. The skill hands MC the
   console path or the one command.
10. **References index**: one line per file saying when to read it.

### 19.3 `references/` files

Each file over 100 lines opens with a table of contents [pkg §3]. Every fact carries its source and
date; gaps stay **[unverified]** [Corrections: confirmed sources only]. All are one level deep from
SKILL.md.

| File | Contents | Sources |
|---|---|---|
| `tailnet-facts.md` | **Staleness rule first** ("every row is a dated claim; re-verify with `tailnet device list --json`"). Tailnet `taild02cf8.ts.net`; tailnet ID not recorded, so `-`; MagicDNS on, HTTPS certs and Serve enabled 2026-09-02 (cert names public in CT logs); MagicDNS failed on the droplet 2026-10-25T23:30Z. Hosts table (role, OS/arch, 100.x, SSH user, Tailscale SSH state, tags with "observed at", source) for albini, claude-factory, pi5, spec5, nomad-b (OS hostname spec5b), pi3, raptop, cybrpwrpc, surface, server-factory-immich, spectre, iphone192, iphone182. The 2026-10-25 change: `tag:fleet` on spec5/nomad-b/pi5 at 23:27:40Z; droplet `tag:dev` unconfirmed. Decisions that bind: P1, P2, P3, P5, P7, P9, P11, P12, P13, P14, P15, P18. Open blocker and the earlier session's self-contradiction (X13). Unknowns: Q15, Q21, F3.5 | [mc §1-§4]; [critic F3, X2, X3, X13]; fleet.yaml 47-178; [sigint p3:138-144] |
| `gotchas.md` | One line each, grouped, each with its source. **Identity and tags:** first tag strips the owner, permanently; cannot remove all tags; tags are lowercase; `autogroup:self` excludes tagged devices; `autogroup:member` vs tagged sources (Q20, see doctor S7b); a tagged source can Tailscale-SSH only to tagged hosts, never in check mode. **Key expiry:** retagging keeps old expiry; re-enabling may drop a device at once (F5). **Tailscale SSH:** claims :22; check mode blocks unattended logins; macOS GUI builds have no SSH server; check URLs are login links (redacted). **Reachability:** ping proves nothing about :22; a policy drop is a timeout (TSMP reject, no RST); `ssh` rules open no network; a stopped backend shows stale peers; a `status` listing ≠ permission. **API:** validate 200 ≠ pass; preview body is a policy; ETag carries quotes; `lastSeen` omitted while connected; each mint = one audit event; no pagination; `/dns/configuration` scope unverified; 401 undocumented but real; `devices:core` reaches every device. **Records and hosts:** a listing whose length equals its print limit is truncated; a cloned SD card shares the node key (nomad-b's machine-id equals spec5's); renaming breaks MagicDNS URLs (spec5 Serve); `tailscale serve` hangs when Serve is off; `tailscale health` is not a subcommand; Android sideloading re-registers the node; "rename is not in the API" is stale (C1); stubs hid three bugs | [mc §5, §6]; [critic F3, F5, F6, R2, R3, R13, R14]; [api §3, §5, §6, §12]; [pol (a)-(d)] |
| `diagnose-port.md` | The §15 ladder in prose; how to read each `diagnose` field; the verdict table with what each proves; the on-host block with what each line proves; ping types (DISCO default, TSMP before policy, ICMP includes policy); per-host notes for spec5 (Tailscale SSH on, check mode, P7, open question MC6 (§28)), nomad-b (plain OpenSSH, P6) and pi5 (plain OpenSSH, `RunSSH:false` as of 2026-09-27); what does not discriminate (ping, flow logs, `sshTests` for plain sshd); `tailscale debug netmap` flagged hidden and unstable; the unverified list | [pol (d), TL;DR, unverified 9-13]; [critic F3.3-F3.4, X1, X10, R14]; [mc §2, P6, P7]; [cliref L620-650] |
| `policy-workflow.md` | The §14.7 loop with exact commands; where drafts live and why (P13). Rule shapes, preferring grants for new rules [pol (a); up P1]: grant `{"src":[...],"dst":[...],"ip":["tcp:22"]}`; the legacy ACL equivalent; `ssh` rule `{"action":"accept"\|"check","src":[...],"dst":[...],"users":[...]}`; `tests` and `sshTests`. **Candidate text for the blocker** (adapt after reading the live policy; never paste blind): (1) grant `tag:dev → tag:fleet`, `ip ["tcp:22"]`; (2) MC's own access to `tag:fleet` using MC's login email as it appears in the live policy (not recorded anywhere [mc §1]) rather than `autogroup:member` until doctor S7b settles Q20; (3) for spec5 (Tailscale SSH): an `ssh` rule `tag:dev → tag:fleet`, users `["spec5"]`, `action: "accept"`, **only if MC says yes to open question MC6 (§28)**, plus a user → `tag:fleet` `ssh` rule in **check** mode so MC's phone and albini keep reaching spec5 (P7) [critic F3.3, R13, R14]; (4) `tests`/`sshTests` asserting each. Never: `"ip":["*:*"]` in grants (U1), `deny` as an SSH action (U2), Convert to grants unprompted, re-serialising HuJSON. Preview flow and why `policy test` replaces it (§14.5). For whoever holds `policy_file` (not us): `If-Match` with the raw ETag, 412 on mismatch, `ts-default` [spec 2291-2351] | [pol (a), (c), (e), (f), U1-U8]; [critic F3.3, R1, R3]; [api §6]; [up §4c P2-P6] |
| `credentials.md` | **The consent text first** (doctor question 1, verbatim). MC's two-client procedure, one action per step, hazard first [cred §12 adapted]: read client = Devices Core Read, Policy file Read, Device posture attributes Read, DNS Read, **no tag** [critic R6]; write client = Devices Core Write + its tag (defined in `tagOwners` first [cred §4]); copy each secret to a password manager (shown once); `tailnet credentials set read` (and `write`) over SSH; write the protected file; `tailnet doctor`. The tag choice and its reach (open question MC4 (§28); TAGS L324). The single-client fallback and its cost (no L2; reads never cached unless narrowing works). Postures (standing vs session-scoped). The scope map (what each scope reaches). What MC sees in the console audit log (mints, refused calls, writes). Revocation (console only: Trust credentials → Revoke → Revoke; kills live tokens [TC L380-388]); what to do if a secret is exposed; secret scanning revokes leaked secrets [cred §11] | [cred §2-§6, §9, §11, §12]; [critic F1, F2, F4, F6, R6, R7, R12]; [api §4] |
| `upstream-corrections.md` | "The official skill at `~/.claude/skills/tailscale` (`tailscale/tailscale-skill@4f05d35`) is wrong on these points. This file wins." Table: upstream `file:line` → claim → first-party evidence → verdict. Rows: A1-A10, C1-C8, P1-P7, O1-O3 [up §4]; the stale `api.md` lines [api §10], **including `api.md:100-103` (A3, preview shape)**; U1-U13 [pol discrepancies]; `enterprise.md:97` (A6). Trust order: TC/spec and dated first-party docs → this skill → upstream | [up §4, §5]; [api §10]; [pol "Discrepancies"] |

---

## 20. The installer

### 20.1 Invocation

`./install-tailnet.sh [--dry-run] [--uninstall] [--no-upstream] [--no-mcp]`; `DRY_RUN=1` equals
`--dry-run`. The bash wrapper checks `python3` ≥ 3.10 and refuses to run as root (credentials and
settings would land in `/root`), then runs `python3 -I installer/install.py "$@"` (`-I` keeps the
environment and the current directory off `sys.path`). Every step in `install.py` is a function
taking `home: Path` and `claude_dir: Path`, so the local steps are unit-testable without the wrapper.
The repo commit (`git rev-parse HEAD`) and a dirty flag are recorded in the install record and the
skill marker.

### 20.2 What goes where

| Artifact | Destination | Mode | Idempotency and safety |
|---|---|---|---|
| CLI package (with `rules.json`) | `~/.local/share/tailnet/lib/tailnet/` | dirs 0755, files 0644 | Copied, not symlinked; replaced atomically (copy to `lib/.tailnet.new`, rename, remove the old) |
| Launcher | `~/.local/bin/tailnet` | 0755 | `#!<resolved sys.executable> -I`, two ABOUTME lines, `sys.path.insert(0, "<abs lib>")`, `from tailnet.cli import main; sys.exit(main())`. `-I` keeps `PYTHONPATH`, the user site and the cwd out of a process that holds a secret. Warns if `~/.local/bin` is not on the login PATH (`bash -lc 'command -v tailnet'`); never edits dotfiles |
| Pinned spec | `~/.local/share/tailnet/spec/tailscale-openapi.yaml` + `SHA256SUMS` | 0644 | sha256 verified on copy |
| Directories | `~/.config/tailnet`, `~/.local/state/tailnet`, `~/.local/state/tailnet/drafts` | 0700 | created or tightened |
| Our skill | `$CLAUDE_CONFIG_DIR/skills/tailnet/` (default `~/.claude/skills/tailnet/`) | — | Copied (an edit in the working repo never changes the live skill mid-session) with marker `.tailnet-install` `{"commit","dirty","installed_at"}`. A target **without** our marker: stop this step, change nothing, report |
| Upstream skill | `$CLAUDE_CONFIG_DIR/skills/tailscale/` | — | §20.3 |
| Docs MCP | user scope, through Claude Code's own CLI | — | §20.5 |
| Settings | `$CLAUDE_CONFIG_DIR/settings.json` | existing mode kept (0600 if new) | §20.4 |
| Install record | `~/.local/share/tailnet/install.json` | 0600 | `{commit, dirty, installed_at, added: {lib, launcher, spec, skill, upstream_copy, upstream_clone, mcp: bool, rules: [...]}}`; read by `--uninstall` and doctor L8 |

The installer **never** creates credentials or the protected file. It ends with `Next (MC):`
create the clients (`references/credentials.md`), `tailnet credentials set read` over SSH, write
the protected file, then `tailnet doctor`.

### 20.3 Upstream skill pinned at `4f05d35`

- Pin `4f05d353efc56962546aa26ccc59bb08ca699ad1` (tag `1.0.0-alpha-1`; HEAD on 2026-10-26
  [up §1; critic spot-check 13]).
- Steps (`upstream.py`, functions take `url` and `pin` so tests can use a local fixture repo):
  `git clone --no-checkout https://github.com/tailscale/tailscale-skill.git
  ~/.local/share/tailnet/upstream/tailscale-skill` (or `git fetch` if present) →
  `git -c advice.detachedHead=false checkout --detach <pin>` → **require `git rev-parse HEAD ==
  <pin>`**, else abort → copy `skills/tailscale/` plus `LICENSE` (BSD-3 [up §1]) to
  `$CLAUDE_CONFIG_DIR/skills/tailscale/` with marker `.tailnet-install` `{"pin": …}`. Skipped when
  the marker already names the pin.
- An existing `skills/tailscale` **without** our marker (for example an `npx skills` symlink) is
  left alone; the installer reports what it is (symlink target, any git HEAD).
- **Not `npx skills`**: it sends telemetry by default, `rm -rf`s an existing target, needs Node
  22.20+, and installs into the project by default [pkg §9; up §6].

### 20.4 `rules.json` and the settings merge (`settings_merge.py`)

`src/tailnet/rules.json` is the single source (status, doctor, guard, installer and the skill test
all read it):

```json
{
  "v": 1,
  "gate": "Bash(*tailnet*--apply*)",
  "ask": [
    "Bash(*tailnet*--apply*)",
    "Bash(*api.tailscale.com*)",
    "WebFetch(domain:api.tailscale.com)",
    "Edit(~/.claude/settings.json)",
    "Bash(*.claude/settings.json*)",
    "Bash(*install-tailnet*)"
  ],
  "deny": [
    "Read(~/.config/tailnet/**)",
    "Edit(~/.config/tailnet/**)",
    "Bash(*.config/tailnet*)",
    "Edit(~/.local/state/tailnet/audit.jsonl)"
  ]
}
```

Why each entry exists:

- `Bash(*tailnet*--apply*)` is MC's gate (L3). The leading `*` matches `tailnet`,
  `~/.local/bin/tailnet` and `python3 -m tailnet` alike; `*` matches anywhere [PERM L185-187];
  `allow_abbrev=False` stops `--appl` slipping past (§5.1).
- `Bash(*api.tailscale.com*)` and `WebFetch(domain:api.tailscale.com)` are **accident-grade
  tripwires** against hand-rolled API calls [PERM L117, L252-260]; obfuscation defeats them.
- `Edit(~/.claude/settings.json)` and `Bash(*.claude/settings.json*)` protect the gate itself:
  bypass mode allows protected-path writes without a prompt [PM L720-731], but an explicit ask rule
  prompts in every mode [PM L34-36]. The Bash form is a text tripwire; a script that opens the file
  itself is not caught, which `status`/`doctor` detect (D21).
- `Bash(*install-tailnet*)`: a reinstall replaces the guard code (D29). The first install happens
  before the rule exists.
- `Read`/`Edit(~/.config/tailnet/**)` keep secrets, the token and the protected list out of the
  transcript and out of the agent's hands; a `Read` deny also blocks Edit and Write on the path
  [PERM L352]; both cover recognised Bash file commands and redirect targets [PERM L356].
  `Bash(*.config/tailnet*)` closes `cp`, `printf >`, `ls -l` and similar at the text level (D22).
  Deny holds in every mode [PM L30].
- `Edit(…/audit.jsonl)` keeps Claude's tools from rewriting history.
- **No `Write(path)` rules**: they are accepted but never match [PERM L358-360] (J1 `must_fix`).
- **No allow rules** (D25).
- When `CLAUDE_CONFIG_DIR` is set, the two settings rules name the real path
  (`Edit(//<abs>/settings.json)`, `Bash(*<abs>/settings.json*)`). One pure function,
  `gate.rules_for(claude_dir) -> {"ask": [...], "deny": [...]}`, does that substitution; the
  installer writes its output and `gate.missing_rules` compares against its output, so both always
  agree. The gate rule itself never changes.

**Merge algorithm** (pure functions `merge(settings, ask, deny) -> (new, added)` and
`remove(settings, recorded) -> (new, removed)`):

1. Read `$CLAUDE_CONFIG_DIR/settings.json` (default `~/.claude/settings.json`). Absent → `{}`.
   **Invalid JSON, a non-object `permissions`, or a non-list `ask`/`deny` → abort this step,
   writing nothing**, and print the rules for MC to add by hand. Never guess at a repair.
2. Append each of our strings not already present (exact match) to `permissions.ask` /
   `permissions.deny`, creating the lists if missing. Never remove, reorder or rewrite another
   entry or key (`defaultMode`, `allow`, hooks, env and the rest stay as they are).
3. Nothing added → no write, no backup, "already present".
4. Otherwise: back up the original bytes to `settings.json.tailnet-bak-<UTC>`; write a temp file in
   the same directory with the original mode, `indent=2` and a trailing newline; `fsync`;
   `os.replace`; re-read with `json.load`; if that fails, restore the backup.
5. Record the added strings in `install.json`.
6. Warnings (never auto-changed): an existing `deny` rule matching `tailnet` (writes would be
   blocked); `permissions.defaultMode == "bypassPermissions"` (INFO: the ask rule still prompts in
   bypass; headless `-p` runs deny writes [PM L56]).
7. `remove` deletes only recorded strings that are still present; an entry MC edited is left and
   reported.

### 20.5 Docs MCP server

- If `claude` is on PATH: `claude mcp get tailscale-docs`. Present with URL
  `https://tailscale.mcp.kapa.ai/` → no-op; present with another URL → leave it, warn; absent →
  `claude mcp add --transport http --scope user tailscale-docs https://tailscale.mcp.kapa.ai/`
  [pkg §8; up §7] and record `mcp: true`.
- Print MC's one command: `claude mcp login tailscale-docs --no-browser` (it prints a URL MC can
  finish on the phone; needs an interactive terminal; headless completion is **[unverified]**
  [pkg Open gaps]).
- `--no-mcp` skips; a missing `claude` binary skips with a message.

### 20.6 Dry run, idempotence, uninstall

- **Dry run** routes every mutation through `act(description, fn)`, which prints `would:
  <description>`; the settings change is printed as a unified diff of the pretty-printed JSON. It
  writes nothing, clones nothing and runs no mutating subprocess (read-only lookups such as
  `command -v claude` and `claude mcp get` are allowed). A test proves "writes nothing" by
  snapshotting the temp home.
- **Idempotent:** a second run reports "no changes" for every step and leaves every byte in place
  except `install.json`'s `last_run`.
- **`--uninstall`** reverses `install.json`: removes the launcher, lib and spec; removes our skill
  and the upstream copy only where the markers are ours, and the clone; removes the MCP entry only
  if we added it and the URL still matches (`claude mcp remove tailscale-docs --scope user`);
  removes settings rules only where the recorded string is still present. It **never touches**
  `~/.config/tailnet/*` (credentials, token cache, protected file), the audit log or drafts; it
  prints their paths and the reminder that removing files is not revocation: console → Trust
  credentials → Revoke, for both clients [TC L380-388].

---

## 21. Test plan

### 21.1 Harness

- **Tiers.** `python3 -m pytest` runs unit + integration and must be pristine (no warnings, no stray
  output; `filterwarnings = ["error"]`). `pyproject.toml`:
  `testpaths = ["tests/unit", "tests/integration", "tests/test_pre_commit.py"]`. **e2e is excluded by
  path, not hidden by a marker**: `make e2e` runs `python3 -m pytest tests/e2e`, and running that
  path always runs it (AE §15.3).
- **netguard** (`tests/netguard.py`, J1 and J2 graft): `sys.addaudithook` that raises on a
  `socket.connect` whose address is not loopback, and on any `subprocess.Popen` / `os.exec*` whose
  executable's basename is `tailscale`. `tests/conftest.py` installs it in the pytest process;
  `tests/run_cli.py` installs it inside every integration CLI process before calling
  `tailnet.cli.main`, so the real CLI process is held to the same rule.
  `test_default_suite_never_leaves_loopback` proves the hook fires.
- **The one seam** (`tests/loopback.py`): a stdlib `ThreadingHTTPServer` on `127.0.0.1:0` with a
  route table `(method, path) → handler | (status, headers, body)`, sequences for retry cases
  (e.g. `429` then `200`), and a recorder of method, path, query, headers and body. Bodies come from
  `tests/fixtures/api/*.json` (spec examples; `_source` stripped before serving) and
  `fixtures/scenario/*.json` (MC-shaped, labelled synthetic). Scenario devices for TCP probes use
  `127.0.0.x` addresses so the probe runs against real loopback sockets.
- **The process.** Integration tests run `[sys.executable, "-I", "tests/run_cli.py", …]` with
  `TAILNET_API_BASE=http://127.0.0.1:<port>`, `TAILNET_HOME=<tmp>/tn`, `HOME=<tmp>`, a minimal
  `PATH`, `LANG=C.UTF-8`. Test posture never runs `tailscale` (D23), so no fake executable exists
  anywhere (J2 `must_fix`; MC's learning that "stubs hid all three bugs" [mc §5]).
- **Fixture secrets** are assembled at runtime (`"test-client-" + "read0001"`); redaction tests
  build `tskey-`-shaped strings at runtime (`"tskey-" + "client-" + "x" * 24`), so the pre-commit
  scan never sees a literal key (MIN §15.1).
- **Fixtures** (`fixtures/README.md` maps each to its spec line): Device field examples [spec
  4461-4822], `testsOrValidationFailed` [spec ~2660-2667], `validateSCIMGroupsNotSynced`,
  `testsOrValidationSuccess` `{}` [spec 2676-2678], `ExampleHuJSONPolicyFile` [spec 6757-6778],
  `ExampleJSONPolicyFile` [spec 6742], DNS bodies [spec 1546, 5613-5653], `Key` [spec 5773-5898],
  `Error` [spec 4823-4829], the token response [OC L132]. `fixtures/status/self-running.json` is a
  synthetic `tailscale status --json` with real field names and indented, spaced formatting
  [ipnstate:43-50, 239-316; mc §5 "spaced JSON"], used only by `selfnode` parser unit tests; e2e E2
  checks the parser against the real binary.

### 21.2 Unit tests (`tests/unit/`)

**`test_repo_rules.py`**: `test_every_code_file_starts_with_two_aboutme_lines`;
`test_api_module_exposes_only_the_two_writes` (`ast`: no other function issues POST or DELETE
except `validate_tests` and `validate_policy`); `test_disable_key_expiry_hardcodes_true`;
`test_only_api_and_tokens_issue_post_requests`; `test_only_localts_runs_the_tailscale_binary`;
`test_pinned_spec_matches_sha256sums`; `test_every_api_fixture_names_its_spec_source`;
`test_default_suite_never_leaves_loopback`.

**`test_redact.py`**: `test_a_client_secret_is_redacted_by_pattern`; `test_a_bearer_token_is_redacted`;
`test_a_registered_secret_without_the_tskey_prefix_is_redacted`;
`test_form_encoded_and_json_secret_fields_are_redacted`;
`test_json_escaped_secrets_are_redacted_after_serialisation`;
`test_a_tailscale_ssh_check_url_is_redacted`; `test_text_without_secrets_is_unchanged`;
`test_the_excepthook_redacts_and_exits_1`.

**`test_posture.py`**: `test_no_override_is_production_with_the_tailscale_api`;
`test_loopback_override_with_a_test_home_is_test_posture`;
`test_localhost_is_accepted_only_if_it_resolves_to_loopback`;
`test_lookalike_and_non_loopback_hosts_are_refused` (parametrised: `127.0.0.1.example.com`,
`localhost.evil`, `127.1`, `0x7f000001`, `[::1]`, `10.0.0.1`, `evil.example`);
`test_https_userinfo_query_path_or_missing_port_is_refused`; `test_base_without_home_is_refused`;
`test_home_without_base_is_refused`; `test_a_test_home_inside_or_containing_the_real_dirs_is_refused`;
`test_real_dirs_come_from_the_password_database_not_home`;
`test_test_posture_places_every_path_under_the_test_home`;
`test_test_posture_disables_environment_proxies`.

**`test_secure_files.py`**: `test_a_0600_file_owned_by_me_is_read`;
`test_a_group_readable_file_is_refused_with_the_chmod_fix`; `test_an_other_readable_file_is_refused`;
`test_a_group_writable_file_is_refused`; `test_a_symlink_is_refused`; `test_a_hard_link_is_refused`;
`test_a_file_owned_by_another_uid_is_refused` (pure, over a constructed `os.stat_result`);
`test_a_group_writable_parent_directory_is_refused`; `test_an_oversized_file_is_refused`;
`test_atomic_write_is_0600_under_umask_000`; `test_atomic_write_leaves_no_partial_file_on_error`;
`test_append_is_one_write_under_an_exclusive_lock`; `test_concurrent_appends_never_interleave`
(several processes, every line parses); `test_error_messages_never_contain_file_contents`.

**`test_credentials.py`**: `test_missing_read_credential_names_the_set_command`;
`test_a_file_secret_is_loaded_and_its_target_checked`;
`test_a_file_target_outside_the_config_dir_is_refused`; `test_an_inline_write_secret_is_refused`;
`test_write_metadata_loads_without_opening_the_write_secret`;
`test_an_api_access_token_is_refused_by_name`; `test_a_tskey_secret_is_refused_in_test_posture`;
`test_a_role_mismatching_its_file_name_is_refused`; `test_no_secret_is_read_from_the_environment`;
`test_modes_none_read_only_two_client_single_client`;
`test_a_read_client_granted_write_scope_means_single_client`;
`test_forget_write_removes_secret_then_metadata_and_logs`.

**`test_tokens.py`** (in-process loopback): `test_only_scopes_that_all_end_in_read_are_cacheable`;
`test_a_missing_or_empty_scope_is_not_cacheable`; `test_legacy_devices_and_all_count_as_write_power`;
`test_scope_is_split_on_spaces_and_commas`;
`test_a_cached_token_is_reused_until_five_minutes_before_expiry`;
`test_a_cache_for_another_client_id_is_ignored`; `test_an_insecure_cache_is_unlinked_with_a_warning`;
`test_the_mint_is_a_form_post_with_grant_type_and_no_scope_in_two_client_mode`;
`test_single_client_read_mints_send_the_four_read_scopes`;
`test_a_400_on_a_scoped_mint_retries_once_without_scope`; `test_a_401_on_mint_is_not_retried`;
`test_every_mint_appends_a_token_mint_line`.

**`test_http.py`** (in-process loopback): `test_every_request_carries_bearer_and_user_agent`;
`test_a_redirect_is_refused_and_the_token_never_reaches_the_target`;
`test_a_read_retries_once_on_429_honouring_retry_after`; `test_retry_after_is_capped_at_thirty_seconds`
(the sleep function is a parameter of `Transport`, injected by the test); `test_a_second_429_on_a_read_is_an_error`;
`test_a_write_makes_exactly_one_request_whatever_the_status` (parametrised: 400, 429, 500, 504,
read timeout); `test_a_401_on_a_cached_token_remints_once_and_retries_once`;
`test_request_id_is_surfaced_in_errors`; `test_a_403_names_the_needed_scope_and_says_possibly`;
`test_a_non_json_error_body_is_excerpted_and_redacted`; `test_oversized_responses_are_refused`.

**`test_devices.py`**: `test_resolve_by_each_reference_form` (parametrised: nodeId, numeric id,
hostname ignoring case, full name with and without the dot, first label, IPv4, IPv6);
`test_a_substring_never_matches`; `test_an_ambiguous_argument_lists_the_candidates`;
`test_online_comes_from_connected_to_control_not_last_seen`;
`test_missing_last_seen_while_disconnected_is_never_seen`; `test_key_expiry_days_left_uses_injected_now`;
`test_a_tagged_device_with_expiry_on_is_flagged`; `test_absent_ssh_enabled_is_unknown_not_false`;
`test_the_table_prints_n_of_n`.

**`test_selfnode.py`**: `test_parse_reads_self_ips_id_and_tags_from_indented_json`;
`test_a_backend_not_running_is_unknown`; `test_self_offline_is_unknown`;
`test_self_joins_by_tailscale_ip_and_records_id_agreement`; `test_no_ip_match_means_another_tailnet`;
`test_two_ip_matches_mean_unknown`; `test_a_disagreeing_self_line_refuses`;
`test_test_posture_takes_self_from_the_line_and_never_runs_tailscale`.

**`test_protected.py`**: `test_a_missing_file_is_unanswered`; `test_exactly_one_self_line_is_required`;
`test_entries_match_node_id_exactly_or_hostname_and_label_ignoring_case`;
`test_comments_and_blank_lines_are_ignored`; `test_a_self_only_file_protects_only_self`;
`test_an_insecure_protected_file_is_refused`.

**`test_gate.py`**: `test_all_rules_present_reports_none_missing`; `test_a_missing_gate_rule_is_reported`;
`test_an_unparseable_settings_file_counts_every_rule_missing`; `test_claude_config_dir_is_honoured`.

**`test_guard.py`** (pure): `test_unknown_self_refuses_every_apply`;
`test_a_missing_gate_refuses_every_apply`; `test_an_unanswered_protected_list_refuses_tag_writes`;
`test_an_unanswered_protected_list_allows_disable_key_expiry`;
`test_disable_key_expiry_on_a_tagged_device_needs_no_confirm`;
`test_disable_key_expiry_on_a_user_device_needs_the_no_expiry_confirm`;
`test_disable_key_expiry_is_allowed_on_protected_devices_and_self`; `test_already_disabled_is_a_noop`;
`test_an_expired_key_warns_but_is_not_refused`; `test_shared_in_devices_are_refused`;
`test_a_retag_needs_the_retag_confirm`; `test_first_tag_on_a_user_device_needs_the_strip_owner_confirm`;
`test_the_confirm_must_match_exactly`; `test_a_confirm_for_a_renamed_device_is_refused`;
`test_every_tag_change_on_a_protected_device_is_refused`;
`test_every_tag_change_on_self_is_refused_even_when_unlisted`;
`test_the_new_set_is_computed_from_the_fresh_pre_read`; `test_an_empty_resulting_set_is_refused`;
`test_removing_an_absent_tag_is_refused`; `test_a_tag_missing_from_tag_owners_is_refused`;
`test_the_client_may_assign_its_exact_tag_set`; `test_the_client_may_assign_tags_its_tag_owns`;
`test_a_set_the_client_cannot_assign_is_refused`; `test_unrecorded_client_tags_refuse_tag_writes`;
`test_tags_are_lowercased`; `test_an_unchanged_set_is_a_noop`;
`test_rule_references_list_every_policy_path_naming_the_tags`;
`test_strip_owner_consequences_include_expiry_and_recovery`;
`test_multi_target_requires_every_target_tagged`; `test_a_refused_target_refuses_the_whole_batch`;
`test_the_apply_line_uses_the_node_id_and_the_printed_confirm`.

**`test_audit.py`**: `test_records_are_single_redacted_json_lines`;
`test_the_log_is_created_0600_and_opened_append_only`; `test_existing_lines_are_never_rewritten`;
`test_last_returns_the_newest_matching_event`; `test_no_record_contains_a_registered_secret`.

**`test_policy_logic.py`**: `test_empty_body_and_empty_object_are_pass`; `test_errors_in_a_200_are_fail`;
`test_warnings_only_is_pass_with_warnings`; `test_a_message_without_data_is_fail`;
`test_an_unknown_200_shape_is_fail`; `test_a_400_is_a_parse_failure_verdict`;
`test_want_got_is_parsed_per_address_and_unparsed_lines_are_kept`;
`test_an_array_shaped_file_is_refused_even_after_leading_comments`;
`test_the_etag_is_stored_raw_and_shown_with_one_quote_pair_stripped`;
`test_readiness_needs_the_validated_hash_and_an_unmoved_live_etag`;
`test_policy_test_refuses_wildcards_ip_sources_and_port_ranges`.

**`test_diagnose_logic.py`** (pure `verdict` and `ssh_candidate`; one test per verdict row):
`test_source_down_stops_everything`; `test_an_expired_key_is_reported_first`;
`test_an_offline_destination_stops_before_probes`; `test_shields_up_is_reported_before_probes`;
`test_tsmp_failure_is_a_path_problem_not_policy`; `test_an_open_port_on_plain_ssh_is_open`;
`test_check_only_admission_for_a_user_is_admitted_check_mode`;
`test_check_only_admission_for_a_tagged_source_is_flagged`; `test_ssh_denied_both_ways_is_ts_ssh_policy`;
`test_a_missing_ssh_user_is_unverified`; `test_a_validate_drop_is_a_policy_drop`;
`test_from_mode_with_policy_allow_is_allowed`; `test_a_reset_with_policy_allow_is_refused_by_host`;
`test_a_timeout_with_allow_on_openssh_is_host_side`;
`test_a_timeout_with_allow_on_tailscale_ssh_is_unexplained`;
`test_unknown_ssh_enabled_is_inconclusive_with_both_hypotheses`;
`test_icmp_success_is_never_port_evidence`; `test_sources_are_identities_never_ip_addresses`;
`test_the_ssh_candidate_strips_tests_and_ssh_tests_and_adds_a_host_alias`;
`test_the_alias_name_avoids_existing_hosts_keys`; `test_tcp_probe_distinguishes_open_refused_timeout`
(real loopback sockets: a listener for `open`; a closed port for `refused`; a listener whose
`listen(0)` backlog is already full for `timeout`, a real Linux behaviour; the test is marked
Linux-only).

**`test_doctor_logic.py`**: `test_settle_gated_steps_run_when_never_settled`;
`test_settle_gated_steps_reuse_answers_younger_than_30_days`;
`test_answers_older_than_30_days_are_re_measured`;
`test_questions_are_emitted_in_priority_order_with_safe_defaults`;
`test_the_protected_proposal_lists_every_device_and_the_self_line`;
`test_audit_events_caused_are_counted`.

**`test_cli_args.py`**: `test_abbreviated_flags_are_usage_errors` (`--appl`, `--confi`, `--rea`);
`test_apply_has_no_value_form`; `test_apply_requires_reason`; `test_the_reason_placeholder_is_refused`;
`test_apply_exists_only_on_the_two_write_commands`; `test_device_tag_takes_exactly_one_device`;
`test_no_flag_accepts_a_secret_a_base_url_a_tailnet_or_force`;
`test_json_is_accepted_before_and_after_the_subcommand`;
`test_the_command_set_is_exactly_the_designed_fourteen`;
`test_every_exit_code_in_the_table_is_reachable`.

**`test_settings_merge.py`**: `test_a_missing_settings_file_is_created_with_only_our_rules`;
`test_existing_rules_and_keys_are_kept_in_order`; `test_a_second_merge_adds_nothing_and_makes_no_backup`;
`test_invalid_json_aborts_without_writing`; `test_a_non_object_permissions_value_aborts_without_writing`;
`test_a_backup_precedes_any_change`; `test_remove_takes_out_only_recorded_rules`;
`test_remove_leaves_an_entry_mc_edited`; `test_claude_config_dir_settings_paths_are_written_absolute`;
`test_a_conflicting_deny_and_a_bypass_default_produce_warnings`.

**`test_installer.py`** (temp `HOME` and `CLAUDE_CONFIG_DIR`; a local fixture git repo stands in for
upstream): `test_install_into_an_empty_home_creates_every_artifact_with_its_mode`;
`test_a_second_install_changes_nothing`; `test_dry_run_writes_nothing` (snapshot);
`test_the_launcher_runs_python_isolated_and_has_aboutme_lines`;
`test_upstream_verify_refuses_a_head_that_is_not_the_pin`;
`test_upstream_verify_accepts_the_pinned_head` (the fixture repo's own HEAD as the pin);
`test_a_foreign_tailscale_skill_is_left_alone`; `test_a_foreign_tailnet_skill_stops_the_step`;
`test_uninstall_never_touches_credentials_protected_audit_or_drafts`;
`test_the_mcp_add_command_is_composed_exactly`.

**`test_skill.py`** (J2 graft from AE §15.1): `test_skill_name_is_tailnet_and_matches_its_directory`;
`test_description_is_at_most_1024_characters`; `test_frontmatter_uses_only_portable_keys`;
`test_skill_md_is_under_250_lines`; `test_hard_rules_sit_within_the_first_5000_tokens` (chars / 4);
`test_every_tailnet_command_named_in_the_skill_exists_in_the_parser`;
`test_allowed_tools_name_only_read_commands`; `test_ask_and_deny_strings_in_the_skill_match_rules_json`;
`test_every_reference_exists_one_level_deep`; `test_reference_files_over_100_lines_start_with_contents`;
`test_upstream_corrections_flags_api_md_100_103`.

**`tests/test_pre_commit.py`** (existing; add): `test_a_staged_oauth_client_secret_is_refused`;
`test_a_staged_api_token_is_refused`; `test_a_prefix_without_a_key_is_allowed`;
`test_runtime_built_fixture_secrets_are_not_staged_literals`.

### 21.3 Integration tests (`tests/integration/`; the real CLI process against loopback)

| File | Tests |
|---|---|
| `test_reads.py` | `test_device_list_prints_every_device_and_n_of_n`; `test_device_list_json_is_one_envelope_with_measured_at_and_request_ids`; `test_device_list_warns_about_tagged_devices_with_expiry_on`; `test_reads_never_send_the_write_secret` (a sentinel in `write.secret`; the recorder asserts no request carries it); `test_one_mint_serves_two_processes`; `test_a_401_on_a_cached_token_remints_once_and_retries_once`; `test_a_second_401_exits_3_without_looping`; `test_a_429_on_a_read_waits_and_retries_once`; `test_a_3xx_is_never_followed`; `test_dns_combines_the_four_endpoints_and_tolerates_a_configuration_refusal`; `test_no_secret_or_token_reaches_stdout_stderr_audit_or_any_file_outside_config` (a battery of passing and failing commands; scans stdout, stderr and every file under `TAILNET_HOME` except `config/`); `test_a_tskey_secret_in_test_posture_sends_zero_requests`; `test_an_unsafe_override_exits_3_and_contacts_nothing`; `test_test_posture_never_runs_tailscale` (netguard would crash the process); `test_status_brief_always_exits_0_and_reports_missing_gate_rules` |
| `test_writes.py` | `test_a_dry_run_sends_no_write_and_mints_no_write_token`; `test_a_dry_run_works_without_a_write_client`; `test_apply_without_a_write_client_is_refused_before_any_write_request`; `test_apply_without_the_gate_rule_is_refused`; `test_an_unanswered_protected_list_refuses_tag_applies_and_dry_runs_warn`; `test_disable_key_expiry_apply_posts_true_once_and_rereads`; `test_multi_target_disable_applies_in_order_and_stops_at_the_first_failure`; `test_a_refused_target_sends_nothing_for_any_target`; `test_tag_apply_posts_the_full_new_set_once_and_rereads`; `test_a_concurrent_console_change_is_kept_by_the_delta`; `test_a_confirm_from_before_a_rename_is_refused`; `test_strip_owner_without_confirm_exits_5_and_sends_nothing`; `test_a_write_to_self_exits_5`; `test_a_tag_change_on_a_protected_device_exits_5`; `test_a_504_with_the_change_visible_is_applied`; `test_a_504_with_the_change_absent_exits_6`; `test_a_2xx_whose_reread_differs_exits_6`; `test_a_400_on_a_tag_write_exits_7_and_explains_the_client_tag_rule`; `test_a_429_on_a_write_is_sent_exactly_once`; `test_the_write_token_never_touches_disk_and_comes_from_the_write_client`; `test_a_held_apply_lock_refuses_a_second_apply`; `test_an_unwritable_audit_log_stops_the_write`; `test_every_attempt_leaves_one_audit_line_with_the_decided_outcome`; `test_the_reason_is_recorded_in_the_audit_line` |
| `test_policy_cli.py` | `test_policy_get_prints_hujson_byte_for_byte_and_the_raw_etag_on_stderr`; `test_draft_files_are_byte_identical_to_the_served_policy`; `test_validate_posts_candidate_bytes_as_hujson_and_records_the_verdict`; `test_validate_failure_exits_8_with_want_got`; `test_validate_warnings_exit_0_and_are_printed`; `test_validate_refuses_an_array_file_without_any_request`; `test_diff_is_ready_only_after_validate_and_with_an_unmoved_live_policy`; `test_diff_reports_a_moved_etag_as_not_ready`; `test_policy_test_posts_one_array_against_live_and_exits_8_on_a_drop` |
| `test_diagnose_cli.py` | `test_from_mode_runs_api_checks_only_and_reports_allowed`; `test_from_mode_reports_a_policy_drop`; `test_a_tailscale_ssh_destination_posts_an_ssh_candidate_with_a_host_alias`; `test_a_failed_accept_probe_is_followed_by_a_check_probe`; `test_a_plain_ssh_destination_uses_array_mode_only`; `test_self_mode_in_test_posture_probes_tcp_for_real_and_records_pings_not_run`; `test_every_validate_request_uses_identities_as_src`; `test_the_on_host_block_is_emitted_for_host_side_verdicts` |
| `test_doctor_cli.py` | `test_doctor_reports_every_check_with_a_time`; `test_doctor_reuses_the_cached_token_and_mints_nothing_new`; `test_doctor_never_sends_a_write_request` (recorder: only GET, `POST /oauth/token`, `POST /acl/validate`); `test_doctor_never_opens_the_write_secret` (sentinel); `test_doctor_settles_once_then_reuses_answers`; `test_doctor_emits_questions_in_priority_order`; `test_doctor_reports_mints_and_audit_events_caused`; `test_doctor_without_a_read_credential_exits_3_with_console_steps` |
| `test_credentials_cli.py` | `test_set_refuses_without_a_terminal`; `test_set_read_over_a_pty_writes_0600_files_and_mints_once` (`pty.fork`, so `getpass` reads a real terminal); `test_set_write_over_a_pty_records_tags_from_the_self_lookup`; `test_set_write_falls_back_to_typed_tags`; `test_forget_write_disarms_without_a_prompt` |

### 21.4 End-to-end (`tests/e2e/`; the real API, read-only, on the droplet)

- `tests/e2e/conftest.py`, a session fixture that **fails loudly, never skips**
  (`pytest.exit(…, returncode=3)` naming the missing piece) when: `TAILNET_API_BASE` or
  `TAILNET_HOME` is set; `~/.config/tailnet/read.json` is absent or fails §8.2 ("run `tailnet
  credentials set read` over SSH"); `tailscale` is missing or not `Running`.
- `tests/e2e/run_live.py` runs the repo CLI in production posture and **raises if `--apply` appears
  in its arguments**, so the suite is read-only by construction (MIN §15.1, J1 graft). No test
  performs a write.
- Every test records `measured_at` and request IDs into the pytest report.

| # | Test | Proves or settles |
|---|---|---|
| E1 | `test_doctor_completes_against_the_real_api` (`--settle --json`; every check has `measured_at`; exit 0 or 8; never 1, 3, 4) | critic §6 steps 1-8 |
| E2 | `test_this_droplet_is_self_by_tailscale_ip` (records `id_agrees`) | §11.3; whether `nodeId == Self.ID` |
| E3 | `test_device_list_counts_every_device_and_names_self` | inventory |
| E4 | `test_the_read_token_is_reused_across_invocations` (exactly one new `token.mint` line across three reads) | §9; critic F6 |
| E5 | `test_policy_get_hujson_and_json_return_raw_etags` | critic R3 |
| E6 | `test_the_live_policy_validates_as_hujson` | critic R1 against reality |
| E7 | `test_the_live_policy_validates_as_json` | the §15 step 6 candidate premise |
| E8 | `test_a_fresh_draft_of_the_live_policy_is_ready_after_validate` | §14 round trip |
| E9 | `test_tailscale_ping_tsmp_exit_codes_on_pong_and_timeout` (a connected peer; then an address in `100.64.0.0/10` assigned to no listed device) | §15 step 4 |
| E10 | `test_diagnose_returns_a_known_verdict_for_every_tagged_device` (asserts the verdict is in the enum, not which) | §15 against reality |
| E11 | `test_diagnose_from_a_user_owned_device_runs_api_checks_only` | `--from` |
| E12 | `test_a_dry_run_tag_change_on_self_is_refused_without_sending` (exit 5; leaves one `refused` audit line, the evidence the guard ran on live state) | guard on real data |
| E13 | `test_a_dry_run_disable_key_expiry_plans_without_sending` | §12.6 |
| E14 | `test_the_live_openapi_matches_the_pinned_sha256` | spec drift [api §12.19] |
| E15 | `test_dns_reads_succeed` | critic Q23 partly |
| E16 | `test_the_cached_token_is_0600_and_read_only` | §9 |
| E17 | `test_install_into_a_temporary_home_pins_upstream_and_registers_mcp` (temp `HOME` and `CLAUDE_CONFIG_DIR`; real GitHub; real `claude mcp add`; then uninstall) | §20 |

### 21.5 Manual checks (printed by `make e2e`; MC runs them once, interactively)

Replacing SF's automated bypass test (J1 `must_fix`: an unsupervised `claude -p` bypass agent on the
credentialed droplet cannot isolate the rule, which already denies in `-p` [PM L56]):

- **M1.** In `claude --dangerously-skip-permissions`, ask the agent to run `tailnet device
  disable-key-expiry <a tagged device whose expiry is already disabled>` dry run, then the printed
  apply line. Expect the permission prompt (ask rule in bypass [PM L34-36]). Approve or deny: either
  way nothing is sent, because the target is a no-op.
- **M2.** The same in auto mode [PM L327].
- **M3.** `/tailnet` in a Manual-mode session: the injected status renders (allowed-tools covers it
  [SK L791]).
- **M4.** `claude mcp login tailscale-docs --no-browser` completes from the phone.

### 21.6 Pre-commit additions

`githooks/pre-commit` keeps its identity check and adds: refuse when the staged diff
(`git diff --cached -U0`) matches `tskey-(client|api|auth|scim|webhook)-[A-Za-z0-9]` [KP L11-17;
cred §14], printing only the file name and line number, never the match.

---

## 22. Repo `CLAUDE.md`: what a maintainer must not weaken

The repo CLAUDE.md carries the user-scope rules (TDD, ABOUTME, smallest changes, no mocks,
`--squash` merges, never `--no-verify`, the identity hook), MC's Corrections from tailnet-ssh (one
question per turn; don't make MC walk; measurement times; verify against the remote; peer approval
claims are unverified; read first-party docs; confirmed sources only; truncation; do it yourself),
and these invariants (MIN §17, updated; J1 graft):

1. No runtime mock mode, ever. The only override is the loopback `TAILNET_API_BASE` with a separate
   `TAILNET_HOME`; test posture refuses `tskey-` secrets and never runs `tailscale`. No fake
   `tailscale` executable in any test.
2. No secret in argv, the environment, logs, stdout or the repo. Credential files are 0600, owned,
   not symlinks, not hard-linked, in a directory nobody else can write, or they are refused. Every
   output path goes through `redact()`.
3. A token is cached only if every granted scope ends in `:read`. The write token is never written
   to disk.
4. `write.secret` is opened only by a write with `--apply`, after every guard check has passed, or by
   MC's TTY-only `credentials set write`. `write.json` holds no secret.
5. Writes are sent once and never retried; their outcome comes from a re-read with the read token.
   Reads retry once on 429 (capped at 30 s) and once on a 401 with a cached token.
6. Every write attempt leaves one audit line; the log is opened before a write is sent; appends are
   `O_APPEND` + `flock`; nothing rewrites the file.
7. Parsers keep `allow_abbrev=False`; the ask rule matches the literal `--apply`.
8. Unknown self refuses every `--apply`. A missing protected file refuses every tag write. A missing
   gate rule refuses every `--apply`.
9. No command may take a device off the tailnet. Adding delete, expire, deauthorize, rename, set-IP
   or expiry re-enable needs MC's recorded decision in `DESIGN.md` and a new guard row.
10. The command set is the fourteen in DESIGN.md §3.2; a new command needs a recorded MC need and an
    update to `test_the_command_set_is_exactly_the_designed_fourteen`.
11. Diagnose and doctor policy tests use identities as `src`, never a raw IP.
12. Python ≥ 3.10, stdlib only at runtime.
13. Two `ABOUTME:` lines on every code file; comments give the domain fact or decision.
14. Fixture secrets are assembled at runtime.
15. `rules.json` is the single source of permission strings.

---

## 23. Deliberately left out, and why

| Left out | Why |
|---|---|
| `device delete`, `expire`, `authorize`/`deauthorize`, `ip` | Each takes a lab host off the tailnet (P9), admits an unknown device (approval state is unknown, critic Q13), or breaks `from=` pins and pf anchors (P11, critic Q17). The console does them in two taps with MC's eyes on it; drift becomes a written proposal, never an action (P18) |
| Key-expiry re-enable | F5: it can disconnect a device at once [spec 606-607]. The CLI cannot even form the request |
| `device rename` | D8: one past need (P4), breaks MagicDNS/Serve URLs [spec 504], verify rule unverified. Add only on MC's recorded request |
| `device show` | D18: `device list --json` has every field |
| Bulk or filter-driven writes | Upstream's `lastSeen` bulk-delete is the anti-pattern [up §8.3]; only an explicit list, and only for R1 |
| `--force`, any guard override | A refusal is final for the CLI; an override would be an agent's first move after a refusal |
| `--expect` fingerprints | D10 |
| `--strip-owner` flag | D12 |
| `doctor --check-write` | D5 |
| `policy preview` command | D17; flow documented §14.5 |
| `policy set` / any `policy_file` write | Decided: MC applies in the console |
| A HuJSON parser or formatter | Decided; the server parses; `json.dumps` would strip MC's comments [pol (f)] |
| PreToolUse write-gate hook | D2 |
| Hash-chained log, write budget, arming TTL, install-manifest hash gate, `FS_IOC_GETFLAGS` probe, versioned lib dirs with rollback | D13 (J2): accident-level gain for real maintenance cost |
| A separate settled-facts store with a TTL | D3: answers live in `doctor.run` audit lines |
| AskUserQuestion payloads in CLI output | D4: generic `questions[]` instead |
| `--tailnet`, `--timeout`, `--version` flags; XDG overrides | D24; one tailnet; fixed paths keep the deny rules aimed at the real location |
| `TAILNET_TAILSCALE_BIN` or any binary override | D23 |
| Allow rules (even opt-in) | D25 |
| Secrets from env or argv; a `file:` secret outside the config dir | §8.2 |
| Automatic write retries | Decided; a 504 may have landed [api §12.9] |
| Logging reads locally | Tailscale doesn't log reads either [AUDIT L404]; an append-only file has no rotation |
| Cross-checking against Tailscale's audit log | Needs `logs:configuration:read` (not in the set) [cred §0.4]; open question MC11 |
| Routes, posture writes, keys list, users, invites, webhooks, settings | Out of scope or refused for OAuth tokens [cred §2, §8; api §12.1-12.5] |
| `whoami` command | Q3 unverified; folded into doctor S3 and `credentials set write` |
| SSH from `diagnose` into hosts | The droplet cannot reach them, which is the problem; the on-host block is handed to MC; tailnet-ssh's fleet audit owns host checks |
| `tailscale debug netmap` automation | Hidden and unstable [pol (d) step 8] |
| `chattr +a` on the audit log | Needs root; Tailscale's log is the tamper-resistant record; README mentions it as optional MC hardening |
| Plugin or marketplace packaging; `npx skills` | Droplet is the only host [critic Q25]; plugin `bin/` on PATH is unverified [pkg §6.5]; `npx skills` sends telemetry and `rm -rf`s targets [pkg §9] |
| `${CLAUDE_SKILL_DIR}`, skill-scoped hooks | Unverified in `references/` and for relative paths [pkg §4] |
| Cloud or Cowork support; federated identity | Droplet only; no OIDC issuer |
| Claude Code sandbox `denyRead` on secrets | It would also block the CLI, a Bash child **[inference]**; a per-command exclusion is **[unverified]** |

---

## 24. Unverified items the design tolerates

| Item | How the design is safe without the answer |
|---|---|
| Q1 narrowing a write-capable client's token | Classify the granted scope; never cache anything write-capable; doctor S2 records it |
| Q2 token tags; Q8/Q9 the TAGS L324 rule and user-owned tagging on the API path | Assume the worst: client-side refusal for sets the client cannot assign; R3 strip-owner gating; protected and self refused |
| Q3 `keyId` for the self-lookup | Best-effort in doctor S3 and `credentials set write`, with typed tags as the fallback |
| Q4 status for a missing scope | Messages say "possibly"; doctor S5 records it |
| Q5 multi-scope string format | Split on whitespace and commas; unknown → not cached |
| Q12 route/SSH fields without the scope | Absent → `null` / `?` |
| Q20 `autogroup:member` and tagged sources | Doctor S7b; drafts use MC's email until settled |
| Q22 empty preview body | No preview command; the documented flow posts the live policy |
| Q23 `dns:read` and `/dns/configuration` | Best-effort; reported, never fails `dns` |
| `nodeId == Self.ID` | Recorded, never required (IP join) |
| `tailscale ping` exit codes on a timeout | e2e E9; diagnose treats an unknown result as `INCONCLUSIVE` |
| The live policy JSON as a validate body | e2e E7; if wrong, `TS_SSH_*` verdicts degrade to `INCONCLUSIVE`; the network verdict is unaffected |
| Whether a host firewall affects Tailscale SSH; the TS SSH banner; disabling expiry on an expired key | Reported as unknown; never relied on |
| A `tool.check` mod approving `--apply` | Named as an L3 failure; doctor L9 states it |
| `claude mcp login --no-browser` on a headless host | MC's one command; failure only loses docs search (curl `.md` fallback) |

---

## 25. README outline (for MC)

1. What this is, in three lines; where it runs (the droplet only).
2. **Three things you may not realise** (§19.2 item 3), each with its read-only command.
3. The levers table (§2) in plain words, and the two postures.
4. First-run sequence (§26), each step saying whose hands it needs.
5. What you will see in the Tailscale console audit log (one mint per hour of reads; doctor's one
   deliberate "Failed request" per 30 days; every write with the Client ID as actor).
6. Disarm, revoke, uninstall; optional `sudo chattr +a ~/.local/state/tailnet/audit.jsonl`.
7. Developer section: `make venv test e2e`, the test tiers, the invariants pointer.

---

## 26. MC's first session (the design in motion)

1. **MC (console):** answer MC1-MC4 (§28), then create the read client (and, if MC1 says so, the
   write client with its tag already in `tagOwners`), following `references/credentials.md`.
2. **Agent:** `./install-tailnet.sh --dry-run`, show MC the plan, then `./install-tailnet.sh`.
3. **MC, over SSH:** `tailnet credentials set read` (and `tailnet credentials set write`). Proves:
   the secret is on disk 0600 and mints.
4. **Agent:** `tailnet doctor`; report what it settled with times and the audit events it caused;
   ask its questions one per turn. MC runs the protected-file block doctor prints (MC5).
5. **Agent:** `tailnet diagnose spec5 nomad-b pi5 --ssh-user spec5` (the user applies only to the
   Tailscale SSH host) and `tailnet diagnose spec5 --from iphone192 --ssh-user spec5`; verdict per
   host, with the on-host block for anything host-side.
6. **Agent:** `policy draft` → edit → `policy validate` → `policy diff` → READY block to MC, with
   MC6 asked first if spec5's verdict needs an accept-mode rule.
7. **MC:** applies it in the console. **Agent:** `policy test` with the same assertions, then
   `diagnose` again.
8. If doctor showed key expiry on for the fleet hosts and MC7 says disable: **agent** dry-runs
   `tailnet device disable-key-expiry spec5 nomad-b pi5`, then runs the printed apply line; **MC**
   approves the one prompt. The agent offers `tailnet credentials forget write` once (MC8).

---

## 27. Judge items: where each is answered

**J1 `must_graft`**

| Item | Where |
|---|---|
| Ask rules prompt in every interactive mode incl. bypass; `-p` denies | §0 item 3, §2 L3, §19.2 rules, §21.5 |
| Override only with `TAILNET_HOME` outside the real dirs, plus the `tskey-` refusal | §7.1, §7.2 |
| Self joined on Tailscale IPs, `BackendState`/`Self.Online`; `id_agrees` recorded by doctor and e2e | §11.3, §16.2 S4, §21.4 E2 |
| Key-expiry disable permitted while the protected list is unanswered | §11.4, §12.3, D7 |
| `diagnose --from`; check-mode probe; host alias; live tests stripped | §15.1, §15.2 step 6 |
| 30-day re-measure; audit-event accounting; spec sha and `ls-remote` checks; questions one per turn | §16.1 L11, §16.3, §16.4 (D3, D4, D19) |
| `--reason`; `next[]` with `who`/`needs`; ask on `WebFetch(domain:api.tailscale.com)`; login-URL redaction; `flock` on every append; `sys.addaudithook`; dns local checks | §5.1, §5.4, §20.4, §10.4, §13.1, §21.1, §18. The `--check-write` ask rule is replaced by D5 |
| Missing scope, legacy `devices`, `all` = write power | §9.2 |
| Needs trace, command-set tripwire, maintainer invariants | §3.2, §21.2 `test_cli_args.py`, §22 |
| e2e runner refuses `--apply`; validate refuses an array-shaped file | §21.4, §5.2 |

**J1 `must_fix`**

| Item | Where |
|---|---|
| Drop the bypass premise; re-decide the hook; rewrite the SKILL.md rule | D2, §2 L3, §19.2 rules |
| Lever failures: settings tampering in bypass; `tool.check` mods | §2 L3 (b)(c), D21, §16.1 L8-L9, §20.4 |
| Remove dead `Write(...)` rules | §20.4 |
| No raw 100.x as a validate `src` | §5.2, §15.2 step 2, §16.2 S7a/S7b |
| Remove the bypass `claude -p` e2e; add a manual interactive check | §21.5 M1-M2 |
| Correct the L2 timing claim | D13, §2 L2 |
| `flock` every audit append | §13.1 |
| Don't require `nodeId == Self.ID` | §11.3 |
| Surface F1/F2 re-consent before the write client exists | §16.4 questions 1-2, §28 MC1-MC2, §19.3 `credentials.md` |
| Don't carry MIN's fail-open self, real-secret override, "server enforces TAGS L324", `failed` for an unverified 5xx | §11.3, §7.2, §12.4, §12.6 (exit 6) |
| Don't carry AE's delete / enable / rename, protected rename or tag removal, agent-writable list, `tailscale` fake | §12.3, §11.4, §21.1 |

**J2 `must_graft`**

| Item | Where |
|---|---|
| Corrected lever facts with citations | §2 |
| `--apply` requires `--reason` (1-200, redacted, in prompt and audit) | §5.1, §13.3 |
| Verb confirm tokens; the dry run prints the full apply line | §12.3, §12.6 step 4, §12.7 |
| Multi-target `disable-key-expiry`, all-or-nothing, in order, one audit line each | §12.5 |
| `diagnose --from` API-only | §15.1 |
| SSH probe: JSON policy, tests stripped, host alias, check probe | §15.2 step 6 |
| Override needs `TAILNET_HOME`; `tskey-` refused; TEST banner | §7 |
| `ProxyHandler({})`; refuse 3xx; `add_unredirected_header` | §10.1 |
| `sys.addaudithook` in the default suite | §21.1 |
| login.tailscale.com check-URL redaction | §10.4 |
| `test_skill.py` | §21.2 |
| Ask tripwires `Bash(*api.tailscale.com*)` and `WebFetch(...)`, labelled accident-only | §20.4, §2 |
| `token.mint` audit line; doctor counts the events it caused | §9.1, §16.4 |
| A disarm command any agent may run | §8.6 (D28) |
| Draft base/candidate/meta; diff readiness; validate records its verdict | §14.2-14.4 |
| Credential parent directory owned and not group/other-writable | §8.2 rule 6 |
| Docs MCP privacy rule | §19.2 item 8 |
| e2e: spec sha; live policy validates as HuJSON and JSON; ping exit codes | §21.4 E14, E6, E7, E9 |
| README and SKILL.md: D13 premise, phone cut off spec5, key expiry on retagged hosts | §19.2 item 3, §25 |
| Single-client read mints send the four read scopes; cache only if read-only | §8.3, §9.1, §9.2 |

**J2 `must_fix`**

| Item | Where |
|---|---|
| Rewrite the bypass claim; name the residual gaps | §2 L3 |
| No PreToolUse hook; no `Write(path)` rules | D2, §20.4 |
| Self fails closed; no fake `tailscale`; `self` line proposed by doctor, written by MC | §11.3, §11.4, D6, §21.1 |
| Distinct exit for sent-but-unconfirmed; audit `failed` + `confirmed:false`; skill says `device list --json` | §5.3, §12.6, D15, §19.2 rules |
| Loopback override never sends the real secret | §7.2 |
| Dry runs and no-ops exit 0; `outcome` separates them | §5.3, §5.4, D16 |
| Protected and self: refuse every tag change; agent never writes the list; Edit deny stays | §11.4, §12.3, §20.4 |
| Don't add delete, enable, `--tailnet`, versioned libs, AUQ payloads, TTL store, hash chain, budget/TTL, manifest gate | §23 (with D3 and D4 resolving the two J1 overlaps) |
| Identities as `src` in diagnose and doctor | §15.2 step 2, §16.2 |
| Document preview; flag upstream A3 | §14.5, §19.3 `upstream-corrections.md` |
| Pre-read and post-read use the read token; write secret only after the guard and only with `--apply`; doctor only stats it; the posture statement | §12.2, §12.6, D20, §16.1 L4, §2 postures |

---

## 28. Open questions only MC can answer

Each has the safe default the build uses until MC answers. The skill asks them one per turn, as an
AskUserQuestion with options (doctor's `questions[]` carries 1, 2, 5 and 7).

| # | Question | Why it matters | Safe default until answered |
|---|---|---|---|
| MC1 | **Re-consent to a write client**, knowing its real reach: Devices Core Write reaches every device; the client can apply its own tag to any device, permanently for user-owned ones (TC L145-147; TAGS L324, L72, L33). The 2026-10-25 answer "devices on tag:fleet only" rested on a false premise [critic F1] | Decides whether L2 ever has a secret behind it | **No write client.** Read-only mode; both write commands refuse with `WRITE_CREDENTIAL_MISSING`; MC disables key expiry in the console if needed |
| MC2 | **Confirm the read client's scope set**: `devices:core:read`, `policy_file:read`, `devices:posture_attributes:read` (required by `policy_file:read`, TC L94) and `dns:read` [critic F2] | No record shows MC approving the two read additions | The build assumes exactly these four; doctor reports the granted scope and question 2 fires if it differs |
| MC3 | **Two clients, or one with every scope?** [critic F4] | One client removes L2 and caching unless narrowing works (Q1) | Two-client; single-client is supported and flagged by `status`/`doctor` |
| MC4 | **Which tag the write client carries** [critic Q16]. `tag:fleet` lets it assign exactly `tag:fleet` to any device (narrowest assignable set, no policy edit, and a mis-stripped device lands in a tag that has rules). An inert tag with `tagOwners` delegation lets it assign the inert tag plus each delegated tag | Bounds what `device tag` can ever do (TAGS L324) | No write client (MC1). When created, the CLI refuses any tag set the recorded client tags cannot assign. Recommendation shown to MC: `tag:fleet`, and never delegate `tag:dev` to it |
| MC5 | **The protected list** [critic Q14] | Which devices the CLI may ever retag | File missing → every tag write refused; `disable-key-expiry` still allowed. Doctor's proposal protects every device |
| MC6 | **Allow `tag:dev` → spec5 Tailscale SSH in `accept` mode?** A tagged source cannot use check mode [tsssh L218], and P7 keeps check mode on spec5 for people | Whether the droplet can ever reach spec5 over Tailscale SSH | Drafts never include an accept-mode `tag:dev` → spec5 `ssh` rule; diagnose reports `TS_SSH_CHECK_FOR_TAGGED` or `TS_SSH_POLICY` and names this question |
| MC7 | **Disable key expiry on spec5, nomad-b and pi5 now?** Console tagging kept their user-era expiry [TAGS L84; critic F3.2] | They drop off the tailnet when it lapses (P9) | Leave it; `device list` and doctor flag `TAGGED_KEY_EXPIRY_ON` with days left on every run |
| MC8 | **Write posture**: standing (`write.json` stays; safe against accidents in every interactive mode) or session-scoped (`credentials forget write` after each write session; holds against a determined agent) | L2 strength vs MC re-typing the secret at a TTY | Standing; the skill offers `credentials forget write` once after a write session and never runs it unprompted |
| MC9 | **Is the droplet the only host?** [critic Q25] | Cloud/Cowork sessions have no secret and don't read `~/.claude/skills` | Droplet only; the skill's `compatibility` says so |
| MC10 | **Do you want a `device rename` command later?** (P4 was a console rename) | Breaks MagicDNS and Serve URLs [spec 504] | Not offered; adding it needs MC's recorded decision and a guard row (invariant 9) |
| MC11 | **Add `logs:configuration:read` to the read client?** It would let doctor cross-check the local log against Tailscale's [cred §0.4, §14] | Reads only; one more scope to approve | Not requested; README mentions it |
| MC12 | **Commit a redacted real `tailscale status --json` capture as a test fixture?** It names hosts and addresses (P13 kept policy drafts out of git) | Parser fixture realism | No; the synthetic fixture stays and e2e E2 checks the real output |

---

## 29. Implementation order (small test-first commits)

Each commit is red then green: write the named tests first, see them fail, implement the minimum,
see the suite pass pristine, commit (imperative subject; `wittyreference <mc8805@outlook.com>`;
merge with `--squash`). The existing identity hook stays armed (`git config core.hooksPath
githooks`).

1. **Scaffold the repo rules.** `pyproject.toml` (pytest config), `Makefile` (`venv`, `test`),
   `CLAUDE.md` (§22), `DESIGN.md` (this spec), `tests/unit/test_repo_rules.py::test_every_code_file_starts_with_two_aboutme_lines`.
2. **Secret scan in pre-commit.** `tests/test_pre_commit.py` new cases → `githooks/pre-commit`.
3. **netguard and loopback seam.** `tests/netguard.py`, `tests/loopback.py`, `tests/conftest.py`;
   `test_default_suite_never_leaves_loopback`.
4. **Pin the spec.** `spec/tailscale-openapi.yaml`, `spec/SHA256SUMS`;
   `test_pinned_spec_matches_sha256sums`.
5. **Redaction.** `test_redact.py` → `redact.py`.
6. **Errors and output envelope.** `test_cli_args.py::test_every_exit_code_in_the_table_is_reachable`
   (error mapping part) → `errors.py`, `output.py`.
7. **Posture and paths.** `test_posture.py` → `posture.py`.
8. **Secure files.** `test_secure_files.py` → `secure_files.py`.
9. **Audit log.** `test_audit.py` → `audit.py`.
10. **Credentials loading and modes.** `test_credentials.py` → `credentials.py` (load, meta, modes,
    forget; `set_interactive` stubbed to raise until commit 26).
11. **HTTP transport.** `test_http.py` → `http.py`.
12. **Tokens and cache.** `test_tokens.py` → `tokens.py`.
13. **API read surface and the write-surface tripwire.** `test_repo_rules.py` `ast` tests →
    `api.py` (reads, plus the two write functions).
14. **CLI skeleton.** `test_cli_args.py` (abbreviations, `--json` placement, `--reason`, the
    fourteen-command tripwire) → `cli.py`, `__main__.py`, `tests/run_cli.py`.
15. **Devices and `device list`.** `test_devices.py`; integration `test_reads.py` (list, envelope,
    expiry warning, one mint across two processes, 401/429/3xx, secret sweep, tskey refusal, unsafe
    override) → `devices.py`, the `device list` command.
16. **Self, protected, gate.** `test_selfnode.py`, `test_protected.py`, `test_gate.py` →
    `localts.py`, `selfnode.py`, `protected.py`, `gate.py`, `rules.json`.
17. **Guard (pure).** `test_guard.py` → `guard.py`.
18. **Write flow: disable-key-expiry.** Integration `test_writes.py` (dry run, no write client, gate
    missing, unanswered list, apply/re-read, multi-target, 504 cases, 2xx mismatch, 429 once, lock,
    audit unwritable, audit lines, reason) → `writes.py`, the `disable-key-expiry` command.
19. **Write flow: device tag.** The tag cases of `test_writes.py` (delta, stale confirm, strip-owner,
    self, protected, 400 explanation) → the `device tag` command.
20. **Policy verdicts.** `test_policy_logic.py` → `policy.parse_verdict`, `parse_want_got`, the
    array-body scanner, readiness.
21. **Policy commands.** Integration `test_policy_cli.py` → `policy get|draft|validate|diff|test`.
22. **DNS.** `test_reads.py::test_dns_…` → `dns` command (local checks guarded by posture).
23. **Diagnose logic.** `test_diagnose_logic.py` → `diagnose.verdict`, `ssh_candidate`,
    `tcp_probe`.
24. **Diagnose command.** Integration `test_diagnose_cli.py` → `diagnose.run`, `--from`, the on-host
    block.
25. **Doctor.** `test_doctor_logic.py`; integration `test_doctor_cli.py` → `doctor.py` (local
    checks, S1-S8, settling from `doctor.run` lines, questions, accounting).
26. **Credentials set over a TTY.** Integration `test_credentials_cli.py` → `credentials.set_interactive`,
    `credentials set|forget` commands.
27. **Status.** `test_reads.py::test_status_brief_…` → `status.py`.
28. **Settings merge.** `test_settings_merge.py` → `installer/settings_merge.py`.
29. **Installer.** `test_installer.py` → `installer/upstream.py`, `installer/install.py`,
    `install-tailnet.sh` (launcher, copies, markers, MCP step, dry run, uninstall).
30. **Skill.** `test_skill.py` → `skill/tailnet/SKILL.md`.
31. **References.** The reference tests in `test_skill.py` → the six `references/*.md` files, built
    from the research files with sources and dates.
32. **e2e suite.** `tests/e2e/conftest.py` (fails loudly), `run_live.py` (refuses `--apply`),
    E1-E17; `make e2e`, which also prints the manual checks M1-M4.
33. **README** (§25) and a final pass over `DESIGN.md`'s change log. Then MC runs, on the droplet:
    `./install-tailnet.sh`, `tailnet credentials set read`, `tailnet doctor`, `make e2e`, and the
    manual checks.
