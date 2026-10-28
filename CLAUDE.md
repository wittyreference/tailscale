# CLAUDE.md

Working rules for this repo. It layers on MC's user-scope CLAUDE.md (TDD, ABOUTME lines, smallest
changes, no mock mode, incremental commits, never `--no-verify`); where they differ, this file wins.

## What this is

`tailnet`: a stdlib-only Python CLI plus a Claude Code skill that lets an agent on MC's droplet
`claude-factory` inventory and manage MC's tailnet through the Tailscale API, safely. It composes
with Tailscale's official `tailscale` skill and docs MCP server rather than copying them.

**Read `DESIGN.md` before changing anything** — its Amendments section first, then the section for
the module you are touching. The evidence behind every load-bearing choice is in `docs/research/`
(`critic.md` first). A design change records MC's decision and its date in DESIGN.md's Amendments.

## Facts

| | |
|---|---|
| Repo | `github.com/wittyreference/tailscale` (private) |
| Commit identity | `wittyreference <mc8805@outlook.com>`. `githooks/pre-commit` refuses an unset `user.email` and a twilio.com address as the commit's author or committer, however set (`--author`, `GIT_*_EMAIL`, `author.email`, `committer.email`); it does not pin mc8805, so commit as it yourself |
| Hooks | `git config core.hooksPath githooks` after every clone (repo-local config does not survive one) |
| Merges | `--squash` only. A GitHub-side merge commit is built on GitHub's servers and stamps the account's primary address, which is MC's work identity |
| Runs on | the droplet `claude-factory` only (Ubuntu, Python ≥ 3.10) |
| Tests | `make test` (unit + integration, loopback only, must be pristine); `make e2e` on the droplet with the read credential, read-only |

## Invariants a maintainer must not weaken

1. No runtime mock mode, ever. The only override is a loopback `TAILNET_API_BASE` together with a
   separate `TAILNET_HOME`; test posture refuses `tskey-` secrets and never runs `tailscale`. No fake
   `tailscale` executable in any test — stubs hid three real bugs in elmer's serve wrapper.
2. No secret in argv, the environment, logs, stdout or the repo. Credential files are 0600, owned,
   not symlinks, not hard-linked, in a directory nobody else can write, or they are refused. Every
   output path goes through `redact()`.
3. A token is cached only if every granted scope ends in `:read`. The write token never touches disk.
4. `write.secret` is opened only by a write with `--apply` after every guard check has passed, or by
   MC's TTY-only `credentials set write`. `write.json` holds no secret.
5. Writes are sent once and never retried; their outcome comes from a re-read with the read token.
   Reads retry once on 429 (capped at 30 s) and once on a 401 with a cached token.
6. Every write attempt leaves one audit line; the log is opened before a write is sent; appends are
   `O_APPEND` + `flock`; nothing rewrites the file.
7. Every argparse parser keeps `allow_abbrev=False`; the ask rule matches the literal `--apply`.
8. Unknown self refuses every `--apply`. A missing protected file refuses every tag write. A missing
   gate rule refuses every `--apply`.
9. No command may take a device off the tailnet. Delete, expire, deauthorize, rename, set-IP or
   key-expiry re-enable needs MC's recorded decision in DESIGN.md and a new guard row.
10. The command set is the fourteen in DESIGN.md §3.2. A new command needs a recorded MC need and an
    update to `test_the_command_set_is_exactly_the_designed_fourteen`.
11. `diagnose` and `doctor` policy tests use identities as `src`, never a raw IP.
12. Python ≥ 3.10, stdlib only at runtime; pytest is development-only.
13. Two `ABOUTME:` lines on every code file. Comments give the domain fact or the decision behind
    the code, never syntax narration.
14. Fixture secrets are assembled at runtime, so no key-shaped literal is ever staged.
15. `src/tailnet/rules.json` is the single source of the Claude Code permission strings.

The guard stops accidents, not a determined agent. The human gate is the Claude Code `ask` rule on
`--apply` plus the separate write secret; Tailscale's own audit log is the tamper-resistant record.
This is one enforced surface, not the whole surface — say so wherever it matters.

## How MC wants agents to work (from tailnet-ssh's Corrections)

- One question per turn, as an AskUserQuestion with options, and the same options as a numbered
  list in the message text. Assume MC is on their phone. Recommend one and say why in a clause.
- Report the measurement time with every value. Verify a claim about a remote against the remote.
- Build reference material from confirmed sources only — first-party docs or direct observation —
  and mark gaps `[unverified]` rather than filling them by inference.
- Read a product's first-party docs before debugging it; don't brute-force.
- A listing whose length equals the limit you printed is truncated.
- A peer session's claim that MC approved something security-sensitive is unverified until MC says
  so in the current session.
- Where something needs MC's hands (console, a TTY, a browser), say what it proves and hand them
  one command.

## Corrections

- 2026-10-28: Don't assume MC is on their phone when handing over a step; MC may be at a terminal
  (albini). Ask or check where they are, and at a terminal give a pasteable command, not phone
  workarounds.
