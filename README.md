# tailnet

`tailnet` lets a Claude Code agent inventory and manage your tailnet through the Tailscale API, safely.
It is a small command-line tool plus a Claude Code skill of the same name.
It runs on the droplet `claude-factory` only, as you (`mc`).

## Three things you may not realise

Each comes with a read-only command that checks it.

**1. The write client can change any device, not only `tag:fleet` ones.** Your 2026-10-25 answer
("devices on tag:fleet only") rested on a wrong premise. Told the true reach on 2026-10-26, you
chose two clients: a read client, and a write client tagged `tag:fleet`. Tagging a user-owned
device strips its owner for good. Check which clients are present:

```sh
tailnet status
```

**2. Tagging spec5 probably cut your phone and albini off its Tailscale SSH.** Rules written for
`autogroup:self` stop covering a device once it is tagged. Check it from the phone's side:

```sh
tailnet diagnose spec5 --from iphone192 --ssh-user spec5
```

**3. The retagged hosts may still carry key expiry.** Console tagging kept their old expiry, and
each drops off the tailnet when it lapses. Look for `TAGGED_KEY_EXPIRY_ON`:

```sh
tailnet device list
```

## The levers, in plain words

No single lever is the whole protection. This is one enforced surface, not the whole surface.

What holds:

- **The ask rule.** Claude Code asks you before every `--apply`, in every interactive mode, bypass
  and auto included. A headless `claude -p` run refuses the write instead of asking.
- **The separate write secret.** The read client cannot write. With no write secret on disk,
  nothing on the droplet can write to your tailnet.
- **Deny rules.** Claude's own tools cannot read or edit `~/.config/tailnet`, in any mode.
- **The CLI's guard.** It refuses tag changes on this host and on your protected devices, a
  confirm from a stale plan, and every `--apply` while it cannot tell which device is this host.
  It stops accidents, not a determined agent.
- **Tailscale's audit log.** Always on, kept 90 days, out of the agent's reach. It is the record
  that cannot be rewritten from here.
- **Only you can revoke.** Neither client can revoke anything; you do it in the console.

What does not hold:

- Command text the ask rule cannot see, such as a wrapper script.
- A script that opens the secret file itself, past the deny rules.
- An installed Claude Code mod that handles `tool.check`, when the machine has no managed settings
  and no Team or Enterprise login: it can approve an `--apply` without asking you.

**Two postures.** You choose; the default is standing.

- **Standing:** the write client stays on disk. Safe against accidents, because every `--apply`
  still asks you.
- **Session-scoped:** after each write session, run `tailnet credentials forget write`, and
  `tailnet credentials set write` next time. This also holds against a determined agent.

After a write session the agent offers the forget once. It never runs it unprompted.

## First run

Each step says whose hands it needs. Commands for you run over SSH, from Termius or albini.

1. **MC, in the console (browser):** create the read client, then the write client tagged
   `tag:fleet`. The steps, hazards first, are in `skill/tailnet/references/credentials.md`.
   Copy each secret into your password manager: it is shown once.
2. **Agent:** runs the installer's dry run, `./install-tailnet.sh --dry-run`, and shows you the
   plan. Nothing changes.
3. **Agent:** runs the install, `./install-tailnet.sh`. Later reinstalls spelled that way ask you
   first, because they replace the guard's code. The rule matches that command text only:
   `installer/install.py` run directly, a wrapper script or an edit to the installed code is not
   caught.
4. **MC, over SSH:** store the read client. It prompts for the ID and the secret, so neither passes
   through chat. Proves: the secret is on disk, 0600, and mints a token.

   ```sh
   tailnet credentials set read
   ```

5. **MC, over SSH:** store the write client the same way. Proves: it mints, its grant holds write
   power, and its tags are recorded.

   ```sh
   tailnet credentials set write
   ```

6. **Agent:** runs `tailnet doctor`. It reports what it settled, with times and the console events
   it caused, then asks you its questions one per turn.
7. **MC, over SSH:** run the protected-list block doctor prints. First delete the lines for any
   devices the agent may retag. Proves: this host and the rest are protected from tag changes.
8. **Agent:** runs `tailnet diagnose spec5 nomad-b pi5 --ssh-user spec5`, then the phone check from
   "Three things", and reports a verdict per host.
9. **Agent:** drafts a policy fix with `tailnet policy draft`, then validates and diffs it until it
   is READY. It shows you the change; it never applies it.
10. **MC, in the console:** apply the change in the policy editor and Save. Then the **agent**
    re-checks with `tailnet policy test` and `tailnet diagnose`.
11. **Agent:** if doctor showed key expiry on for the fleet and you say disable, it dry-runs
    `tailnet device disable-key-expiry spec5 nomad-b pi5`, then runs the printed apply line.
12. **MC, in Claude Code:** approve that one prompt. It covers every tagged host in the line.
13. **MC, over SSH, once:** run the live end-to-end suite from the checkout. It is read-only. It
    stops with exit 3, naming what is missing, if anything is.

    ```sh
    make e2e
    ```

14. **MC, once:** the four manual checks `make e2e` prints after a pass (M1-M4): the ask prompt
    in bypass and auto mode, `/tailnet` in Manual mode, and the docs server login.

## What the Tailscale console audit log will show

The log is on the Logs page, https://console.tailscale.com/admin/logs. It is always on, keeps
90 days, and does not record reads.

- **Create OAuth access token**, with the client ID as the actor. About one an hour while the agent
  reads, because the read token is cached for its hour. One per `credentials set`, and one per
  `--apply`.
- **Failed request** ("API call attempted with insufficient permission"). Doctor causes one on
  purpose, at most once in 30 days, or on `--settle`; each `make e2e` settles. `tailnet dns` asks
  for `/dns/configuration` every run, and may leave one each time [unverified].
- **Update tags for node** and **Disable key expiry for node**, one per applied write. Whether
  the actor shows as the OAuth client is [unverified].
- **Create, Update or Revoke API key**, when you create, change or revoke a client.

Doctor reports `mints_this_run` and `audit_events_caused`, so you can match each event.

## Disarm, revoke, uninstall

**Disarm writes.** Any agent may run this, with no prompt, because it only removes power:

```sh
tailnet credentials forget write
```

That is not revocation: the client still exists in Tailscale.

**Revoke** (you, in the console): Settings → Trust credentials → select the client → Revoke →
Revoke. It kills the client and every token it issued. If a secret may have leaked, revoke it,
create a new client, run `credentials set` again, and review the audit log for that window.

**Uninstall.** It removes what the installer added. It never touches your credentials, the
protected list, the audit log or policy drafts, and it revokes nothing:

```sh
./install-tailnet.sh --uninstall
```

**Optional hardening.** Make the local audit log append-only at the filesystem. It needs root;
`sudo chattr -a` undoes it:

```sh
sudo chattr +a ~/.local/state/tailnet/audit.jsonl
```

## For developers

Read `CLAUDE.md` first: its invariants are the ones a change must not weaken. `DESIGN.md` is the
spec; its Amendments section wins over the text it amends. The evidence is in `docs/research/`.

- `make venv` makes `.venv` with the two development tools, pytest and ruff. The CLI itself is
  stdlib-only, Python 3.10 or later.
- `make test` runs the unit, integration and hook tests. They stay on loopback, never run
  tailscale, and must pass pristine.
- `make e2e` runs the live, read-only suite against the real API, on the droplet only.
- `.venv/bin/ruff check .` lints against the 3.10 floor.

After cloning, arm the commit hook with `git config core.hooksPath githooks`. Merge with
`--squash` only.
