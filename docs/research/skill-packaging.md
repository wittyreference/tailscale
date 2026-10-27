# Skill packaging: how Claude Code skills are packaged and loaded

Reference notes for the `wittyreference/tailscale` repo: a stdlib-only Python CLI plus a Claude Code skill that drives it. Every claim below has a source tag. `[unverified]` marks a gap that no first-party source closed. Nothing in this file comes from memory or from guessing.

**Date conventions.** The Claude Code docs pages (`code.claude.com/docs/en/*.md`) have no "Last validated" line, and their `last-modified` header only gives the response time. They are cited as "fetched 2026-10-26". Tailscale pages give their own "Last validated" date. Source-code observations cite `file:line`.

Short source keys used throughout (full URLs are in [Sources](#sources)):

| Key | Source |
|---|---|
| CC-skills | code.claude.com/docs/en/skills.md |
| CC-plug-* | code.claude.com/docs/en/plugins/{overview,create,components,manifest-reference,marketplace-reference,create-marketplace,host-marketplace,install,loading,cli-reference}.md |
| CC-mcp, CC-mcpq | code.claude.com/docs/en/mcp.md, mcp-quickstart.md |
| CC-hooks, CC-cli | code.claude.com/docs/en/hooks.md, cli-reference.md |
| AS-spec, AS-home, AS-scripts | agentskills.io/specification.md, home.md, skill-creation/using-scripts.md |
| PL-bp | platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices.md |
| TS-skill, TS-ai | tailscale.com/docs/features/tailscale-skill.md (Last validated Jul 24, 2026), tailscale.com/docs/develop-with-ai.md (Last validated Jul 28, 2026) |
| VS-* | github.com/vercel-labs/skills README.md and docs/*.md (raw, main branch, fetched 2026-10-26) |
| VS-src | npm `skills@1.7.4` tarball, `package/dist/cli.mjs` |
| UP | upstream clone `tailscale/tailscale-skill` @ `4f05d353efc5` (2026-07-09) |

---

## 1. What a skill is

- A skill is a directory with a `SKILL.md` file in it: YAML frontmatter between `---` markers, then Markdown instructions. It may also hold `scripts/`, `references/`, `assets/` and any other files. [AS-spec "Directory structure"; AS-home]
- Claude Code skills follow the Agent Skills open standard and add Claude Code-only features: invocation control, subagent execution (`context: fork`) and dynamic context injection. [CC-skills intro]
- Claude Code has merged custom commands into skills. `.claude/commands/deploy.md` and `.claude/skills/deploy/SKILL.md` both create `/deploy`. [CC-skills intro note]
- Claude Code reads frontmatter only when the opening `---` is the file's **first line**. If the YAML fails to parse, the skill still loads, but with no fields set, so Claude can't match it by `description`. `--debug` shows the parse error. [CC-skills "Frontmatter reference", "Skill not triggering"]

## 2. Frontmatter fields

### 2.1 Claude Code (all optional; only `description` is recommended)

Claude Code ignores an unrecognised field name and reports no error, and field names must match exactly, hyphens included. Boolean fields accept `true/false/yes/no/on/off/1/0` in any case (v2.1.218+). [CC-skills "Frontmatter reference"]

| Field | Documented behaviour [CC-skills "Frontmatter reference" table] |
|---|---|
| `name` | Command name shown in the `/` menu. Defaults to the directory name. In a personal or project skill dir, both `name` and the directory name invoke the skill. |
| `description` | What the skill does and when to use it. If omitted, the first non-empty body line is used. The combined `description` + `when_to_use` is **truncated at 1,536 chars** in the skill listing (configurable with `skillListingMaxDescChars`). |
| `when_to_use` | Extra trigger context, appended to `description`, and counted in the 1,536 cap. |
| `argument-hint` | Hint shown in autocomplete, e.g. `[issue-number]`. |
| `arguments` | Named positional args for `$name` substitution. |
| `disable-model-invocation` | `true` means Claude can't load the skill on its own and its description is **not in context**. It also blocks subagent preloading and scheduled-task firing. Default `false`. If Claude tries anyway, Claude Code blocks the call. |
| `user-invocable` | `false` hides the skill from the `/` menu, and typing `/name` won't run it. Claude can still invoke it. Default `true`. |
| `allowed-tools` | Tools Claude may use **without asking during the turn that invokes the skill**. The grant clears at the next user message. It **does not restrict** which tools are available. Accepts a space- or comma-separated string, or a YAML list. |
| `disallowed-tools` | Removes tools while the skill is active. Clears at the next user message. |
| `model` | Model override for the rest of the current turn. |
| `effort` | `low`/`medium`/`high`/`xhigh`/`max`. |
| `context` | `fork` runs the skill in a subagent that does not see the conversation history. |
| `agent` | Subagent type for `context: fork`. Default `general-purpose`. |
| `background` | Only with `fork`. `false` makes the turn wait for the result (v2.1.218+). |
| `hooks` | Hooks registered **when the skill is invoked**. They then stay registered for the rest of the session. |
| `paths` | Globs that limit auto-activation to matching files. |
| `shell` | `bash` (default) or `powershell`, for `!` injection. |
| `metadata` | Free-form YAML map. Claude Code ignores its contents. |
| `license`, `compatibility` | From the Agent Skills spec. Claude Code accepts them and ignores them. `compatibility` is at most 500 chars. |

Command files in `.claude/commands/` accept the same fields except `name` and `paths`. [CC-skills]

### 2.2 Agent Skills standard (portable subset)

| Field | Required | Constraint [AS-spec "Frontmatter"] |
|---|---|---|
| `name` | Yes | 1-64 chars, lowercase `a-z0-9` and `-` only. Can't start or end with `-` and can't contain `--`. **Must match the parent directory name.** |
| `description` | Yes | 1-1024 chars. Says what the skill does and when to use it. |
| `license` | No | License name, or a reference to a bundled license file. |
| `compatibility` | No | 1-500 chars. Environment requirements. |
| `metadata` | No | Map from **string keys to string values**. |
| `allowed-tools` | No | Space-separated string. Marked **Experimental**. |

- Uploads to claude.ai, the Skills API, and `package_skill.py` from anthropics/skills accept **only** `name`, `description`, `license`, `compatibility`, `metadata` and `allowed-tools`. Any other key is a **hard error**, e.g. `Unexpected key(s) in SKILL.md frontmatter: argument-hint`. That rule also applies when you enable a personal skill for your claude.ai account. [CC-skills "Using skill frontmatter outside Claude Code"]
- On the platform (API/claude.ai), `name` can't contain XML tags or the reserved words "anthropic" or "claude", and `description` can't contain XML tags. [PL-bp "Skill structure"]
- Validator: `skills-ref validate ./my-skill` (github.com/agentskills/agentskills/tree/main/skills-ref). [AS-spec "Validation"] [unverified: tool not run]
- Claude Code's own check: `claude plugin validate .claude/skills` or `claude plugin validate ~/.claude/skills` finds SKILL.md files whose frontmatter doesn't parse (v2.1.233+). [CC-skills "Skill not triggering"; CC-plug-cli "plugin validate"]

## 3. Size guidance and progressive disclosure

- Keep `SKILL.md` **under 500 lines**, and move detailed reference material into separate files. [CC-skills tip under "Add supporting files"; AS-spec "Progressive disclosure"; PL-bp "Token budgets"]
- The standard loads skills in three stages. Metadata (~100 tokens; `name` + `description`) loads at startup for every skill. The body (**< 5000 tokens recommended**) loads on activation. Resources load only when needed. [AS-spec "Progressive disclosure"]
- In Claude Code, the descriptions of skills Claude can auto-invoke are in context **every turn**, and the full body loads only on invocation. [CC-skills "Control who invokes a skill" table; CC-plug-overview "What an enabled plugin adds"]
- The skill listing's character budget is 1% of the context window. When it overflows, descriptions of the least-invoked skills are dropped first. [CC-skills "Skill descriptions are cut short"]
- Keep file references **one level deep** from `SKILL.md`. [AS-spec "File references"; PL-bp "Avoid deeply nested references"] Claude may only partly read a file it reaches through another reference file, e.g. with `head -100`. [PL-bp]
- A reference file over 100 lines should start with a table of contents. [PL-bp "Structure longer reference files with a table of contents"]
- Tell the agent whether it should **run** a script or **read** it. [PL-bp "Provide utility scripts"]
- **Lifecycle.** Rendered `SKILL.md` content enters the conversation as one message and stays there; Claude Code does **not** re-read the file on later turns. After auto-compaction, the most recent invocation of each skill is re-attached, keeping only its **first 5,000 tokens**, within a **25,000-token** shared budget filled from the most recently invoked skill. "Put the most important instructions near the top of `SKILL.md`." [CC-skills "Skill content lifecycle", "Claude stops following a skill"]
- A rule that must hold every time belongs in a **hook**, not a skill. [CC-skills "Claude stops following a skill"; CC-plug-components "Skills"]

## 4. How a skill refers to its own files

### 4.1 Substitution variables (Claude Code)

[CC-skills "Available string substitutions"]

| Variable | Meaning |
|---|---|
| `${CLAUDE_SKILL_DIR}` | **The directory containing the skill's `SKILL.md`.** For plugin skills this is the skill's own subdirectory, not the plugin root. "Use this in bash injection commands to reference scripts or files bundled with the skill, regardless of the current working directory." |
| `${CLAUDE_PROJECT_DIR}` | Project root. The same value hooks and MCP servers get as `CLAUDE_PROJECT_DIR`. |
| `${CLAUDE_PLUGIN_ROOT}` | Plugin install dir. Substituted **only in plugin skills**. |
| `${CLAUDE_PLUGIN_DATA}` | Plugin's persistent data dir, which survives updates. Plugin skills only. |
| `${CLAUDE_SESSION_ID}`, `${CLAUDE_EFFORT}` | Session id, current effort level. |
| `$ARGUMENTS`, `$ARGUMENTS[N]`, `$N`, `$name` | Invocation arguments. |

- `${CLAUDE_SKILL_DIR}` and `${CLAUDE_PROJECT_DIR}` are substituted in two places: the **skill's markdown content** and **Bash rules in `allowed-tools`**. Putting the same variable in both lets a bundled script run with no permission prompt. The documented example is `allowed-tools: Bash(${CLAUDE_SKILL_DIR}/scripts/render.sh *)`. [CC-skills]
- A backslash does **not** escape a `${CLAUDE_*}` variable. [CC-skills]
- The plugin path variables are **not** in the environment of commands Claude runs through the Bash tool. Write the `${...}` reference in the Markdown body and Claude Code substitutes it inline. [CC-plug-manifest "Where each variable resolves"]
- Injected `!` commands run in the **session shell's current working directory**, which moves when Claude runs `cd`. "Use `${CLAUDE_SKILL_DIR}` or `${CLAUDE_PROJECT_DIR}` in paths that must resolve the same way every time." [CC-skills "How injected commands run"]
- The Agent Skills guide instead says to use relative paths from the skill root, "because the agent runs commands from there". [AS-scripts "Referencing scripts from SKILL.md"] For Claude Code this conflicts with the cwd fact above. See [Contradictions](#contradictions-and-stale-claims).
- [unverified] Whether `${CLAUDE_SKILL_DIR}` is substituted inside `references/*.md` files that Claude opens later with Read. The docs name only "the skill's markdown content". Treat it as `SKILL.md` only.
- [unverified] For a symlinked skill folder, whether `${CLAUDE_SKILL_DIR}` resolves to the link path or to the target. The docs say only that Claude Code "reads `SKILL.md` from the target".

### 4.2 Dynamic context injection

- `` !`cmd` `` (at the start of a line or after whitespace) and fenced ` ```! ` blocks run **before** Claude sees the skill, and their output replaces the placeholder. [CC-skills "Inject dynamic context"]
- A failed command (any non-zero exit, except exit 1 from search/compare commands) **aborts the whole invocation**. Append `|| true` when a non-zero exit is expected. [CC-skills "When an injected command fails"]
- Each command is checked against permission rules first. Outside auto mode, anything short of "allow" aborts the invocation, so pre-approve the command with `allowed-tools`. Deny and ask rules still override `allowed-tools`. [CC-skills "Permission checks on injected commands"]
- Default timeout is 2 minutes (the Bash tool default), and stderr is merged into stdout. [CC-skills "How injected commands run"]
- `disableSkillShellExecution: true` replaces each command with `[shell command execution disabled by policy]`. In a local session, `!` commands are never run for skills **synced from claude.ai**. [CC-skills]

### 4.3 Skill-scoped hooks

- A skill's `hooks` are registered when the skill is invoked and keep running for the rest of the session. `once: true` removes a hook after its first successful run. [CC-hooks "Hooks in skills and agents"]
- Each skill source (the project, the personal folder, each plugin) may register at most 1,024 hooks per session (v2.1.304+). Under a managed `strictPluginOnlyCustomization` hooks lock, only plugin, bundled and managed-dir skills keep their frontmatter hooks. [CC-hooks "Limits on skill hooks"]
- [unverified] What a relative `command` path in a skill hook (e.g. `./scripts/security-check.sh` in the doc example) resolves against.

## 5. Where skills load from, and precedence

### 5.1 Locations

[CC-skills "Choose where skills load"]

| Location | Path | Loads in |
|---|---|---|
| Enterprise | `.claude/skills/<name>/SKILL.md` in the managed settings dir | Every user on the machine |
| Personal | `~/.claude/skills/<name>/SKILL.md` | All your projects on this machine. **Not Cowork or cloud sessions.** |
| Project | `.claude/skills/<name>/SKILL.md` | Sessions in this repo (and its parent-dir chain up to the repo root). Not cloud threads in a claude.ai *project*. |
| Nested | `<subdir>/.claude/skills/...` | Loads once Claude reads or edits a file in `<subdir>` |
| `--add-dir` | `<dir>/.claude/skills/...` | That session |
| Plugin | `<plugin>/skills/<name>/SKILL.md` | Wherever the plugin is enabled, as `/plugin-name:skill-name` |
| claude.ai account | Skills enabled on the account | Cowork, cloud, and signed-in terminal sessions (synced to `~/.claude/skills/synced/`) |

- **Cloud sessions** (claude.ai/code, cloud scheduled tasks) don't read `~/.claude/skills/`. For those sessions, enable the skill on the claude.ai account or commit it to the repo's `.claude/skills/`. Plugins enabled only in user settings, or declared in the repo's `.claude/settings.json`, don't load in cloud sessions. [CC-skills "Use skills in Cowork and cloud sessions"; CC-plug-install]
- Don't name a skill folder `synced` (any case). A skill named `anthropic-skills` or `anthropic-skills:*` doesn't load outside a plugin. [CC-skills]
- Claude Code watches `~/.claude/skills/`, project `.claude/skills/` and `--add-dir` skills dirs, and picks up `SKILL.md` edits without a restart. Live change detection covers SKILL.md text only. [CC-skills "Edit a skill during a session"]
- **Symlinks.** A `<skill-name>` entry in the enterprise, personal or project location **may be a symlink to a directory elsewhere**. Claude Code reads `SKILL.md` from the target and loads the skill once, even if several locations point at the same target. Plugin skills handle symlinks differently (§6.6). [CC-skills "Skill folders also follow these rules"]
- `claude plugin validate` does **not** follow symlinks inside the directory you name. It warns about linked entries and skips them. If the named dir is itself a symlink, it reports an error and checks nothing. [CC-plug-cli "Validate a directory"]

### 5.2 Same name in two places

[CC-skills "Resolve skills that share a name"]

| Same name in | Which one runs |
|---|---|
| Enterprise / personal / project | **Enterprise > personal > project**. With `deploy` in both `~/.claude/skills/` and the project, `/deploy` runs the personal one. |
| Local skill vs bundled skill | Yours replaces the bundled command, but not its aliases |
| Local skill vs built-in command | Yours replaces it in a local terminal session, but not its aliases |
| Skill vs `.claude/commands/` file | The skill |
| Project-root vs nested | Both load, and the nested one gets a directory-qualified name, e.g. `/apps/web:deploy` |
| Local vs `--add-dir` | The local one. The added one runs as `/<prefix>:<name>` (v2.1.309+) |
| **Plugin skill vs any of the above** | **Both load**, because plugin skills are namespaced `/plugin:skill`. A plugin skill's bare `/name` also works unless another command holds that name. [CC-skills "How a skill gets its command name"] |
| Synced claude.ai skill vs anything | The other one wins. The synced skill runs only as `/anthropic-skills:<name>` |

- Name comparison ignores case, spacing, invisible characters and compatibility forms such as fullwidth letters (v2.1.228+). [CC-skills]
- Both the directory name and the frontmatter `name` must avoid zero-width, control, private-use and bidi characters, `<` and `>`, and irregular blanks. A refused directory name means the skill doesn't load. [CC-skills "Characters a skill name can't hold"]

### 5.3 Visibility controls

- `skillOverrides` in settings sets each skill to `on`, `name-only`, `user-invocable-only` or `off`. It does **not** affect plugin skills, which are managed through `/plugin`. [CC-skills "Override skill visibility from settings"]
- Permission rules: `Skill(name)` matches exactly and `Skill(name *)` matches with any arguments. Deny all skills with `Skill`. [CC-skills "Restrict Claude's skill access"]

## 6. Plugins: bundling skills with MCP servers

### 6.1 Layout

[CC-plug-create "Plugin layout"; CC-plug-manifest "Standard layout"]

```
<plugin-root>/
├── .claude-plugin/plugin.json   # manifest (optional); ONLY this file goes here
├── skills/<name>/SKILL.md       # skills (or a single SKILL.md at the root)
├── commands/  agents/  hooks/hooks.json  monitors/monitors.json
├── bin/                         # on the Bash tool's PATH while enabled
├── settings.json                # only `agent` and `subagentStatusLine` take effect
├── .mcp.json                    # MCP servers
└── .lsp.json
```

- Components saved inside `.claude-plugin/` don't load. A `.mcp.json` at `~/.claude/.mcp.json` doesn't load either. [CC-plug-create warning]
- A `CLAUDE.md` at the plugin root is **not** loaded. Put instructions in a skill. [CC-plug-components "Skills"; CC-plug-manifest]
- Plugin skills are `/<plugin>:<dir>`, or `/<plugin>:<name>` when frontmatter `name` is set. [CC-plug-components "Skills"]
- A root `SKILL.md`, with no `skills/` dir and no `skills` key, loads as one skill. Set `name`, or a marketplace install names the skill after its cache directory. [CC-plug-components]
- Files in `bin/` are on the Bash tool's `PATH` while the plugin is enabled. They come **after** the user's own PATH, so they can't shadow system commands. **claude.ai and Cowork don't install a plugin that has a top-level `bin/`.** [CC-plug-components "Executables"]

### 6.2 `plugin.json` essentials

[CC-plug-manifest "Fields", "name", "version"]

- Only `name` is required: kebab-case, no spaces, `@`, `:` or path separators. Every component is namespaced under it.
- Names that **start with `claude-`, `anthropic-`, `anthropics-` or `cc-plugin-`**, names that **are** `claude`/`anthropic`/`claude-code`/..., and names that put `official` beside claude/anthropic are **errors**. A whole-word `claude` elsewhere in the name is a warning.
- `version` is not checked against semver. If set, it **pins users to that version until it changes**. Omit it (from both `plugin.json` and the marketplace entry) to have users track commits. [CC-plug-host "Release a new version"; CC-plug-loading "How Claude Code computes the version"]
- Component paths must start with `./`, stay inside the plugin root (`..` fails), and exist. [CC-plug-manifest "Path rules"]
- `skills` **adds to** the default `skills/` scan. `commands`/`agents` **replace** their defaults. `hooks`/`mcpServers`/`lspServers` **merge**. [CC-plug-manifest]
- An unknown top-level key is stripped with a warning. An unknown key inside a `userConfig` option, `channels`, `lspServers` or `monitors` entry is an error, and the plugin doesn't load. [CC-plug-manifest "Unrecognized fields"]

### 6.3 MCP servers inside a plugin

- Declare them in `.mcp.json` at the plugin root (same shape as a project `.mcp.json`; the `mcpServers` wrapper is optional), or inline in `plugin.json` `mcpServers`. When both define the same name, the manifest wins. [CC-plug-components "MCP servers"; CC-mcp "Plugin-provided MCP servers"]
- Server name: `plugin:<plugin>:<server>`. Tool name: `mcp__plugin_<plugin>_<server>__<tool>`, with characters outside `[A-Za-z0-9_-]` replaced by `_`. Use the full tool name in permission rules, `allowed-tools` and hook matchers. A matcher on the bare server key never fires. [CC-mcp; CC-plug-components]
- Path variables are substituted in stdio `command`/`args`/`env` and in http/sse/ws `url`/`headers`/`headersHelper`. [CC-plug-manifest; CC-mcp]
- A remote `https://` server is the only MCP form that reaches claude.ai and Cowork users. Local stdio servers run in Claude Code and in local Cowork only. [CC-plug-components "Reach users on claude.ai and Cowork"]
- Plugin servers connect automatically while the plugin is enabled. Users toggle them in `/mcp` but add and remove them only by installing or uninstalling the plugin. [CC-mcp]
- A plugin MCP server that **points at the same URL** as a local/project/user server is a duplicate, and the higher scope wins. Precedence is **local > project > user > plugin > claude.ai connectors**, and the whole entry comes from the winning source. URLs differing only in case, default port or a trailing slash count as the same endpoint. [CC-mcp "Scope hierarchy and precedence"]
- A remote server entry with an empty `url` shows as `not configured` and isn't treated as an error. That makes it a sanctioned placeholder. [CC-mcp "Server status detail"]

### 6.4 User configuration and secrets

[CC-plug-manifest "User configuration"; CC-plug-components "Ask the user for configuration values"]

- `userConfig` options take `type` (`string|number|boolean|directory|file`), `title`, `description`, and optionally `required`, `default`, `options`, `multiple`, `sensitive`, `min`/`max`.
- `sensitive: true` masks input and stores the value in the platform's **secure credential store** instead of `settings.json`. Non-sensitive values go under `pluginConfigs` in `settings.json`.
- Where a value reaches: `${user_config.KEY}` is substituted in MCP and LSP config, exec-form hook `args`, and skill/agent content. **In skill/agent content only non-sensitive values are substituted; a sensitive value becomes a placeholder.** Hook processes get `CLAUDE_PLUGIN_OPTION_<KEY>`. Shell-form hooks, monitor commands and MCP `headersHelper` reject `${user_config.*}`.
- The dialog appears only through `/plugin` in a session. `--plugin-dir` and `claude plugin install` never prompt; use `--config KEY=VALUE` or `claude plugin configure --values-stdin`.
- Neither path gives a userConfig value to a command Claude runs through the **Bash tool**. Path variables are absent there [CC-plug-manifest], and `CLAUDE_PLUGIN_OPTION_*` is listed only for hook processes.

### 6.5 Loading a plugin without a marketplace

- `claude --plugin-dir ./my-plugin` (repeatable; also accepts `.zip` or a folder of plugins, v2.1.265+), `--plugin-url <zip>`, or `CLAUDE_CODE_PLUGIN_DIRS` (v2.1.280+). These load for **one session**, as `<name>@inline`. [CC-plug-create "Develop without a marketplace"]
- **Skills-directory plugin.** A folder under `~/.claude/skills/` or the project's `.claude/skills/` that holds `.claude-plugin/plugin.json` loads every session as `<name>@skills-dir`, with its own agents, hooks and MCP servers. `claude plugin init <name>` scaffolds one. Its root `SKILL.md` is also a plain personal skill (`/my-tool`), while skills under its `skills/` are `/my-tool:<skill>`. A project-scope one needs workspace trust, and its MCP servers go through per-server approval. Admins can block skills-dir plugins. [CC-plug-create "Make a plugin load in every session"; CC-plug-loading "Plugins shared through a repository"; CC-skills]
- For a project skills-dir plugin, Claude Code reads `.claude/skills/` of the session's **primary working directory only**. It does not search parent dirs. [CC-plug-loading "Check why a repository plugin didn't load"]
- [unverified] Whether `bin/` in a skills-dir plugin goes on PATH. The `bin/` docs don't qualify by origin.
- **Name conflicts between plugin origins**, highest first: managed `enabledPlugins` > `--plugin-dir`/`--plugin-url`/`CLAUDE_CODE_PLUGIN_DIRS` > installed marketplace plugin > skills-dir plugin (the personal copy beats the project copy) > synced from claude.ai. The comparison is by **manifest name**. [CC-plug-loading "Name conflicts"]

### 6.6 Install cache, data dir, symlinks

- Marketplace plugins are copied to `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/` (`${CLAUDE_PLUGIN_ROOT}`), which changes every version. Durable state goes in `~/.claude/plugins/data/<id>/` (`${CLAUDE_PLUGIN_DATA}`), which by default is deleted when the plugin is uninstalled from its last scope. [CC-plug-loading "Find plugins on disk"; CC-plug-manifest "Environment variables"]
- `--plugin-dir` and skills-dir plugins load **in place**, never copied. Relative-path plugins in a marketplace added from a local path also load in place, so edits apply at the next session or on `/reload-plugins` with no version bump. [CC-plug-loading "In-place and copied plugins"]
- When Claude Code caches a copy: a symlink that stays inside the plugin is kept, one pointing elsewhere in the same marketplace is dereferenced, and one pointing **outside the marketplace is skipped**. Local-path installs keep only in-plugin symlinks. A copied plugin can't read files above its root, e.g. `../shared`. [CC-plug-host "Share files within a marketplace with symlinks"; CC-plug-loading]

## 7. A personal marketplace from a private GitHub repo

### 7.1 `marketplace.json`

[CC-plug-create-mkt; CC-plug-mkt-ref "Top-level fields", "Plugin entries", "Plugin sources"]

- File: `<root>/.claude-plugin/marketplace.json`. **Required:** `name`, `owner` (`{name}` required), and `plugins[]`. Each entry needs `name` and `source`.
- Marketplace `name` uses letters, digits, `.`, `_` and `-`, starts alphanumeric, and has no `..`. Users type it after `@`. Claude Code takes it from this field, **not the repo name**. One registered marketplace per name. [CC-plug-host "Host your marketplace"]
- Reserved marketplace names include official names such as `claude-plugins-official` and `agent-skills`, anything impersonating them, any non-ASCII name, `inline`, `builtin`, `skills-dir`, `synced`, `npm`, `pip`, `uv`, `cargo`, `github`, `gh`, the prefix `claudeai-`, JS object member names, and the `<owner>-<repo>` download folder of another registered GitHub marketplace. [CC-plug-mkt-ref "Reserved names"]
- Source types: a relative path (`"./plugins/x"`, or `"."`/`"./"` for the marketplace root itself), `github`, `url`, `git-subdir`, `npm`, `archive` (v2.1.224+), and `command` (v2.1.229+). `github`/`url`/`git-subdir` take `ref` and `sha`. [CC-plug-mkt-ref]
- The docs cover a **plugin at the marketplace root** (`"source": "./"`) in their submodule rules. `claude plugin validate` on a dir that holds both `marketplace.json` and `plugin.json` checks both (v2.1.289+). [CC-plug-mkt-ref "Git submodules"; CC-plug-cli "Validate a directory"] [unverified: single-repo marketplace + plugin not tested end to end]
- Keep the entry `name` equal to the plugin's manifest `name`. The entry name is the install id and `enabledPlugins` key; the manifest name is the skill prefix. [CC-plug-create-mkt "Keep the entry name and the manifest name the same"; CC-plug-loading]
- Keep plugin files out of Git LFS, because clones never fetch LFS content. [CC-plug-host]

### 7.2 Adding and installing

- Shell: `claude plugin marketplace add owner/repo[#ref]` (default `--scope user`; also `project` and `local`), then `claude plugin install <plugin>@<marketplace>` (default user scope). In a session, use `/plugin marketplace add …` and `/plugin install …`. In one step: `claude plugin install <plugin> --marketplace owner/repo` (v2.1.292+). [CC-plug-cli "plugin marketplace add"; CC-plug-install]
- Accepted source forms: `owner/repo`, `owner/repo#ref`, `owner/repo@ref`, `git@host:path`, `https://….git`, `https://github.com/owner/repo`, a local dir or `.json` path, or a hosted `marketplace.json` URL. A bare `host/path` without `https://` is read as GitHub shorthand and rejected. [CC-plug-cli; CC-plug-install]
- **Private repo access.** Claude Code runs `git` with prompts turned off and uses the machine's existing credentials; "Claude Code has no git token of its own, and `marketplace.json` has no field for one." With `owner/repo` it probes `ssh -T git@github.com` and uses SSH if that works, otherwise HTTPS. Set `CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1` to skip the probe. SSH needs a passphrase-free (agent-loaded) key and the host in `known_hosts`. HTTPS needs a credential helper that already holds a credential (e.g. `gh auth login` then `gh auth setup-git`), because askpass and `GIT_ASKPASS` are disabled. `GITHUB_TOKEN` in the environment does **not** authenticate by itself; it works only through a credential helper. [CC-plug-host "Grant access to a private marketplace"; CC-plug-install "Add a private marketplace"]
- Installs from `/plugin` inside a session and plugin **updates don't fall back** from SSH to HTTPS, so users without a GitHub SSH key should keep `CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1` set. [CC-plug-host "Serve users who have no git-host account"]
- **Updates.** Background auto-update is **off by default** for third-party marketplaces. Turn it on under `/plugin` → Marketplaces → Enable auto-update. Otherwise run `/plugin marketplace update <name>` or `claude plugin update <plugin>@<mkt>`. A user gets a new copy only when the computed version changes. That version is plugin.json `version`, then the entry `version`, then the 12-char commit SHA. [CC-plug-host "Keep users up to date"; CC-plug-loading "Versions and updates", "When auto-update runs"]
- Install scopes: **user** (`~/.claude/settings.json` `enabledPlugins`), **project** (`.claude/settings.json`; each collaborator still installs it), **local** (`.claude/settings.local.json`). Precedence is local > project > user. [CC-plug-install "Choose an install scope"]
- A **cloud session** doesn't load plugins from local settings, and doesn't add `extraKnownMarketplaces` from a repo (that needs workspace trust). [CC-plug-install; CC-plug-loading]

## 8. Adding a remote HTTP MCP server at user scope

- Syntax: `claude mcp add --transport http <name> <url>`, plus optional `--header "Authorization: Bearer …"`. HTTP is the recommended transport for remote servers. [CC-mcp "Option 1"]
- User scope, documented order 1: `claude mcp add --transport http hubspot --scope user https://mcp.hubspot.com/anthropic`. [CC-mcp "User scope"]
- User scope, documented order 2: `claude mcp add --scope user --transport http claude-code-docs https://code.claude.com/docs/mcp`. [CC-mcpq "Use a server in all your projects"]
- Flags: `-s`/`--scope` (`local` default, `project`, `user`), `-t`/`--transport`, `-H`/`--header`, `-e`/`--env`. For stdio servers, `--` separates Claude's options from the server command. [CC-mcp tips; CC-mcp "Option 3"]
- Storage: `local` writes to `~/.claude.json` under the project's entry. `user` writes to the `~/.claude.json` top-level `mcpServers`. `project` writes `.mcp.json` at the repo root, which needs approval in interactive sessions and is loaded without asking in `-p`, SDK and cloud sessions. With `CLAUDE_CONFIG_DIR` set, `.claude.json` lives inside that dir. [CC-mcpq "Find your configuration on disk"; CC-mcp "Project scope"]
- Scope is fixed when a server is added. To change it, `claude mcp remove <name> --scope <old>` and re-add. Re-adding the same name at the same scope fails with `... already exists in local config`. [CC-mcpq "Change server scope"; CC-mcp]
- Check with `claude mcp list` (health status) and `claude mcp get <name>`, or `/mcp` in a session. [CC-mcpq; CC-mcp]
- In JSON config an `http` entry needs `"type": "http"` (`streamable-http` is an accepted alias). A `url` with no `type` is skipped as a misconfigured stdio entry. [CC-mcp "Option 1"]
- **OAuth.** A 401/403 response flags the server in `/mcp` for a browser sign-in. Tokens are stored securely and refreshed automatically. From the shell, `claude mcp login <name>` works; it detects a missing browser (SSH, Linux without a display) and prints the URL, or you can force that with `--no-browser`. It needs an interactive terminal for the paste-back (`ssh -t`). `claude -p` and SDK runs can't do the OAuth flow, so sign in interactively first. [CC-mcp "Authenticate with remote MCP servers", "Authenticate from the command line"; CC-cli]
- **Tailscale's docs MCP server** is at `https://tailscale.mcp.kapa.ai/`. It is a remote MCP server with a tool that searches the Tailscale docs and returns passages with source URLs. Tailscale's JSON example is `{"mcpServers":{"tailscale-docs":{"type":"http","url":"https://tailscale.mcp.kapa.ai/"}}}`. "The first time you connect, your client opens a browser window to authorize access." Tailscale says to install the skill and the MCP server together because they cover different needs. [TS-ai "MCP server for the documentation", Last validated Jul 28, 2026]
- The documented forms above give this command for it: `claude mcp add --transport http --scope user tailscale-docs https://tailscale.mcp.kapa.ai/`, then `claude mcp login tailscale-docs --no-browser` on a headless Nomad. [composed from CC-mcp + TS-ai; unverified: not run]

## 9. The `npx skills` tool

- **Package:** npm `skills`, latest **1.7.4** (published 2026-10-19T20:35:25Z), description "The open agent skills ecosystem", **MIT**, repo `github.com/vercel-labs/skills`. npm maintainers are `rauchg` and `quuu`. The latest version was published by GitHub Actions through npm trusted publishing (OIDC). Its bins are `skills` and `add-skill`. It needs **Node >= 22.20.0**. [registry.npmjs.org/skills; VS-src package/package.json]
- Its README bills it as a **Vercel Labs product** ("The CLI for the open agent skills ecosystem"), with a directory at skills.sh. Telemetry is on by default; `DISABLE_TELEMETRY=1` or `DO_NOT_TRACK=1` turns it off. [VS-README]
- Tailscale's documented install is `npx skills add https://github.com/tailscale/tailscale-skill`. The manual alternative is to copy the repo's `skills/tailscale` dir to `~/.claude/skills/tailscale`. [TS-skill "Get started", Last validated Jul 24, 2026; UP README.md]
- **Where it installs for Claude Code:** project path `.claude/skills/`, global path `~/.claude/skills/` (`-g`). [VS-agents table] In the source, the global dir is `${CLAUDE_CONFIG_DIR:-~/.claude}/skills`. [VS-src dist/cli.mjs:1400, 1509-1516]
- **Default scope is the current project.** Pass `-g` for user scope. The default method is **symlink**, with `--copy` as the alternative. [VS-README "Install a Skill"; VS-commands "Installation Scope", "Installation Methods"]
- **Symlink mode detail** (source observation, not in the README). The skill is copied to a canonical dir `<base>/.agents/skills/<name>`, where base is the home dir for `-g` or the cwd for project installs. Then a **relative symlink** is made at the agent dir, e.g. `~/.claude/skills/<name>`. If the symlink fails, it copies instead. [VS-src dist/cli.mjs:1186-1187, 2210-2211, 2289-2290, 2320-2360, 2249-2275]
- The install dir name is `sanitizeName(skill.name || basename(path))`, so the frontmatter `name` decides it. The upstream skill's `name: tailscale` therefore installs at `~/.claude/skills/tailscale`. [VS-src dist/cli.mjs:2185-2187, 2287; UP skills/tailscale/SKILL.md:2]
- **It destroys an existing directory at the target.** `createSymlink` runs `rm(linkPath, {recursive: true})` when the target exists and is not a symlink. Copy mode calls `cleanAndCreateDirectory` (`rm -rf`) first. The interactive summary lists `overwrites: Claude Code` before you confirm, and `-y` skips that confirmation. [VS-src dist/cli.mjs:2256-2260, 2230-2236, 4943-4945; VS-commands "Options" `-y`]
- Lock file: `~/.agents/.skill-lock.json`, or `$XDG_STATE_HOME/skills/.skill-lock.json`. [VS-src dist/cli.mjs:3753-3759]
- Private repos: it uses existing git credentials, then `gh repo clone`, then SSH. `GITHUB_TOKEN`/`GH_TOKEN` are optional for API access. [VS-commands "Private Repositories"]
- It also discovers skills declared in `.claude-plugin/marketplace.json` and `plugin.json`. [VS-creating-skills "Plugin Manifest Discovery"]
- Other commands: `list`, `find`, `check`, `update [-g|-p]`, `remove`, `init`, and `use`. Non-interactive install: `npx skills add <src> --skill <n> -g -a claude-code -y`. [VS-commands]

## 10. The upstream Tailscale skill as packaged

- Repo layout: `skills/tailscale/SKILL.md` plus 17 files in `skills/tailscale/references/*.md`. It has no `scripts/`, no plugin manifest and no MCP config. Frontmatter is `name: tailscale` and a long `description`. [UP tree; UP skills/tailscale/SKILL.md:1-17]
- It is reference-only: "The skill supplies reference material, not access. It does not authenticate to your tailnet and does not change your configuration." It is alpha and unsupported. [TS-skill "Limitations", Last validated Jul 24, 2026]
- Invocation: explicitly with `/tailscale`, or implicitly by description match, which varies by agent. [TS-skill "Get started"]

---

## Open gaps ([unverified])

- Whether `${CLAUDE_SKILL_DIR}` is substituted in `references/*.md`, or only in `SKILL.md`.
- Whether `${CLAUDE_SKILL_DIR}` gives the symlink path or the real target for a symlinked skill folder.
- Whether `${CLAUDE_SKILL_DIR}` is substituted for claude.ai-synced skills in local sessions. The docs list only `${CLAUDE_PROJECT_DIR}` and `${CLAUDE_SESSION_ID}` as left literal.
- Whether a skills-directory plugin's `bin/` is put on the Bash tool's PATH.
- What a relative `command` in a skill-frontmatter hook resolves against.
- Whether one repo can serve end to end as both the marketplace and its own root plugin (`"source": "./"`) for a private GitHub install. The docs describe the shape but this was not run.
- Whether the Tailscale docs MCP server's OAuth completes through `claude mcp login --no-browser` on a headless Pi.
- Whether `npx skills add` without `-a` on a machine that has only Claude Code installs to Claude Code alone. The README says it "detects installed agents and lets you choose".
- The `skills-ref validate` tool was not run.

## Contradictions and stale claims

1. **Script path resolution.** The Agent Skills guide says script paths in code blocks "are relative to the **skill directory root**, because the agent runs commands from there" [AS-scripts]. Claude Code says injected commands run in "the session shell's current working directory", which moves with `cd`, and tells you to use `${CLAUDE_SKILL_DIR}` for stable paths [CC-skills "How injected commands run", "Available string substitutions"]. In Claude Code, a bare `scripts/foo.py` resolves against the project cwd, not the skill dir.
2. **`name` vs directory.** The spec says `name` "Must match the parent directory name" [AS-spec]. Claude Code lets `name` differ, and then both invoke the skill: `.claude/skills/deploy-staging/` with `name: deploy` gives `/deploy` [CC-skills "How a skill gets its command name"].
3. **`metadata` type.** The spec says a map of string to string [AS-spec]. Claude Code says a "Free-form YAML map" and drops a value only if it isn't a map [CC-skills].
4. **`allowed-tools` form and meaning.** The spec says a space-separated string, experimental [AS-spec]. Claude Code accepts space- or comma-separated strings or a YAML list, and the grant lasts only for the invoking turn without restricting other tools [CC-skills].
5. **Description length.** The spec and the platform cap `description` at 1024 chars [AS-spec; PL-bp]. Claude Code truncates description + `when_to_use` at 1,536 chars in its listing [CC-skills].
6. **MCP tool naming.** The platform best-practices page says to reference MCP tools as `ServerName:tool_name` [PL-bp "MCP tool references"]. Claude Code's callable names are `mcp__plugin_<plugin>_<server>__<tool>` for plugin servers and `mcp__<server>__<tool>` otherwise (implied by the "bare server key" matcher note) [CC-mcp "Plugin MCP tool names"]. The platform form does not match Claude Code tool names.
7. **Where `npx skills add` puts things.** Tailscale says the command "installs the skill into your agent's skills directory" and gives the manual copy target as `~/.claude/skills/tailscale` [TS-skill]. The skills CLI installs to the **current project** by default (`./.claude/skills/`, with the canonical copy in `./.agents/skills/`) unless `-g` is given [VS-README; VS-commands; VS-src]. Tailscale's wording leaves out the project-vs-global default.
8. **Reserved words in names differ by surface.** The platform bans "anthropic" and "claude" in skill `name` [PL-bp]. Claude Code bans `anthropic-skills` names for skills [CC-skills] and `claude-*`/`anthropic-*` prefixes for **plugin** names [CC-plug-manifest]. A skill name containing `claude` loads locally but fails a claude.ai upload.

## Sources

All fetched 2026-10-26 with `curl` (Markdown form where offered). Claude Code pages have no "Last validated" date.

- https://code.claude.com/docs/llms.txt (index)
- https://code.claude.com/docs/en/skills.md
- https://code.claude.com/docs/en/plugins/overview.md
- https://code.claude.com/docs/en/plugins/create.md
- https://code.claude.com/docs/en/plugins/components.md
- https://code.claude.com/docs/en/plugins/manifest-reference.md
- https://code.claude.com/docs/en/plugins/marketplace-reference.md
- https://code.claude.com/docs/en/plugins/create-marketplace.md
- https://code.claude.com/docs/en/plugins/host-marketplace.md
- https://code.claude.com/docs/en/plugins/install.md
- https://code.claude.com/docs/en/plugins/loading.md
- https://code.claude.com/docs/en/plugins/cli-reference.md
- https://code.claude.com/docs/en/mcp.md
- https://code.claude.com/docs/en/mcp-quickstart.md
- https://code.claude.com/docs/en/hooks.md
- https://code.claude.com/docs/en/cli-reference.md
- https://agentskills.io/llms.txt, https://agentskills.io/home.md, https://agentskills.io/specification.md, https://agentskills.io/skill-creation/using-scripts.md
- https://platform.claude.com/docs/en/agents-and-tools/agent-skills/best-practices.md
- https://tailscale.com/docs/features/tailscale-skill.md (Last validated Jul 24, 2026)
- https://tailscale.com/docs/develop-with-ai.md (Last validated Jul 28, 2026)
- https://tailscale.com/docs/llms.txt (index)
- https://registry.npmjs.org/skills (package metadata; latest 1.7.4)
- https://registry.npmjs.org/skills/-/skills-1.7.4.tgz → `package/dist/cli.mjs`, `package/package.json` (direct source observation; line numbers cited inline)
- https://raw.githubusercontent.com/vercel-labs/skills/main/README.md and `docs/agents.md`, `docs/commands.md`, `docs/creating-skills.md`, `docs/troubleshooting.md`
- Upstream clone `tailscale/tailscale-skill` @ `4f05d353efc56962546aa26ccc59bb08ca699ad1` (2026-07-09): `README.md`, `skills/tailscale/SKILL.md`
- Local observation: `claude --version` → `2.1.310 (Claude Code)`; `node --version` → `v22.22.0` (this cloud container, not the Nomad)
