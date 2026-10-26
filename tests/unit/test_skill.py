# ABOUTME: Tests for the tailnet skill (DESIGN.md §19): SKILL.md's frontmatter, size and order, every command,
# ABOUTME: flag and permission string it names held to the parser and rules.json, and the six references.

import re
from pathlib import Path

from tailnet import __version__, cli, doctor, gate

REPO = Path(__file__).resolve().parents[2]
SKILL_DIR = REPO / "skill" / "tailnet"
SKILL_MD = SKILL_DIR / "SKILL.md"

# The keys a claude.ai upload, the Skills API and package_skill.py accept; any other key is a
# hard error there [pkg §2.2]. Claude Code ignores the ones it does not use.
PORTABLE_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}

# After auto-compaction Claude Code re-attaches only the first 5,000 tokens of a skill [SK L613;
# pkg §3]; §21.2 estimates tokens as characters / 4. The count below starts at the file's first
# byte, frontmatter included, which is more than Claude Code renders, and adds room for what the
# injected `tailnet status --brief` prints there: six lines, the longest a list of missing rules.
TOKEN_BUDGET_CHARS = 5_000 * 4
INJECTED_STATUS_ALLOWANCE = 2_000

# §5.2 marks these ten R; the other four write, or need MC's terminal, or remove power.
READ_COMMANDS = {
    "status", "doctor", "device list", "policy get", "policy draft", "policy validate",
    "policy diff", "policy test", "dns", "diagnose",
}


def skill_text():
    """SKILL.md as it will be installed."""
    return SKILL_MD.read_text(encoding="utf-8")


# --- A strict reader for the YAML the frontmatter uses ---
#
# The CLI is stdlib-only and so is its test suite, which has no YAML parser. SKILL.md's
# frontmatter needs only top-level keys whose values are plain or double-quoted scalars, folded
# `>-` blocks, lists of scalars and one map of scalars. This reader takes exactly that and refuses
# anything else, so a construct it might misread fails the test instead of passing it.

_KEY_LINE = re.compile(r"([a-z][a-z0-9-]*):(?: (.*))?")
_CHILD_KEY = re.compile(r"  ([a-z][a-z0-9-]*): (.+)")
# A plain scalar may not open with a YAML indicator, nor hold ": " or " #", which would end it.
_PLAIN_START = re.compile(r"[-?:,\[\]{}#&*!|>'\"%@`\s]")


def _scalar(text):
    """One scalar: double-quoted without escapes, or plain."""
    if text.startswith('"'):
        assert len(text) >= 2 and text.endswith('"'), f"unterminated quote: {text!r}"
        inner = text[1:-1]
        assert '"' not in inner and "\\" not in inner, f"escapes are outside the subset: {text!r}"
        return inner
    assert text and not _PLAIN_START.match(text), f"not a plain scalar: {text!r}"
    assert ": " not in text and " #" not in text and not text.endswith((":", " ")), text
    return text


def parse_frontmatter(text):
    """Split SKILL.md into (frontmatter as a dict, body); refuse YAML outside the subset."""
    lines = text.split("\n")
    # Claude Code reads frontmatter only when `---` is the very first line [pkg §1].
    assert lines[0] == "---", "SKILL.md must open with --- on its first line"
    end = lines.index("---", 1)
    header, body = lines[1:end], "\n".join(lines[end + 1:])
    doc, at = {}, 0
    while at < len(header):
        match = _KEY_LINE.fullmatch(header[at])
        assert match, f"frontmatter line {at + 2} is outside the subset: {header[at]!r}"
        key, value = match.group(1), match.group(2)
        assert key not in doc, f"duplicate frontmatter key {key}"
        at += 1
        block = []
        while at < len(header) and header[at].startswith("  "):
            block.append(header[at])
            at += 1
        if value == ">-":
            # Folding joins lines with one space only when every line has the same indent.
            assert block and all(not line[2:].startswith(" ") for line in block), key
            doc[key] = " ".join(line[2:].rstrip() for line in block)
        elif value is None:
            if all(line.startswith("  - ") for line in block):
                doc[key] = [_scalar(line[4:]) for line in block]
            else:
                children = [_CHILD_KEY.fullmatch(line) for line in block]
                assert block and all(children), f"{key}: neither a list nor a map"
                doc[key] = {m.group(1): _scalar(m.group(2)) for m in children}
        else:
            assert not block, f"{key} has a value and an indented block"
            doc[key] = _scalar(value)
    return doc, body


def test_the_frontmatter_reader_refuses_what_it_cannot_read():
    # The reader is what every frontmatter test rests on, so it is held to a known answer.
    doc, body = parse_frontmatter('---\nname: x\nd: >-\n  a: b\n  c\nl:\n  - Bash(t s *)\n'
                                  'm:\n  k: "1.0"\n---\nbody')
    assert doc == {"name": "x", "d": "a: b c", "l": ["Bash(t s *)"], "m": {"k": "1.0"}}
    assert body == "body"
    for bad in ("---\nname: a: b\n---\n", "---\nname: [x]\n---\n", "---\nn:\n  - a\n  b: c\n---\n",
                "---\nname: x\nname: y\n---\n", "---\nd: |\n  x\n---\n", "\n---\nname: x\n---\n"):
        try:
            parse_frontmatter(bad)
        except (AssertionError, ValueError):
            continue
        raise AssertionError(f"accepted {bad!r}")


def frontmatter():
    """SKILL.md's frontmatter."""
    return parse_frontmatter(skill_text())[0]


def body():
    """SKILL.md below its frontmatter."""
    return parse_frontmatter(skill_text())[1]


# --- Frontmatter ---


def test_skill_name_is_tailnet_and_matches_its_directory():
    # The standard requires `name` to equal the parent directory's name [pkg §2.2]; upstream
    # owns `tailscale`, so ours is `tailnet` (§19.1).
    assert frontmatter()["name"] == "tailnet" == SKILL_DIR.name


def test_description_is_at_most_1024_characters():
    description = frontmatter()["description"]
    assert 0 < len(description) <= 1024, len(description)


def test_frontmatter_uses_only_portable_keys():
    doc = frontmatter()
    assert set(doc) <= PORTABLE_KEYS, set(doc) - PORTABLE_KEYS
    assert {"name", "description"} <= set(doc)
    # The standard's metadata is a map of string keys to string values [pkg §2.2].
    assert all(isinstance(v, str) for v in doc["metadata"].values())
    assert isinstance(doc["allowed-tools"], list)


def test_frontmatter_values_meet_the_upload_limits():
    # A claude.ai upload refuses a name outside 1-64 lowercase letters, digits and single
    # hyphens or holding a reserved word, an XML tag in name or description, and a
    # compatibility over 500 characters [pkg §2.2].
    doc = frontmatter()
    name = doc["name"]
    assert re.fullmatch(r"[a-z0-9](?:-?[a-z0-9])*", name) and len(name) <= 64
    assert not {"anthropic", "claude"} & set(name.split("-"))
    for key in ("name", "description"):
        assert not re.search(r"<[^>]*>", doc[key]), f"{key} holds an XML tag"
    assert 0 < len(doc["compatibility"]) <= 500


def test_frontmatter_metadata_matches_the_code_it_describes():
    # The metadata names the CLI version, the upstream pin and the OpenAPI pin; each is held
    # to the one place the code keeps it, so the skill cannot describe another build.
    metadata = frontmatter()["metadata"]
    assert metadata["version"] == __version__
    assert metadata["upstream-skill-pin"] == doctor.UPSTREAM_PIN
    [pin] = (REPO / "spec" / "SHA256SUMS").read_text().split()[:1]
    assert metadata["openapi-sha256"] == pin == doctor.PINNED_SPEC_SHA256


# --- Size and order ---


def test_skill_md_is_under_250_lines():
    assert len(skill_text().splitlines()) < 250


def section(text, heading):
    """The (start, end) character offsets of the `## heading` section in `text`."""
    match = re.search(rf"^## {re.escape(heading)}\s*$", text, re.MULTILINE)
    assert match, f"no '## {heading}' section"
    following = re.search(r"^## ", text[match.end():], re.MULTILINE)
    return match.start(), match.end() + (following.start() if following else len(text))


def test_hard_rules_sit_within_the_first_5000_tokens():
    text = skill_text()
    start, end = section(text, "Hard rules")
    rules = text[start:end]
    assert len(re.findall(r"^- ", rules, re.MULTILINE)) >= 10, "the hard rules are missing"
    # They come straight after the title and the live state, ahead of every other section.
    assert not re.search(r"^## ", body()[:body().index("## Hard rules")], re.MULTILINE)
    assert end + INJECTED_STATUS_ALLOWANCE <= TOKEN_BUDGET_CHARS, end


def test_the_only_injected_command_is_status_brief_under_the_title():
    # A `!` command runs before Claude sees the skill, and outside auto mode anything short
    # of "allow" aborts the invocation [pkg §4.2]. One read that always exits 0 is all there
    # may be, and allowed-tools must pre-approve it.
    text = body()
    injected = re.findall(r"(?:^|\s)!`([^`]*)`", text)
    assert injected == ["tailnet status --brief"]
    assert "```!" not in text
    lines = [line for line in text.splitlines() if line.strip()]
    assert lines[0].startswith("# ") and lines[1] == "!`tailnet status --brief`"
    assert any(permits(rule, "tailnet status --brief") for rule in frontmatter()["allowed-tools"])


# --- Commands, flags and permission strings ---


def code_texts(text):
    """Every inline code span and every line of a fenced block in `text`."""
    texts, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            texts.append(line)
        else:
            texts.extend(re.findall(r"`([^`\n]+)`", line))
    return texts


# `tailnet` as a command word: not part of a path, a file name, the skill's name in `/tailnet`,
# or a permission pattern such as `Bash(*tailnet*--apply*)`.
_INVOCATION = re.compile(r"(?<![\w./~*-])tailnet(?![\w.*/-])")
_WORD = re.compile(r"[a-z][a-z-]*")


def invocations(text):
    """Each `tailnet …` command named in code in `text`, as (command words, the rest)."""
    found = []
    for code in code_texts(text):
        starts = [m.end() for m in _INVOCATION.finditer(code)]
        for at, start in enumerate(starts):
            stop = starts[at + 1] - len("tailnet") if at + 1 < len(starts) else len(code)
            rest = code[start:stop]
            words = []
            for token in rest.split():
                if not _WORD.fullmatch(token):
                    break
                words.append(token)
            # A bare `tailnet`, or one followed by a placeholder, names the CLI, not a command.
            if words:
                found.append((words, rest))
    return found


def resolve(words, leaves):
    """The leaf command these leading words name, or None."""
    if words[0] in leaves:
        return words[0]
    pair = " ".join(words[:2])
    return pair if pair in leaves else None


def test_every_tailnet_command_named_in_the_skill_exists_in_the_parser():
    leaves = cli.leaves(cli.build_parser())
    named = invocations(body())
    assert len(named) > 14
    for words, rest in named:
        command = resolve(words, leaves)
        assert command, f"`tailnet{rest}` names no command the parser has"
        # Every flag it shows is one that command takes: an agent copies these lines.
        options = leaves[command]._option_string_actions
        for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest):
            assert flag in options, f"`tailnet{rest}`: {command} has no {flag}"


def test_the_skill_names_all_fourteen_commands_as_the_parser_does():
    leaves = cli.leaves(cli.build_parser())
    named = {resolve(words, leaves) for words, _ in invocations(body())}
    assert named == set(leaves)
    assert len(named) == 14


def permits(rule, command):
    """Whether an allowed-tools `Bash(pattern)` rule matches this command line.

    `*` matches anything, and a trailing ` *` also matches the bare command [PERM L186].
    """
    match = re.fullmatch(r"Bash\((.+)\)", rule)
    if not match:
        return False
    pattern = match.group(1)
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    if re.fullmatch(regex, command):
        return True
    return pattern.endswith(" *") and command == pattern[:-2]


def test_allowed_tools_name_only_read_commands():
    leaves = set(cli.leaves(cli.build_parser()))
    assert READ_COMMANDS < leaves
    rules = frontmatter()["allowed-tools"]
    assert rules
    for rule in rules:
        # Each pre-approves one command, or one command word's group, and nothing else.
        match = re.fullmatch(r"Bash\(tailnet ((?:[a-z][a-z-]* ?)+) \*\)", rule)
        assert match, f"{rule} is not a Bash(tailnet <command> *) rule"
        prefix = match.group(1)
        covered = {leaf for leaf in leaves if leaf == prefix or leaf.startswith(prefix + " ")}
        assert covered, f"{rule} covers no command"
        assert covered <= READ_COMMANDS, f"{rule} pre-approves {covered - READ_COMMANDS}"
        assert "--apply" not in rule
    # And, checked the other way, no write command line slips under any rule.
    for write in leaves - READ_COMMANDS:
        line = f"tailnet {write} x --apply --reason why"
        assert not any(permits(rule, line) for rule in rules), write


def test_ask_and_deny_strings_in_the_skill_match_rules_json():
    # rules.json is the single source of the permission strings (CLAUDE.md invariant 15), so
    # a rule the skill quotes must be spelled exactly as the installer writes it.
    shipped = gate.rules()
    known = set(shipped["ask"]) | set(shipped["deny"])
    quoted = re.findall(r"\b(?:Bash|Read|Edit|Write|WebFetch|Glob|Grep)\([^()\n]*\)", body())
    assert shipped["gate"] in quoted
    unknown = sorted(set(quoted) - known)
    assert unknown == [], f"permission strings not in rules.json: {unknown}"


# --- What MC decided (DESIGN.md Amendments A1, A3) ---


def bullets(text):
    """The top-level `- ` items of a Markdown section, each joined into one line."""
    items = []
    for line in text.splitlines():
        if line.startswith("- "):
            items.append(line[2:])
        elif items and line.startswith("  ") and line.strip():
            items[-1] += " " + line.strip()
    return items


def test_the_write_client_consent_is_stated_as_mc_s_answer_not_asked():
    # A1: MC answered on 2026-10-26, so the first of the three things states the answer;
    # doctor no longer asks it, and the skill must not send an agent to ask it again.
    text = skill_text()
    start, end = section(text, "Before you start: three things MC may not realise")
    things = bullets(text[start:end])
    assert len(things) == 3
    first = things[0]
    assert "2026-10-26" in first and "two clients" in first.lower()
    assert "?" not in first
    assert "write-client-consent" not in text


def test_questions_go_one_per_turn_with_a_numbered_list_and_a_recommendation():
    # A3: MC answers from the phone, where the picker can be dismissed, so the same options
    # also go out as a numbered list, with one recommended and why.
    text = skill_text()
    start, end = section(text, "Hard rules")
    [rule] = [b for b in bullets(text[start:end]) if "AskUserQuestion" in b]
    lowered = rule.lower()
    assert "one question per turn" in lowered
    assert "numbered list" in lowered and "recommend" in lowered and "why" in lowered


# --- The references (DESIGN.md §19.3) ---

REFERENCES = SKILL_DIR / "references"
# §19.3's six files: what the skill reads on demand, beyond SKILL.md.
REFERENCE_FILES = {"tailnet-facts.md", "gotchas.md", "diagnose-port.md", "policy-workflow.md",
                   "credentials.md", "upstream-corrections.md"}
# One of our references as SKILL.md names it. A path with anything in front, such as upstream's
# `~/.claude/skills/tailscale/references/<topic>.md`, belongs to another skill.
_OUR_REFERENCE = re.compile(r"(?<![\w./~-])references/([^\s`)]+)")


def reference_text(name):
    """One reference file, as it will be installed."""
    return (REFERENCES / name).read_text(encoding="utf-8")


def test_every_reference_exists_one_level_deep():
    # Claude may read only part of a file it reaches through another reference, with head
    # -100 [pkg §3], so SKILL.md names every reference itself and none sits deeper.
    entries = sorted(REFERENCES.iterdir())
    assert all(path.is_file() and not path.is_symlink() for path in entries)
    assert {path.name for path in entries} == REFERENCE_FILES
    assert set(_OUR_REFERENCE.findall(body())) == REFERENCE_FILES
    # The index at the end gives each its own line saying when to read it.
    text = skill_text()
    start, end = section(text, "References")
    indexed = [_OUR_REFERENCE.findall(item) for item in bullets(text[start:end])]
    assert sorted(name for names in indexed for name in names) == sorted(REFERENCE_FILES)


def github_anchor(heading):
    """The anchor GitHub gives a heading: lowercased, punctuation dropped, spaces as hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def test_reference_files_over_100_lines_start_with_contents():
    # A reference over 100 lines opens with a table of contents [pkg §3], so even a partial
    # read shows everything the file holds and where.
    long_files = [name for name in sorted(REFERENCE_FILES)
                  if len(reference_text(name).splitlines()) > 100]
    assert long_files
    for name in long_files:
        text = reference_text(name)
        headings = re.findall(r"^## (.+)$", text, re.MULTILINE)
        assert headings and headings[0] == "Contents", f"{name}: the first section is not Contents"
        start, end = section(text, "Contents")
        assert text[:start].count("\n") < 30, f"{name}: Contents starts too far down"
        # Its list names every other section, in order, by the anchor each link points at.
        links = re.findall(r"^(?:\d+\.|-) \[[^\]]+\]\(#([^)\s]+)\)$", text[start:end],
                           re.MULTILINE)
        assert links == [github_anchor(h) for h in headings[1:]], name


def test_upstream_corrections_flags_api_md_100_103():
    # Upstream posts {"src","dst"} to the preview endpoint, which takes `type` and
    # `previewFor` and a policy file as its body [spec 2381-2440]: copied, the request fails
    # (§14.5). The corrections file must say so, and say that it wins over upstream.
    text = reference_text("upstream-corrections.md")
    assert "This file wins" in text[:text.index("## ")]
    rows = [line for line in text.splitlines()
            if line.startswith("|") and "`references/api.md:100-103`" in line]
    assert any("**Wrong**" in row and "previewFor" in row and "policy file" in row
               for row in rows)


def test_tailnet_facts_opens_with_the_staleness_rule():
    # §19.3: every row there is a dated claim about the past, so the rule comes before any.
    text = reference_text("tailnet-facts.md")
    opening = text[:text.index("## ")]
    assert "Staleness rule" in opening and "tailnet device list --json" in opening


def test_credentials_reference_records_mc_s_answer_and_keeps_the_consent_text():
    # A1: the reference records MC's 2026-10-26 answer instead of asking again, and keeps
    # the consent text as the record of what MC accepted.
    text = reference_text("credentials.md")
    start, end = section(text, "1. What MC accepted (2026-10-26)")
    record = text[start:end]
    assert "Devices → Core: Write reaches every device" in record
    assert "MC chose **Two clients**" in record and "Do not ask again" in record


def test_credentials_reference_names_every_form_a_protected_entry_takes():
    # A59: an entry names a device in any form a DEVICE argument takes, and a line naming no
    # device is warned of in every tag plan; MC hand-writes the file, so the reference says so.
    text = reference_text("credentials.md")
    start, end = section(text, "5. The protected file")
    part = text[start:end]
    for form in ("nodeId", "legacy id", "hostname", "MagicDNS name", "first label",
                 "Tailscale address", "PROTECTED_LINE_UNMATCHED"):
        assert form in part, form


def test_every_reference_file_ends_with_its_dated_sources():
    # §19.3: every fact carries its source and date, so each file ends with what it rests on
    # and when that was read.
    for name in sorted(REFERENCE_FILES):
        text = reference_text(name)
        last = re.findall(r"^## (.+)$", text, re.MULTILINE)[-1]
        assert re.fullmatch(r"(?:\d+\. )?Sources", last), f"{name} does not end with its sources"
        start, end = section(text, last)
        # Its opening line says when they were read, which is the date every fact carries.
        assert re.search(r"^Read\b.*\b20\d\d-\d\d-\d\d\b", text[start:end], re.MULTILINE), \
            f"{name}: the sources do not say when they were read"
