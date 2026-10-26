# ABOUTME: Tests for README.md, MC's guide (DESIGN.md §25): its outline, every command it names held to the
# ABOUTME: parser and the Makefile, and the phone-sized shape it promises: short paragraphs, one command a block.

import re
from pathlib import Path

from test_skill import code_texts, invocations, resolve

from tailnet import cli

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"

# §25's outline after the opening lines, in order; each heading must hold its words.
OUTLINE = [
    "Three things you may not realise",
    "The levers",
    "First run",
    "Tailscale console",
    "Disarm, revoke, uninstall",
    "For developers",
]
# A paragraph or list item longer than this does not fit a phone screen without scrolling.
MAX_WORDS = 60


def text():
    """README.md as MC reads it."""
    return README.read_text(encoding="utf-8")


def sections():
    """Each `## ` section's heading and body, in order."""
    parts = re.split(r"^## (.+)$", text(), flags=re.MULTILINE)
    return list(zip(parts[1::2], parts[2::2]))


def section(words):
    """The body of the one section whose heading holds `words`."""
    [body] = [body for head, body in sections() if words.lower() in head.lower()]
    return body


def prose_units(body):
    """Each paragraph and each list item outside code blocks and tables, as one string."""
    units, current, fenced = [], [], False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        starts_item = re.match(r"(?:[-*]|\d+\.) ", stripped)
        if fenced or not stripped or stripped.startswith(("|", "#")) or starts_item:
            if current:
                units.append(" ".join(current))
            current = [stripped] if starts_item and not fenced else []
            continue
        current.append(stripped)
    if current:
        units.append(" ".join(current))
    return units


def codes(body):
    """Every code span and code block line in `body`, without the indent a list item gives it."""
    return [code.strip() for code in code_texts(body)]


def fenced_blocks(body):
    """The lines of each fenced code block, a block indented under a list item included."""
    found = re.findall(r"^[ \t]*```[a-z]*\n(.*?)^[ \t]*```", body,
                       flags=re.MULTILINE | re.DOTALL)
    return [block.strip("\n").splitlines() for block in found]


def test_the_readme_follows_the_design_s_outline():
    heads = [head for head, _ in sections()]
    assert len(heads) == len(OUTLINE), heads
    for head, words in zip(heads, OUTLINE):
        assert words.lower() in head.lower(), (head, words)
    # What it is, in three lines, under the title and before the first section.
    title, *intro = [line for line in text().split("\n## ", 1)[0].splitlines() if line.strip()]
    assert title.startswith("# ") and 1 <= len(intro) <= 3, intro
    assert "claude-factory" in " ".join(intro) and "only" in " ".join(intro)


def test_every_tailnet_command_in_the_readme_exists_in_the_parser():
    leaves = cli.leaves(cli.build_parser())
    named = invocations(text())
    assert len(named) >= 10
    for words, rest in named:
        command = resolve(words, leaves)
        assert command, f"`tailnet{rest}` names no command the parser has"
        options = leaves[command]._option_string_actions
        for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", rest):
            assert flag in options, f"`tailnet{rest}`: {command} has no {flag}"


def test_every_make_target_and_installer_flag_in_the_readme_exists():
    makefile = (REPO / "Makefile").read_text(encoding="utf-8")
    targets = re.search(r"^\.PHONY:(.*)$", makefile, flags=re.MULTILINE).group(1).split()
    installer = (REPO / "install-tailnet.sh").read_text(encoding="utf-8")
    for code in codes(text()):
        for target in re.findall(r"(?<![\w./-])make ([a-z][a-z0-9-]*)", code):
            assert target in targets, f"`{code}`: the Makefile has no {target} target"
        if "install-tailnet.sh" in code:
            for flag in re.findall(r"(?<![\w-])--[a-z][a-z-]*", code):
                assert flag in installer, f"`{code}`: the installer takes no {flag}"


def test_the_three_things_each_carry_their_read_only_command():
    body = section("Three things")
    for command in ("tailnet status", "tailnet diagnose spec5 --from iphone192 --ssh-user spec5",
                    "tailnet device list"):
        assert command in codes(body), command
    assert "TAGGED_KEY_EXPIRY_ON" in body and "2026-10-26" in body


def test_the_levers_are_in_plain_words_with_both_postures():
    body = section("The levers")
    assert "standing" in body.lower() and "session-scoped" in body.lower()
    assert "one enforced surface, not the whole surface" in body
    for lever in ("ask", "write secret", "deny", "audit log", "revoke"):
        assert lever in body.lower(), lever


def test_each_first_run_step_says_whose_hands_it_needs():
    steps = re.findall(r"^\d+\. (.*)$", section("First run"), flags=re.MULTILINE)
    assert len(steps) >= 8
    for step in steps:
        assert re.match(r"\*\*(MC|Agent)\b", step), step
    body = section("First run")
    for command in ("tailnet credentials set read", "tailnet doctor", "make e2e"):
        assert command in codes(body), command


def test_the_console_section_names_each_event_mc_will_see():
    body = section("Tailscale console")
    for event in ("Create OAuth access token", "Failed request", "Update tags",
                  "Disable key expiry", "90 days"):
        assert event in body, event
    # Whether a write's actor is the OAuth client is not established (credentials research §9).
    assert "[unverified]" in body


def test_disarm_is_not_revocation_and_only_mc_revokes():
    body = section("Disarm, revoke, uninstall")
    for command in ("tailnet credentials forget write", "./install-tailnet.sh --uninstall",
                    "sudo chattr +a ~/.local/state/tailnet/audit.jsonl"):
        assert command in codes(body), command
    assert "not revocation" in body and "Trust credentials" in body


def test_every_code_block_holds_exactly_one_command():
    blocks = fenced_blocks(text())
    # The blocks under first-run steps are indented; they must be seen too, not only the rest.
    assert any(lines[0].startswith(" ") for lines in blocks)
    assert any(not lines[0].startswith(" ") for lines in blocks)
    for lines in blocks:
        assert len([line for line in lines if line.strip()]) == 1, lines


def test_paragraphs_stay_phone_sized():
    for unit in prose_units(text()):
        assert len(unit.split()) <= MAX_WORDS, f"{len(unit.split())} words: {unit[:80]}…"
