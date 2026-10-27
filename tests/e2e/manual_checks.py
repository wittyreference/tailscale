# ABOUTME: Prints the manual checks M1-M4 (DESIGN.md §21.5) that `make e2e` shows after a passing run. MC runs
# ABOUTME: each once, by hand: they prove the ask gate and the skill in sessions no automated test can stand in for.

import sys

# An unsupervised `claude -p` agent cannot test the ask rule, because headless runs deny the
# call instead of prompting [PM L56]; these replace that test (§21.5, J1 must_fix).
CHECKS = (
    ("M1", ("In `claude --dangerously-skip-permissions`, ask the agent to dry-run "
            "`tailnet device disable-key-expiry <a tagged device whose expiry is already "
            "disabled>`, then to run the apply line it prints. Expect the permission prompt: "
            "ask rules prompt even in bypass mode [PM L34-36]. Approve or deny; either way "
            "nothing is sent, because that target is a no-op.")),
    ("M2", ("The same as M1 in auto mode. Expect the same prompt: ask rules still force one "
            "there [PM L327].")),
    ("M3", ("In a Manual-mode session, type `/tailnet`. Expect the injected status to render, "
            "because the skill's allowed-tools cover it [SK L791].")),
    ("M4", ("Run `claude mcp login tailscale-docs --no-browser` and finish the login from "
            "your phone. Expect it to complete there.")),
)


def text():
    """The checks as MC reads them on a phone: one numbered paragraph each."""
    lines = ["Manual checks (DESIGN.md §21.5): run each once, interactively, on claude-factory."]
    lines += [f"{label}. {check}" for label, check in CHECKS]
    return "\n".join(lines) + "\n"


def main():
    """Print the checks."""
    sys.stdout.write(text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
