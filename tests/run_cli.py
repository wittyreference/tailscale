# ABOUTME: Integration launcher: installs netguard in the CLI process, then runs the real tailnet CLI.
# ABOUTME: Run as `python -I tests/run_cli.py ARGS…`, so each CLI process is held to the suite's rule.

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
# -I leaves this script's directory and PYTHONPATH off sys.path, so both are named here.
sys.path[:0] = [str(TESTS), str(TESTS.parent / "src")]

import netguard

# Installed before anything from tailnet is imported, so the CLI never runs unguarded: a
# connect off loopback or any attempt to run tailscale crashes the process (§21.1).
netguard.install()

from tailnet.cli import main

sys.exit(main())
