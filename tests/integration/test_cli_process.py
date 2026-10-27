# ABOUTME: Integration tests for the CLI as a real process: tests/run_cli.py launches it under netguard
# ABOUTME: in test posture, and stdout holds exactly one envelope while stderr carries the banner.

import ast
import json
from pathlib import Path

RUN_CLI = Path(__file__).resolve().parents[1] / "run_cli.py"


def test_the_cli_process_prints_one_envelope_and_the_test_banner(cli, loopback):
    result = cli("--json", "dns")
    assert result.returncode == 3
    env = json.loads(result.stdout)
    assert (env["command"], env["posture"], env["error"]["code"]) == (
        "dns", "test", "CREDENTIAL_MISSING")
    assert result.stderr.startswith(
        f"TEST POSTURE: API {loopback.base_url}, home {cli.home.resolve()}. "
        "Nothing here touches the real tailnet.\n")
    # With no read credential in the test home, nothing is contacted.
    assert loopback.requests == []


def test_a_usage_error_in_the_process_exits_2(cli):
    result = cli("device", "tag", "pi5", "--add", "tag:fleet", "--appl")
    assert result.returncode == 2
    assert result.stdout.startswith("USAGE: ")


def test_the_launcher_installs_netguard_before_the_cli_loads():
    # The CLI process must be held to the suite's rule from its first line (§21.1): the guard
    # is installed before anything from tailnet is imported.
    tree = ast.parse(RUN_CLI.read_text(encoding="utf-8"))
    order = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            modules = []
        if any(module.split(".")[0] == "tailnet" for module in modules):
            order.append("import tailnet")
        elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
              and ast.unparse(node.value.func) == "netguard.install"):
            order.append("install")
    assert order[:2] == ["install", "import tailnet"]
