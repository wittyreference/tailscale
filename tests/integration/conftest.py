# ABOUTME: Integration harness: runs the real CLI as its own process through tests/run_cli.py, in test
# ABOUTME: posture against the loopback seam, with the minimal environment DESIGN.md §21.1 describes.

import subprocess
import sys
from pathlib import Path

import pytest

from tailnet.posture import Posture

TESTS = Path(__file__).resolve().parents[1]
RUN_CLI = TESTS / "run_cli.py"


class Cli:
    """Runs `tailnet ARGS…` as a separate process pointed at one loopback seam and one test home.

    The environment is built from nothing, so no variable from the developer's shell (a
    proxy, a real HOME, PYTHONPATH) can reach the process; -I keeps the rest out.
    """

    def __init__(self, base_url, tmp_path):
        self.home = tmp_path / "tn"
        self.env = {
            "TAILNET_API_BASE": base_url,
            "TAILNET_HOME": str(self.home),
            "HOME": str(tmp_path),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
        }

    def __call__(self, *args, env=None, unset=(), timeout=60, text=True):
        """Run one command; return the CompletedProcess with text stdout and stderr.

        `env` adds or replaces variables and `unset` removes them, so a test can run the
        process with an override missing as well as with one changed. `text=False` keeps
        the output as bytes, untouched by newline translation, for byte-for-byte checks.
        """
        environ = {name: value for name, value in {**self.env, **(env or {})}.items()
                   if name not in unset}
        return subprocess.run([sys.executable, "-I", str(RUN_CLI), *args], capture_output=True,
                              text=text, env=environ, timeout=timeout, check=False)


@pytest.fixture
def cli(loopback, tmp_path):
    """The CLI as a process, in test posture at this test's loopback seam."""
    return Cli(loopback.base_url, tmp_path)


@pytest.fixture
def home(cli, tmp_path):
    """The posture the CLI process will decide, built here so a test can lay out its files."""
    environ = {name: cli.env[name] for name in ("TAILNET_API_BASE", "TAILNET_HOME")}
    return Posture.from_env(environ, real_home=tmp_path / "real")
