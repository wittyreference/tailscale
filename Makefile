# ABOUTME: Entry points for tailnet: make venv, test and e2e for development; make install-dry-run shows
# ABOUTME: what install-tailnet.sh would change; install and uninstall run that script by name (§20).

PYTHON ?= python3
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test e2e install-dry-run

# The venv's python is the only file target, and the venv is made before pip installs into it,
# so a failed install (offline, say) would leave a python make reads as up to date, and every
# later `make test` would stop on a missing pytest. On a failed recipe make deletes the target.
.DELETE_ON_ERROR:

# pytest and ruff are development-only; the CLI itself imports nothing outside the
# stdlib (DESIGN.md §3.1). Pinned so the 3.10 floor and the droplet run the same tools.
venv: $(PY)

$(PY):
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install --quiet pytest==9.1.1 ruff==0.17.2

# Unit, integration and hook tests, loopback only. pyproject.toml names the tiers and
# turns every warning into a failure, so a pass here is a pristine pass.
test: $(PY)
	$(PY) -m pytest

# The read-only suite against the real API (§21.4), run on the droplet with MC's read
# credential. Without one, or without a Running tailscale, its conftest stops with exit 3
# naming what is missing; it never skips. The manual checks M1-M4 (§21.5) print only after
# a passing run, so a failure is always the last thing on the screen.
e2e: $(PY)
	$(PY) -m pytest tests/e2e
	@$(PY) -I tests/e2e/manual_checks.py

# The dry run prints every change the installer would make and makes none (§20.6). There is
# no install or uninstall target: Claude Code's `Bash(*install-tailnet*)` ask rule matches the
# command text an agent writes, never what make runs, so `make install` would replace the
# guard's code, and `make uninstall` take out the gate rules, without asking MC (D29). Run
# ./install-tailnet.sh and ./install-tailnet.sh --uninstall by name.
install-dry-run:
	./install-tailnet.sh --dry-run
