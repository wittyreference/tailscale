# ABOUTME: Developer entry points for tailnet: make venv, make test, make e2e.
# ABOUTME: install, install-dry-run and uninstall arrive with the installer (DESIGN.md §29 item 29).

PYTHON ?= python3
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test e2e

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

# The read-only suite against the real API is §29 item 32. Until it exists this target
# fails rather than passing on nothing, so nobody reads a green e2e that never ran.
e2e:
	@echo "make e2e: the end-to-end suite (DESIGN.md §21.4) is not built yet; it lands with §29 item 32. Nothing was run." >&2
	@exit 1
