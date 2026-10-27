#!/usr/bin/env bash
# ABOUTME: Installs tailnet for the user who runs it: needs Python 3.10 or later and refuses root, then runs
# ABOUTME: install.py isolated (-I). Options: --dry-run (or DRY_RUN=1), --uninstall, --no-upstream, --no-mcp.

set -euo pipefail

# Everything lands in the invoking user's home. Run as root, the credentials directory, the
# launcher and the Claude Code settings would land in root's home, not MC's.
if [ "$(id -u)" -eq 0 ]; then
    echo "install-tailnet: refusing to run as root: the credentials directory, the launcher and" \
         "the Claude Code settings would land in root's home, not yours. Run it as yourself." >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "install-tailnet: python3 is not on PATH; tailnet needs Python 3.10 or later." >&2
    exit 1
fi

# The CLI is written for 3.10 and later: older ones lack the syntax and library it uses.
if ! python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "install-tailnet: tailnet needs Python 3.10 or later; python3 is" \
         "$(python3 -I -c 'import sys; print(sys.version.split()[0])')." >&2
    exit 1
fi

# The checkout this script sits in, wherever it is run from.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# -I keeps PYTHONPATH, the user site and the current directory off sys.path, so nothing
# beside this checkout can stand in for the code being installed.
exec python3 -I "$here/installer/install.py" "$@"
