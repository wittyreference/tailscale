# ABOUTME: `python -m tailnet` runs the CLI, exactly as the installed launcher does (DESIGN.md §4).
# ABOUTME: The exit status is the one main() returns, from the §5.3 table.

import sys

from tailnet.cli import main

sys.exit(main())
