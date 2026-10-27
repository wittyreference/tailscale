# ABOUTME: e2e helper for E9: one real `tailscale ping --tsmp` through tailnet's localts, printed as JSON. No
# ABOUTME: tailnet command pings an address outside the inventory, and the e2e pytest process never runs tailscale.

import json
import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
OVERRIDES = ("TAILNET_API_BASE", "TAILNET_HOME")
# diagnose's own probe timeout (§15.2 step 4), so E9 measures the exit codes diagnose reads.
PING_TIMEOUT = 5


def main(argv):
    """Ping one Tailscale address once with TSMP and print {ip, exit, output, measured_at}.

    The exit status is what diagnose reads as `path_ok`, and what it means on a timeout is
    the open question E9 settles [unverified, §15.2], so it is printed exactly, never judged.
    """
    present = [name for name in OVERRIDES if name in os.environ]
    if present:
        raise SystemExit(f"ping_live: {' and '.join(present)} set: this helper runs tailscale in "
                         "production posture only; unset it")
    if len(argv) != 1:
        raise SystemExit("usage: ping_live.py TAILSCALE-IP")
    # -I keeps PYTHONPATH and this directory off sys.path, so the package comes from the repo.
    sys.path.insert(0, str(SRC))
    from tailnet import localts
    from tailnet.output import now_utc
    from tailnet.posture import Posture

    posture = Posture.from_env(os.environ)
    measured_at = now_utc()
    result = localts.ping(posture, argv[0], "tsmp", PING_TIMEOUT)
    print(json.dumps({"ip": argv[0], "exit": result.exit, "output": result.output,
                      "measured_at": measured_at}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
