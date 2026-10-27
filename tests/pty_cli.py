# ABOUTME: Runs the tailnet CLI on a real terminal for the credentials tests: pty.fork, then each prompt is
# ABOUTME: answered from a script, so getpass reads a terminal exactly as it does in MC's SSH session.

# Usage: python -I tests/pty_cli.py SCRIPT_JSON ARGS...
#   SCRIPT_JSON is a list of [prompt, answer] pairs: wait for the prompt, then type the answer
#   and Enter. Prints {"exit": N, "transcript": "..."} on stdout: everything the terminal showed.
#
# It is its own process because forking the pytest process, which runs the loopback server's
# threads, is unsafe and warns on Python 3.12+; this one has a single thread.

import json
import os
import pty
import select
import signal
import sys
import time
from pathlib import Path

RUN_CLI = Path(__file__).resolve().parent / "run_cli.py"
# Long enough for a slow CI box to start Python and mint over loopback; short enough that a
# prompt the CLI never prints fails the test rather than hanging it.
WAIT = 30


def _read(fd, transcript):
    """Append whatever the terminal has, waiting up to a tenth of a second; False at its end.

    On Linux the controlling side reads EIO once the child has exited and closed the terminal.
    """
    ready, _, _ = select.select([fd], [], [], 0.1)
    if not ready:
        return True
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        return False
    transcript.extend(chunk)
    return bool(chunk)


def main():
    """Fork the CLI onto a new terminal, play the script against it, and report the result."""
    script = json.loads(sys.argv[1])
    pid, fd = pty.fork()
    if pid == 0:
        # The child: a session leader whose controlling terminal is the new pty, which is what
        # getpass opens as /dev/tty. run_cli installs netguard before the CLI starts.
        os.execv(sys.executable, [sys.executable, "-I", str(RUN_CLI), *sys.argv[2:]])
    transcript, seen, alive = bytearray(), 0, True
    for prompt, answer in script:
        marker = prompt.encode("utf-8")
        deadline = time.monotonic() + WAIT
        while alive and transcript.find(marker, seen) < 0 and time.monotonic() < deadline:
            alive = _read(fd, transcript)
        found = transcript.find(marker, seen)
        if found < 0:
            break
        seen = found + len(marker)
        os.write(fd, answer.encode("utf-8") + b"\n")
    deadline = time.monotonic() + WAIT
    while alive and time.monotonic() < deadline:
        alive = _read(fd, transcript)
    # The terminal closes a moment before the child can be reaped, so give it that moment.
    reap_by = time.monotonic() + 5
    finished, status = os.waitpid(pid, os.WNOHANG)
    while finished == 0 and time.monotonic() < reap_by:
        time.sleep(0.05)
        finished, status = os.waitpid(pid, os.WNOHANG)
    if finished == 0:
        # Still waiting for an answer the script did not have: end it rather than hang.
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
    os.close(fd)
    print(json.dumps({"exit": os.waitstatus_to_exitcode(status),
                      "transcript": transcript.decode("utf-8", "replace")}))


if __name__ == "__main__":
    main()
