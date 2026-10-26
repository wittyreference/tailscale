# ABOUTME: Test-process guard: an audit hook that refuses any network traffic off loopback and any
# ABOUTME: attempt to run the tailscale binary, so no test can reach the real API or the real tailnet.

import ipaddress
import os
import re
import socket
import sys

# A word "tailscale" inside a shell command line: preceded by a separator or a path slash,
# followed by a separator. A trailing "/" means a directory of that name, which is allowed.
_SHELL_WORD = re.compile(r"(?:^|[\s;&|()`'\"/=])tailscale(?=$|[\s;&|()`'\"])")
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
_BINARY = "tailscale"


class NetguardViolation(RuntimeError):
    """Raised inside the offending call when a test tries to leave loopback or run tailscale.

    Raising from an audit hook aborts the operation before anything is sent or executed,
    which is the point: the suite fails loudly instead of quietly touching the tailnet.
    """


def _loopback_ip(text):
    """Return True for a literal loopback address, False for any other literal, None for a name."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    # ::ffff:127.0.0.1 is IPv4 loopback carried in IPv6; judge it as the IPv4 it is.
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def address_violation(family, address, verb="connect to"):
    """Judge one destination address for a socket family; None means it stays on this machine.

    Takes the family rather than a socket so the rule can be tested on a host without IPv6.
    """
    if family == socket.AF_UNIX:
        return None
    if family not in (socket.AF_INET, socket.AF_INET6):
        return f"netguard: refused to {verb} on socket family {family!r}: tests stay on loopback"
    host = address[0]
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    verdict = _loopback_ip(host)
    if verdict is None:
        # A name is resolved before the kernel sees it, and that lookup can leave the box.
        return f"netguard: refused to {verb} {host!r} by name: tests use literal loopback addresses"
    if not verdict:
        return f"netguard: refused to {verb} {host}: tests never leave loopback"
    return None


def _lookup_violation(host, reverse):
    """Judge a name lookup: only lookups a resolver never answers over the network pass."""
    if host is None:
        return None
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if host == "localhost":
        return None
    verdict = _loopback_ip(host)
    # A forward lookup of any literal is parsed locally. A reverse lookup of a literal
    # asks a resolver about it, so only loopback literals stay local.
    if verdict is True or (verdict is False and not reverse):
        return None
    return f"netguard: refused to resolve {host!r}: a DNS query leaves loopback"


def _names_tailscale(word):
    """Say whether one argv word would run the tailscale binary.

    A bare word is a program name to a wrapper like env or sudo, whatever the current
    directory holds; only a path that is a directory (a checkout named tailscale) passes.
    """
    word = os.fsdecode(word)
    if os.path.basename(word) != _BINARY:
        return False
    return "/" not in word or not os.path.isdir(word)


def _exec_violation(executable, argv):
    """Judge one process launch: refuse tailscale run directly, via a wrapper, or via a shell."""
    words = [os.fsdecode(word) for word in argv or []]
    if executable is not None:
        words.insert(0, os.fsdecode(executable))
    shell = bool(words) and os.path.basename(words[0]) in _SHELLS and "-c" in words
    for word in words:
        # Every word is checked, not just the first: `env tailscale` and `sudo tailscale`
        # run it too.
        if _names_tailscale(word) or (shell and _SHELL_WORD.search(word)):
            return f"netguard: refused to run tailscale ({' '.join(words)}): tests never run it"
    return None


def violation(event, args):
    """Return why an audit event must be refused, or None if it is allowed.

    Pure apart from reading socket families and checking whether a path is a directory,
    so each rule can be tested without sending or running anything.
    """
    if event == "socket.connect":
        return address_violation(args[0].family, args[1], "connect to")
    if event in ("socket.sendto", "socket.sendmsg"):
        # sendmsg on a connected socket carries no address; its connect was already judged.
        if args[1] is None:
            return None
        return address_violation(args[0].family, args[1], "send to")
    if event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"):
        return _lookup_violation(args[0], reverse=False)
    if event == "socket.gethostbyaddr":
        return _lookup_violation(args[0], reverse=True)
    if event == "subprocess.Popen":
        return _exec_violation(args[0], args[1])
    if event in ("os.exec", "os.posix_spawn"):
        return _exec_violation(args[0], args[1])
    if event == "os.spawn":
        return _exec_violation(args[1], args[2])
    if event == "os.system":
        command = os.fsdecode(args[0])
        if _SHELL_WORD.search(command):
            return f"netguard: refused to run tailscale ({command}): tests never run it"
    return None


_WATCHED = frozenset({
    "socket.connect", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr",
    "subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system",
})
_installed = False


def _hook(event, args):
    """The audit hook itself: every audited event in the process passes through here."""
    if event in _WATCHED:
        message = violation(event, args)
        if message is not None:
            raise NetguardViolation(message)


def install():
    """Install the guard in this process.

    Audit hooks cannot be removed once added, so the guard holds for the rest of the
    process and a second call is a no-op rather than a second hook.
    """
    global _installed
    if not _installed:
        sys.addaudithook(_hook)
        _installed = True
