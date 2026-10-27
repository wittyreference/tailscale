# ABOUTME: Tests for tests/netguard.py, the audit hook that keeps the default suite on loopback.
# ABOUTME: Decisions are checked directly on real (never connected) sockets and real argv shapes.

import socket

import netguard
import pytest


def connect_verdict(family, address):
    """Ask netguard about a connect from a socket of the given family; nothing is sent."""
    return netguard.address_violation(family, address)


def test_a_connect_event_is_judged_by_its_real_socket_family():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        assert netguard.violation("socket.connect", (sock, ("127.0.0.1", 80))) is None
        assert "loopback" in netguard.violation("socket.connect", (sock, ("192.0.2.1", 9)))


@pytest.mark.parametrize("family,address", [
    (socket.AF_INET, ("127.0.0.1", 80)),
    (socket.AF_INET, ("127.5.5.5", 22)),
    (socket.AF_INET6, ("::1", 80, 0, 0)),
    (socket.AF_INET6, ("::ffff:127.0.0.1", 80, 0, 0)),
])
def test_a_connect_to_a_loopback_address_is_allowed(family, address):
    assert connect_verdict(family, address) is None


@pytest.mark.parametrize("family,address", [
    (socket.AF_INET, ("192.0.2.1", 9)),
    (socket.AF_INET, ("100.64.0.1", 22)),
    (socket.AF_INET, ("10.0.0.1", 443)),
    (socket.AF_INET, ("0.0.0.0", 80)),
    (socket.AF_INET6, ("2001:db8::1", 80, 0, 0)),
    (socket.AF_INET6, ("::ffff:192.0.2.1", 80, 0, 0)),
])
def test_a_connect_off_loopback_is_refused(family, address):
    assert "loopback" in connect_verdict(family, address)


@pytest.mark.parametrize("host", ["localhost", "api.tailscale.com", "127.0.0.1.example.com"])
def test_a_connect_by_host_name_is_refused(host):
    # The kernel never sees a name; a connect by name resolves it first, which leaves the box.
    assert connect_verdict(socket.AF_INET, (host, 80)) is not None


def test_a_unix_socket_connect_is_allowed(tmp_path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        assert netguard.violation("socket.connect", (sock, str(tmp_path / "s"))) is None


def test_a_datagram_sent_off_loopback_is_refused():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        assert netguard.violation("socket.sendto", (sock, ("192.0.2.1", 53))) is not None
        assert netguard.violation("socket.sendto", (sock, ("127.0.0.1", 53))) is None
        assert netguard.violation("socket.sendmsg", (sock, None)) is None


@pytest.mark.parametrize("event,args", [
    ("socket.getaddrinfo", ("localhost", 80, 0, 0, 0)),
    ("socket.getaddrinfo", ("127.0.0.1", 80, 0, 0, 0)),
    ("socket.getaddrinfo", (None, 80, 0, 0, 0)),
    ("socket.gethostbyname", ("localhost",)),
    ("socket.gethostbyaddr", ("127.0.0.1",)),
])
def test_local_name_lookups_are_allowed(event, args):
    assert netguard.violation(event, args) is None


@pytest.mark.parametrize("event,args", [
    ("socket.getaddrinfo", ("api.tailscale.com", 443, 0, 0, 0)),
    ("socket.getaddrinfo", ("localhost.evil", 80, 0, 0, 0)),
    ("socket.gethostbyname", ("evil.example",)),
    ("socket.gethostbyname_ex", ("evil.example",)),
    ("socket.gethostbyaddr", ("192.0.2.1",)),
    ("socket.gethostbyaddr", ("claude-factory",)),
])
def test_a_name_lookup_that_would_query_a_resolver_is_refused(event, args):
    # A DNS query leaves the box even when no connect follows it.
    assert netguard.violation(event, args) is not None


@pytest.mark.parametrize("event,args", [
    ("subprocess.Popen", ("tailscale", ["tailscale", "status"], None, None)),
    ("subprocess.Popen", ("/usr/bin/tailscale", ["/usr/bin/tailscale", "version"], None, None)),
    ("subprocess.Popen", (b"/usr/bin/tailscale", [b"/usr/bin/tailscale"], None, None)),
    ("subprocess.Popen", ("env", ["env", "tailscale", "ping", "pi5"], None, None)),
    ("subprocess.Popen", ("/bin/sh", ["/bin/sh", "-c", "tailscale status --json"], None, None)),
    ("subprocess.Popen", ("/bin/sh", ["/bin/sh", "-c", "echo hi; /usr/sbin/tailscale up"], None, None)),
    ("os.exec", ("/usr/bin/tailscale", ["tailscale", "status"], None)),
    ("os.posix_spawn", ("/usr/bin/tailscale", ["tailscale"], None)),
    ("os.spawn", (0, "/usr/bin/tailscale", ["tailscale"], None)),
    ("os.system", (b"x=$(tailscale ip -4)",)),
])
def test_every_way_of_running_tailscale_is_refused(event, args):
    assert "tailscale" in netguard.violation(event, args)


def test_other_programs_and_a_directory_named_tailscale_are_allowed(tmp_path):
    checkout = tmp_path / "tailscale"
    checkout.mkdir()
    assert netguard.violation("subprocess.Popen", ("git", ["git", "-C", str(checkout), "log"],
                                                   None, None)) is None
    assert netguard.violation("subprocess.Popen", ("/bin/sh", ["/bin/sh", "-c", f"ls {checkout}/"],
                                                   None, None)) is None
    assert netguard.violation("os.exec", ("/usr/bin/python3", ["python3", "-V"], None)) is None


def test_events_netguard_does_not_watch_pass():
    assert netguard.violation("open", ("/etc/hosts", "r", 0)) is None


@pytest.mark.parametrize("proxy", ["http://127.0.0.1:42185", "http://user:pw@localhost:42185/",
                                   "socks5://[::1]:42185"])
def test_a_connect_to_a_loopback_proxy_is_refused(proxy):
    # A proxy listening on loopback forwards whatever it is sent off the box, so reaching it
    # is leaving loopback in all but address.
    proxies = [proxy]
    family = socket.AF_INET6 if "[" in proxy else socket.AF_INET
    host = "::1" if "[" in proxy else "127.0.0.1"
    assert "proxy" in netguard.address_violation(family, (host, 42185), proxies=proxies)
    assert netguard.address_violation(family, (host, 42186), proxies=proxies) is None


def test_the_proxies_come_from_the_environment_at_connect_time(monkeypatch):
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            with pytest.raises(netguard.NetguardViolation, match="proxy"):
                sock.connect(("127.0.0.1", port))
