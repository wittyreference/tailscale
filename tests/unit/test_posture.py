# ABOUTME: Tests for tailnet.posture: production versus test posture, the override rules and every path
# ABOUTME: (DESIGN.md §7). The override is the only way a run is pointed anywhere but the real API.

import dataclasses
import os
import pwd
import urllib.request
from pathlib import Path

import pytest

from tailnet import errors
from tailnet.posture import Posture, all_loopback

PRODUCTION_API = "https://api.tailscale.com/api/v2"


def override(base, home):
    """An environment that asks for test posture with this base URL and home."""
    return {"TAILNET_API_BASE": base, "TAILNET_HOME": str(home)}


def refusal(environ, real_home):
    """Run from_env expecting a refusal; return the LocalError it raised."""
    with pytest.raises(errors.LocalError) as caught:
        Posture.from_env(environ, real_home=real_home)
    return caught.value


def test_no_override_is_production_with_the_tailscale_api(tmp_path):
    posture = Posture.from_env({}, real_home=tmp_path)
    assert posture.kind == "production"
    assert posture.api_base == PRODUCTION_API
    assert posture.config_dir == tmp_path / ".config" / "tailnet"
    assert posture.state_dir == tmp_path / ".local" / "state" / "tailnet"
    assert posture.drafts_dir == tmp_path / ".local" / "state" / "tailnet" / "drafts"
    assert posture.claude_settings == tmp_path / ".claude" / "settings.json"
    assert posture.runs_tailscale is True
    # None is urllib's "use the environment's proxies": production honours HTTPS_PROXY.
    assert posture.proxies is None


def test_claude_config_dir_moves_the_settings_file_in_production(tmp_path):
    elsewhere = tmp_path / "claude-config"
    posture = Posture.from_env({"CLAUDE_CONFIG_DIR": str(elsewhere)}, real_home=tmp_path)
    assert posture.claude_settings == elsewhere / "settings.json"


def test_loopback_override_with_a_test_home_is_test_posture(tmp_path):
    home = tmp_path / "tn"
    posture = Posture.from_env(override("http://127.0.0.1:8080", home), real_home=tmp_path / "real")
    assert posture.kind == "test"
    assert posture.api_base == "http://127.0.0.1:8080/api/v2"
    assert posture.runs_tailscale is False
    # A trailing slash names the same server and must not double the separator.
    slash = Posture.from_env(override("http://127.0.0.1:8080/", home), real_home=tmp_path / "real")
    assert slash.api_base == "http://127.0.0.1:8080/api/v2"


def test_localhost_is_accepted_only_if_it_resolves_to_loopback(tmp_path):
    # This machine's own resolver answers for localhost from its hosts file.
    posture = Posture.from_env(override("http://localhost:9", tmp_path / "tn"),
                               real_home=tmp_path / "real")
    assert posture.api_base == "http://localhost:9/api/v2"
    # The rule the lookup is held to: every address loopback, and at least one address.
    assert all_loopback(["127.0.0.1", "::1"]) is True
    assert all_loopback(["127.0.0.1", "10.0.0.1"]) is False
    assert all_loopback(["192.0.2.7"]) is False
    assert all_loopback(["::ffff:10.0.0.1"]) is False
    assert all_loopback(["not-an-address"]) is False
    assert all_loopback([]) is False


@pytest.mark.parametrize("host", [
    "127.0.0.1.example.com", "localhost.evil", "127.1", "0x7f000001", "[::1]", "10.0.0.1",
    "evil.example", "LOCALHOST", "127.0.0.2",
])
def test_lookalike_and_non_loopback_hosts_are_refused(tmp_path, host):
    # Each is refused on its spelling, before any lookup: netguard would fail the test if a
    # resolver were asked about any of these names.
    exc = refusal(override(f"http://{host}:9", tmp_path / "tn"), tmp_path / "real")
    assert exc.code == "ENV_UNSAFE_OVERRIDE"


@pytest.mark.parametrize("base", [
    "https://127.0.0.1:9",
    "http://user@127.0.0.1:9",
    "http://user:pw@127.0.0.1:9",
    "http://127.0.0.1:9?x=1",
    "http://127.0.0.1:9/?x=1",
    "http://127.0.0.1:9#frag",
    "http://127.0.0.1:9/api",
    "http://127.0.0.1:9/api/v2",
    "http://127.0.0.1",
    "http://127.0.0.1/",
    "http://127.0.0.1:",
    "http://127.0.0.1:0",
    "http://127.0.0.1:65536",
    "http://127.0.0.1:9x",
    "127.0.0.1:9",
    "//127.0.0.1:9",
    " http://127.0.0.1:9",
    "http://127.0.0.1:9\n",
    "http://127.0.0.1:\t9",
    "HTTP://127.0.0.1:9",
    "",
])
def test_https_userinfo_query_path_or_missing_port_is_refused(tmp_path, base):
    exc = refusal(override(base, tmp_path / "tn"), tmp_path / "real")
    assert exc.code == "ENV_UNSAFE_OVERRIDE"
    # The value may hold a password in its userinfo, so the message never echoes it.
    assert "pw@" not in exc.message


def test_base_without_home_is_refused(tmp_path):
    exc = refusal({"TAILNET_API_BASE": "http://127.0.0.1:9"}, tmp_path)
    assert exc.code == "ENV_UNSAFE_OVERRIDE"
    assert "TAILNET_HOME" in exc.message


def test_home_without_base_is_refused(tmp_path):
    exc = refusal({"TAILNET_HOME": str(tmp_path / "tn")}, tmp_path)
    assert exc.code == "HOME_WITHOUT_BASE"
    assert "TAILNET_API_BASE" in exc.message


def test_an_empty_variable_counts_as_set(tmp_path):
    # An exported-but-empty variable is still an override request; dropping it silently to
    # production would be the fallback §7.2 rule 4 forbids.
    assert refusal({"TAILNET_HOME": ""}, tmp_path).code == "HOME_WITHOUT_BASE"
    assert refusal({"TAILNET_API_BASE": ""}, tmp_path).code == "ENV_UNSAFE_OVERRIDE"


def test_a_test_home_inside_or_containing_the_real_dirs_is_refused(tmp_path):
    real = tmp_path / "real"
    config, state = real / ".config" / "tailnet", real / ".local" / "state" / "tailnet"
    config.mkdir(parents=True)
    state.mkdir(parents=True)
    link = tmp_path / "link-to-config"
    link.symlink_to(config)
    homes = [
        config, config / "sub", state, state / "x", real, real / ".config", real / ".local",
        Path("/"), link, link / "sub", real / ".config" / ".." / ".config" / "tailnet",
    ]
    for home in homes:
        exc = refusal(override("http://127.0.0.1:9", home), real)
        assert exc.code == "ENV_UNSAFE_OVERRIDE", home
    # A relative home would move with the working directory, so it is refused as well.
    assert refusal(override("http://127.0.0.1:9", "tn"), real).code == "ENV_UNSAFE_OVERRIDE"
    # Containment is by path component: a sibling whose name merely starts the same is fine.
    sibling = Posture.from_env(override("http://127.0.0.1:9", real / ".config" / "tailnet-other"),
                               real_home=real)
    assert sibling.kind == "test"


def test_real_dirs_come_from_the_password_database_not_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    posture = Posture.from_env({"HOME": str(tmp_path)})
    pw_dir = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    assert posture.config_dir == pw_dir / ".config" / "tailnet"
    assert posture.state_dir == pw_dir / ".local" / "state" / "tailnet"
    assert posture.claude_settings == pw_dir / ".claude" / "settings.json"


def test_the_home_rule_uses_the_password_database_too(tmp_path, monkeypatch):
    # With HOME pointed elsewhere, a test home equal to the real home is still refused.
    monkeypatch.setenv("HOME", str(tmp_path))
    pw_dir = pwd.getpwuid(os.geteuid()).pw_dir
    exc = refusal(override("http://127.0.0.1:9", pw_dir), None)
    assert exc.code == "ENV_UNSAFE_OVERRIDE"


def test_test_posture_places_every_path_under_the_test_home(tmp_path):
    home = tmp_path / "tn"
    posture = Posture.from_env(
        {**override("http://127.0.0.1:9", home), "CLAUDE_CONFIG_DIR": str(tmp_path / "cc")},
        real_home=tmp_path / "real")
    paths = {f.name: getattr(posture, f.name) for f in dataclasses.fields(posture)
             if isinstance(getattr(posture, f.name), Path)}
    assert set(paths) == {"config_dir", "state_dir", "drafts_dir", "claude_settings"}
    for name, path in paths.items():
        assert path.is_relative_to(home.resolve()), name
    assert posture.config_dir == home.resolve() / "config"
    assert posture.state_dir == home.resolve() / "state"
    assert posture.drafts_dir == home.resolve() / "state" / "drafts"
    # CLAUDE_CONFIG_DIR is the real settings; a test run reads its own copy.
    assert posture.claude_settings == home.resolve() / "claude" / "settings.json"


def test_test_posture_disables_environment_proxies(tmp_path, monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:3128")
    test = Posture.from_env(override("http://127.0.0.1:9", tmp_path / "tn"),
                            real_home=tmp_path / "real")
    assert test.proxies == {}
    # The value is what urllib's ProxyHandler takes: {} means no proxy whatever the environment.
    assert urllib.request.ProxyHandler(test.proxies).proxies == {}
    production = Posture.from_env({}, real_home=tmp_path / "real")
    assert "https" in urllib.request.ProxyHandler(production.proxies).proxies
