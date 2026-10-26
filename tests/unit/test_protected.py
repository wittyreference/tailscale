# ABOUTME: Tests for tailnet.protected: parsing MC's hand-written protected list, what each entry matches,
# ABOUTME: and loading it under the private-file checks, where a missing file means "unanswered" (§11.4).

import os

import pytest

from tailnet import devices, errors, protected
from tailnet.posture import Posture

# The example from DESIGN.md §11.4, as MC would write it.
EXAMPLE = """\
# MC's protected list. Written by MC, never by an agent. One entry per line.
self nXyz123CNTRL            # claude-factory (required: exactly one self line)
spec5                        # Elmer console; Tailscale SSH host; Serve URL (P1, P2, P7)
nAbc456CNTRL                 # pi5 (a nodeId survives a rename)

albini
iphone192
"""


def device(node_id, hostname, name):
    """A normalised device with just the fields the protected list matches on."""
    return devices.normalise({"nodeId": node_id, "hostname": hostname, "name": name,
                              "addresses": [], "tags": []})


FACTORY = device("nXyz123CNTRL", "claude-factory", "claude-factory.tail0000.ts.net")
SPEC5 = device("nSpec5x1CNTRL", "spec5", "spec5.tail0000.ts.net")
PI5 = device("nAbc456CNTRL", "raspberrypi", "pi5.tail0000.ts.net")
PHONE = device("nPhone01CNTRL", "Michaels-iPhone", "iphone192.tail0000.ts.net")
OTHER = device("nOther01CNTRL", "nomad-b", "nomad-b.tail0000.ts.net")


def malformed(text):
    """Parse expecting a refusal; return it."""
    with pytest.raises(errors.LocalError) as caught:
        protected.parse(text)
    return caught.value


@pytest.fixture
def posture(tmp_path):
    """A test posture with its private config directory in place."""
    environ = {"TAILNET_API_BASE": "http://127.0.0.1:9", "TAILNET_HOME": str(tmp_path / "tn")}
    posture = Posture.from_env(environ, real_home=tmp_path / "real")
    posture.config_dir.mkdir(mode=0o700, parents=True)
    return posture


def put(posture, text, mode=0o600):
    """Write the protected file with an exact mode, as MC's here-document would."""
    path = posture.config_dir / "protected"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_a_missing_file_is_unanswered(posture, tmp_path):
    # Absence is MC's question not yet answered, not an empty list: tag writes refuse on it.
    assert protected.load(posture) is None
    elsewhere = Posture.from_env({"TAILNET_API_BASE": "http://127.0.0.1:9",
                                  "TAILNET_HOME": str(tmp_path / "never-made")},
                                 real_home=tmp_path / "real")
    assert protected.load(elsewhere) is None


@pytest.mark.parametrize("text", [
    "spec5\n",                                   # no self line
    "self nA1CNTRL\nself nB2CNTRL\n",            # two
    "self\n",                                    # a self line without its nodeId
    "self nA1CNTRL nB2CNTRL\n",                  # two nodeIds
    "self n/../x\n",                             # not a nodeId
    "",
])
def test_exactly_one_self_line_is_required(text):
    stop = malformed(text)
    assert (stop.exit, stop.code) == (3, "PROTECTED_MALFORMED")


def test_entries_match_node_id_exactly_or_hostname_and_label_ignoring_case():
    listed = protected.parse("self nXyz123CNTRL\nSPEC5\nnAbc456CNTRL\nIPHONE192\n")
    assert listed.protects(SPEC5) == "listed as SPEC5"            # hostname, any case
    assert listed.protects(PI5) == "listed as nAbc456CNTRL"       # nodeId, exactly
    assert listed.protects(PHONE) == "listed as IPHONE192"        # first label, any case
    assert listed.protects(OTHER) is None
    # A nodeId is compared exactly: another spelling is not that node.
    assert protected.parse("self nXyz123CNTRL\nNABC456CNTRL\n").protects(PI5) is None
    # Never by substring or prefix.
    for entry in ("spec", "pi5.tail0000", "nAbc456", "iphone"):
        assert protected.parse(f"self nXyz123CNTRL\n{entry}\n").protects(PI5) is None, entry
        assert protected.parse(f"self nXyz123CNTRL\n{entry}\n").protects(PHONE) is None, entry


def test_an_entry_protects_a_device_by_every_form_a_device_argument_names_it_by():
    # §5.1's resolver takes a DEVICE by nodeId, legacy id, hostname, MagicDNS name, first label
    # or Tailscale address. An entry MC writes in any of those forms names the same device, so
    # the list never protects less than the CLI can target (A59).
    pi5 = devices.normalise({"nodeId": "nAbc456CNTRL", "id": "1004", "hostname": "raspberrypi",
                             "name": "pi5.tail0000.ts.net",
                             "addresses": ["100.64.0.13", "fd7a:115c:a1e0::d"], "tags": []})
    for entry in ("1004", "pi5.tail0000.ts.net", "PI5.tail0000.ts.net.", "100.64.0.13",
                  "fd7a:115c:a1e0:0:0:0:0:d", "FD7A:115C:A1E0::D"):
        assert devices.resolve(entry, [pi5, OTHER]) is pi5, entry
        listed = protected.parse(f"self nXyz123CNTRL\n{entry}\n")
        assert listed.protects(pi5) == f"listed as {entry}", entry
        assert listed.protects(OTHER) is None, entry
        assert listed.unmatched([pi5, OTHER]) == [], entry
    # Another address, or one that is not a whole address, names nothing.
    for entry in ("100.64.0.1", "100.64.0", "fd7a:115c:a1e0::"):
        assert protected.parse(f"self nXyz123CNTRL\n{entry}\n").protects(pi5) is None, entry


def test_unmatched_names_the_lines_that_match_no_device_never_their_text():
    listed = protected.parse("self nXyz123CNTRL\n# a comment\nspec5\noldbox\n\nnAbc456CNTRL\n"
                             "100.64.9.9\n")
    assert listed.unmatched([FACTORY, SPEC5, PI5]) == [4, 7]
    assert listed.unmatched([]) == [3, 4, 6, 7]


def test_comments_and_blank_lines_are_ignored():
    parsed = protected.parse(EXAMPLE)
    assert parsed.self_node_id == "nXyz123CNTRL"
    assert [entry.text for entry in parsed.entries] == ["spec5", "nAbc456CNTRL", "albini",
                                                        "iphone192"]
    # The why after an entry is MC's own words, and it is what a listing shows.
    assert parsed.protects(SPEC5) == ("listed as spec5: Elmer console; Tailscale SSH host; "
                                      "Serve URL (P1, P2, P7)")
    assert parsed.protects(PI5) == "listed as nAbc456CNTRL: pi5 (a nodeId survives a rename)"
    assert not parsed.self_only


def test_a_self_only_file_protects_only_self():
    parsed = protected.parse("self nXyz123CNTRL   # claude-factory\n")
    assert parsed.self_only
    assert parsed.protects(FACTORY) == "the self line: self is always protected"
    for other in (SPEC5, PI5, PHONE, OTHER):
        assert parsed.protects(other) is None


def test_a_line_naming_two_entries_is_malformed_and_names_the_line_not_its_text():
    stop = malformed("self nXyz123CNTRL\nspec5 nomad-b\n")
    assert stop.code == "PROTECTED_MALFORMED"
    assert "line 2" in stop.message
    # The file is MC's, behind a deny rule: a refusal says where, never what it says.
    assert "nomad-b" not in stop.message and "spec5" not in stop.message


def test_the_file_loads_through_the_private_file_checks(posture):
    put(posture, EXAMPLE)
    parsed = protected.load(posture)
    assert parsed.self_node_id == "nXyz123CNTRL" and len(parsed.entries) == 4


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o604, 0o602])
def test_an_insecure_protected_file_is_refused(posture, mode):
    path = put(posture, EXAMPLE, mode)
    with pytest.raises(errors.LocalError) as caught:
        protected.load(posture)
    stop = caught.value
    assert (stop.exit, stop.code) == (3, "PROTECTED_MALFORMED")
    assert f"mode {mode:04o}" in stop.message
    assert any(step["do"] == f"chmod 600 {path}" for step in stop.next)
    assert "spec5" not in stop.message


def test_a_symlinked_or_hard_linked_protected_file_is_refused(posture, tmp_path):
    real = tmp_path / "elsewhere"
    real.write_text(EXAMPLE, encoding="utf-8")
    real.chmod(0o600)
    os.symlink(real, posture.config_dir / "protected")
    with pytest.raises(errors.LocalError) as caught:
        protected.load(posture)
    assert caught.value.code == "PROTECTED_MALFORMED" and "symlink" in caught.value.message
    os.unlink(posture.config_dir / "protected")
    os.link(real, posture.config_dir / "protected")
    with pytest.raises(errors.LocalError) as caught:
        protected.load(posture)
    assert caught.value.code == "PROTECTED_MALFORMED" and "hard links" in caught.value.message


def test_an_oversized_or_undecodable_file_is_refused(posture):
    put(posture, "self nXyz123CNTRL\n" + "# padding\n" * 7000)
    with pytest.raises(errors.LocalError) as caught:
        protected.load(posture)
    assert caught.value.code == "PROTECTED_MALFORMED" and "limit" in caught.value.message
    path = posture.config_dir / "protected"
    path.write_bytes(b"self nXyz123CNTRL\n\xff\xfe\n")
    with pytest.raises(errors.LocalError) as caught:
        protected.load(posture)
    assert caught.value.code == "PROTECTED_MALFORMED"
