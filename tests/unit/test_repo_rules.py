# ABOUTME: Repository-wide rules from CLAUDE.md, checked as tests so breaking one fails `make test`.
# ABOUTME: Covers ABOUTME headers, the loopback-only suite, the pinned spec and the API write surface.

import ast
import hashlib
import json
import re
import socket
import subprocess
from pathlib import Path

import netguard
import pytest

REPO = Path(__file__).resolve().parents[2]
SPEC = REPO / "spec"
PACKAGE = REPO / "src" / "tailnet"

# DESIGN.md §4: code is *.py, *.sh, githooks/*, the Makefile and anything run through a
# shebang (the generated launcher is one). Data files and Markdown are exempt.
CODE_SUFFIXES = {".py", ".sh"}
CODE_NAMES = {"Makefile"}


def repo_files():
    """List every file git would commit: tracked ones plus untracked ones not ignored.

    Untracked files are included so a new file is held to the rules before its first
    commit, not after it.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO, capture_output=True, check=True,
    )
    paths = (REPO / name for name in listing.stdout.decode().split("\0") if name)
    return sorted(path for path in paths if path.is_file())


def is_code(path):
    """Say whether DESIGN.md §4 counts this file as executable code."""
    if path.suffix in CODE_SUFFIXES or path.name in CODE_NAMES:
        return True
    if path.parent.name == "githooks":
        return True
    with path.open("rb") as handle:
        return handle.read(2) == b"#!"


def has_two_aboutme_lines(path):
    """Say whether the file opens (after any shebang) with two non-empty ABOUTME lines."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    head = lines[:2]
    return len(head) == 2 and all(
        line.startswith("# ABOUTME: ") and line[len("# ABOUTME: "):].strip() for line in head
    )


def test_every_code_file_starts_with_two_aboutme_lines():
    code = [path for path in repo_files() if is_code(path)]
    # An empty listing would pass vacuously, so prove the walk saw this very file.
    assert Path(__file__).resolve() in code
    missing = [str(path.relative_to(REPO)) for path in code if not has_two_aboutme_lines(path)]
    assert missing == [], f"code files without two leading '# ABOUTME: ' lines: {missing}"


def test_default_suite_never_leaves_loopback():
    # tests/conftest.py installs netguard before any test runs, so it must be live here.
    # 192.0.2.1 is TEST-NET-1 (RFC 5737): even a broken guard would send nothing real.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        with pytest.raises(netguard.NetguardViolation, match="loopback"):
            sock.connect(("192.0.2.1", 9))
    with pytest.raises(netguard.NetguardViolation, match="tailscale"):
        subprocess.run(["tailscale", "version"], check=False)
    # Loopback itself still works: that is where the seam lives.
    with socket.create_server(("127.0.0.1", 0)) as listener, \
            socket.create_connection(listener.getsockname(), timeout=2):
        pass


def test_pinned_spec_matches_sha256sums():
    # Every [spec NNNN] citation in DESIGN.md is a line of this exact file, so its bytes
    # must not move without a deliberate re-pin of both files.
    pins = [line.split() for line in (SPEC / "SHA256SUMS").read_text().splitlines() if line.strip()]
    assert [name.lstrip("*") for _, name in pins] == ["tailscale-openapi.yaml"]
    for digest, name in pins:
        assert hashlib.sha256((SPEC / name.lstrip("*")).read_bytes()).hexdigest() == digest


FIXTURES = REPO / "tests" / "fixtures"


def test_every_api_fixture_names_its_spec_source():
    # A fixture is only evidence if it says where it came from: an api/ body cites the spec
    # lines it copies, a scenario/ body says it is synthetic, and the README maps them all.
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    files = sorted(path for path in FIXTURES.rglob("*") if path.is_file()
                   and path.name != "README.md")
    assert any(path.parent.name == "api" for path in files)
    for path in files:
        relative = path.relative_to(FIXTURES).as_posix()
        assert f"`{relative}`" in readme, f"{relative} is not mapped in tests/fixtures/README.md"
        if path.suffix != ".json":
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        source = doc.get("_source") if isinstance(doc, dict) else None
        assert isinstance(source, str), f"{relative} has no _source"
        if path.parent.name == "api":
            assert re.search(r"\bspec \d+", source), f"{relative} cites no spec line"
        else:
            assert source.startswith("synthetic"), f"{relative} does not say it is synthetic"


# HTTP methods that change something. GET is the only other method the CLI uses.
SENDING = {"POST", "PUT", "PATCH", "DELETE"}
# DESIGN.md §12.3: the only two writes, and the two policy calls that POST to /acl/validate,
# which "does not modify the tailnet policy file in any way" [spec 2518].
API_WRITES = {"set_device_tags", "disable_key_expiry"}
API_POSTS = API_WRITES | {"validate_tests", "validate_policy"}


def parsed(path):
    """Parse a source file with ast."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def method_strings(node):
    """Every string literal under `node` that names a method which changes something."""
    return [n for n in ast.walk(node) if isinstance(n, ast.Constant) and n.value in SENDING]


def top_level_functions(tree):
    """The module's own functions by name."""
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def request_calls(tree):
    """Every call of a `.request(...)` method: how api.py hands a request to the transport."""
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "request"]


def test_api_module_exposes_only_the_two_writes():
    tree = parsed(PACKAGE / "api.py")
    functions = top_level_functions(tree)
    senders = {name for name, fn in functions.items() if method_strings(fn)}
    assert senders == API_POSTS
    # No module constant, class or lambda names a sending method outside those functions.
    assert len(method_strings(tree)) == sum(len(method_strings(functions[n])) for n in senders)
    calls = request_calls(tree)
    assert calls, "api.py must reach the transport through .request(...)"
    for call in calls:
        # The method is a literal at every call, and so is the retry decision: nothing can
        # pass a method or idempotent=False through a variable or **kwargs.
        assert call.args and isinstance(call.args[0], ast.Constant), ast.unparse(call)
        keywords = {kw.arg: kw.value for kw in call.keywords}
        assert None not in keywords, ast.unparse(call)
        assert isinstance(keywords.get("idempotent"), ast.Constant), ast.unparse(call)
    never_retried = {name for name, fn in functions.items()
                     for call in request_calls(fn) for kw in call.keywords
                     if kw.arg == "idempotent" and kw.value.value is False}
    assert never_retried == API_WRITES
    # The public functions that take the write token are exactly the two writes.
    takes_write_token = {name for name, fn in functions.items() if not name.startswith("_")
                         and "write_token" in [a.arg for a in fn.args.args + fn.args.kwonlyargs]}
    assert takes_write_token == API_WRITES


def test_disable_key_expiry_hardcodes_true():
    tree = parsed(PACKAGE / "api.py")
    fn = top_level_functions(tree)["disable_key_expiry"]
    # No parameter could carry the value: re-enabling expiry is R4, and has no code path.
    args = fn.args
    assert [a.arg for a in args.args] == ["session", "node_id", "write_token"]
    assert (args.vararg, args.kwarg, args.kwonlyargs, args.defaults) == (None, None, [], [])
    [body] = [n for n in ast.walk(fn) if isinstance(n, ast.Dict)]
    assert [key.value for key in body.keys] == ["keyExpiryDisabled"]
    assert isinstance(body.values[0], ast.Constant) and body.values[0].value is True
    # The field is named nowhere else in api.py, so no other function can send it.
    mentions = [n for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and n.value == "keyExpiryDisabled"]
    assert len(mentions) == 1


def test_only_api_and_tokens_issue_post_requests():
    modules = sorted(PACKAGE.rglob("*.py"))
    assert PACKAGE / "api.py" in modules
    senders = {path.name for path in modules if method_strings(parsed(path))}
    assert senders == {"api.py", "tokens.py"}
    # tokens.py sends one POST, and only to the token endpoint.
    assert len(method_strings(parsed(PACKAGE / "tokens.py"))) == 1
    from tailnet import tokens
    assert tokens.TOKEN_PATH == "/oauth/token"
    # And only the transport holds an HTTP client, so nothing can go around it.
    clients = {"urllib.request", "http.client", "http"}
    importers = set()
    for path in modules:
        for node in ast.walk(parsed(path)):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module]
            if clients & set(names):
                importers.add(path.name)
    assert importers == {"http.py"}


# Every way the os module starts another program. A module that touches none of these and
# never imports subprocess cannot run tailscale, however it spells the name.
OS_PROCESS_CALLS = re.compile(r"(system|popen|exec\w*|spawn\w*|posix_spawnp?|fork\w*)")


def starts_programs(tree):
    """Say whether a module imports subprocess or reaches an os function that starts a program."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name.split(".")[0] == "subprocess"
                                                for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == "subprocess":
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "os" and any(
                OS_PROCESS_CALLS.fullmatch(a.name) for a in node.names):
            return True
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id == "os" and OS_PROCESS_CALLS.fullmatch(node.attr)):
            return True
    return False


# doctor's install and drift checks (§16.1 L8, L11) ask three other programs: git for the
# upstream clone's HEAD and the upstream pin, claude for the docs MCP server, bash for the
# login PATH. That is the one exception, held to one function and a fixed list.
DOCTOR_PROGRAMS = {"git", "claude", "bash"}


def calls_named(tree, name):
    """Every call of a function by this name, plain or as a method."""
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and getattr(n.func, "id", getattr(n.func, "attr", None)) == name]


def test_only_localts_runs_the_tailscale_binary():
    # localts is the one place tailscale runs, and it refuses in test posture (§7.1). Netguard
    # catches a run at test time; this catches the code that could make one before it exists.
    modules = sorted(PACKAGE.rglob("*.py"))
    runners = {path.name for path in modules if starts_programs(parsed(path))}
    assert runners == {"localts.py", "doctor.py"}
    # The check itself sees each way in.
    for source in ("import subprocess", "from subprocess import run", "os.execv('x', [])",
                   "from os import posix_spawn", "os.system('x')"):
        assert starts_programs(ast.parse(source)), source
    # doctor reaches subprocess in exactly one function, which refuses test posture and any
    # word naming tailscale at run time, and every call of it names an allowed program as a
    # literal: nothing can pass it a program through a variable.
    tree = parsed(PACKAGE / "doctor.py")
    users = {name for name, fn in top_level_functions(tree).items()
             if any(isinstance(n, ast.Name) and n.id == "subprocess" for n in ast.walk(fn))}
    assert users == {"run_program"}
    calls = calls_named(tree, "run_program")
    assert calls
    for call in calls:
        argv = call.args[1]
        assert isinstance(argv, ast.List), ast.unparse(call)
        program = argv.elts[0]
        assert isinstance(program, ast.Constant) and program.value in DOCTOR_PROGRAMS
        assert not [e for e in argv.elts if isinstance(e, ast.Constant) and e.value == "tailscale"]
    from tailnet import doctor
    assert doctor.PROGRAMS == DOCTOR_PROGRAMS
