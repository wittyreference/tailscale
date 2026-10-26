# ABOUTME: The command line: the argparse grammar of DESIGN.md §5, dispatch to the fourteen commands, and
# ABOUTME: the one place an error becomes an envelope and an exit code. No parser ever abbreviates.

import argparse
import os
import sys
import traceback

from tailnet import devices, dns, errors, status
from tailnet.output import Envelope, emit
from tailnet.posture import API_PATH, Posture
from tailnet.redact import install_excepthook, redact

PROG = "tailnet"
REASON_MAX = 200
# The dry run prints the apply line with this placeholder for MC's reason (§12.6 step 4).
PLACEHOLDER = "<why>"

# Which §29 item builds each command; until then it is registered so the grammar and the
# fourteen-command tripwire hold, and running it says plainly that it is not built yet.
_BUILT_BY = {
    "status": 27, "doctor": 25, "device list": 15, "device tag": 19,
    "device disable-key-expiry": 18, "policy get": 21, "policy draft": 21, "policy validate": 21,
    "policy diff": 21, "policy test": 21, "dns": 22, "diagnose": 24, "credentials set": 26,
    "credentials forget": 26,
}


class _Parser(argparse.ArgumentParser):
    """An ArgumentParser that never accepts an abbreviated flag and never exits on bad input.

    allow_abbrev is forced off on every parser, sub-parsers included (they are built from
    this class): otherwise `--appl` would mean `--apply` and slip past the ask rule
    `Bash(*tailnet*--apply*)` that puts every write in front of MC (§5.1, L3). An error
    raises UsageError instead of printing and exiting, so --json still gets one envelope.
    """

    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        """Report a grammar error as exit 2, USAGE, pointing at this command's --help."""
        raise errors.UsageError("USAGE", f"{self.prog}: {message}",
                                next=[{"who": "agent", "run": f"{self.prog} --help",
                                       "why": "shows this command's grammar"}])


def _common():
    """The parent parser every parser shares, so --json works before or after any command word.

    Its default is suppressed: a sub-parser's own default would otherwise overwrite a
    --json given earlier on the line.
    """
    parser = _Parser(add_help=False)
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="print exactly one tailnet.v1 JSON envelope on stdout")
    return parser


def _write_flags(parser):
    """The flags only the two write commands take (§5.2): a dry run unless --apply is given."""
    parser.add_argument("--confirm", metavar="TOKEN",
                        help="the confirm token the dry run printed, such as retag:pi5")
    # store_true has no value form, so --apply=yes is a usage error (§5.1).
    parser.add_argument("--apply", action="store_true",
                        help="send the write; MC is asked to approve the exact command")
    parser.add_argument("--reason", metavar="TEXT",
                        help="required with --apply: one line for MC, 1-200 characters")


def build_parser():
    """Build the whole grammar: fourteen leaf commands, each naming itself in `command`."""
    common = _common()
    top = _Parser(prog=PROG, parents=[common],
                  description="Inventory and manage MC's tailnet through the Tailscale API.")
    commands = top.add_subparsers(dest="group", metavar="COMMAND", required=True)

    def leaf(subparsers, name, command, summary):
        """Add one leaf command that records its full name for dispatch."""
        parser = subparsers.add_parser(name, parents=[common], help=summary, description=summary)
        parser.set_defaults(command=command)
        return parser

    def group(name, summary):
        """Add a command word that only groups leaf commands, such as `device`."""
        parser = commands.add_parser(name, parents=[common], help=summary, description=summary)
        return parser.add_subparsers(dest="action", metavar="ACTION", required=True)

    status = leaf(commands, "status", "status", "local state only: no API call, always exit 0")
    status.add_argument("--brief", action="store_true", help="at most six lines")
    doctor = leaf(commands, "doctor", "doctor", "local checks and the read-only API steps")
    doctor.add_argument("--settle", action="store_true",
                        help="re-measure the answers that cost console audit events")

    device = group("device", "list devices, change tags, or disable key expiry")
    leaf(device, "list", "device list", "every device, never truncated")
    tag = leaf(device, "tag", "device tag", "plan or apply a tag change on one device")
    tag.add_argument("device", metavar="DEVICE", help="nodeId, id, hostname, name or address")
    tag.add_argument("--add", action="append", default=[], metavar="TAG", help="tag to add")
    tag.add_argument("--remove", action="append", default=[], metavar="TAG",
                     help="tag to remove")
    _write_flags(tag)
    expiry = leaf(device, "disable-key-expiry", "device disable-key-expiry",
                  "plan or apply turning key expiry off")
    expiry.add_argument("devices", nargs="+", metavar="DEVICE",
                        help="one device, or several when every one is tagged")
    _write_flags(expiry)

    policy = group("policy", "read, draft, validate and test the policy file")
    get = leaf(policy, "get", "policy get", "the live policy, byte for byte")
    get.add_argument("--format", choices=("hujson", "json"), default="hujson")
    get.add_argument("--out", metavar="FILE", help="write it here (0600) instead of stdout")
    draft = leaf(policy, "draft", "policy draft", "fetch the live policy into a new draft")
    draft.add_argument("--name", metavar="NAME", help="a short topic for the draft directory")
    validate = leaf(policy, "validate", "policy validate", "validate a draft or a policy file")
    validate.add_argument("target", metavar="TARGET", help="a draft directory or a file")
    diff = leaf(policy, "diff", "policy diff", "diff a draft against its base; say if it is ready")
    diff.add_argument("draft", metavar="DRAFT", help="a draft directory")
    test = leaf(policy, "test", "policy test", "test access against the live policy")
    test.add_argument("--src", required=True, metavar="SRC",
                      help="a user, group:, tag: or host alias; never an IP")
    test.add_argument("--accept", action="append", default=[], metavar="HOST:PORT")
    test.add_argument("--deny", action="append", default=[], metavar="HOST:PORT")
    test.add_argument("--proto", metavar="PROTO", help="tcp for SSH questions")

    leaf(commands, "dns", "dns", "the tailnet's DNS settings and this host's view of them")
    diagnose = leaf(commands, "diagnose", "diagnose", "why a port on a device is unreachable")
    diagnose.add_argument("devices", nargs="+", metavar="DEVICE")
    diagnose.add_argument("--port", type=int, default=22, metavar="N")
    diagnose.add_argument("--ssh-user", metavar="USER")
    diagnose.add_argument("--from", dest="from_device", metavar="DEVICE",
                          help="ask the API about another source device; no local probe")

    credentials = group("credentials", "store or forget the OAuth clients")
    store = leaf(credentials, "set", "credentials set", "MC only: needs a terminal")
    store.add_argument("role", choices=("read", "write"))
    forget = leaf(credentials, "forget", "credentials forget",
                  "remove a role's files; `forget write` disarms writes")
    forget.add_argument("role", choices=("read", "write", "token"))
    return top


def walk(parser, words=()):
    """Yield (command words, parser) for this parser and every parser below it."""
    yield words, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from walk(child, (*words, name))


def leaves(parser):
    """The leaf commands, by their space-joined words: the commands a user can run."""
    return {" ".join(words): child for words, child in walk(parser)
            if words and not any(isinstance(a, argparse._SubParsersAction)
                                 for a in child._actions)}


def _check_reason(args):
    """Hold --reason to §5.1: required with --apply, 1-200 characters, never the placeholder."""
    reason = args.reason
    if reason is not None:
        # A reason that still holds <why> anywhere was pasted from the dry run unedited.
        if PLACEHOLDER in reason.lower():
            raise errors.UsageError("REASON_PLACEHOLDER",
                                    f"--reason still holds the placeholder {PLACEHOLDER}: replace "
                                    "it with one line for MC saying why")
        if len(reason) > REASON_MAX:
            raise errors.UsageError("USAGE", f"--reason is {len(reason)} characters; at most "
                                             f"{REASON_MAX}")
    if args.apply and (reason is None or not reason.strip()):
        raise errors.UsageError("REASON_REQUIRED",
                                "--apply needs --reason TEXT: one line saying why; MC sees it in "
                                "the permission prompt and the audit log keeps it")


def _check(args):
    """The grammar argparse cannot express, checked before anything is read or sent."""
    if hasattr(args, "apply"):
        _check_reason(args)
    if args.command == "device tag" and not (args.add or args.remove):
        raise errors.UsageError("USAGE", "device tag needs at least one --add TAG or --remove TAG")


def _not_built(posture, args):
    """Stand in for a command whose §29 item has not landed: a clear internal error, exit 1."""
    raise errors.TailnetError(errors.INTERNAL, "INTERNAL",
                              f"`tailnet {args.command}` is not built yet; it lands with "
                              f"DESIGN.md §29 item {_BUILT_BY[args.command]}")


# Each command's handler takes the posture and the parsed arguments and returns an Envelope.
HANDLERS = dict.fromkeys(_BUILT_BY, _not_built)
HANDLERS["device list"] = devices.run_list
HANDLERS["dns"] = dns.run
HANDLERS["status"] = status.run


def _wants_json(argv):
    """Whether --json was given, read before parsing so even a grammar error gets an envelope."""
    if "--" in argv:
        argv = argv[:argv.index("--")]
    return "--json" in argv


def _command_of(argv):
    """The command's name from the words given, best effort, for an envelope made before parsing."""
    words = [word for word in argv if not word.startswith("-")]
    for size in (2, 1):
        name = " ".join(words[:size])
        if name in _BUILT_BY:
            return name
    return PROG


def _banner(posture):
    """Say on stderr, on every test-posture run, that nothing here touches the real tailnet."""
    api = posture.api_base.removesuffix(API_PATH)
    home = posture.config_dir.parent
    sys.stderr.write(redact(f"TEST POSTURE: API {api}, home {home}. "
                            "Nothing here touches the real tailnet.\n"))
    sys.stderr.flush()


def _run(posture, argv):
    """Parse and dispatch one command; return its Envelope, or an int when --help printed."""
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as stop:
        # Only --help gets here: every grammar error raises UsageError instead.
        return stop.code if isinstance(stop.code, int) else 0
    _check(args)
    return HANDLERS[args.command](posture, args)


def main(argv=None):
    """Run one command and return its exit code; every entry point calls this.

    The posture is decided first, before any argument is trusted or any file read (§7.2),
    and an unsafe override refuses with nothing contacted. From then on every outcome,
    a bug included, ends as one envelope: with --json, stdout holds exactly one object.
    """
    install_excepthook()
    argv = list(sys.argv[1:] if argv is None else argv)
    json_mode = _wants_json(argv)
    command = _command_of(argv)
    try:
        posture = Posture.from_env(os.environ)
    except errors.TailnetError as exc:
        # Neither posture holds: the override was refused and nothing falls back to production.
        # Status alone still answers 0, saying so, because the skill injects it (§17).
        if command == "status":
            env = status.refused(exc)
        else:
            env = Envelope.from_error(command, "unknown", exc)
        emit(env, json_mode)
        return env.exit
    if posture.kind == "test":
        _banner(posture)
    try:
        env = _run(posture, argv)
        if isinstance(env, int):
            return env
    except errors.TailnetError as exc:
        env = Envelope.from_error(command, posture.kind, exc)
    # A bug of any kind still ends as an envelope (exit 1), so that is what is caught here.
    except Exception as exc:  # noqa: BLE001
        if os.environ.get("TAILNET_DEBUG") == "1":
            sys.stderr.write(redact(traceback.format_exc()))
        else:
            sys.stderr.write("tailnet: run again with TAILNET_DEBUG=1 to see the redacted "
                             "traceback.\n")
        env = Envelope.from_error(command, posture.kind, exc)
    emit(env, json_mode)
    return env.exit
