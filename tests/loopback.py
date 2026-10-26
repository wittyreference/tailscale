# ABOUTME: The one test seam: a real HTTP server on 127.0.0.1 that answers from a route table and
# ABOUTME: records every request, standing in for api.tailscale.com in unit and integration tests.

import json
import socketserver
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class Recorded:
    """One request exactly as the seam received it, for tests to assert on."""

    method: str
    path: str
    query: str
    headers: dict
    body: bytes

    def header(self, name):
        """Return a request header by name, ignoring case as HTTP does; None when absent."""
        return self.headers.get(name.lower())

    def json(self):
        """Parse the body as JSON."""
        return json.loads(self.body)

    def form(self):
        """Parse a form-encoded body, as the OAuth token endpoint receives it."""
        return parse_qs(self.body.decode("utf-8"), keep_blank_values=True)


def _encode(headers, body):
    """Turn a route's body into bytes and default its Content-Type."""
    headers = dict(headers)
    if isinstance(body, (dict, list)):
        # Fixture files name their spec source in "_source"; the real API never sends it.
        if isinstance(body, dict):
            body = {k: v for k, v in body.items() if k != "_source"}
        body = json.dumps(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    elif body is None:
        body = b""
    return headers, body


class _Route:
    """The replies for one (method, path): one reply repeats, several are served once each."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.served = 0

    def next_reply(self):
        """Return the next reply, or None once a sequence is used up."""
        if len(self.replies) == 1:
            return self.replies[0]
        if self.served >= len(self.replies):
            return None
        reply = self.replies[self.served]
        self.served += 1
        return reply


class _Server(ThreadingHTTPServer):
    """ThreadingHTTPServer that skips the reverse DNS lookup of its own address."""

    def server_bind(self):
        """Bind without HTTPServer's getfqdn(), which asks a resolver and could leave the box."""
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address):
        """Swallow socketserver's traceback print; the seam reports problems as `unexpected`."""


class _Handler(BaseHTTPRequestHandler):
    """Records the request, then answers it from the owning Loopback's route table."""

    def _serve(self):
        """Handle every method the same way: record first, then reply."""
        seam = self.server.seam
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        request = Recorded(
            method=self.command,
            path=parts.path,
            query=parts.query,
            headers={name.lower(): value for name, value in self.headers.items()},
            body=self.rfile.read(length),
        )
        status, headers, body = seam._reply_for(request)
        headers, body = _encode(headers, body)
        try:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # The client gave up first, which is what a timeout test sets out to cause.
            pass

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

    def log_message(self, format, *args):
        """Stay silent: the default writes a line per request to stderr, and runs are pristine."""


class Loopback:
    """A running stand-in for the Tailscale API on 127.0.0.1, with a route table and a recorder.

    Routes map (method, path) to replies. A reply is a (status, headers, body) tuple, where a
    dict or list body is sent as JSON, or a callable that takes the Recorded request and
    returns such a tuple. Requests with no route, past the end of a reply sequence, or whose
    handler raised are answered 404 or 500 and listed in `unexpected`.
    """

    def __init__(self):
        self.requests = []
        self.unexpected = []
        self._routes = {}
        self._lock = threading.Lock()
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.seam = self
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()

    @property
    def port(self):
        """The ephemeral port the kernel assigned."""
        return self._server.server_address[1]

    @property
    def base_url(self):
        """The TAILNET_API_BASE value a test posture run points at this seam."""
        return f"http://127.0.0.1:{self.port}"

    def route(self, method, path, *replies):
        """Answer `method path` (the path without its query) with the given replies."""
        if not replies:
            raise ValueError("a route needs at least one reply")
        with self._lock:
            self._routes[(method, path)] = _Route(replies)

    def _reply_for(self, request):
        """Record the request and pick its reply; runs on the server's request thread."""
        where = f"{request.method} {request.path}"
        with self._lock:
            self.requests.append(request)
            route = self._routes.get((request.method, request.path))
            reply = None if route is None else route.next_reply()
            if route is None:
                self.unexpected.append(f"{where}: no route")
                return 404, {}, {"message": f"loopback: no route for {where}"}
            if reply is None:
                self.unexpected.append(f"{where}: all {len(route.replies)} replies already served")
                return 500, {}, {"message": f"loopback: replies exhausted for {where}"}
        if callable(reply):
            try:
                reply = reply(request)
            # Any handler bug, whatever its type, must reach the test as `unexpected` rather
            # than die silently on the server thread.
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self.unexpected.append(f"{where}: handler raised {type(exc).__name__}: {exc}")
                return 500, {}, {"message": f"loopback: handler failed for {where}"}
        return reply

    def close(self):
        """Stop serving and release the port."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
