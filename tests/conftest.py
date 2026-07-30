"""Shared fixtures.

Most behaviour is pinned against a local HTTP server rather than the internet,
so the tests are deterministic and say something even offline. The handful of
claims that genuinely need the real world — TLS, HTTP/2, HTTP/3 — are marked
`live` and skipped when there is no network.
"""

import json
import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import cronet


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "live: needs the internet; skipped when it is unreachable"
    )


class _EchoHandler(BaseHTTPRequestHandler):
    """Answers just enough to exercise a client.

    Routes:
        /echo         the request's method, headers in order, and body, as JSON
        /status/<n>   an empty response with status <n>
        /redirect/<n> redirects <n> times, then lands on /echo
        /slow         sleeps a second before answering
        /bytes/<n>    <n> bytes of body
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        """Stay quiet; a test run is not a place for an access log."""

    def _body(self) -> bytes:
        length = int(self.headers.get("content-length", "0"))
        return self.rfile.read(length) if length else b""

    def _send(
        self,
        status: int,
        payload: bytes = b"",
        location: str = "",
        set_cookie: str = "",
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            if location:
                self.send_header("location", location)
            if set_cookie:
                self.send_header("set-cookie", set_cookie)
            self.end_headers()
            if payload:
                self.wfile.write(payload)
        except BrokenPipeError:
            # Expected: the timeout and cancellation tests hang up mid-answer.
            pass

    def _handle(self) -> None:
        body = self._body()
        path = self.path
        if path.startswith("/status/"):
            self._send(int(path.removeprefix("/status/")))
        elif path.startswith("/redirect/"):
            remaining = int(path.removeprefix("/redirect/"))
            target = f"/redirect/{remaining - 1}" if remaining > 1 else "/echo"
            self._send(302, location=target)
        elif path.startswith("/bytes/"):
            count = int(path.removeprefix("/bytes/"))
            self._send(200, b"x" * count)
        elif path.startswith("/set-cookie/"):
            name, value = path.removeprefix("/set-cookie/").split("/")
            self._send(200, b"{}", set_cookie=f"{name}={value}; Path=/")
        elif path.startswith("/set-cookie-then-redirect/"):
            name, value = path.removeprefix("/set-cookie-then-redirect/").split("/")
            # The cookie rides on the redirect, so only a client that reads
            # each hop will have it in hand for the request that follows.
            self._send(302, location="/echo", set_cookie=f"{name}={value}; Path=/")
        elif path == "/slow":
            time.sleep(1.0)
            self._send(200, b"{}")
        else:
            payload = json.dumps(
                {
                    "method": self.command,
                    "path": path,
                    # In order, and repeats kept: header order is the point.
                    "headers": [[name, value] for name, value in self.headers.items()],
                    "body": body.decode("latin-1"),
                }
            ).encode()
            self._send(200, payload)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


@pytest.fixture(scope="session")
def server() -> Iterator[str]:
    """A local HTTP/1.1 server; yields its base URL."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def session() -> Iterator[cronet.Session]:
    """A session that is closed however the test ends."""
    with cronet.Session(timeout=30.0) as open_session:
        yield open_session


def _has_network() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def network() -> None:
    """Skips the test when the internet is not reachable."""
    if not _has_network():
        pytest.skip("no network")
