"""What a redirect is allowed to carry to a different origin.

Credentials belong to the origin they were given for. A redirect that carries
them somewhere else hands a token to a host the caller never named, which is
how a redirect becomes a leak. requests and httpx both strip on cross-origin;
so does this.
"""

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import cronet


class _Handler(BaseHTTPRequestHandler):
    """Redirects /to/<url> onward, and echoes the headers it was sent."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        """Stay quiet."""

    def do_GET(self) -> None:
        if self.path.startswith("/to/"):
            self.send_response(302)
            self.send_header("location", self.path.removeprefix("/to/"))
            self.send_header("content-length", "0")
            self.end_headers()
            return
        payload = json.dumps(
            {name.lower(): value for name, value in self.headers.items()}
        ).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@contextmanager
def _origin() -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture
def two_origins() -> Iterator[tuple[str, str]]:
    with _origin() as first, _origin() as second:
        yield first, second


def _headers_seen(response: cronet.Response) -> dict[str, str]:
    seen: dict[str, str] = json.loads(response.content)
    return seen


def test_bearer_auth_is_not_carried_across_origins(
    two_origins: tuple[str, str],
) -> None:
    first, second = two_origins
    with cronet.Session(cookies=True) as session:
        response = session.get(f"{first}/to/{second}/echo", bearer_auth="SECRET")

    assert response.status_code == 200
    assert "authorization" not in _headers_seen(response), "the token was forwarded"


def test_an_explicit_authorization_header_is_not_carried_across_origins(
    two_origins: tuple[str, str],
) -> None:
    first, second = two_origins
    with cronet.Session(cookies=True) as session:
        response = session.get(
            f"{first}/to/{second}/echo", headers={"authorization": "Bearer SECRET"}
        )

    assert "authorization" not in _headers_seen(response), "the header was forwarded"


def test_credentials_survive_a_same_origin_redirect(
    two_origins: tuple[str, str],
) -> None:
    first, _ = two_origins
    with cronet.Session(cookies=True) as session:
        response = session.get(f"{first}/to/{first}/echo", bearer_auth="SECRET")

    # Same origin is the case where carrying them is the whole point.
    assert _headers_seen(response).get("authorization") == "Bearer SECRET"
