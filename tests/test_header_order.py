"""The order a request's headers reach the wire in.

Header order is a fingerprint, and reproducing Chrome's is most of why this
library exists, so the order is pinned here rather than left to be noticed by
whoever is watching a capture. A Chromium bump that moves a header fails these
tests instead of quietly changing what every user's traffic looks like.

The subtle one is Referer. Chromium strips it from the caller's list and
re-appends it (net/url_request/url_request_http_job.cc, so that no plugin can
override a referrer policy), which puts it after everything else the caller
sent. It still lands in Chrome's own position, because in Chrome the headers
that follow it — accept-encoding, accept-language — are added by the network
stack after the caller's list, not by the caller. Send those by hand and
Referer ends up behind them instead, which is why doing so is refused.
"""

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import cronet

# What Chrome sends ahead of the stack's own headers, in Chrome's order.
CHROME_PREFIX = [
    ("sec-ch-ua", '"Chromium";v="150", "Not?A_Brand";v="24"'),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", '"Linux"'),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64)"),
    ("accept", "text/html,application/xhtml+xml"),
    ("sec-fetch-site", "same-origin"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
    ("referer", "https://example.com/"),
]


class _Recorder(BaseHTTPRequestHandler):
    """Records the header names of every request, in the order they arrived."""

    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    seen: ClassVar[list[list[str]]] = []

    def log_message(self, format: str, *args: object) -> None:
        """Stay quiet."""

    def do_GET(self) -> None:
        type(self).seen.append([name for name, _ in self.headers.items()])
        body = b"{}"
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\ncontent-length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )


@pytest.fixture
def recorder() -> Iterator[tuple[str, list[list[str]]]]:
    """A server that records header order; yields its URL and the recording."""
    _Recorder.seen = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/x", _Recorder.seen
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _without_hop_headers(names: list[str]) -> list[str]:
    """The names HTTP/1.1 itself requires, dropped — they are not a fingerprint."""
    return [name for name in names if name.lower() not in ("host", "connection")]


def test_caller_header_order_reaches_the_wire_unchanged(
    recorder: tuple[str, list[list[str]]],
) -> None:
    url, seen = recorder
    sent = CHROME_PREFIX[:-1]  # every header except referer

    with cronet.Session() as session:
        session.get(url, headers=sent)

    arrived = _without_hop_headers(seen[0])
    expected = [name for name, _ in sent]
    assert arrived[: len(expected)] == expected, arrived


def test_referer_lands_where_chrome_puts_it(
    recorder: tuple[str, list[list[str]]],
) -> None:
    """Last in the caller's list, and still ahead of the stack's own headers."""
    url, seen = recorder

    with cronet.Session(accept_language="en-US,en;q=0.9") as session:
        session.get(url, headers=CHROME_PREFIX)

    arrived = [name.lower() for name in _without_hop_headers(seen[0])]
    assert arrived == [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
    ], arrived


def test_the_stack_adds_accept_encoding_after_the_callers_headers(
    recorder: tuple[str, list[list[str]]],
) -> None:
    url, seen = recorder

    with cronet.Session() as session:
        session.get(url, headers=[("user-agent", "Mozilla/5.0")])

    arrived = [name.lower() for name in _without_hop_headers(seen[0])]
    assert arrived == ["user-agent", "accept-encoding"], arrived


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("accept-encoding", "identity"),
        ("accept-language", "fr-FR"),
        ("host", "elsewhere.example"),
        ("connection", "close"),
        ("content-length", "999"),
        ("Accept-Encoding", "identity"),  # the check is case-insensitive
    ],
)
def test_a_stack_owned_header_is_refused_on_a_request(name: str, value: str) -> None:
    with cronet.Session() as session, pytest.raises(ValueError) as raised:
        session.get("https://example.com", headers=[(name, value)])

    assert name in str(raised.value), raised.value


def test_a_stack_owned_header_is_refused_on_a_session() -> None:
    with pytest.raises(ValueError) as raised:
        cronet.Session(headers={"accept-encoding": "identity"})

    assert "accept-encoding" in str(raised.value), raised.value


def test_the_refusal_names_what_to_use_instead() -> None:
    with pytest.raises(ValueError) as raised:
        cronet.Session(headers={"accept-language": "fr-FR"})

    assert "accept_language=" in str(raised.value), raised.value


def test_an_ordinary_header_is_still_accepted(
    recorder: tuple[str, list[list[str]]],
) -> None:
    """The guard must not stop a name that merely looks similar."""
    url, seen = recorder

    with cronet.Session() as session:
        session.get(url, headers=[("accept", "text/html"), ("x-content-length", "1")])

    arrived = [name.lower() for name in _without_hop_headers(seen[0])]
    assert "accept" in arrived and "x-content-length" in arrived, arrived
