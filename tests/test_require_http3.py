"""Refusing to fall back from HTTP/3 when the caller cannot afford to.

Chromium carries QUIC over no proxy protocol, so a proxied session reaches
HTTP/2 and says nothing about it — `Response.http_version` reads "h2" and no
error is raised, because falling back is what a browser does. A fleet that
moved to this library for its HTTP/3 behaviour would keep sending HTTP/2 and
never find out from the library.

`require_http3=True` turns that silence into a failure: at the point the
session is opened where the answer is already knowable, and per response
otherwise.
"""

import pytest

import cronet

from . import socks5_server

PROXY_LOOPBACK = "<-loopback>"


def test_an_http_proxy_cannot_promise_http3() -> None:
    """An HTTP proxy tunnels TCP and has nowhere to put a datagram."""
    with pytest.raises(ValueError) as raised:
        cronet.Session(proxy="http://127.0.0.1:8080", require_http3=True)

    message = str(raised.value)
    assert "SOCKS5" in message, message
    assert "HTTP/2" in message, message


def test_a_socks5_proxy_may_promise_http3() -> None:
    """Whether a SOCKS5 proxy relays UDP is only knowable by asking it.

    So this is not refused when the session opens; a proxy that turns out not
    to relay UDP raises ProtocolDowngraded per response instead.
    """
    with cronet.Session(proxy="socks5://127.0.0.1:1080", require_http3=True) as s:
        assert s.require_http3


def test_requiring_http3_while_switching_it_off_is_refused() -> None:
    with pytest.raises(ValueError) as raised:
        cronet.Session(http3=False, require_http3=True)

    assert "contradicts" in str(raised.value), raised.value


def test_a_plain_http_response_is_refused_when_http3_is_required(server: str) -> None:
    """The local server speaks HTTP/1.1, which is exactly the downgrade case."""
    with (
        cronet.Session(require_http3=True) as session,
        pytest.raises(cronet.ProtocolDowngraded) as raised,
    ):
        session.get(f"{server}/echo")

    assert "not HTTP/3" in str(raised.value), raised.value


def test_the_refusal_carries_the_response_it_refused(server: str) -> None:
    with cronet.Session(require_http3=True) as session:
        try:
            session.get(f"{server}/echo")
        except cronet.ProtocolDowngraded as downgraded:
            # Typed `object` on the exception, to keep errors.py free of an
            # import back to response.py; narrowed here so the test can read it.
            assert isinstance(downgraded.response, cronet.Response)
            assert downgraded.response.status_code == 200
            assert downgraded.response.http_version != "h3"
            assert downgraded.response.content
        else:
            pytest.fail("a non-HTTP/3 response did not raise")


def test_a_streamed_response_is_refused_too(server: str) -> None:
    with (
        cronet.Session(require_http3=True) as session,
        pytest.raises(cronet.ProtocolDowngraded),
        session.stream("GET", f"{server}/echo"),
    ):
        pass


@pytest.mark.asyncio
async def test_the_async_session_refuses_a_downgrade_too(server: str) -> None:
    async with cronet.AsyncSession(require_http3=True) as session:
        with pytest.raises(cronet.ProtocolDowngraded):
            await session.get(f"{server}/echo")


def test_the_default_still_falls_back_quietly(server: str) -> None:
    """The guard is opt-in: without it a downgrade stays a browser's behaviour."""
    with cronet.Session() as session:
        response = session.get(f"{server}/echo")

    assert response.status_code == 200
    assert response.http_version != "h3"


def test_a_proxied_session_still_works_without_the_requirement(server: str) -> None:
    """The refusal is about the promise, not about proxies."""
    with (
        socks5_server.running() as proxy,
        cronet.Session(proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK) as session,
    ):
        assert session.get(f"{server}/echo").status_code == 200


@pytest.mark.live
def test_http3_is_reached_directly_when_required(network: None) -> None:
    """The promise is keepable without a proxy, which is the whole asymmetry."""
    with cronet.Session(
        require_http3=True, quic_hints=["cloudflare-quic.com"]
    ) as session:
        response = session.get("https://cloudflare-quic.com/")

    assert response.http_version == "h3", response.http_version
