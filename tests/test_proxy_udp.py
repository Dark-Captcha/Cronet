"""QUIC reaching a destination through a SOCKS5 proxy's UDP relay.

Upstream Chromium refuses to speak QUIC to any proxy that is not itself a QUIC
proxy, so a proxied request always arrived over HTTP/2.
`patches/0004-socks5-udp-quic.patch` adds the SOCKS5 UDP association of
RFC 1928, and these tests hold that wiring in place: the client has to actually
send UDP ASSOCIATE, and has to stop asking when the proxy says no.

A local proxy cannot prove HTTP/3 end to end, because that needs a QUIC server
on the other side of it. What it can prove is the part that was missing for
years and cannot be seen from outside the client — that the command is sent at
all, and that datagrams follow it. The end-to-end result is measured against a
real proxy and recorded in the release notes.

The requests here are expected to fail: the local server speaks neither QUIC
nor TLS. What is asserted is what the proxy was asked for on the way.
"""

import contextlib

import cronet

from . import socks5_server

PROXY_LOOPBACK = "<-loopback>"


def _quic_hint(server: str) -> tuple[str, int]:
    """The local server, as a hint that HTTP/3 is worth trying there."""
    host, port = server.removeprefix("http://").split(":")
    return host, int(port)


def _https(server: str) -> str:
    """The local server addressed over https, so that QUIC is considered.

    Chromium looks for an alternative HTTP/3 service only on an https URL, and
    only for a destination it can resolve — which is why this points at the
    real local server rather than at an invented name.
    """
    return server.replace("http://", "https://") + "/"


def test_a_quic_request_asks_the_proxy_to_relay_udp(server: str) -> None:
    """The command upstream Chromium never sends."""
    with (
        socks5_server.running(relay_udp=True) as proxy,
        cronet.Session(
            proxy=proxy.url,
            proxy_bypass=PROXY_LOOPBACK,
            quic_hints=[_quic_hint(server)],
            timeout=10.0,
        ) as session,
        contextlib.suppress(cronet.CronetError),
    ):
        session.get(_https(server))

    assert socks5_server.COMMAND_UDP_ASSOCIATE in proxy.commands_seen, (
        f"commands seen: {proxy.commands_seen}"
    )


def test_the_relay_receives_the_datagrams_it_is_sent(server: str) -> None:
    """The association is not merely opened; datagrams travel through it."""
    with (
        socks5_server.running(relay_udp=True) as proxy,
        cronet.Session(
            proxy=proxy.url,
            proxy_bypass=PROXY_LOOPBACK,
            quic_hints=[_quic_hint(server)],
            timeout=10.0,
        ) as session,
        contextlib.suppress(cronet.CronetError),
    ):
        session.get(_https(server))

    assert proxy.datagrams_relayed, (
        "the association was opened but carried no datagrams"
    )


def test_an_authenticated_proxy_is_asked_to_relay_udp(server: str) -> None:
    """Credentials and the association have to work together, not instead."""
    with socks5_server.running("someone", "secret", relay_udp=True) as proxy:
        credentialled = f"socks5://someone:secret@127.0.0.1:{proxy.server_address[1]}"
        with (
            cronet.Session(
                proxy=credentialled,
                proxy_bypass=PROXY_LOOPBACK,
                quic_hints=[_quic_hint(server)],
                timeout=10.0,
            ) as session,
            contextlib.suppress(cronet.CronetError),
        ):
            session.get(_https(server))

    # Once per connection: the association, and the TCP attempts beside it.
    assert proxy.credentials_seen, "no credentials reached the proxy"
    assert set(proxy.credentials_seen) == {("someone", "secret")}
    assert socks5_server.COMMAND_UDP_ASSOCIATE in proxy.commands_seen


def test_a_proxy_without_udp_still_serves_ordinary_requests(server: str) -> None:
    """Refusing UDP ASSOCIATE must not break the TCP path beside it."""
    with (
        socks5_server.running(relay_udp=False) as proxy,
        cronet.Session(
            proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK, timeout=15.0
        ) as session,
    ):
        assert session.get(f"{server}/echo").status_code == 200
        assert socks5_server.COMMAND_CONNECT in proxy.commands_seen
