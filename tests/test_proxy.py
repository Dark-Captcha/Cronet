"""Proxy support, checked against a proxy this suite runs itself.

Chromium bypasses the proxy for loopback addresses unless the bypass list says
otherwise, so every test here that wants its local traffic proxied passes
"<-loopback>" — which is the rule that removes that implicit exception.
"""

import json

import pytest

import cronet

from . import socks5_server

# Removes Chromium's built-in "never proxy localhost" rule.
PROXY_LOOPBACK = "<-loopback>"


def test_a_request_goes_through_a_socks5_proxy(server: str) -> None:
    host, port = server.removeprefix("http://").split(":")

    with socks5_server.running() as proxy:
        with cronet.Session(proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK) as session:
            response = session.get(f"{server}/echo")

        assert response.status_code == 200
        assert json.loads(response.content)["method"] == "GET"
        assert proxy.connections == [(host, int(port))], proxy.connections


def test_the_client_offers_no_authentication_when_it_has_none(server: str) -> None:
    with socks5_server.running() as proxy:
        with cronet.Session(proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK) as session:
            session.get(f"{server}/echo")

        assert proxy.offered_methods == [{socks5_server.AUTH_NONE}], (
            f"offered {proxy.offered_methods}"
        )


def test_loopback_is_not_proxied_unless_asked(server: str) -> None:
    with socks5_server.running() as proxy:
        with cronet.Session(proxy=proxy.url) as session:
            response = session.get(f"{server}/echo")

        assert response.status_code == 200
        assert proxy.connections == [], "loopback should have gone direct"
        assert response.proxy == "direct", response.proxy


def test_a_named_host_can_be_bypassed(server: str) -> None:
    with socks5_server.running() as proxy:
        with cronet.Session(
            proxy=proxy.url, proxy_bypass=f"{PROXY_LOOPBACK};127.0.0.1"
        ) as session:
            response = session.get(f"{server}/echo")

        assert proxy.connections == [], "the bypassed host still went via the proxy"
        assert response.proxy == "direct", response.proxy


def test_an_unreachable_proxy_fails_the_request(server: str) -> None:
    # Port 1 is reserved; nothing listens there.
    with (
        cronet.Session(
            proxy="socks5://127.0.0.1:1", proxy_bypass=PROXY_LOOPBACK
        ) as session,
        pytest.raises(cronet.RequestError) as raised,
    ):
        session.get(f"{server}/echo")

    assert raised.value.net_error < 0


def test_the_response_names_the_proxy_it_used(server: str) -> None:
    with socks5_server.running() as proxy:
        proxy_address = f"127.0.0.1:{proxy.server_address[1]}"
        with cronet.Session(proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK) as session:
            response = session.get(f"{server}/echo")

    # Chromium reports the proxy as a bare host and port, without its scheme.
    assert response.proxy == proxy_address, response.proxy


def test_requests_still_work_after_the_proxy_refuses_one(server: str) -> None:
    # No credentials configured, so the proxy will turn this request down.
    with (
        socks5_server.running("someone", "secret") as proxy,
        cronet.Session(proxy=proxy.url, proxy_bypass=PROXY_LOOPBACK) as session,
        pytest.raises(cronet.RequestError),
    ):
        session.get(f"{server}/echo")

    # A direct session afterwards is unaffected.
    with cronet.Session() as session:
        assert session.get(f"{server}/echo").status_code == 200


@pytest.mark.xfail(
    reason="Chromium's SOCKS5 client does not implement RFC 1929 yet",
    strict=True,
)
def test_a_socks5_proxy_that_demands_a_password_is_satisfied(server: str) -> None:
    with socks5_server.running("someone", "secret") as proxy:
        with cronet.Session(
            proxy=proxy.url,
            proxy_bypass=PROXY_LOOPBACK,
            proxy_username="someone",
            proxy_password="secret",
        ) as session:
            response = session.get(f"{server}/echo")

        assert response.status_code == 200
        assert proxy.credentials_seen == [("someone", "secret")]
