"""The cookie jar, and the redirect handling that only exists to serve it.

`history` lives here rather than with the other response fields because it is
only ever populated when a jar is in use: that is what makes the session follow
redirects one hop at a time instead of letting Chromium do it silently.
"""

import pytest

import cronet

from . import echoed


def test_no_cookies_are_kept_without_a_jar(server: str) -> None:
    with cronet.Session() as session:
        session.get(f"{server}/set-cookie/who/me")
        response = session.get(f"{server}/echo")

    assert "cookie" not in echoed.headers(response)


def test_a_cookie_is_stored_and_sent_back(server: str) -> None:
    with cronet.Session(cookies=True) as session:
        session.get(f"{server}/set-cookie/who/me")
        response = session.get(f"{server}/echo")

    assert echoed.headers(response)["cookie"] == "who=me"


def test_a_jar_can_be_shared_between_sessions(server: str) -> None:
    jar = cronet.CookieJar()
    with cronet.Session(cookies=jar) as first:
        first.get(f"{server}/set-cookie/shared/yes")

    with cronet.Session(cookies=jar) as second:
        response = second.get(f"{server}/echo")

    assert echoed.headers(response)["cookie"] == "shared=yes"
    assert len(jar) == 1


def test_a_jar_can_be_emptied(server: str) -> None:
    jar = cronet.CookieJar()
    with cronet.Session(cookies=jar) as session:
        session.get(f"{server}/set-cookie/temporary/1")
        assert len(jar) == 1

        jar.clear()
        response = session.get(f"{server}/echo")

    assert "cookie" not in echoed.headers(response)


def test_a_cookie_set_during_a_redirect_chain_is_kept(server: str) -> None:
    with cronet.Session(cookies=True) as session:
        response = session.get(f"{server}/set-cookie-then-redirect/mid/chain")

    # The cookie was set on the 302, so only a client that reads each hop has
    # it in hand for the request that follows.
    assert response.status_code == 200
    assert echoed.headers(response)["cookie"] == "mid=chain"


def test_history_records_each_redirect_hop(server: str) -> None:
    with cronet.Session(cookies=True) as session:
        response = session.get(f"{server}/redirect/3")

    assert response.status_code == 200
    assert [hop.status_code for hop in response.history] == [302, 302, 302]
    assert response.url.endswith("/echo")


def test_history_is_empty_without_a_jar(session: cronet.Session, server: str) -> None:
    response = session.get(f"{server}/redirect/2")

    # Chromium followed these itself and does not report the hops.
    assert response.history == ()
    assert response.redirect_count == 2


def test_max_redirects_zero_returns_the_redirect_itself_with_a_jar(
    server: str,
) -> None:
    # The same request without a jar returns the 302, so holding one must not
    # turn a deliberate max_redirects=0 into a failure.
    with cronet.Session(cookies=True) as session:
        response = session.get(f"{server}/redirect/1", max_redirects=0)

    assert response.status_code == 302, f"got {response!r}"
    assert response.headers["location"] == "/echo"


def test_running_past_max_redirects_raises_with_a_jar(server: str) -> None:
    with (
        cronet.Session(cookies=True) as session,
        pytest.raises(cronet.TooManyRedirects),
    ):
        session.get(f"{server}/redirect/5", max_redirects=2)
