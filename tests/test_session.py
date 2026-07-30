"""What a blocking session promises."""

import json

import pytest

import cronet


def test_get_returns_the_servers_status_and_body(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo")

    assert response.status_code == 200, f"got {response!r}"
    assert response.ok
    assert json.loads(response.content)["method"] == "GET"


def test_request_headers_keep_the_order_they_were_given(
    session: cronet.Session, server: str
) -> None:
    sent = [("x-one", "1"), ("x-two", "2"), ("x-three", "3"), ("x-four", "4")]

    response = session.get(f"{server}/echo", headers=sent)

    seen = [name.lower() for name, _ in json.loads(response.content)["headers"]]
    ours = [name for name in seen if name.startswith("x-")]
    assert ours == ["x-one", "x-two", "x-three", "x-four"], f"order was {seen}"


def test_a_request_header_replaces_the_sessions_without_moving_it(
    server: str,
) -> None:
    with cronet.Session(
        headers=[("x-first", "a"), ("x-second", "b"), ("x-third", "c")]
    ) as session:
        response = session.get(f"{server}/echo", headers={"x-second": "replaced"})

    echoed = json.loads(response.content)["headers"]
    ours = [(name.lower(), value) for name, value in echoed if name.startswith("x-")]
    assert ours == [
        ("x-first", "a"),
        ("x-second", "replaced"),
        ("x-third", "c"),
    ], f"got {ours}"


def test_post_with_json_sets_the_content_type(
    session: cronet.Session, server: str
) -> None:
    response = session.post(f"{server}/echo", json={"hello": "world"})

    echoed = json.loads(response.content)
    headers = {name.lower(): value for name, value in echoed["headers"]}
    assert headers["content-type"] == "application/json"
    assert json.loads(echoed["body"]) == {"hello": "world"}


def test_post_with_data_sends_a_form(session: cronet.Session, server: str) -> None:
    response = session.post(f"{server}/echo", form={"a": "1", "b": "2"})

    echoed = json.loads(response.content)
    headers = {name.lower(): value for name, value in echoed["headers"]}
    assert headers["content-type"] == "application/x-www-form-urlencoded"
    assert echoed["body"] == "a=1&b=2"


def test_giving_two_bodies_is_rejected(session: cronet.Session, server: str) -> None:
    with pytest.raises(TypeError, match="only one of"):
        session.post(f"{server}/echo", body=b"x", json={"a": 1})


def test_an_empty_body_is_not_sent_as_a_body(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo")

    echoed = json.loads(response.content)
    assert echoed["body"] == ""


def test_redirects_are_followed_and_counted(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/redirect/3")

    assert response.status_code == 200
    assert response.redirect_count == 3, f"counted {response.redirect_count}"
    assert response.url.endswith("/echo"), f"landed on {response.url}"


def test_max_redirects_zero_returns_the_redirect_itself(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/redirect/1", max_redirects=0)

    assert response.status_code == 302, f"got {response!r}"
    assert response.headers["location"] == "/echo"


def test_running_past_max_redirects_raises(
    session: cronet.Session, server: str
) -> None:
    with pytest.raises(cronet.TooManyRedirects):
        session.get(f"{server}/redirect/5", max_redirects=2)


def test_a_slow_response_times_out(session: cronet.Session, server: str) -> None:
    with pytest.raises(cronet.Timeout):
        session.get(f"{server}/slow", timeout=0.2)


def test_a_host_that_does_not_resolve_raises_connection_failed(
    session: cronet.Session,
) -> None:
    with pytest.raises(cronet.ConnectionFailed) as raised:
        session.get("http://does-not-exist.invalid/")

    assert raised.value.net_error < 0, "an error code should have been carried"


def test_a_url_that_cannot_be_parsed_raises(session: cronet.Session) -> None:
    # A TypeError, not a RequestError: nothing was ever sent, so this is a
    # mistake in the call rather than something the network did.
    with pytest.raises(TypeError, match="no scheme"):
        session.get("not a url at all")


def test_a_closed_session_refuses_further_requests(server: str) -> None:
    session = cronet.Session()
    session.close()

    assert session.closed
    with pytest.raises(cronet.SessionClosed):
        session.get(f"{server}/echo")


def test_closing_twice_is_harmless(server: str) -> None:
    session = cronet.Session()
    session.close()
    session.close()

    assert session.closed


def test_an_error_status_can_be_raised_on_demand(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/status/404")

    assert not response.ok
    with pytest.raises(cronet.HTTPStatusError):
        response.raise_for_status()


def test_a_success_status_passes_raise_for_status(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo")

    assert response.raise_for_status() is response


def test_an_empty_body_reads_as_empty(session: cronet.Session, server: str) -> None:
    response = session.get(f"{server}/bytes/0")

    assert response.content == b""
    assert response.text == ""


def test_a_large_body_arrives_whole(session: cronet.Session, server: str) -> None:
    size = 5 * 1024 * 1024

    response = session.get(f"{server}/bytes/{size}")

    assert len(response.content) == size, f"got {len(response.content)} of {size}"


def test_metrics_describe_the_request(session: cronet.Session, server: str) -> None:
    response = session.get(f"{server}/echo")

    assert response.metrics.request_start_us > 0
    assert response.metrics.total_us >= 0
    assert response.metrics.received_bytes > 0
    # Microseconds, not milliseconds: a millisecond epoch would be about 1.7e12
    # today, and this must be about a thousand times that.
    assert response.metrics.request_start_us > 1e15, response.metrics.request_start_us


def test_the_version_is_the_chromium_it_was_built_from() -> None:
    assert cronet.version().count(".") == 3, cronet.version()


@pytest.mark.live
def test_https_negotiates_http2(network: None) -> None:
    with cronet.Session() as session:
        response = session.get("https://example.com/")

    assert response.status_code == 200
    assert response.http_version == "h2", f"negotiated {response.http_version}"


@pytest.mark.live
def test_a_bad_certificate_is_refused(network: None) -> None:
    with cronet.Session() as session, pytest.raises(cronet.CertificateError):
        session.get("https://expired.badssl.com/")


def _accept_encoding(session: cronet.Session, server: str) -> str:
    response = session.get(f"{server}/echo")
    echoed: list[list[str]] = json.loads(response.content)["headers"]
    return next(v for name, v in echoed if name.lower() == "accept-encoding")


def test_brotli_is_advertised_when_enabled(server: str) -> None:
    with cronet.Session(brotli=True) as session:
        assert "br" in _accept_encoding(session, server)


def test_brotli_is_not_advertised_when_disabled(server: str) -> None:
    with cronet.Session(brotli=False) as session:
        assert "br" not in _accept_encoding(session, server)


@pytest.mark.live
def test_a_compressed_response_arrives_decompressed(network: None) -> None:
    with cronet.Session() as session:
        response = session.get("https://www.cloudflare.com/")

    # The server compresses; what lands here must be the plain document.
    assert response.status_code == 200
    assert response.content.lstrip()[:1] == b"<", response.content[:40]
