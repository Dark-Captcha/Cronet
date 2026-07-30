"""Query strings, authentication and the User-Agent."""

import pytest

import cronet

from . import echoed


def test_query_is_added_to_the_query_string(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo", query={"a": "1", "b": "two"})

    assert echoed.request(response)["path"] == "/echo?a=1&b=two"


def test_query_joins_one_the_url_already_had(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo?first=0", query={"second": "1"})

    assert echoed.request(response)["path"] == "/echo?first=0&second=1"


def test_query_may_repeat_a_name(session: cronet.Session, server: str) -> None:
    response = session.get(f"{server}/echo", query=[("tag", "a"), ("tag", "b")])

    assert echoed.request(response)["path"] == "/echo?tag=a&tag=b"


def test_basic_auth_sets_the_authorization_header(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo", basic_auth=("aladdin", "opensesame"))

    # The example from RFC 7617.
    assert echoed.headers(response)["authorization"] == "Basic YWxhZGRpbjpvcGVuc2VzYW1l"


def test_bearer_auth_sets_the_authorization_header(
    session: cronet.Session, server: str
) -> None:
    response = session.get(f"{server}/echo", bearer_auth="a-token")

    assert echoed.headers(response)["authorization"] == "Bearer a-token"


def test_giving_two_kinds_of_auth_is_rejected(
    session: cronet.Session, server: str
) -> None:
    with pytest.raises(TypeError, match="only one of"):
        session.get(f"{server}/echo", basic_auth=("a", "b"), bearer_auth="c")


def test_an_explicit_authorization_header_wins(
    session: cronet.Session, server: str
) -> None:
    response = session.get(
        f"{server}/echo",
        headers={"authorization": "Custom mine"},
        bearer_auth="ignored",
    )

    assert echoed.headers(response)["authorization"] == "Custom mine"


def test_a_chrome_user_agent_is_sent_by_default(
    session: cronet.Session, server: str
) -> None:
    user_agent = echoed.headers(session.get(f"{server}/echo"))["user-agent"]

    assert user_agent == cronet.default_user_agent()
    assert user_agent.startswith("Mozilla/5.0 ")
    assert f"Chrome/{cronet.version().split('.')[0]}.0.0.0" in user_agent


def test_the_user_agent_can_be_replaced(server: str) -> None:
    with cronet.Session(user_agent="my-crawler/1.0") as session:
        response = session.get(f"{server}/echo")

    assert echoed.headers(response)["user-agent"] == "my-crawler/1.0"


def test_an_empty_user_agent_is_sent_as_an_empty_header(server: str) -> None:
    # Chromium always emits the header; asking for no User-Agent gets one with
    # nothing in it rather than none at all.
    with cronet.Session(user_agent="") as session:
        response = session.get(f"{server}/echo")

    assert echoed.headers(response)["user-agent"] == ""


def test_elapsed_is_reported_in_seconds(session: cronet.Session, server: str) -> None:
    response = session.get(f"{server}/echo")

    assert 0.0 <= response.elapsed < 30.0, response.elapsed
