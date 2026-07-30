"""The guards that turn a silent wrong answer into a loud one.

Everything here used to be accepted and quietly ignored, which is worse than
failing: the request went out with settings the caller did not ask for.
"""

import json
import re
from typing import Any

import pytest

import cronet


def untyped(session: cronet.Session | cronet.AsyncSession) -> Any:
    """The same session, seen the way an unchecked caller sees it.

    The whole point of these guards is the caller a type checker never
    inspects — a REPL, a notebook, a script nobody runs mypy over. Calling
    through a typed reference would prove the opposite of what is claimed
    here, because mypy would reject the call before it ever ran.
    """
    return session


def test_an_unknown_option_is_refused(session: cronet.Session, server: str) -> None:
    # requests spells this allow_redirects; until it was refused, passing it
    # followed the redirect anyway and said nothing.
    with pytest.raises(TypeError, match="allow_redirects"):
        untyped(session).get(f"{server}/echo", allow_redirects=False)


def test_a_misspelled_option_suggests_the_right_one(
    session: cronet.Session, server: str
) -> None:
    with pytest.raises(TypeError, match="did you mean 'timeout'"):
        untyped(session).get(f"{server}/echo", timout=1)


def test_the_refusal_lists_what_is_accepted(
    session: cronet.Session, server: str
) -> None:
    with pytest.raises(TypeError, match=r"Accepted: .*basic_auth.*query"):
        untyped(session).get(f"{server}/echo", verify=False)


def test_a_misspelled_upload_option_suggests_files(
    session: cronet.Session, server: str
) -> None:
    with pytest.raises(TypeError, match="did you mean 'files'"):
        untyped(session).post(f"{server}/echo", file={"f": b"x"})


@pytest.mark.asyncio
async def test_an_unknown_option_is_refused_asynchronously(server: str) -> None:
    async with cronet.AsyncSession() as session:
        with pytest.raises(TypeError, match="unknown request option"):
            await untyped(session).get(f"{server}/echo", cookies={"a": "b"})


def test_a_url_without_a_scheme_says_so(session: cronet.Session) -> None:
    with pytest.raises(
        TypeError, match=re.escape("did you mean 'https://example.com'")
    ):
        session.get("example.com")


def test_a_url_with_an_unusable_scheme_says_so(session: cronet.Session) -> None:
    with pytest.raises(TypeError, match="only http and https"):
        session.get("ftp://example.com/file")


def test_a_url_with_no_host_says_so(session: cronet.Session) -> None:
    with pytest.raises(TypeError, match="names no host"):
        session.get("http:///nowhere")


def test_options_is_available_on_both_session_types() -> None:
    assert hasattr(cronet.Session, "options")
    assert hasattr(cronet.AsyncSession, "options")


def test_every_verb_reaches_the_server(session: cronet.Session, server: str) -> None:
    for verb in ("get", "post", "put", "patch", "delete", "options"):
        response = getattr(session, verb)(f"{server}/echo")
        assert response.status_code == 200, verb
        assert json.loads(response.content)["method"] == verb.upper(), verb


def test_head_sends_head(session: cronet.Session, server: str) -> None:
    # HEAD has no body to echo, so the status is the whole claim.
    assert session.head(f"{server}/echo").status_code == 200
