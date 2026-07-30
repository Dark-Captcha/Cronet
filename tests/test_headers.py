"""What the Headers mapping promises, with no network in sight."""

import pytest

from cronet import Headers


def test_lookup_ignores_case() -> None:
    headers = Headers({"Content-Type": "text/html"})

    assert headers["content-type"] == "text/html"
    assert headers["CONTENT-TYPE"] == "text/html"
    assert "Content-TYPE" in headers


def test_order_is_kept() -> None:
    headers = Headers([("b", "1"), ("a", "2"), ("c", "3")])

    assert [name for name, _ in headers.items()] == ["b", "a", "c"]


def test_repeats_are_kept_and_joined_on_lookup() -> None:
    headers = Headers([("set-cookie", "a=1"), ("set-cookie", "b=2")])

    assert headers.get_list("set-cookie") == ["a=1", "b=2"]
    assert headers["set-cookie"] == "a=1, b=2"
    assert len(headers) == 1, "one name, however many values"


def test_a_missing_name_raises() -> None:
    headers = Headers({"a": "1"})

    with pytest.raises(KeyError):
        headers["absent"]
    assert headers.get("absent") is None


def test_empty_headers_are_empty() -> None:
    headers = Headers()

    assert len(headers) == 0
    assert headers.items() == ()
    assert list(headers) == []


def test_defaults_are_kept_where_they_stand_when_overridden() -> None:
    defaults = Headers([("first", "a"), ("second", "b"), ("third", "c")])

    merged = Headers({"second": "replaced"}).with_defaults(defaults)

    assert merged.items() == (
        ("first", "a"),
        ("second", "replaced"),
        ("third", "c"),
    )


def test_new_names_are_appended_after_the_defaults() -> None:
    defaults = Headers([("first", "a")])

    merged = Headers({"second": "b"}).with_defaults(defaults)

    assert merged.items() == (("first", "a"), ("second", "b"))


def test_overriding_matches_without_regard_to_case() -> None:
    defaults = Headers([("User-Agent", "old")])

    merged = Headers({"user-agent": "new"}).with_defaults(defaults)

    assert merged.items() == (("user-agent", "new"),), merged.items()


def test_defaults_alone_survive_an_empty_override() -> None:
    defaults = Headers([("a", "1"), ("b", "2")])

    merged = Headers().with_defaults(defaults)

    assert merged.items() == (("a", "1"), ("b", "2"))
