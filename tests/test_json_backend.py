"""JSON goes through msgspec when it is installed, and the standard library
otherwise. Both paths have to produce the same values, because which one runs
depends only on what happens to be installed alongside.
"""

import json

import pytest

from cronet import _json


@pytest.fixture
def stdlib_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Forces the fallback path for one test."""
    monkeypatch.setattr(_json, "ACCELERATED", False)


VALUES = [
    {"a": 1, "b": [1, 2, 3], "c": None},
    [],
    {},
    {"nested": {"deep": {"deeper": True}}},
    {"unicode": "héllo — wörld", "emoji": "🙂"},
    {"big": 2**53},
    "just a string",
    123,
    None,
]


@pytest.mark.parametrize("value", VALUES)
def test_a_value_survives_a_round_trip(value: object) -> None:
    assert _json.decode(_json.encode(value)) == value


@pytest.mark.parametrize("value", VALUES)
def test_the_fallback_agrees_with_the_standard_library(
    value: object, stdlib_backend: None
) -> None:
    assert _json.decode(_json.encode(value)) == value
    assert json.loads(_json.encode(value)) == value


def test_malformed_json_raises_value_error() -> None:
    # msgspec raises its own DecodeError, which subclasses ValueError, so a
    # caller catching ValueError works whichever backend is in play.
    with pytest.raises(ValueError):
        _json.decode(b"{not json")


def test_malformed_json_raises_value_error_on_the_fallback(
    stdlib_backend: None,
) -> None:
    with pytest.raises(ValueError):
        _json.decode(b"{not json")


def test_the_backend_reports_itself() -> None:
    assert isinstance(_json.ACCELERATED, bool)
