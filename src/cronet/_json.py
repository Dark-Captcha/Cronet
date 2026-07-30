"""JSON, encoded and decoded as fast as the environment allows.

msgspec is several times quicker than the standard library at both ends, so it
is used when it happens to be installed. It is deliberately *not* a dependency:
this package requires nothing outside the standard library, and falls back to
`json` when msgspec is absent. The two produce the same values, so which one is
in play changes only the speed.

Check `ACCELERATED` to see which is in use.
"""

import json

try:
    from msgspec.json import decode as _msgspec_decode
    from msgspec.json import encode as _msgspec_encode

    ACCELERATED = True
except ImportError:
    ACCELERATED = False


def decode(data: bytes) -> object:
    """Parse JSON from bytes.

    Args:
        data: The document to parse.

    Returns:
        The parsed value.

    Raises:
        ValueError: The bytes are not valid JSON. msgspec raises its own
            DecodeError, which subclasses ValueError, so catching ValueError
            works whichever backend is in use.
    """
    if ACCELERATED:
        return _msgspec_decode(data)
    return json.loads(data)


def encode(value: object) -> bytes:
    """Serialise `value` as JSON bytes.

    Args:
        value: Anything the backend can represent.

    Returns:
        The encoded document.
    """
    if ACCELERATED:
        return _msgspec_encode(value)
    return json.dumps(value).encode()
