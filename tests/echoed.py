"""Reading back what the echo server in conftest.py was actually sent.

Shared by the test modules that assert on the request rather than on the
response, since "what went out on the wire" is the claim most of them make.
"""

import json
from typing import cast

import cronet


def request(response: cronet.Response) -> dict[str, object]:
    """The whole echo document: method, path, headers and body."""
    parsed: dict[str, object] = json.loads(response.content)
    return parsed


def headers(response: cronet.Response) -> dict[str, str]:
    """The headers the server received, lowercased for lookup."""
    pairs = cast(list[list[str]], request(response)["headers"])
    return {name.lower(): value for name, value in pairs}
