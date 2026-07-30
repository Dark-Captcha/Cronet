"""Cookie storage.

Cronet deliberately runs with its cookie store switched off, so nothing below
the C ABI remembers a Set-Cookie header. This puts a jar back on the Python
side, built on `http.cookiejar` from the standard library — which already knows
the domain, path, expiry and Secure rules that make cookie handling correct
rather than merely plausible.

A jar is safe to share between threads and between sessions.
"""

import threading
from collections.abc import Iterator
from email.message import Message
from http.client import HTTPResponse
from http.cookiejar import Cookie
from http.cookiejar import CookieJar as _StandardJar
from typing import cast
from urllib.request import Request

from .headers import Headers


class _ResponseAdapter:
    """Presents response headers the way http.cookiejar expects to read them."""

    __slots__ = ("_message",)

    def __init__(self, headers: Headers) -> None:
        message = Message()
        for name, value in headers.items():
            message[name] = value
        self._message = message

    def info(self) -> Message:
        return self._message


class CookieJar:
    """A cookie store, shared by whichever sessions are given it.

    Example:
        >>> jar = CookieJar()
        >>> with Session(cookies=jar) as session:
        ...     session.get("https://example.com/login")
        ...     session.get("https://example.com/account")  # sends what was set
    """

    def __init__(self) -> None:
        self._jar = _StandardJar()
        self._lock = threading.Lock()

    def header_for(self, url: str) -> str | None:
        """The Cookie header to send with a request to `url`, if any.

        Args:
            url: The absolute URL about to be requested.

        Returns:
            The header value, or None when no stored cookie applies.
        """
        request = Request(url)
        with self._lock:
            self._jar.add_cookie_header(request)
        return request.get_header("Cookie")

    def store(self, url: str, headers: Headers) -> None:
        """Take in any Set-Cookie headers from a response to `url`.

        Args:
            url: The URL the response came from.
            headers: That response's headers.
        """
        if "set-cookie" not in headers:
            return
        # extract_cookies is annotated for an HTTPResponse but only ever calls
        # info() on it, which is the whole of the adapter above.
        response = cast(HTTPResponse, _ResponseAdapter(headers))
        with self._lock:
            self._jar.extract_cookies(response, Request(url))

    def clear(self) -> None:
        """Forget every cookie."""
        with self._lock:
            self._jar.clear()

    def __iter__(self) -> Iterator[Cookie]:
        # A snapshot taken under the lock, not a live view: a jar is shared
        # between sessions, so a response arriving mid-loop would otherwise
        # mutate the store while it is being walked.
        with self._lock:
            return iter(list(self._jar))

    def __len__(self) -> int:
        with self._lock:
            return len(self._jar)

    def __repr__(self) -> str:
        return f"CookieJar({len(self)} cookies)"
