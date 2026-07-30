"""Chromium's network stack, as a Python library.

This is Cronet — the networking core of Chrome — built standalone from
Chromium source and driven through a small C ABI. What that buys over an
ordinary HTTP client is that the connection really is Chrome's: the same TLS
stack, the same HTTP/2 and HTTP/3 implementations, the same connection reuse
and DNS behaviour.

Nothing outside the standard library is needed to use it.

Example:
    >>> from cronet import Session
    >>> with Session() as session:
    ...     response = session.get("https://example.com")
    ...     print(response.status_code, response.http_version)
    200 h2
"""

from .cookies import CookieJar
from .errors import (
    Cancelled,
    CertificateError,
    ConnectionFailed,
    CronetError,
    HTTPStatusError,
    LibraryError,
    ProxyFailed,
    RequestError,
    SessionClosed,
    Timeout,
    TooManyRedirects,
)
from .headers import Headers
from .request import Priority, RequestOptions
from .response import NO_TIME, Metrics, Response
from .session import (
    AsyncSession,
    Cache,
    Session,
    default_user_agent,
    version,
)
from .tls import DETERMINISTIC, TlsProfile

__all__ = [
    "DETERMINISTIC",
    "NO_TIME",
    "AsyncSession",
    "Cache",
    "Cancelled",
    "CertificateError",
    "ConnectionFailed",
    "CookieJar",
    "CronetError",
    "HTTPStatusError",
    "Headers",
    "LibraryError",
    "Metrics",
    "Priority",
    "ProxyFailed",
    "RequestError",
    "RequestOptions",
    "Response",
    "Session",
    "SessionClosed",
    "Timeout",
    "TlsProfile",
    "TooManyRedirects",
    "default_user_agent",
    "version",
]
