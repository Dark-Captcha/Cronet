"""Everything this package raises.

The split is by what a caller would do about it: retry, fix the request, fix
the proxy, or give up. Every transport failure carries the Chromium network
error code that produced it, because that code is the most precise thing there
is to look up.
"""


class CronetError(Exception):
    """Base class for every error this package raises."""


class LibraryError(CronetError):
    """The native library could not be loaded, or refused a configuration."""


class SessionClosed(CronetError):
    """The session was used after it was closed."""


class RequestError(CronetError):
    """A request produced no response.

    `net_error` is the Chromium error code, negative, as documented in
    Chromium's net_error_list.h — for example -105 for ERR_NAME_NOT_RESOLVED.
    """

    def __init__(self, message: str, *, net_error: int = 0, url: str = "") -> None:
        super().__init__(message)
        self.net_error = net_error
        self.url = url


class ConnectionFailed(RequestError):
    """The connection could not be made, or died before the response."""


class Timeout(RequestError):
    """The request did not finish inside the time allowed."""


class Cancelled(RequestError):
    """The request was cancelled, or its session was closed under it."""


class TooManyRedirects(RequestError):
    """The redirect chain ran past the limit."""


class ProxyFailed(RequestError):
    """The proxy refused the connection, or would not authenticate."""


class CertificateError(RequestError):
    """The server's TLS certificate was not acceptable."""


class HTTPStatusError(CronetError):
    """A response carried an error status, and was asked to raise.

    `response` is the `Response` that raised, kept so a caller can read the
    status and body it was refused on. It is typed as `object` rather than
    `Response` because `response` imports this module to define
    `raise_for_status`, and naming the class here would close that circle.
    """

    def __init__(self, message: str, *, response: object) -> None:
        super().__init__(message)
        self.response = response


# Chromium groups its network errors into bands by first digit, which is what
# makes a range test meaningful here: -100..-199 is connection, -200..-299 is
# certificate. The codes below fall inside a band but mean something a caller
# handles differently, so each is named against Chromium's net_error_list.h.
_PROXY_ERRORS = frozenset(
    {
        -115,  # TUNNEL_CONNECTION_FAILED
        -127,  # PROXY_AUTH_REQUESTED
        -130,  # PROXY_CONNECTION_FAILED
        -131,  # MANDATORY_PROXY_CONFIGURATION_FAILED
        -136,  # PROXY_CERTIFICATE_INVALID
        -144,  # PROXY_AUTH_UNSUPPORTED
        -336,  # NO_SUPPORTED_PROXIES
    }
)
_SSL_ERRORS = frozenset(
    {
        -107,  # SSL_PROTOCOL_ERROR
        -113,  # SSL_VERSION_OR_CIPHER_MISMATCH
        -117,  # SSL_UNSAFE_NEGOTIATION
        -122,  # SSL_RENEGOTIATION_REQUESTED
        -126,  # SSL_HANDSHAKE_NOT_COMPLETED
        -141,  # SSL_CLIENT_AUTH_SIGNATURE_FAILED
        -164,  # SSL_DECOMPRESSION_FAILURE_ALERT
    }
)
_TIMEOUT_ERRORS = frozenset(
    {
        -7,  # TIMED_OUT
        -118,  # CONNECTION_TIMED_OUT
    }
)

_CANCELLED = -3  # ABORTED
_REDIRECT_LIMIT = -31  # This library's own; see CRONET_ERROR_TOO_MANY_REDIRECTS.


def error_for(net_error: int, message: str, url: str) -> RequestError:
    """The exception that fits `net_error`."""
    text = f"{message or f'network error {net_error}'} for {url}" if url else message
    if net_error in _TIMEOUT_ERRORS:
        return Timeout(text, net_error=net_error, url=url)
    if net_error == _CANCELLED:
        return Cancelled(text, net_error=net_error, url=url)
    if net_error == _REDIRECT_LIMIT:
        return TooManyRedirects(text, net_error=net_error, url=url)
    if net_error in _PROXY_ERRORS:
        return ProxyFailed(text, net_error=net_error, url=url)
    if net_error in _SSL_ERRORS or -300 < net_error <= -200:
        return CertificateError(text, net_error=net_error, url=url)
    if -200 < net_error <= -100:
        return ConnectionFailed(text, net_error=net_error, url=url)
    return RequestError(text, net_error=net_error, url=url)
