"""Turning a caller's options into one native call, and following where it leads.

`Session` and `AsyncSession` differ only in how they wait for the network, so
everything about *what* gets sent is written once, here: the option guards, the
URL and query handling, the body encodings, and the redirect walk a session
makes while it is holding a cookie jar.

Nothing in this module performs a request or knows how one is awaited.
"""

import base64
import difflib
import mimetypes
import secrets
import string
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import TypedDict, cast

from . import _bridge, _json
from ._bridge import CallSettings
from .cookies import CookieJar
from .errors import TooManyRedirects
from .headers import Headers
from .response import Response

type HeaderSource = Mapping[str, str] | Iterable[tuple[str, str]] | None
type QuerySource = Mapping[str, str] | Sequence[tuple[str, str]] | None

# One file to upload: its bytes alone, which names the part after its own
# field; or a filename beside them; or both plus an explicit media type.
type FileContent = bytes | str
type FileSpec = FileContent | tuple[str, FileContent] | tuple[str, FileContent, str]
type FileSource = Mapping[str, FileSpec] | Sequence[tuple[str, FileSpec]] | None


class Priority(StrEnum):
    """How urgently a request is scheduled against its siblings."""

    THROTTLED = "throttled"
    IDLE = "idle"
    LOWEST = "lowest"
    LOW = "low"
    MEDIUM = "medium"
    HIGHEST = "highest"


_PRIORITIES = {
    Priority.THROTTLED: _bridge.PRIORITY_THROTTLED,
    Priority.IDLE: _bridge.PRIORITY_IDLE,
    Priority.LOWEST: _bridge.PRIORITY_LOWEST,
    Priority.LOW: _bridge.PRIORITY_LOW,
    Priority.MEDIUM: _bridge.PRIORITY_MEDIUM,
    Priority.HIGHEST: _bridge.PRIORITY_HIGHEST,
}


class RequestOptions(TypedDict, total=False):
    """Everything `Session.request` accepts besides the method and URL.

    The body may be given in exactly one of three shapes: `body` for bytes or
    text, `form` for url-encoded fields, `json` for anything serialisable.
    `files` turns the request into a multipart upload, and is the one that may
    be combined with `form` — the fields then travel as parts beside the files.
    A body option left at None counts as absent rather than as an empty body.

    Passing a name that is not one of these is a TypeError, not something
    quietly dropped; see `check_options` for why that is worth the noise.

    Attributes:
        headers: Sent after the session's own. A name the session already set
            is replaced where it stands, so overriding one value does not
            disturb the order the session established.
        query: Added to whatever query string the URL already carries.
        body: Sent as given; text is encoded as UTF-8.
        form: Fields, sent url-encoded — or as multipart parts when `files` is
            given too.
        files: Files, sent as multipart/form-data. See `FileSpec` for the
            shapes one file may take.
        json: Any value the JSON backend can represent, sent as
            application/json.
        basic_auth: (username, password), sent as an Authorization header.
        bearer_auth: A token, sent as "Authorization: Bearer <token>".
        timeout: Seconds this request may take; None for no limit. Absent means
            the session's own default, which is why this is a TypedDict — a
            plain default could not tell "no limit" from "unset".
        max_redirects: Redirects to follow for this request; None for the
            session's default. Zero returns the redirect itself, unfollowed, as
            a successful response rather than as a failure.
        priority: A `Priority`, or its value as a string. Defaults to MEDIUM.
        disable_cache: Skip the session's cache for this request.
    """

    headers: HeaderSource
    query: QuerySource
    body: bytes | str | None
    form: Mapping[str, str] | None
    files: FileSource
    json: object
    basic_auth: tuple[str, str]
    bearer_auth: str
    timeout: float | None
    max_redirects: int | None
    priority: Priority | str
    disable_cache: bool


# Headers the network stack fills in for itself. A caller that sets one of
# these does not merely add a value: it moves the name to wherever the caller
# put it, which is a different request order from the one Chrome sends — and
# order is exactly what this library exists to reproduce. Chromium accepts them
# all silently, so nothing downstream would ever report the difference.
#
# The value beside each name is what to reach for instead.
STACK_OWNED_HEADERS = {
    "accept-encoding": "the session's brotli= setting decides this",
    "accept-language": "pass accept_language= to the session",
    "host": "Chromium derives this from the URL",
    "connection": "Chromium manages connection reuse itself",
    "content-length": "Chromium counts the body it is given",
}


def check_headers(headers: HeaderSource, *, source: str) -> None:
    """Reject headers the network stack owns.

    Args:
        headers: What the caller supplied.
        source: Where they came from, for the message — "a request" or
            "the session".

    Raises:
        ValueError: A header named here is one Chromium fills in itself.
    """
    if headers is None:
        return
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    for name, _value in pairs:
        instead = STACK_OWNED_HEADERS.get(name.lower())
        if instead is not None:
            raise ValueError(
                f"{name!r} was set on {source}, but Chromium sets it itself — "
                f"{instead}. Setting it by hand moves the header to where you "
                "put it, which is not where Chrome sends it, so the request "
                "stops matching a browser's."
            )


def check_options(options: RequestOptions) -> None:
    """Reject anything `request` does not understand.

    Without this an unknown keyword is silently dropped: `allow_redirects=False`
    from requests, `verify=False` from httpx, or a plain typo all vanish and the
    request goes out with settings the caller did not ask for. The type checker
    catches these; nobody running plain Python gets that.

    Raises:
        TypeError: An option name is not one `request` accepts.
    """
    unknown = options.keys() - RequestOptions.__optional_keys__
    if not unknown:
        return
    known = sorted(RequestOptions.__optional_keys__)
    complaints = []
    for name in sorted(unknown):
        closest = difflib.get_close_matches(name, known, n=1)
        suggestion = f" — did you mean {closest[0]!r}?" if closest else ""
        complaints.append(f"{name!r}{suggestion}")
    raise TypeError(
        f"unknown request option{'s' if len(complaints) > 1 else ''}: "
        f"{', '.join(complaints)}. Accepted: {', '.join(known)}"
    )


def checked_url(url: str) -> str:
    """`url` if it is one this library can request.

    Raises:
        TypeError: The URL has no scheme, no host, or a scheme that is not
            http or https.
    """
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme:
        guess = url.split("/", 1)[0]
        raise TypeError(f"{url!r} has no scheme — did you mean 'https://{guess}'?")
    if parts.scheme not in ("http", "https"):
        raise TypeError(
            f"{url!r} uses the {parts.scheme!r} scheme; only http and https work"
        )
    if not parts.hostname:
        raise TypeError(f"{url!r} names no host")
    return url


def with_query(url: str, params: QuerySource) -> str:
    """`url` with `params` added to its query string."""
    if not params:
        return url
    parts = urllib.parse.urlsplit(url)
    pairs = list(params.items() if isinstance(params, Mapping) else params)
    existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query = urllib.parse.urlencode(existing + pairs)
    return urllib.parse.urlunsplit(parts._replace(query=query))


def authorization(options: RequestOptions) -> str | None:
    """The Authorization header value the options ask for, if any."""
    basic = options.get("basic_auth")
    bearer = options.get("bearer_auth")
    if basic is not None and bearer is not None:
        raise TypeError("give only one of basic_auth or bearer_auth")
    if basic is not None:
        username, password = basic
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {encoded}"
    if bearer is not None:
        return f"Bearer {bearer}"
    return None


# Chrome builds its multipart boundary as "----WebKitFormBoundary" followed by
# sixteen random characters, and a body claiming to come from a browser should
# look like one. The randomness is also what keeps the boundary from colliding
# with the content it delimits, which is why no scan of the parts is needed.
BOUNDARY_PREFIX = "----WebKitFormBoundary"
_BOUNDARY_ALPHABET = string.ascii_letters + string.digits
_BOUNDARY_LENGTH = 16

# A part header carries its name and filename inside quotes, so the three
# characters that could end the quoting early are percent-encoded. Browsers do
# exactly this; without it a crafted filename writes headers of its own.
_QUOTED = str.maketrans({'"': "%22", "\r": "%0D", "\n": "%0A"})


def generate_boundary() -> str:
    """A multipart boundary in the shape Chrome uses."""
    return BOUNDARY_PREFIX + "".join(
        secrets.choice(_BOUNDARY_ALPHABET) for _ in range(_BOUNDARY_LENGTH)
    )


def _disposition(name: str, filename: str | None) -> str:
    """The Content-Disposition value for one part."""
    value = f'form-data; name="{name.translate(_QUOTED)}"'
    if filename is not None:
        value += f'; filename="{filename.translate(_QUOTED)}"'
    return value


def _file_part(name: str, spec: FileSpec) -> tuple[str, str, bytes]:
    """One file field as its filename, media type and bytes.

    Args:
        name: The form field the file is uploaded under.
        spec: Content alone, or a filename beside it, or both plus a media
            type.

    Returns:
        The filename to declare, the media type, and the content.
    """
    if isinstance(spec, bytes | str):
        filename, content, declared = name, spec, None
    elif len(spec) == 2:
        filename, content = spec
        declared = None
    else:
        filename, content, declared = spec
    media_type = (
        declared or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    )
    return (
        filename,
        media_type,
        content.encode() if isinstance(content, str) else content,
    )


def encode_multipart(
    fields: Sequence[tuple[str, str]],
    files: Sequence[tuple[str, FileSpec]],
    boundary: str,
) -> bytes:
    """A multipart/form-data body carrying `fields` and then `files`.

    Args:
        fields: Plain text fields, in order.
        files: File fields, in order, each as described by `FileSpec`.
        boundary: The delimiter, without its leading dashes.

    Returns:
        The encoded body, which the caller announces with a Content-Type of
        "multipart/form-data; boundary=<boundary>".
    """
    body = bytearray()
    for name, value in fields:
        body += f"--{boundary}\r\n".encode()
        body += f"Content-Disposition: {_disposition(name, None)}\r\n\r\n".encode()
        body += value.encode()
        body += b"\r\n"
    for name, spec in files:
        filename, media_type, content = _file_part(name, spec)
        body += f"--{boundary}\r\n".encode()
        body += f"Content-Disposition: {_disposition(name, filename)}\r\n".encode()
        body += f"Content-Type: {media_type}\r\n\r\n".encode()
        body += content
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body)


def _pairs[T](source: Mapping[str, T] | Sequence[tuple[str, T]]) -> list[tuple[str, T]]:
    """`source` as an ordered list of pairs, however it was given."""
    return list(source.items() if isinstance(source, Mapping) else source)


def encode_body(options: RequestOptions) -> tuple[bytes, str | None]:
    """The request body, and the media type it implies.

    Returns:
        The encoded body, and a Content-Type to add when the caller set none —
        None when the body implies no particular type.

    Raises:
        TypeError: The options ask for more than one kind of body. `form` and
            `files` together are the one accepted combination, since that is
            what a browser sends for a form carrying an upload.
    """
    files = options.get("files")
    given = [name for name in ("body", "form", "json") if options.get(name) is not None]
    if len(given) > 1:
        raise TypeError(f"give only one of body, form or json, not {given}")
    if files is not None and given not in ([], ["form"]):
        raise TypeError(
            f"files may be given with form, but not with {given[0]} — a "
            "multipart body carries its fields as parts of its own"
        )

    if files is not None:
        fields = options.get("form")
        boundary = generate_boundary()
        return (
            encode_multipart(_pairs(fields) if fields else [], _pairs(files), boundary),
            f"multipart/form-data; boundary={boundary}",
        )

    body = options.get("body")
    if body is not None:
        return (body.encode() if isinstance(body, str) else body), None
    form = options.get("form")
    if form is not None:
        return (
            urllib.parse.urlencode(dict(form)).encode(),
            "application/x-www-form-urlencoded",
        )
    if options.get("json") is not None:
        return _json.encode(options["json"]), "application/json"
    return b"", None


def build_call(
    method: str,
    url: str,
    options: RequestOptions,
    *,
    defaults: Headers,
    cookies: CookieJar | None,
    max_redirects: int,
) -> CallSettings:
    """One native call, composed from a session's defaults and these options.

    Args:
        method: HTTP method, uppercased by the bridge.
        url: The absolute URL, query string already applied.
        options: What the caller passed to `request`.
        defaults: The session's own headers, which these are laid over.
        cookies: The session's jar, consulted when the caller set no Cookie.
        max_redirects: How many redirects the native side may follow itself.

    Returns:
        The settings the bridge starts a call from.
    """
    body, implied_type = encode_body(options)
    merged = Headers(options.get("headers")).with_defaults(defaults)

    # Added only where the caller has not spoken for the name themselves, and
    # appended, so an explicit ordering is never disturbed.
    additions: list[tuple[str, str]] = []
    if implied_type and "content-type" not in merged:
        additions.append(("content-type", implied_type))
    credentials = authorization(options)
    if credentials and "authorization" not in merged:
        additions.append(("authorization", credentials))
    if cookies is not None and "cookie" not in merged:
        cookie = cookies.header_for(url)
        if cookie:
            additions.append(("cookie", cookie))
    if additions:
        merged = Headers([*merged.items(), *additions])

    return CallSettings(
        method=method,
        url=url,
        headers=merged.items(),
        body=body,
        priority=_PRIORITIES[Priority(options.get("priority", Priority.MEDIUM))],
        max_redirects=max_redirects,
        disable_cache=options.get("disable_cache", False),
    )


def origin(url: str) -> tuple[str, str, int | None]:
    """The scheme, host and port `url` belongs to."""
    parts = urllib.parse.urlsplit(url)
    return parts.scheme, parts.hostname or "", parts.port


def next_hop(
    method: str, url: str, response: Response, options: RequestOptions
) -> tuple[str, str, RequestOptions] | None:
    """Where a redirect leads, or None when the response is the last one.

    Args:
        method: The method that produced `response`.
        url: The URL that produced it, for resolving a relative Location.
        response: The response to examine.
        options: The options the request was made with.

    Returns:
        The method, URL and options for the next hop, or None to stop.
    """
    location = response.headers.get("location")
    if not location or not 300 <= response.status_code < 400:
        return None

    target = urllib.parse.urljoin(url, location)
    carried = dict(options)

    # Chromium's own rule, from net/url_request/redirect_info.cc: a 303 becomes
    # a GET unless it was a HEAD, and 301 and 302 become one only for POST.
    # Anything else keeps its method, and only a method change drops the body.
    status = response.status_code
    if (status == 303 and method.upper() != "HEAD") or (
        status in (301, 302) and method.upper() == "POST"
    ):
        method = "GET"
        for name in ("body", "form", "files", "json"):
            carried.pop(name, None)

    # Credentials belong to the origin they were given for. Following a
    # redirect elsewhere while still carrying them hands them to a host the
    # caller never named, which is how a redirect turns into a token leak.
    if origin(url) != origin(target):
        for name in ("basic_auth", "bearer_auth"):
            carried.pop(name, None)
        headers = Headers(options.get("headers"))
        if "authorization" in headers or "cookie" in headers:
            carried["headers"] = [
                (name, value)
                for name, value in headers.items()
                if name.lower() not in ("authorization", "cookie")
            ]

    return method, target, cast(RequestOptions, carried)


class RedirectChain:
    """A redirect chain walked one hop at a time.

    Chromium follows redirects itself and does not report the responses it
    passed through, so a session holding a cookie jar asks for a single hop at
    a time instead — which is what lets a cookie set part way along the chain
    be stored before the next request goes out, and what fills
    `Response.history`.

    The walk is driven from outside, so the blocking and asyncio sessions share
    it without either one knowing how the other waits:

        chain = RedirectChain(method, url, options, limit=20, cookies=jar)
        while (pending := chain.pending) is not None:
            chain.receive(perform(*pending))
        return chain.result()
    """

    __slots__ = ("_cookies", "_final", "_history", "_limit", "_pending", "_start")

    def __init__(
        self,
        method: str,
        url: str,
        options: RequestOptions,
        *,
        limit: int,
        cookies: CookieJar,
    ) -> None:
        """Begin a chain at `url`.

        Args:
            method: The method to start with.
            url: The absolute URL to start at.
            options: The options every hop is made with, minus whatever a
                method change or a change of origin drops along the way.
            limit: How many redirects may be followed before the chain fails.
            cookies: The jar each hop's Set-Cookie headers are stored in.
        """
        self._pending: tuple[str, str, RequestOptions] | None = (method, url, options)
        self._limit = limit
        self._cookies = cookies
        self._history: list[Response] = []
        self._final: Response | None = None
        self._start = url

    @property
    def pending(self) -> tuple[str, str, RequestOptions] | None:
        """The method, URL and options of the next hop, or None when finished."""
        return self._pending

    def receive(self, response: Response) -> None:
        """Take in the response to `pending` and work out where to go next.

        Raises:
            TooManyRedirects: The chain would run past its limit.
            RuntimeError: The chain had already finished.
        """
        if self._pending is None:
            raise RuntimeError("this redirect chain has already finished")
        method, url, options = self._pending
        self._cookies.store(url, response.headers)

        hop = next_hop(method, url, response, options)
        # A limit of zero asks for the redirect itself, unfollowed, exactly as
        # it does when Chromium is the one following — the jar must not turn a
        # deliberate `max_redirects=0` into a failure.
        if hop is None or self._limit == 0:
            response.history = tuple(self._history)
            self._final = response
            self._pending = None
            return
        if len(self._history) >= self._limit:
            raise TooManyRedirects(
                f"more than {self._limit} redirects from {self._start}",
                net_error=_bridge.ERROR_TOO_MANY_REDIRECTS,
                url=self._start,
            )
        self._history.append(response)
        self._pending = hop

    def result(self) -> Response:
        """The response the chain ended on.

        Raises:
            RuntimeError: The chain has not finished yet.
        """
        if self._final is None:
            raise RuntimeError("this redirect chain has not finished")
        return self._final
