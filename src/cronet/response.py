"""What a request gives back.

`Response` is built by a session, never by a caller, and covers both kinds: one
read whole, and one still arriving. The difference between them is confined to
`stream`, so a caller that loops with `iter_bytes()` need not know which it
holds.

`Metrics` and `NO_TIME` are re-exported from `_bridge`, where they are built
straight out of the C struct. They are named here too because this is where a
caller meets them.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Self

from . import _json
from ._bridge import NO_TIME, Metrics, RawResponse
from .errors import HTTPStatusError
from .headers import Headers

__all__ = ["NO_TIME", "Metrics", "Response"]


@dataclass(slots=True, kw_only=True, eq=False)
class Response:
    """A response, read whole. Made by a session, not by callers.

    The body arrives already decompressed: Chromium undoes gzip, deflate,
    brotli and zstd before this sees it, so `content` is what the server meant
    to send.

    Attributes:
        status_code: The HTTP status.
        reason: The status text the server sent, which may be empty — HTTP/2
            and HTTP/3 do not carry one at all.
        headers: Response headers, in the order the server sent them.
        content: The body, already decompressed.
        url: The final URL, after any redirects that were followed.
        http_version: "http/1.1", "h2" or "h3" once ALPN has run; "unknown"
            when it has not, as on any plaintext HTTP connection.
        redirect_count: How many redirects were followed to get here.
        from_cache: Whether the session's cache answered this.
        proxy: Host and port of the proxy used, or "direct".
        metrics: Per-phase timings, in microseconds since the epoch.
        history: Each earlier hop, oldest first, when the session followed
            redirects one at a time — which it does only with a cookie jar in
            use. Empty when Chromium followed them itself, because it does not
            report the intermediate responses.
    """

    status_code: int
    reason: str
    headers: Headers
    content: bytes
    url: str
    http_version: str
    redirect_count: int
    from_cache: bool
    proxy: str
    metrics: Metrics
    history: tuple[Response, ...] = ()

    # Set only while a response is being streamed. `content` is empty until the
    # body has been read, because the point of streaming is not to hold it.
    stream: Iterator[bytes] | None = field(default=None, repr=False)

    def iter_bytes(self) -> Iterator[bytes]:
        """The body in pieces, as the network delivers them.

        Reading is what lets the transfer continue: the library holds a bounded
        amount and stops pulling from the socket until this drains it, so a
        slow consumer slows the transfer instead of filling memory.

        Returns:
            The pieces, in order. A response already read whole yields its
            body once, so a caller need not care which kind it was handed.
        """
        if self.stream is None:
            return iter((self.content,) if self.content else ())
        return self.stream

    def read(self) -> bytes:
        """Read the rest of a streaming body and keep it as `content`."""
        if self.stream is not None:
            self.content = b"".join(self.stream)
            self.stream = None
        return self.content

    @classmethod
    def from_raw(cls, raw: RawResponse, content: bytes) -> Self:
        """A response from the call's metadata and the body read off it."""
        return cls(
            status_code=raw.status_code,
            reason=raw.reason,
            headers=Headers(raw.headers),
            content=content,
            url=raw.url,
            http_version=raw.http_version,
            redirect_count=raw.redirect_count,
            from_cache=raw.from_cache,
            proxy=raw.proxy,
            metrics=raw.metrics,
        )

    @property
    def elapsed(self) -> float:
        """Seconds from the request starting to its last byte, or -1.0."""
        total = self.metrics.total_us
        return -1.0 if total == NO_TIME else total / 1_000_000.0

    @property
    def ok(self) -> bool:
        """Whether the status is in the 2xx range."""
        return 200 <= self.status_code < 300

    @property
    def encoding(self) -> str:
        """The charset named by Content-Type, or utf-8 when none is."""
        for parameter in self.headers.get("content-type", "").split(";")[1:]:
            name, _, value = parameter.partition("=")
            if name.strip().lower() == "charset":
                return value.strip().strip('"') or "utf-8"
        return "utf-8"

    @property
    def text(self) -> str:
        """The body decoded with `encoding`, replacing anything undecodable."""
        return self.content.decode(self.encoding, errors="replace")

    def json(self) -> object:
        """The body parsed as JSON.

        Returns:
            The parsed value.

        Raises:
            ValueError: The body is not valid JSON.
        """
        return _json.decode(self.content)

    def raise_for_status(self) -> Self:
        """Return self, or raise when the status is 4xx or 5xx.

        Raises:
            HTTPStatusError: The status was 400 or above.
        """
        if self.status_code >= 400:
            raise HTTPStatusError(
                f"{self.status_code} {self.reason} for {self.url}", response=self
            )
        return self

    def __repr__(self) -> str:
        return (
            f"<Response [{self.status_code}] {self.http_version} "
            f"{len(self.content)} bytes from {self.url}>"
        )
