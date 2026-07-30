"""Sessions: the handle every request is made through.

A session owns one native engine, which owns one network thread and the
connection pools, DNS cache and TLS session cache its requests share. Making a
second request to the same host through one session is what makes it cheap.

What a request is made *of* lives in `request`; this module is only the two
ways of waiting for one. Nothing here touches C — everything below the surface
goes through `_bridge`, the only module that knows the native library exists.

Both session types are safe to use from many threads at once, and keep no state
whose integrity depends on the GIL, so they behave the same on the
free-threaded build of Python.
"""

import asyncio
import contextlib
from collections.abc import Iterable, Iterator, Mapping
from enum import StrEnum
from types import TracebackType
from typing import Self, Unpack

from . import _bridge, _json
from ._bridge import CallSettings, EngineSettings
from .cookies import CookieJar
from .errors import Timeout
from .headers import Headers
from .request import (
    HeaderSource,
    RedirectChain,
    RequestOptions,
    build_call,
    check_options,
    checked_url,
    with_query,
)
from .response import Response
from .tls import TlsProfile

# A host known to speak HTTP/3: a bare name, or a name with its port.
type QuicHint = str | tuple[str, int]


class Cache(StrEnum):
    """Where a session may keep cached responses."""

    OFF = "off"
    MEMORY = "memory"
    DISK = "disk"


_CACHE_MODES = {
    Cache.OFF: _bridge.CACHE_DISABLED,
    Cache.MEMORY: _bridge.CACHE_IN_MEMORY,
    Cache.DISK: _bridge.CACHE_ON_DISK,
}


def version() -> str:
    """The Chromium version the bundled network stack was built from.

    Returns:
        A dotted version, for example "150.0.7871.100".
    """
    return _bridge.version()


def default_user_agent() -> str:
    """The User-Agent a session sends unless told otherwise.

    Built from the Chromium version this library was compiled from, in the
    reduced form Chrome has sent since version 101 — the minor, build and patch
    fields are always zero.

    Returns:
        A Chrome User-Agent string for this platform.
    """
    major = version().split(".")[0]
    return (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{major}.0.0.0 Safari/537.36"
    )


class _BaseSession:
    """The settings and engine handling both session types share."""

    def __init__(
        self,
        *,
        headers: HeaderSource = None,
        proxy: str | None = None,
        proxy_bypass: str | None = None,
        proxy_username: str | None = None,
        proxy_password: str | None = None,
        user_agent: str | None = None,
        accept_language: str | None = None,
        http2: bool = True,
        http3: bool = True,
        quic_hints: Iterable[QuicHint] | None = None,
        brotli: bool = True,
        cookies: CookieJar | bool = False,
        cache: Cache | str = Cache.OFF,
        cache_size: int = 0,
        storage_path: str | None = None,
        timeout: float | None = 30.0,
        max_redirects: int = 20,
        tls: TlsProfile | None = None,
        experimental_options: Mapping[str, object] | None = None,
    ) -> None:
        """Open a session.

        Args:
            headers: Sent with every request, in this order.
            proxy: Chromium proxy rules, for example "socks5://127.0.0.1:1080"
                or "http=http://a:8080;https=socks5://b:1080". Schemes: http,
                https, socks4, socks5, direct.
            proxy_bypass: Hosts to reach directly, for example
                "localhost;*.internal". Chromium never proxies loopback unless
                this contains "<-loopback>".
            proxy_username: Offered pre-emptively as Basic auth. Applies to
                http and https proxies only; Chromium's SOCKS client does not
                authenticate.
            proxy_password: Password for `proxy_username`.
            user_agent: Sent when a request sets no User-Agent of its own.
                Defaults to a Chrome User-Agent matching the Chromium this was
                built from. Chromium always emits the header, so "" sends an
                empty one rather than none.
            accept_language: Sent when a request sets no Accept-Language.
            http2: Allow HTTP/2.
            http3: Allow HTTP/3 over QUIC. Without a hint below, a host is only
                reached over HTTP/3 once an earlier response advertised it.
            quic_hints: Hosts already known to speak HTTP/3, as "example.com"
                or ("example.com", 443), so the first request goes over QUIC.
            brotli: Advertise brotli in Accept-Encoding.
            cookies: True to keep a jar of this session's own, or a CookieJar
                to share one. False, the default, sends and stores none. With a
                jar in use, redirects are followed one hop at a time so cookies
                set part-way through a chain are kept, and each hop appears in
                `Response.history`.
            cache: "off", "memory" or "disk".
            cache_size: Cache size in bytes; 0 lets Chromium choose.
            storage_path: Directory for an on-disk cache. Required by
                cache="disk".
            timeout: Default seconds per request; None for no limit.
            max_redirects: Default redirects to follow.
            tls: Shape of the TLS ClientHello. See `cronet.TlsProfile`.
            experimental_options: Cronet experimental options, passed through
                as JSON. Merged under anything `tls` sets.

        Raises:
            LibraryError: The configuration was rejected — an unparseable proxy
                rule, or an on-disk cache with no storage_path.
        """
        self.headers = Headers(headers)
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.cookies: CookieJar | None
        if isinstance(cookies, CookieJar):
            self.cookies = cookies
        else:
            self.cookies = CookieJar() if cookies else None

        options = dict(experimental_options or {})
        if tls is not None:
            options.update(tls.to_options())

        hints: list[tuple[str, int]] = []
        for hint in quic_hints or ():
            hints.append((hint, 443) if isinstance(hint, str) else hint)

        self._engine = _bridge.Engine(
            EngineSettings(
                user_agent=default_user_agent() if user_agent is None else user_agent,
                accept_language=accept_language or "",
                experimental_options=_json.encode(options).decode() if options else "",
                storage_path=storage_path or "",
                proxy_rules=proxy or "",
                proxy_bypass_rules=proxy_bypass or "",
                proxy_username=proxy_username or "",
                proxy_password=proxy_password or "",
                quic_hints=tuple(hints),
                enable_quic=http3,
                enable_http2=http2,
                enable_brotli=brotli,
                cache_mode=_CACHE_MODES[Cache(cache)],
                cache_max_bytes=cache_size,
            )
        )

    @property
    def closed(self) -> bool:
        """Whether this session has been closed."""
        return self._engine.closed

    def start_net_log(self, path: str, *, log_all: bool = False) -> None:
        """Record a Chromium NetLog to `path` until `stop_net_log`.

        Args:
            path: File to write the JSON trace to.
            log_all: Include socket bytes and cookies — far more detail, and it
                includes credentials.
        """
        self._engine.start_net_log(path, log_all)

    def stop_net_log(self) -> None:
        """Finish the NetLog and flush it to disk."""
        self._engine.stop_net_log()

    def _call(
        self, method: str, url: str, options: RequestOptions, max_redirects: int
    ) -> CallSettings:
        """These options as a native call, over this session's defaults."""
        return build_call(
            method,
            url,
            options,
            defaults=self.headers,
            cookies=self.cookies,
            max_redirects=max_redirects,
        )

    def _target(self, url: str, options: RequestOptions) -> str:
        """The URL to request, checked and with any query parameters applied."""
        check_options(options)
        return with_query(checked_url(url), options.get("query"))

    def _chain(
        self, method: str, url: str, options: RequestOptions, cookies: CookieJar
    ) -> RedirectChain:
        """A hop-by-hop redirect walk for a session that holds a jar."""
        return RedirectChain(
            method, url, options, limit=self._redirect_limit(options), cookies=cookies
        )

    def _redirect_limit(self, options: RequestOptions) -> int:
        limit = options.get("max_redirects")
        return self.max_redirects if limit is None else limit

    def _timeout_seconds(self, options: RequestOptions) -> float | None:
        """Seconds this request may take, or None for no limit.

        A missing key means "use the session's"; a present None means "no
        limit". A TypedDict distinguishes the two on its own, so no sentinel
        value is needed to tell them apart.
        """
        return options.get("timeout", self.timeout)

    def _timeout_ms(self, options: RequestOptions) -> int:
        seconds = self._timeout_seconds(options)
        return -1 if seconds is None else max(0, int(seconds * 1000))

    def _timed_out(self, url: str, options: RequestOptions) -> Timeout:
        """The error a request that ran out of time reports."""
        return Timeout(
            f"no response from {url} within {self._timeout_seconds(options)}s — "
            "raise timeout=, or pass timeout=None for no limit",
            net_error=_bridge.ERROR_TIMED_OUT,
            url=url,
        )


class Session(_BaseSession):
    """A blocking session.

    Safe to share between threads: a request releases the GIL while it waits,
    so requests made from different threads genuinely overlap.

    Example:
        >>> with Session() as session:
        ...     response = session.get("https://example.com")
        ...     print(response.status_code, response.http_version)
    """

    def request(
        self, method: str, url: str, **options: Unpack[RequestOptions]
    ) -> Response:
        """Make a request and read the whole response.

        Args:
            method: HTTP method, for example "GET".
            url: Absolute URL to request.
            **options: See `RequestOptions`. `headers` are sent after the
                session's own, with a name the session already sets replaced
                where it stands; `timeout` is in seconds, None for no limit,
                and defaults to the session's.

        Returns:
            The response, with its body already decompressed.

        Raises:
            Timeout: The request did not finish in time.
            TooManyRedirects: The redirect chain ran past the limit.
            RequestError: The request produced no response; which subclass says
                what kind of failure it was.
            SessionClosed: The session was already closed.
        """
        target = self._target(url, options)
        if self.cookies is None:
            return self._perform(method, target, options, self._redirect_limit(options))

        # With a jar in use each hop is made separately, so a cookie set part
        # way along a chain is stored before the next request goes out.
        chain = self._chain(method, target, options, self.cookies)
        while (pending := chain.pending) is not None:
            hop_method, hop_url, hop_options = pending
            chain.receive(self._perform(hop_method, hop_url, hop_options, 0))
        return chain.result()

    def _perform(
        self, method: str, url: str, options: RequestOptions, max_redirects: int
    ) -> Response:
        """One request, following at most `max_redirects` redirects natively."""
        call = self._engine.start(self._call(method, url, options, max_redirects))
        try:
            timeout_ms = self._timeout_ms(options)
            try:
                if not call.wait_for_headers(timeout_ms):
                    raise TimeoutError
                # Raises here if the call failed before any headers arrived.
                call.result()
                # The whole-body read is the streaming read, run to the end —
                # one mechanism, so the two cannot drift apart.
                content = b"".join(call.iter_body(timeout_ms))
            except TimeoutError as expired:
                call.cancel()
                call.wait(-1)
                raise self._timed_out(url, options) from expired
            # Read again now the call has finished: Cronet collects the metrics
            # during teardown, so the metadata seen at the headers is not the
            # final one. This also surfaces a failure that arrived mid-body.
            return Response.from_raw(call.result(), content)
        finally:
            call.close()

    @contextlib.contextmanager
    def stream(
        self, method: str, url: str, **options: Unpack[RequestOptions]
    ) -> Iterator[Response]:
        """Make a request and hand back its response before the body arrives.

        The status and headers are readable straight away; the body is pulled
        with `Response.iter_bytes()` as it comes off the network. Nothing holds
        the whole body, so a response larger than memory is a loop rather than
        a problem, and a consumer that reads slowly slows the transfer down
        instead of filling memory.

        Redirects are followed natively, so a streamed request does not walk a
        cookie jar hop by hop.

        Args:
            method: HTTP method, for example "GET".
            url: Absolute URL to request.
            **options: See `RequestOptions`.

        Yields:
            The response, its body still arriving. It stops being readable when
            the block ends. `metrics` is empty here, because Cronet only
            collects it once the call has finished — read the response whole if
            you need the timings.

        Example:
            >>> with session.stream("GET", url) as response:
            ...     for piece in response.iter_bytes():
            ...         sink.write(piece)
        """
        target = self._target(url, options)
        settings = self._call(method, target, options, self._redirect_limit(options))
        call = self._engine.start(settings)
        timeout_ms = self._timeout_ms(options)
        try:
            try:
                if not call.wait_for_headers(timeout_ms):
                    raise TimeoutError
            except TimeoutError as expired:
                raise self._timed_out(target, options) from expired
            response = Response.from_raw(call.result(), b"")
            response.stream = call.iter_body(timeout_ms)
            yield response
        finally:
            if not call.wait(0):
                call.cancel()
            call.close()

    def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a GET request. See `request`."""
        return self.request("GET", url, **options)

    def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a POST request. See `request`."""
        return self.request("POST", url, **options)

    def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a PUT request. See `request`."""
        return self.request("PUT", url, **options)

    def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a PATCH request. See `request`."""
        return self.request("PATCH", url, **options)

    def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a DELETE request. See `request`."""
        return self.request("DELETE", url, **options)

    def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a HEAD request. See `request`."""
        return self.request("HEAD", url, **options)

    def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make an OPTIONS request. See `request`."""
        return self.request("OPTIONS", url, **options)

    def close(self) -> None:
        """Cancel anything in flight and release the engine. Idempotent."""
        self._engine.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class AsyncSession(_BaseSession):
    """A session for asyncio.

    Waiting happens on a descriptor the native library makes readable when a
    call finishes, so no thread is parked per request and the event loop is
    never blocked on the network.

    Example:
        >>> async with AsyncSession() as session:
        ...     response = await session.get("https://example.com")
    """

    async def request(
        self, method: str, url: str, **options: Unpack[RequestOptions]
    ) -> Response:
        """Make a request and read the whole response.

        Takes the same options as `Session.request` and raises the same errors.
        Cancelling the awaiting task cancels the request itself.
        """
        target = self._target(url, options)
        if self.cookies is None:
            limit = self._redirect_limit(options)
            return await self._perform(method, target, options, limit)

        chain = self._chain(method, target, options, self.cookies)
        while (pending := chain.pending) is not None:
            hop_method, hop_url, hop_options = pending
            chain.receive(await self._perform(hop_method, hop_url, hop_options, 0))
        return chain.result()

    async def _perform(
        self, method: str, url: str, options: RequestOptions, max_redirects: int
    ) -> Response:
        """One request, following at most `max_redirects` redirects natively."""
        seconds = self._timeout_seconds(options)
        call = self._engine.start(self._call(method, url, options, max_redirects))
        try:
            try:
                async with asyncio.timeout(seconds):
                    await self._wait_for_headers(call)
                    # Raises here if the call failed before any headers.
                    call.result()
                    content = await self._read_body(call)
            except TimeoutError as timed_out:
                raise Timeout(
                    f"no response within {seconds} seconds",
                    net_error=_bridge.ERROR_TIMED_OUT,
                    url=url,
                ) from timed_out
            # Read again now the call has finished: Cronet collects the metrics
            # during teardown, so the metadata seen at the headers is not the
            # final one. This also surfaces a failure that arrived mid-body.
            return Response.from_raw(call.result(), content)
        finally:
            if not call.wait(0):
                # Cancelled or timed out rather than finished: stop the request
                # so freeing it does not wait on the network.
                call.cancel()
            call.close()

    async def _progress(self, call: _bridge.Call) -> None:
        """Wait for the call's next sign of life, without blocking the loop."""
        loop = asyncio.get_running_loop()
        descriptor = call.descriptor
        ready = loop.create_future()

        def on_readable() -> None:
            loop.remove_reader(descriptor)
            if not ready.done():
                ready.set_result(None)

        loop.add_reader(descriptor, on_readable)
        try:
            await ready
        finally:
            loop.remove_reader(descriptor)

    async def _wait_for_headers(self, call: _bridge.Call) -> None:
        """Wait until the headers arrive, or the call ends without any."""
        while True:
            call.drain()
            if call.state != _bridge.CALL_STARTED:
                return
            await self._progress(call)

    async def _read_body(self, call: _bridge.Call) -> bytes:
        """The whole body, read the same way a streaming consumer reads it."""
        pieces: list[bytes] = []
        while True:
            # Drained before reading, so bytes arriving mid-read leave the
            # descriptor readable rather than being missed.
            call.drain()
            piece = call.read()
            while piece:
                pieces.append(piece)
                piece = call.read()
            if piece is None:
                return b"".join(pieces)
            await self._progress(call)

    async def get(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a GET request. See `request`."""
        return await self.request("GET", url, **options)

    async def post(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a POST request. See `request`."""
        return await self.request("POST", url, **options)

    async def put(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a PUT request. See `request`."""
        return await self.request("PUT", url, **options)

    async def patch(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a PATCH request. See `request`."""
        return await self.request("PATCH", url, **options)

    async def delete(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a DELETE request. See `request`."""
        return await self.request("DELETE", url, **options)

    async def head(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make a HEAD request. See `request`."""
        return await self.request("HEAD", url, **options)

    async def options(self, url: str, **options: Unpack[RequestOptions]) -> Response:
        """Make an OPTIONS request. See `request`."""
        return await self.request("OPTIONS", url, **options)

    async def aclose(self) -> None:
        """Cancel anything in flight and release the engine. Idempotent.

        The waiting happens off the event loop, because tearing an engine down
        blocks until its network thread has stopped.
        """
        await asyncio.to_thread(self._engine.close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()
