"""The bridge between Python and the native library.

This is the only module that converts between Python values and C memory. It
takes plain Python in, hands plain Python back, and never lets a ctypes object
escape — so the modules above it are ordinary Python that happen to be fast,
and the C ABI can change shape without any of them noticing.

The layering is deliberate and worth keeping:

    session.py, request.py, response.py   the surface written against
    _bridge.py                            marshalling and handle lifetimes
    _binding.py                           loading the library, checking its ABI
    _abi.py                               the ctypes declarations, generated
    libcronet.so                          Chromium's network stack
"""

import contextlib
import ctypes
import os
import select
import threading
import time
import weakref
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Self

from . import _abi, _binding
from ._abi import (
    CronetEngineConfig,
    CronetHeader,
    CronetMetrics,
    CronetQuicHint,
    CronetRequest,
)
from ._binding import lib
from .errors import LibraryError, RequestError, SessionClosed, error_for

type HeaderPairs = tuple[tuple[str, str], ...]

# Republished so that nothing above this layer has to import the raw ctypes
# declarations to name a priority, a cache mode or an error.
PRIORITY_THROTTLED = _abi.PRIORITY_THROTTLED
PRIORITY_IDLE = _abi.PRIORITY_IDLE
PRIORITY_LOWEST = _abi.PRIORITY_LOWEST
PRIORITY_LOW = _abi.PRIORITY_LOW
PRIORITY_MEDIUM = _abi.PRIORITY_MEDIUM
PRIORITY_HIGHEST = _abi.PRIORITY_HIGHEST

CACHE_DISABLED = _abi.CACHE_DISABLED
CACHE_IN_MEMORY = _abi.CACHE_IN_MEMORY
CACHE_ON_DISK = _abi.CACHE_ON_DISK

ERROR_TIMED_OUT = _abi.ERROR_TIMED_OUT
ERROR_TOO_MANY_REDIRECTS = _abi.ERROR_TOO_MANY_REDIRECTS

CALL_STARTED = _abi.CALL_STARTED
CALL_HEADERS = _abi.CALL_HEADERS
CALL_DONE = _abi.CALL_DONE


@dataclass(frozen=True, slots=True)
class EngineSettings:
    """Everything the native engine is built from, as plain Python."""

    user_agent: str = ""
    accept_language: str = ""
    experimental_options: str = ""
    storage_path: str = ""
    proxy_rules: str = ""
    proxy_bypass_rules: str = ""
    proxy_username: str = ""
    proxy_password: str = ""
    quic_hints: tuple[tuple[str, int], ...] = ()
    enable_quic: bool = True
    enable_http2: bool = True
    enable_brotli: bool = True
    cache_mode: int = _abi.CACHE_DISABLED
    cache_max_bytes: int = 0


@dataclass(frozen=True, slots=True)
class CallSettings:
    """One request, as plain Python."""

    method: str
    url: str
    headers: HeaderPairs = ()
    body: bytes = b""
    priority: int = _abi.PRIORITY_MEDIUM
    max_redirects: int = 20
    disable_cache: bool = False


# A timing the request never reached — a reused socket has no dns_start, and a
# plain HTTP request has no ssl_start. Taken from the binding rather than
# written out again, so it cannot drift from CRONET_NO_TIME in the header.
NO_TIME = _abi.NO_TIME


@dataclass(frozen=True, slots=True)
class Metrics:
    """When each phase of a request happened, in microseconds since the epoch.

    Microseconds because that is the resolution Cronet actually reports; a
    phase that did not happen is NO_TIME.

    Defined here rather than beside Response because this is where it is built,
    straight out of the C struct — one copy at the boundary and none after.
    """

    request_start_us: int
    dns_start_us: int
    dns_end_us: int
    connect_start_us: int
    connect_end_us: int
    ssl_start_us: int
    ssl_end_us: int
    send_start_us: int
    send_end_us: int
    response_start_us: int
    request_end_us: int
    sent_bytes: int
    received_bytes: int
    socket_reused: bool

    @classmethod
    def from_native(cls, metrics: CronetMetrics) -> Self:
        """These timings, copied out of the C struct once, at the boundary."""
        return cls(
            request_start_us=metrics.request_start_us,
            dns_start_us=metrics.dns_start_us,
            dns_end_us=metrics.dns_end_us,
            connect_start_us=metrics.connect_start_us,
            connect_end_us=metrics.connect_end_us,
            ssl_start_us=metrics.ssl_start_us,
            ssl_end_us=metrics.ssl_end_us,
            send_start_us=metrics.send_start_us,
            send_end_us=metrics.send_end_us,
            response_start_us=metrics.response_start_us,
            request_end_us=metrics.request_end_us,
            sent_bytes=metrics.sent_bytes,
            received_bytes=metrics.received_bytes,
            socket_reused=bool(metrics.socket_reused),
        )

    @property
    def total_us(self) -> int:
        """How long the whole request took, or NO_TIME if unrecorded."""
        if self.request_start_us == NO_TIME or self.request_end_us == NO_TIME:
            return NO_TIME
        return self.request_end_us - self.request_start_us


@dataclass(frozen=True, slots=True)
class RawResponse:
    """A call's metadata, copied out of native memory.

    No body: the body is streamed out of the call with `Call.read`, so that
    nothing has to hold a whole response in memory to hand over the first byte
    of it.
    """

    status_code: int
    reason: str
    headers: HeaderPairs
    url: str
    http_version: str
    redirect_count: int
    from_cache: bool
    proxy: str
    metrics: Metrics = field(repr=False)


def version() -> str:
    """The Chromium version the native library was built from."""
    return _binding.version()


def _countdown(timeout_ms: int) -> Iterator[int]:
    """Milliseconds still available, once per round of waiting.

    Yields -1 for ever when `timeout_ms` is negative, which is how "no limit"
    is spelled all the way down to poll(); otherwise it runs out, and the
    caller decides what running out means.
    """
    if timeout_ms < 0:
        while True:
            yield -1
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            return
        yield remaining


def _as_bytes(value: str) -> bytes:
    return value.encode() if value else b""


def _build_engine_config(
    settings: EngineSettings,
) -> tuple[CronetEngineConfig, list[object]]:
    """A native config, and the buffers it points at."""
    keepalive: list[object] = []
    config = CronetEngineConfig()
    lib.cronet_engine_config_init(ctypes.byref(config))
    config.user_agent = _as_bytes(settings.user_agent)
    config.accept_language = _as_bytes(settings.accept_language)
    config.experimental_options = _as_bytes(settings.experimental_options)
    config.storage_path = _as_bytes(settings.storage_path)
    config.proxy_rules = _as_bytes(settings.proxy_rules)
    config.proxy_bypass_rules = _as_bytes(settings.proxy_bypass_rules)
    config.proxy_username = _as_bytes(settings.proxy_username)
    config.proxy_password = _as_bytes(settings.proxy_password)
    config.enable_quic = int(settings.enable_quic)
    config.enable_http2 = int(settings.enable_http2)
    config.enable_brotli = int(settings.enable_brotli)
    config.cache_mode = settings.cache_mode
    config.cache_max_bytes = settings.cache_max_bytes

    if settings.quic_hints:
        hints = (CronetQuicHint * len(settings.quic_hints))()
        for index, (host, port) in enumerate(settings.quic_hints):
            hints[index].host = host.encode()
            hints[index].port = port
            hints[index].alternate_port = port
        keepalive.append(hints)
        config.quic_hints = ctypes.cast(hints, ctypes.POINTER(CronetQuicHint))
        config.quic_hint_count = len(settings.quic_hints)
    return config, keepalive


def _build_request(settings: CallSettings) -> tuple[CronetRequest, list[object]]:
    """A native request, and the buffers it points at.

    ctypes aims the struct straight at Python buffers, so every one is returned
    beside it; letting one be collected would leave the struct pointing into
    freed memory.
    """
    keepalive: list[object] = []
    request = CronetRequest()
    lib.cronet_request_init(ctypes.byref(request))

    method = settings.method.upper().encode()
    url = settings.url.encode()
    keepalive += [method, url]
    request.method = method
    request.url = url

    if settings.headers:
        array = (CronetHeader * len(settings.headers))()
        for index, (name, value) in enumerate(settings.headers):
            name_bytes = name.encode("latin-1")
            value_bytes = value.encode("latin-1")
            keepalive += [name_bytes, value_bytes]
            array[index].name = name_bytes
            array[index].value = value_bytes
        keepalive.append(array)
        request.headers = ctypes.cast(array, ctypes.POINTER(CronetHeader))
        request.header_count = len(settings.headers)

    if settings.body:
        buffer = (ctypes.c_ubyte * len(settings.body)).from_buffer_copy(settings.body)
        keepalive.append(buffer)
        request.body = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        request.body_size = len(settings.body)

    request.priority = settings.priority
    request.max_redirects = settings.max_redirects
    request.disable_cache = int(settings.disable_cache)
    return request, keepalive


def _read_response(call: int, url: str) -> RawResponse:
    """Copy a finished call's result into Python, or raise what went wrong."""
    pointer = lib.cronet_call_response(call)
    if not pointer:
        raise RequestError("the call has not finished", url=url)
    raw = pointer.contents

    if raw.error_code != 0:
        message = (raw.error_message or b"").decode(errors="replace")
        raise error_for(raw.error_code, message, url)

    # Header values are latin-1 by the HTTP grammar, so decoding that way
    # cannot fail on any byte a server is allowed to send.
    headers = tuple(
        (
            raw.headers[index].name.decode("latin-1"),
            raw.headers[index].value.decode("latin-1"),
        )
        for index in range(raw.header_count)
    )
    proxy = (raw.proxy_server or b"").decode()
    return RawResponse(
        status_code=raw.status_code,
        reason=(raw.status_text or b"").decode("latin-1"),
        headers=headers,
        url=(raw.final_url or b"").decode(),
        http_version=(raw.negotiated_protocol or b"").decode(),
        redirect_count=raw.redirect_count,
        from_cache=bool(raw.was_cached),
        # Chromium spells "no proxy" as an empty host with port zero. The other
        # two are belt and braces against the ABI ever reporting it otherwise.
        proxy="direct" if proxy in ("", ":0", "direct://") else proxy,
        metrics=Metrics.from_native(raw.metrics),
    )


class Call:
    """One request in flight.

    Exists so a caller can wait however it likes — blocking, or by watching
    `descriptor` from an event loop — without either style knowing that the
    other exists, and without a callback ever running on a network thread.
    """

    __slots__ = ("_buffer", "_engine", "_handle", "_keepalive", "url")

    #: How much body one read asks for. Matches the native read buffer, so a
    #: full one is handed over in a single copy.
    CHUNK_SIZE = 64 * 1024

    def __init__(
        self, engine: Engine, handle: int, url: str, keepalive: list[object]
    ) -> None:
        self._engine = engine
        self._handle = handle
        self._keepalive = keepalive
        self._buffer = (ctypes.c_ubyte * self.CHUNK_SIZE)()
        self.url = url

    @property
    def descriptor(self) -> int:
        """A descriptor that becomes readable whenever the call progresses."""
        fd: int = lib.cronet_call_fd(self._handle)
        return fd

    @property
    def state(self) -> int:
        """How far the call has got: STARTED, HEADERS or DONE."""
        state: int = lib.cronet_call_state_of(self._handle)
        return state

    def read(self) -> bytes | None:
        """The next piece of body.

        Returns:
            The bytes read; `b""` when none are buffered right now, which is
            not the end — wait on `descriptor` and read again; or None once
            the body is complete.
        """
        count: int = lib.cronet_call_read(self._handle, self._buffer, self.CHUNK_SIZE)
        if count == _abi.EOF:
            return None
        if count == 0:
            return b""
        return bytes(memoryview(self._buffer)[:count])

    def drain(self) -> None:
        """Clear pending wakeups from `descriptor`.

        Done before reading, never after: anything that arrives while the body
        is being read then leaves the descriptor readable, so the next wait
        returns at once instead of missing the wakeup.
        """
        with contextlib.suppress(OSError):
            os.read(self.descriptor, 8)

    def wait_for_progress(self, timeout_ms: int) -> bool:
        """Block until the call progresses. Returns False on timeout."""
        poller = select.poll()
        poller.register(self.descriptor, select.POLLIN)
        return bool(poller.poll(None if timeout_ms < 0 else timeout_ms))

    def wait_for_headers(self, timeout_ms: int) -> bool:
        """Block until the headers arrive or the call ends without any."""
        for remaining in _countdown(timeout_ms):
            self.drain()
            if self.state != _abi.CALL_STARTED:
                return True
            if not self.wait_for_progress(remaining):
                return False
        return self.state != _abi.CALL_STARTED

    def iter_body(self, timeout_ms: int) -> Iterator[bytes]:
        """The body, in pieces, as the network delivers them.

        Reading is what lets the transfer continue: the library holds a bounded
        amount and stops pulling from the socket until this drains it, so a
        slow consumer slows the transfer rather than filling memory.

        Raises:
            TimeoutError: The call made no progress within the time allowed.
        """
        for remaining in _countdown(timeout_ms):
            # Drained before reading, so that anything arriving mid-read leaves
            # the descriptor readable rather than being missed.
            self.drain()
            piece = self.read()
            while piece:
                yield piece
                piece = self.read()
            if piece is None:
                return
            if not self.wait_for_progress(remaining):
                raise TimeoutError
        raise TimeoutError

    def wait(self, timeout_ms: int) -> bool:
        """Block until the call finishes or the timeout runs out.

        Args:
            timeout_ms: Milliseconds to wait; negative waits forever, zero polls.

        Returns:
            Whether the call has finished.
        """
        return bool(lib.cronet_call_wait(self._handle, timeout_ms))

    def cancel(self) -> None:
        """Ask the network thread to abandon the request."""
        lib.cronet_call_cancel(self._handle)

    def result(self) -> RawResponse:
        """The finished result, or raise what went wrong."""
        return _read_response(self._handle, self.url)

    def close(self) -> None:
        """Free the call. Every call must be closed exactly once."""
        self._engine._free_call(self._handle)
        # The native side has let go of the buffers only now.
        self._keepalive.clear()


class Engine:
    """A native engine, and the bookkeeping that makes closing it safe.

    Closing has to be ordered: no new call may start once shutdown begins,
    every call already running is cancelled and collected, and only then is the
    engine destroyed. That order is what stops a request on one thread from
    reaching into an engine another thread has freed.
    """

    # __weakref__ is listed because the finalizer below holds a weak reference,
    # which __slots__ otherwise makes impossible.
    __slots__ = (
        "__weakref__",
        "_calls_in_flight",
        "_finalizer",
        "_handle",
        "_idle",
        "_live_calls",
        "_lock",
    )

    def __init__(self, settings: EngineSettings) -> None:
        config, keepalive = _build_engine_config(settings)
        handle = lib.cronet_engine_create(ctypes.byref(config))
        keepalive.clear()
        if not handle:
            raise LibraryError(
                _binding.last_error() or "the engine could not be created"
            )
        self._handle: int | None = handle
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._live_calls: set[int] = set()
        self._calls_in_flight = 0
        # Frees the engine if a session is dropped without being closed. A call
        # still in flight then is cancelled but never collected, so closing
        # properly remains the right thing to do.
        self._finalizer = weakref.finalize(self, lib.cronet_engine_destroy, handle)

    def start(self, settings: CallSettings) -> Call:
        """Begin a call. The caller must close the result exactly once."""
        request, keepalive = _build_request(settings)
        handle = self._claim()
        call: int | None
        try:
            call = lib.cronet_call_start(handle, ctypes.byref(request))
        except BaseException:
            self._release()
            raise
        if not call:
            self._release()
            raise RequestError(
                _binding.last_error() or "the request could not be started",
                url=settings.url,
            )
        with self._lock:
            self._live_calls.add(call)
            # A close() that began while this call was starting has already
            # passed the cancel loop, so cancel it here instead of leaving it
            # to run to completion after the session was closed.
            if self._handle is None:
                lib.cronet_call_cancel(call)
        return Call(self, call, settings.url, keepalive)

    def _free_call(self, call: int) -> None:
        with self._lock:
            self._live_calls.discard(call)
        lib.cronet_call_free(call)
        self._release()

    def _release(self) -> None:
        with self._lock:
            self._calls_in_flight -= 1
            self._idle.notify_all()

    def close(self) -> None:
        """Cancel everything in flight, wait for it, then destroy the engine."""
        with self._lock:
            if self._handle is None:
                return
            self._handle = None
            for call in self._live_calls:
                lib.cronet_call_cancel(call)
            while self._calls_in_flight:
                self._idle.wait()
        self._finalizer()

    @property
    def closed(self) -> bool:
        """Whether this engine has been closed."""
        with self._lock:
            return self._handle is None

    def _claim(self) -> int:
        """Reserve the engine against close() for one native call.

        Every call into the library has to hold the engine open for its own
        duration; reading the handle under the lock and then calling outside it
        is not enough, because close() destroys the engine the moment the lock
        is free. Counting the call is what close() waits on.
        """
        with self._lock:
            handle = self._handle
            if handle is None:
                raise SessionClosed("this session has been closed")
            self._calls_in_flight += 1
        return handle

    def start_net_log(self, path: str, log_all: bool) -> None:
        """Begin writing a NetLog trace to `path`."""
        handle = self._claim()
        try:
            started = lib.cronet_engine_start_net_log(
                handle, path.encode(), int(log_all)
            )
        finally:
            self._release()
        if not started:
            raise LibraryError(
                f"a NetLog could not be written to {path} — the path must be "
                "writable, and only one log may run at a time"
            )

    def stop_net_log(self) -> None:
        """Finish the NetLog and flush it to disk. Does nothing if none runs."""
        handle = self._claim()
        try:
            lib.cronet_engine_stop_net_log(handle)
        finally:
            self._release()
