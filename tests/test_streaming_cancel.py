"""Cancelling a request whose body is still arriving.

This is the case the rest of the suite missed: every other cancellation test
parks the request *before* the response headers, so the body pump never starts
and the teardown race is never reached. A server that sends headers and then
dribbles the body is what makes it reachable.

Until the network-thread re-posts were routed through CallState's lock, every
test here crashed the process rather than failing.
"""

import asyncio
import contextlib
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

import cronet

CHUNKS = 400
CHUNK = b"x" * 4096


def _dribble(connection: socket.socket) -> None:
    """Send headers, then a body slowly enough to be interrupted."""
    try:
        connection.recv(65536)
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"content-type: application/octet-stream\r\n"
            b"content-length: %d\r\n\r\n" % (CHUNKS * len(CHUNK))
        )
        for _ in range(CHUNKS):
            connection.sendall(CHUNK)
            time.sleep(0.002)
    except OSError:
        # The client hung up mid-body, which is the whole point.
        pass
    finally:
        connection.close()


@contextmanager
def dribbling_server() -> Iterator[str]:
    """A server that answers every connection with a slow body."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    running = True

    def serve() -> None:
        while running:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=_dribble, args=(connection,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/slow-body"
    finally:
        running = False
        listener.close()
        thread.join(timeout=5)


def test_timing_out_mid_body_does_not_crash() -> None:
    with dribbling_server() as url, cronet.Session(timeout=0.15) as session:
        for _ in range(20):
            with pytest.raises(cronet.Timeout):
                session.get(url)


def test_closing_the_session_mid_body_does_not_crash() -> None:
    with dribbling_server() as url:
        session = cronet.Session(timeout=None)
        started = threading.Barrier(7, timeout=10)

        def fetch() -> None:
            started.wait()
            # Whatever the close does to this request, it must not crash.
            with contextlib.suppress(cronet.CronetError):
                session.get(url)

        threads = [threading.Thread(target=fetch) for _ in range(6)]
        for thread in threads:
            thread.start()
        started.wait()
        time.sleep(0.1)
        session.close()

        for thread in threads:
            thread.join(timeout=30)
        assert not any(thread.is_alive() for thread in threads), "a thread hung"


@pytest.mark.asyncio
async def test_cancelling_a_task_mid_body_does_not_crash() -> None:
    with dribbling_server() as url:
        async with cronet.AsyncSession(timeout=None) as session:
            tasks = [asyncio.create_task(session.get(url)) for _ in range(20)]
            await asyncio.sleep(0.1)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

            # The session survives, which is the claim that matters after a
            # use-after-free: the process is not merely still up by luck.
            assert (await session.get(url)).status_code == 200


@pytest.mark.asyncio
async def test_timing_out_mid_body_does_not_crash_asynchronously() -> None:
    with dribbling_server() as url:
        async with cronet.AsyncSession(timeout=0.15) as session:
            for _ in range(5):
                results = await asyncio.gather(
                    *(session.get(url) for _ in range(8)), return_exceptions=True
                )
                assert all(isinstance(result, cronet.Timeout) for result in results), (
                    results
                )
