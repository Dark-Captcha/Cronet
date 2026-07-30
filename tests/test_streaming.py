"""Streaming: the body arrives in pieces, and the consumer sets the pace.

This is what the v1 design could not do. The body used to accumulate in a
std::string on the network thread and reach Python only once the call had
finished, so the first byte cost the whole transfer and a response larger than
memory was simply out of reach. These are the claims that changed.
"""

import gc
import resource
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import cronet

CHUNK = b"x" * 8192


@contextmanager
def paced_server(chunks: int, delay: float = 0.0) -> Iterator[str]:
    """A server that sends headers, then a body a piece at a time."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    running = True

    def answer(connection: socket.socket) -> None:
        try:
            connection.recv(65536)
            connection.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"content-type: application/octet-stream\r\n"
                b"content-length: %d\r\n\r\n" % (chunks * len(CHUNK))
            )
            for _ in range(chunks):
                connection.sendall(CHUNK)
                if delay:
                    time.sleep(delay)
        except OSError:
            pass  # The client hung up early, which several tests do on purpose.
        finally:
            connection.close()

    def serve() -> None:
        while running:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=answer, args=(connection,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/body"
    finally:
        running = False
        listener.close()
        thread.join(timeout=5)


def test_headers_arrive_before_the_body_is_complete() -> None:
    # The claim v1 could not make: something useful is readable while the body
    # is still on the wire.
    with (
        paced_server(chunks=40, delay=0.01) as url,
        cronet.Session() as session,
        session.stream("GET", url) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        # Nothing of the body has been collected yet.
        assert response.content == b""


def test_the_body_arrives_in_more_than_one_piece() -> None:
    with (
        paced_server(chunks=40, delay=0.005) as url,
        cronet.Session() as session,
        session.stream("GET", url) as response,
    ):
        pieces = list(response.iter_bytes())

    assert len(pieces) > 1, f"the whole body came in {len(pieces)} piece"
    assert b"".join(pieces) == CHUNK * 40


def test_streaming_and_reading_whole_agree() -> None:
    with paced_server(chunks=8) as url, cronet.Session() as session:
        whole = session.get(url).content
        with session.stream("GET", url) as response:
            streamed = b"".join(response.iter_bytes())

    assert streamed == whole
    assert len(whole) == 8 * len(CHUNK)


def test_read_collects_a_streaming_body_into_content() -> None:
    with (
        paced_server(chunks=4) as url,
        cronet.Session() as session,
        session.stream("GET", url) as response,
    ):
        assert response.read() == CHUNK * 4
        assert response.content == CHUNK * 4
        # Reading again is harmless once it has been collected.
        assert response.read() == CHUNK * 4


def test_iter_bytes_also_works_on_a_response_read_whole() -> None:
    # So a caller can loop over either kind without asking which it holds.
    with paced_server(chunks=2) as url, cronet.Session() as session:
        response = session.get(url)

    assert b"".join(response.iter_bytes()) == CHUNK * 2


def _resident_kilobytes() -> int:
    with open("/proc/self/statm", encoding="ascii") as statm:
        return int(statm.read().split()[1]) * resource.getpagesize() // 1024


def test_a_body_far_larger_than_memory_held_does_not_accumulate() -> None:
    # Backpressure, stated as something observable: 256 MiB streamed through
    # while discarding each piece must not grow the process by anything like
    # 256 MiB. Under v1 the whole body was buffered natively and then copied
    # into one Python bytes, so this could only have failed.
    total = 32768 * len(CHUNK)
    with paced_server(chunks=32768) as url, cronet.Session(timeout=None) as session:
        gc.collect()
        settled = _resident_kilobytes()
        received = 0
        with session.stream("GET", url) as response:
            for piece in response.iter_bytes():
                received += len(piece)
        gc.collect()
        growth = _resident_kilobytes() - settled

    assert received == total, f"got {received} of {total}"
    assert growth < 32 * 1024, (
        f"streaming {total // 1024 // 1024} MiB grew memory by {growth} KiB"
    )
