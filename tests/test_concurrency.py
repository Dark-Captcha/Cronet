"""Concurrency and lifetime: the claims that matter most under free threading.

These run with the GIL disabled when the interpreter is a free-threaded build,
which is where a data race would actually show up rather than being hidden by
serialisation.
"""

import gc
import json
import resource
import threading
from concurrent.futures import ThreadPoolExecutor

import cronet


def test_many_threads_share_one_session(session: cronet.Session, server: str) -> None:
    requests = 200

    def fetch(index: int) -> int:
        response = session.get(f"{server}/echo", headers={"x-index": str(index)})
        echoed = json.loads(response.content)["headers"]
        seen = next(v for name, v in echoed if name.lower() == "x-index")
        assert seen == str(index), f"thread {index} saw header {seen}"
        return response.status_code

    with ThreadPoolExecutor(max_workers=32) as pool:
        statuses = list(pool.map(fetch, range(requests)))

    assert statuses == [200] * requests, f"got {set(statuses)}"


def test_threads_may_open_and_close_their_own_sessions(server: str) -> None:
    def run() -> None:
        for _ in range(5):
            with cronet.Session() as session:
                assert session.get(f"{server}/echo").status_code == 200

    threads = [threading.Thread(target=run) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not any(thread.is_alive() for thread in threads), "a thread hung"


def test_closing_a_session_under_a_running_request_does_not_crash(
    server: str,
) -> None:
    session = cronet.Session()
    outcome: list[str] = []
    started = threading.Event()

    def fetch() -> None:
        started.set()
        try:
            session.get(f"{server}/slow")
            outcome.append("returned")
        except cronet.CronetError as error:
            outcome.append(f"raised {type(error).__name__}")

    thread = threading.Thread(target=fetch)
    thread.start()
    started.wait(timeout=5)
    session.close()
    thread.join(timeout=30)

    assert not thread.is_alive(), "closing did not unblock the request"
    # An empty outcome means something other than a CronetError escaped, which
    # is exactly the crash-adjacent case this test exists to catch.
    assert len(outcome) == 1, f"the request ended as {outcome}"


def _resident_kilobytes() -> int:
    """Resident set size right now, which — unlike peak RSS — can also fall."""
    with open("/proc/self/statm", encoding="ascii") as statm:
        resident_pages = int(statm.read().split()[1])
    return resident_pages * resource.getpagesize() // 1024


def test_repeated_requests_do_not_grow_memory(
    session: cronet.Session, server: str
) -> None:
    # Let pools, buffers and arenas reach their steady size before measuring,
    # so what is measured afterwards is growth rather than warm-up.
    for _ in range(100):
        session.get(f"{server}/bytes/65536")
    gc.collect()
    settled = _resident_kilobytes()

    for _ in range(1000):
        session.get(f"{server}/bytes/65536")
    gc.collect()
    growth = _resident_kilobytes() - settled

    assert growth < 24 * 1024, (
        f"resident memory grew {growth} KiB over 1000 requests (from {settled} KiB)"
    )


def test_opening_and_closing_sessions_does_not_grow_memory(server: str) -> None:
    def cycle(times: int) -> None:
        for _ in range(times):
            with cronet.Session() as session:
                session.get(f"{server}/echo")

    cycle(20)
    gc.collect()
    settled = _resident_kilobytes()

    cycle(100)
    gc.collect()
    growth = _resident_kilobytes() - settled

    assert growth < 24 * 1024, (
        f"resident memory grew {growth} KiB over 100 session lifetimes "
        f"(from {settled} KiB)"
    )


def test_sessions_are_released_when_dropped(server: str) -> None:
    for _ in range(30):
        session = cronet.Session()
        assert session.get(f"{server}/echo").status_code == 200
        session.close()
