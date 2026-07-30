"""What an asyncio session promises.

The claim worth testing hardest is that waiting for the network does not block
the event loop, because that is the whole reason this type exists separately
from the blocking one.
"""

import asyncio
import json
import time

import pytest

import cronet


@pytest.mark.asyncio
async def test_get_returns_the_servers_response(server: str) -> None:
    async with cronet.AsyncSession() as session:
        response = await session.get(f"{server}/echo")

    assert response.status_code == 200
    assert json.loads(response.content)["method"] == "GET"


@pytest.mark.asyncio
async def test_post_sends_its_body(server: str) -> None:
    async with cronet.AsyncSession() as session:
        response = await session.post(f"{server}/echo", json={"a": 1})

    assert json.loads(json.loads(response.content)["body"]) == {"a": 1}


@pytest.mark.asyncio
async def test_the_event_loop_keeps_running_during_a_request(server: str) -> None:
    ticks = 0

    async def tick() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    ticker = asyncio.create_task(tick())
    try:
        async with cronet.AsyncSession() as session:
            await session.get(f"{server}/slow")
    finally:
        ticker.cancel()

    # The server sleeps a second; a loop that was free ticks about a hundred
    # times in that second, one that was blocked ticks a handful.
    assert ticks > 50, f"the loop only ticked {ticks} times during a 1s request"


@pytest.mark.asyncio
async def test_gathered_requests_overlap(server: str) -> None:
    async with cronet.AsyncSession() as session:
        started = time.monotonic()
        responses = await asyncio.gather(
            *(session.get(f"{server}/slow") for _ in range(10))
        )
        elapsed = time.monotonic() - started

    assert [response.status_code for response in responses] == [200] * 10
    # Ten one-second requests run together take about a second, not ten.
    assert elapsed < 5.0, f"ten overlapping requests took {elapsed:.1f}s"


@pytest.mark.asyncio
async def test_a_slow_response_times_out(server: str) -> None:
    async with cronet.AsyncSession() as session:
        with pytest.raises(cronet.Timeout):
            await session.get(f"{server}/slow", timeout=0.2)


@pytest.mark.asyncio
async def test_cancelling_the_task_cancels_the_request(server: str) -> None:
    async with cronet.AsyncSession() as session:
        task = asyncio.create_task(session.get(f"{server}/slow"))
        await asyncio.sleep(0.1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        # The session survives its cancelled request and still works.
        assert (await session.get(f"{server}/echo")).status_code == 200


@pytest.mark.asyncio
async def test_a_closed_session_refuses_further_requests(server: str) -> None:
    session = cronet.AsyncSession()
    await session.aclose()

    assert session.closed
    with pytest.raises(cronet.SessionClosed):
        await session.get(f"{server}/echo")


@pytest.mark.asyncio
async def test_closing_twice_is_harmless() -> None:
    session = cronet.AsyncSession()
    await session.aclose()
    await session.aclose()

    assert session.closed


@pytest.mark.asyncio
async def test_many_requests_in_flight_do_not_exhaust_descriptors(
    server: str,
) -> None:
    async with cronet.AsyncSession() as session:
        for _ in range(20):
            responses = await asyncio.gather(
                *(session.get(f"{server}/echo") for _ in range(25))
            )
            assert all(response.status_code == 200 for response in responses)


@pytest.mark.live
@pytest.mark.asyncio
async def test_https_works_asynchronously(network: None) -> None:
    async with cronet.AsyncSession() as session:
        response = await session.get("https://example.com/")

    assert response.status_code == 200
    assert response.http_version == "h2"
