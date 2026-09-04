from __future__ import annotations

import asyncio
from collections.abc import Callable


async def to_thread[**P, R](function: Callable[P, R], *args: P.args, **kwargs: P.kwargs) -> R:
    """Run blocking work while tolerating CPython 3.14.0's missed wakeup."""
    worker = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    while not worker.done():  # noqa: ASYNC110 - timer is the compatibility mechanism
        await asyncio.sleep(0.01)
    return worker.result()
