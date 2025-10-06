from __future__ import annotations

import asyncio
from typing import Any, Awaitable, TypeVar


_T = TypeVar("_T")


def run_async(awaitable: Awaitable[_T]) -> _T:
    """Run an awaitable using asyncio, preferring uvloop when available."""
    try:
        import uvloop  # type: ignore

        uvloop.install()
    except ModuleNotFoundError:
        pass

    return asyncio.run(awaitable)
