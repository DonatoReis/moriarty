from __future__ import annotations

import asyncio

import pytest

from moriarty.modules.orchestrator import Orchestrator, TaskContext


def test_orchestrator_run_success() -> None:
    orchestrator: Orchestrator[int] = Orchestrator(concurrency=2, timeout=1.0)

    async def runner() -> int:
        return await orchestrator.run(TaskContext(name="success", metadata={}), lambda: asyncio.sleep(0, result=42))

    assert asyncio.run(runner()) == 42


def test_orchestrator_run_timeout() -> None:
    orchestrator: Orchestrator[int] = Orchestrator(concurrency=1, timeout=0.05)

    async def operation() -> int:
        await asyncio.sleep(0.2)
        return 1

    async def runner() -> None:
        await orchestrator.run(TaskContext(name="timeout", metadata={}), operation)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(runner())
