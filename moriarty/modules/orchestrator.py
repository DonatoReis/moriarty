from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, TypeVar

import structlog

_T = TypeVar("_T")

logger = structlog.get_logger(__name__)


@dataclass
class TaskContext:
    name: str
    metadata: dict[str, Any]


class Orchestrator(Generic[_T]):
    """Basic concurrency-guarded orchestrator for network workers."""

    def __init__(self, concurrency: int, timeout: float) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = timeout

    async def run(self, context: TaskContext, operation: Callable[[], Awaitable[_T]]) -> _T:
        async with self._semaphore:
            logger.info(
                "orchestrator.task.start",
                task=context.name,
                **context.metadata,
            )
            try:
                result = await asyncio.wait_for(operation(), timeout=self._timeout)
            except asyncio.TimeoutError:
                logger.warning(
                    "orchestrator.task.timeout",
                    task=context.name,
                    timeout_s=self._timeout,
                    **context.metadata,
                )
                raise
            except Exception:
                logger.exception(
                    "orchestrator.task.error",
                    task=context.name,
                    **context.metadata,
                )
                raise
            else:
                logger.info(
                    "orchestrator.task.success",
                    task=context.name,
                    **context.metadata,
                )
                return result


__all__ = ["Orchestrator", "TaskContext"]
