from __future__ import annotations

import logging
import sys
from typing import Literal

import structlog

LogStyle = Literal["structured", "pretty"]


def configure_logging(style: LogStyle = "structured", verbose: bool = False) -> None:
    """Configure structlog for Moriarty CLI."""
    level = logging.DEBUG if verbose else logging.INFO

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", key="ts"),
        structlog.stdlib.PositionalArgumentsFormatter(),
    ]

    if style == "structured":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        level=level,
        handlers=[logging.StreamHandler(sys.stderr)],
    )


__all__ = ["configure_logging", "LogStyle"]
