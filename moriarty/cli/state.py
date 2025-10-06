from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..logging.config import LogStyle


@dataclass
class GlobalOptions:
    concurrency: int = 50
    timeout: float = 8.0
    proxy: Optional[str] = None
    headless: str = "auto"
    allowlist_domain: Optional[str] = None
    output: Optional[str] = None
    format: str = "table"
    redact: bool = True
    verbose: bool = False
    quiet: bool = False
    professional_mode: bool = False
    seed: Optional[int] = None
    dry_run: bool = False
    plan_only: bool = False
    sign: bool = False
    resume_path: Optional[str] = None
    http3: bool = False
    doh: Optional[str] = None
    dot: Optional[str] = None
    logs: LogStyle = "structured"


@dataclass
class CLIState:
    options: GlobalOptions


__all__ = ["CLIState", "GlobalOptions"]
