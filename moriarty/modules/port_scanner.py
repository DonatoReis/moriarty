"""Port scanning assíncrono com fingerprints básicos."""
from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Dict, List, Optional

import random

import structlog

logger = structlog.get_logger(__name__)


PROFILES = {
    "quick": [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443],
    "full": list(range(1, 1025)),
    "extended": [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        161,
        389,
        443,
        445,
        465,
        587,
        631,
        993,
        995,
        1023,
        1433,
        1521,
        2049,
        3128,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        9000,
    ],
}


@dataclass
class PortScanResult:
    port: int
    status: str
    banner: Optional[str] = None


class PortScanner:
    """Execução assíncrona de port scanning com banners e fingerprint simples."""

    def __init__(
        self,
        target: str,
        profile: str = "quick",
        concurrency: int = 200,
        timeout: float = 1.5,
        stealth_level: int = 0,
    ):
        self.target = target
        self.profile = profile if profile in PROFILES else "quick"
        self.stealth_level = max(0, stealth_level)
        adjusted_concurrency = concurrency
        if self.stealth_level >= 3:
            adjusted_concurrency = min(concurrency, 80)
        elif self.stealth_level == 2:
            adjusted_concurrency = min(concurrency, 120)
        self.concurrency = max(10, adjusted_concurrency)
        self.timeout = timeout

    async def scan(self) -> List[PortScanResult]:
        sem = asyncio.Semaphore(self.concurrency)
        ports = PROFILES[self.profile]
        results: List[PortScanResult] = []

        async def worker(port: int):
            async with sem:
                res = await self._probe(port)
                if res:
                    results.append(res)

        await asyncio.gather(*(worker(p) for p in ports))
        results.sort(key=lambda r: r.port)
        return results

    async def _probe(self, port: int) -> Optional[PortScanResult]:
        try:
            if self.stealth_level:
                await asyncio.sleep(random.uniform(0.01, 0.2) * self.stealth_level)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout,
            )
        except Exception:
            return None

        banner = None
        try:
            await writer.drain()
            reader._transport.set_read_buffer_limits(1024)
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.5)
            if banner_bytes:
                banner = banner_bytes.decode(errors="ignore").strip()
        except Exception:
            banner = None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        return PortScanResult(port=port, status="open", banner=banner)


__all__ = ["PortScanner", "PortScanResult", "PROFILES"]
