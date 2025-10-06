from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any, Dict

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class RDAPResponse:
    url: str
    payload: Dict[str, Any]
    status: int
    latency_ms: float


class RDAPClient:
    def __init__(self, base_url: str = "https://rdap.org", timeout: float = 8.0, http2: bool = True) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http2 = http2

    async def fetch(self, path: str) -> RDAPResponse:
        url = f"{self._base_url}/{path.lstrip('/')}"
        logger.info("rdap.request.start", url=url)
        start = perf_counter()
        async with httpx.AsyncClient(timeout=self._timeout, http2=self._http2) as client:
            response = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
        latency_ms = (perf_counter() - start) * 1000
        if response.status_code >= 400:
            logger.warning(
                "rdap.request.error",
                url=url,
                status=response.status_code,
                latency_ms=round(latency_ms, 2),
            )
            response.raise_for_status()
        payload = response.json()
        logger.info(
            "rdap.request.success",
            url=url,
            status=response.status_code,
            latency_ms=round(latency_ms, 2),
        )
        return RDAPResponse(url=url, payload=payload, status=response.status_code, latency_ms=latency_ms)


__all__ = ["RDAPClient", "RDAPResponse"]
