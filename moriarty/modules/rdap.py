from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import structlog

from .orchestrator import Orchestrator, TaskContext
from ..net.rdap_client import RDAPClient, RDAPResponse

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class RDAPResult:
    query: str
    response: Dict[str, Any]
    url: str
    status: int
    latency_ms: float


class RDAPService:
    def __init__(
        self,
        client: RDAPClient,
        orchestrator: Orchestrator[RDAPResponse],
    ) -> None:
        self._client = client
        self._orchestrator = orchestrator

    async def domain(self, domain: str) -> RDAPResult:
        logger.info("rdap.lookup.start", kind="domain", value=domain)
        response = await self._orchestrator.run(
            TaskContext(name="rdap_domain", metadata={"value": domain}),
            lambda: self._client.fetch(f"domain/{domain}"),
        )
        logger.info("rdap.lookup.success", kind="domain", value=domain)
        return self._to_result(domain, response)

    async def ip(self, ip_value: str) -> RDAPResult:
        logger.info("rdap.lookup.start", kind="ip", value=ip_value)
        response = await self._orchestrator.run(
            TaskContext(name="rdap_ip", metadata={"value": ip_value}),
            lambda: self._client.fetch(f"ip/{ip_value}"),
        )
        logger.info("rdap.lookup.success", kind="ip", value=ip_value)
        return self._to_result(ip_value, response)

    @staticmethod
    def _to_result(query: str, rdap_response: RDAPResponse) -> RDAPResult:
        return RDAPResult(
            query=query,
            response=rdap_response.payload,
            url=rdap_response.url,
            status=rdap_response.status,
            latency_ms=rdap_response.latency_ms,
        )


__all__ = ["RDAPResult", "RDAPService"]
