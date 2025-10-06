from __future__ import annotations

from dataclasses import dataclass

import structlog

from .orchestrator import Orchestrator, TaskContext
from ..net.dns_client import DNSClient, DNSLookupResult

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class DNSScanResult:
    domain: str
    records: DNSLookupResult


class DNSScanService:
    def __init__(
        self,
        domain: str,
        orchestrator: Orchestrator[DNSLookupResult],
        dns_client: DNSClient,
    ) -> None:
        self._domain = domain
        self._orchestrator = orchestrator
        self._dns_client = dns_client

    async def run(self) -> DNSScanResult:
        logger.info("dns.scan.start", domain=self._domain)
        records = await self._orchestrator.run(
            TaskContext(name="dns_lookup", metadata={"domain": self._domain}),
            lambda: self._dns_client.lookup_domain(self._domain),
        )
        logger.info("dns.scan.success", domain=self._domain)
        return DNSScanResult(domain=self._domain, records=records)


__all__ = ["DNSScanResult", "DNSScanService"]
