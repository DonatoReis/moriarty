from __future__ import annotations

from dataclasses import dataclass

import structlog

from .orchestrator import Orchestrator, TaskContext
from ..net.tls_client import TLSCertificate, TLSClient, TLSInspection

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class TLSScanResult:
    host: str
    port: int
    inspection: TLSInspection


class TLSScanService:
    def __init__(
        self,
        client: TLSClient,
        orchestrator: Orchestrator[TLSInspection],
        host: str,
        port: int,
    ) -> None:
        self._client = client
        self._orchestrator = orchestrator
        self._host = host
        self._port = port

    async def run(self) -> TLSScanResult:
        logger.info("tls.scan.start", host=self._host, port=self._port)
        inspection = await self._orchestrator.run(
            TaskContext(
                name="tls_inspection",
                metadata={"host": self._host, "port": self._port},
            ),
            lambda: self._client.inspect(self._host, self._port),
        )
        logger.info("tls.scan.success", host=self._host, port=self._port)
        return TLSScanResult(host=self._host, port=self._port, inspection=inspection)


__all__ = ["TLSScanService", "TLSScanResult", "TLSCertificate"]
