from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import List, Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class TLSCertificate:
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    subject_alt_names: List[str]


@dataclass(slots=True)
class TLSInspection:
    host: str
    port: int
    protocol: Optional[str]
    cipher: Optional[str]
    certificates: List[TLSCertificate]
    latency_ms: float


class TLSClient:
    def __init__(self, timeout: float = 8.0, verify: bool = False) -> None:
        self._timeout = timeout
        self._verify = verify

    async def inspect(self, host: str, port: int = 443) -> TLSInspection:
        logger.info("tls.inspect.start", host=host, port=port)
        start = perf_counter()
        try:
            protocol, cipher, certificates = await asyncio.wait_for(
                asyncio.to_thread(self._inspect_sync, host, port),
                timeout=self._timeout,
            )
        except Exception:
            logger.exception("tls.inspect.error", host=host, port=port)
            raise
        latency_ms = (perf_counter() - start) * 1000
        logger.info(
            "tls.inspect.success",
            host=host,
            port=port,
            latency_ms=round(latency_ms, 2),
            certificates=len(certificates),
        )
        return TLSInspection(
            host=host,
            port=port,
            protocol=protocol,
            cipher=cipher,
            certificates=certificates,
            latency_ms=latency_ms,
        )

    def _inspect_sync(self, host: str, port: int) -> tuple[Optional[str], Optional[str], List[TLSCertificate]]:
        context = ssl.create_default_context()
        if not self._verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=self._timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher_info = tls_sock.cipher()
                protocol = tls_sock.version()
                der_cert = tls_sock.getpeercert(binary_form=True)
                cert_dict = tls_sock.getpeercert()

        certificate = self._parse_cert(der_cert, cert_dict)
        return protocol, cipher_info[0] if cipher_info else None, [certificate]

    def _parse_cert(self, der_bytes: bytes, cert_dict: dict[str, object]) -> TLSCertificate:
        fingerprint = hashlib.sha256(der_bytes).hexdigest()
        subject_components = cert_dict.get("subject", [])
        subject = ", ".join("=".join(component) for rdn in subject_components for component in rdn)
        issuer_components = cert_dict.get("issuer", [])
        issuer = ", ".join("=".join(component) for rdn in issuer_components for component in rdn)
        not_before = self._parse_time(cert_dict.get("notBefore"))
        not_after = self._parse_time(cert_dict.get("notAfter"))
        sans = [value for key, value in cert_dict.get("subjectAltName", []) if value]
        return TLSCertificate(
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            fingerprint_sha256=fingerprint,
            subject_alt_names=sans,
        )

    @staticmethod
    def _parse_time(value: Optional[object]) -> datetime:
        if isinstance(value, str):
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return datetime.fromtimestamp(0)


__all__ = ["TLSClient", "TLSInspection", "TLSCertificate"]
