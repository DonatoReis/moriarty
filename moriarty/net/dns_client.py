from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Dict, List, Optional

import aiodns
import httpx
import structlog

from .dns_cache import DNSCache, get_global_cache


@dataclass(slots=True)
class MXRecord:
    priority: int
    exchange: str


@dataclass(slots=True)
class TXTRecord:
    text: str


@dataclass(slots=True)
class DNSLookupResult:
    a: List[str]
    aaaa: List[str]
    mx: List[MXRecord]
    txt: List[TXTRecord]
    spf: List[str]
    dmarc: List[str]


class DNSClient:
    def __init__(
        self,
        timeout: float = 8.0,
        use_cache: bool = True,
        doh_endpoint: Optional[str] = None,
        dot_server: Optional[str] = None,
    ) -> None:
        self._resolver = aiodns.DNSResolver(timeout=timeout)
        self._timeout = timeout
        self._logger = structlog.get_logger(__name__)
        self._use_cache = use_cache
        self._cache = get_global_cache() if use_cache else None
        self._doh_endpoint = doh_endpoint  # Ex: https://cloudflare-dns.com/dns-query
        self._dot_server = dot_server  # Ex: 1.1.1.1:853
        
        if doh_endpoint:
            self._logger.info("dns.doh.enabled", endpoint=doh_endpoint)
        if dot_server:
            self._logger.info("dns.dot.enabled", server=dot_server)

    async def lookup_domain(self, domain: str) -> DNSLookupResult:
        start = perf_counter()
        self._logger.info("dns.lookup.start", domain=domain, timeout_s=self._timeout)
        a_task = asyncio.create_task(self._query(domain, "A"))
        aaaa_task = asyncio.create_task(self._query(domain, "AAAA"))
        mx_task = asyncio.create_task(self._query(domain, "MX"))
        txt_task = asyncio.create_task(self._query(domain, "TXT"))
        dmarc_task = asyncio.create_task(self._query(f"_dmarc.{domain}", "TXT"))

        a_records = await a_task
        aaaa_records = await aaaa_task
        mx_records = await mx_task
        txt_records = await txt_task
        dmarc_records = await dmarc_task

        mx_structured = [
            MXRecord(priority=int(entry.get("priority", 0)), exchange=str(entry.get("host")))
            for entry in mx_records
            if "host" in entry
        ]

        txt_structured = [
            TXTRecord(text=str(entry.get("text", "")))
            for entry in txt_records
            if entry.get("text")
        ]

        spf_records = [record.text for record in txt_structured if record.text.lower().startswith("v=spf1")]
        dmarc_structured = [
            TXTRecord(text=str(entry.get("text", "")))
            for entry in dmarc_records
            if entry.get("text")
        ]

        result = DNSLookupResult(
            a=[entry.get("host") for entry in a_records if entry.get("host")],
            aaaa=[entry.get("host") for entry in aaaa_records if entry.get("host")],
            mx=sorted(mx_structured, key=lambda mx: (mx.priority, mx.exchange)),
            txt=txt_structured,
            spf=spf_records,
            dmarc=[record.text for record in dmarc_structured],
        )
        latency_ms = (perf_counter() - start) * 1000
        self._logger.info(
            "dns.lookup.success",
            domain=domain,
            latency_ms=round(latency_ms, 2),
            a=len(result.a),
            aaaa=len(result.aaaa),
            mx=len(result.mx),
        )
        return result

    async def _query(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        # Verifica cache primeiro
        if self._cache:
            cached = await self._cache.get(domain, record_type)
            if cached is not None:
                return cached
        
        # DoH (DNS-over-HTTPS)
        if self._doh_endpoint:
            try:
                result = await self._query_doh(domain, record_type)
                if result and self._cache:
                    await self._cache.set(domain, record_type, result, ttl=300)
                return result
            except Exception as e:
                self._logger.warning("dns.doh.error", error=str(e), domain=domain)
                # Fallback para DNS tradicional
        
        # DNS tradicional
        try:
            result = await self._resolver.query(domain, record_type)
        except aiodns.error.DNSError:
            self._logger.warning("dns.lookup.miss", domain=domain, record_type=record_type)
            return []

        if isinstance(result, list):
            records = [self._record_to_dict(entry) for entry in result]
            
            # Salva no cache com TTL
            if self._cache and records:
                ttl = getattr(result[0], 'ttl', 300) if result else 300
                await self._cache.set(domain, record_type, records, ttl=ttl)
            
            return records

        return []
    
    async def _query_doh(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """Consulta DNS via HTTPS (DoH)."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(
                self._doh_endpoint,
                params={
                    "name": domain,
                    "type": record_type,
                },
                headers={"Accept": "application/dns-json"},
            )
            response.raise_for_status()
            data = response.json()
            
            # Converte resposta DoH para formato compatível
            answers = data.get("Answer", [])
            if not answers:
                return []
            
            records = []
            for answer in answers:
                if record_type == "A" or record_type == "AAAA":
                    records.append({"host": answer.get("data"), "ttl": answer.get("TTL", 300)})
                elif record_type == "MX":
                    parts = answer.get("data", "").split()
                    if len(parts) == 2:
                        records.append({"priority": int(parts[0]), "host": parts[1], "ttl": answer.get("TTL", 300)})
                elif record_type == "TXT":
                    records.append({"text": answer.get("data", ""), "ttl": answer.get("TTL", 300)})
            
            return records

    @staticmethod
    def _record_to_dict(record: Any) -> Dict[str, Any]:
        return {
            key: getattr(record, key)
            for key in dir(record)
            if not key.startswith("_") and not callable(getattr(record, key))
        }


__all__ = ["DNSClient", "DNSLookupResult", "MXRecord", "TXTRecord"]
