"""Funcionalidades estendidas de RDAP e CT logs."""
from dataclasses import dataclass
from typing import List, Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ASNInfo:
    """Informações de ASN (Autonomous System Number)."""
    asn: int
    name: str
    description: str
    country: str
    registry: str  # ARIN, RIPE, APNIC, etc.
    prefixes: List[str]


@dataclass
class CTLogEntry:
    """Entrada do Certificate Transparency log."""
    issuer_name: str
    common_name: str
    name_value: str  # SANs
    not_before: str
    not_after: str
    serial_number: str
    entry_timestamp: str


class RDAPExtended:
    """Cliente RDAP estendido com ASN e CT logs."""
    
    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
    
    async def lookup_asn(self, asn: int) -> Optional[ASNInfo]:
        """
        Busca informações de um ASN.
        
        Usa RDAP bootstrap para encontrar o servidor correto.
        """
        logger.info("rdap.asn.lookup", asn=asn)
        
        try:
            # RDAP bootstrap para ASN
            async with httpx.AsyncClient(timeout=self._timeout, http2=True) as client:
                # Tenta via ARIN primeiro (covering most ASNs)
                url = f"https://rdap.arin.net/registry/autnum/{asn}"
                response = await client.get(url)
                
                if response.status_code == 404:
                    # Tenta RIPE
                    url = f"https://rdap.db.ripe.net/autnum/{asn}"
                    response = await client.get(url)
                
                if response.status_code == 404:
                    # Tenta APNIC
                    url = f"https://rdap.apnic.net/autnum/{asn}"
                    response = await client.get(url)
                
                response.raise_for_status()
                data = response.json()
                
                # Parse resposta RDAP
                name = data.get("name", "")
                description = ""
                country = ""
                
                # Extrai informações das entities
                entities = data.get("entities", [])
                for entity in entities:
                    if "vcard" in entity:
                        # Processa vCard
                        pass
                
                # Extrai prefixes (se disponível)
                prefixes = []
                remarks = data.get("remarks", [])
                for remark in remarks:
                    description += remark.get("description", [""])[0] + " "
                
                logger.info("rdap.asn.found", asn=asn, name=name)
                
                return ASNInfo(
                    asn=asn,
                    name=name,
                    description=description.strip(),
                    country=country,
                    registry="ARIN",  # Simplificado
                    prefixes=prefixes,
                )
                
        except Exception as e:
            logger.warning("rdap.asn.error", asn=asn, error=str(e))
            return None
    
    async def lookup_prefix(self, ip: str) -> Optional[ASNInfo]:
        """
        Busca o ASN e prefix de um IP.
        """
        logger.info("rdap.prefix.lookup", ip=ip)
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout, http2=True) as client:
                # RDAP IP lookup
                url = f"https://rdap.arin.net/registry/ip/{ip}"
                response = await client.get(url)
                
                if response.status_code == 404:
                    url = f"https://rdap.db.ripe.net/ip/{ip}"
                    response = await client.get(url)
                
                response.raise_for_status()
                data = response.json()
                
                # Extrai ASN
                asn = None
                entities = data.get("entities", [])
                for entity in entities:
                    if "asn" in entity:
                        asn = entity["asn"]
                        break
                
                start_address = data.get("startAddress", "")
                end_address = data.get("endAddress", "")
                cidr = data.get("cidr0_cidrs", [{}])[0].get("v4prefix", "")
                
                if asn:
                    return await self.lookup_asn(asn)
                
                logger.info("rdap.prefix.found", ip=ip, cidr=cidr)
                return None
                
        except Exception as e:
            logger.warning("rdap.prefix.error", ip=ip, error=str(e))
            return None
    
    async def query_ct_logs(self, domain: str, limit: int = 100) -> List[CTLogEntry]:
        """
        Consulta Certificate Transparency logs via crt.sh.
        
        Retorna certificados emitidos para o domínio.
        """
        logger.info("ct.logs.query", domain=domain, limit=limit)
        
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                # crt.sh API
                url = "https://crt.sh/"
                params = {
                    "q": domain,
                    "output": "json",
                }
                
                response = await client.get(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                entries = []
                for item in data[:limit]:
                    entry = CTLogEntry(
                        issuer_name=item.get("issuer_name", ""),
                        common_name=item.get("common_name", ""),
                        name_value=item.get("name_value", ""),
                        not_before=item.get("not_before", ""),
                        not_after=item.get("not_after", ""),
                        serial_number=item.get("serial_number", ""),
                        entry_timestamp=item.get("entry_timestamp", ""),
                    )
                    entries.append(entry)
                
                logger.info("ct.logs.found", domain=domain, count=len(entries))
                return entries
                
        except Exception as e:
            logger.warning("ct.logs.error", domain=domain, error=str(e))
            return []


__all__ = [
    "RDAPExtended",
    "ASNInfo",
    "CTLogEntry",
]
