"""Coleta passiva de inteligência sobre domínios (Passive Recon)."""
from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
import structlog

from .technology_profiler import profile_domain
from ..net.rdap_client import RDAPClient

logger = structlog.get_logger(__name__)


@dataclass
class PassiveReconResult:
    """Estrutura consolidada dos artefatos coletados."""

    domain: str
    subdomains: Dict[str, List[str]] = field(default_factory=dict)
    credentials: Dict[str, Any] = field(default_factory=dict)
    leaks: Dict[str, Any] = field(default_factory=dict)
    technologies: Dict[str, Any] = field(default_factory=dict)
    reputation: Dict[str, Any] = field(default_factory=dict)
    rdap: Optional[Dict[str, Any]] = None
    whois: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "credentials": self.credentials,
            "leaks": self.leaks,
            "technologies": self.technologies,
            "reputation": self.reputation,
            "whois": self.whois,
            "rdap": self.rdap,
        }


class PassiveRecon:
    """Orquestra integrações passivas usando as credenciais do ConfigManager."""

    def __init__(self, domain: str, timeout: float = 15.0):
        self.domain = domain.lower().strip()
        self.timeout = timeout

        try:
            from moriarty.core.config_manager import config_manager

            self.config = config_manager
        except Exception:  # pragma: no cover - fallback ao rodar fora do cli
            self.config = None

        self.session = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)

    async def close(self) -> None:
        await self.session.aclose()

    async def collect(self) -> PassiveReconResult:
        """Executa todas as coletas em paralelo."""
        result = PassiveReconResult(domain=self.domain)

        tasks = [
            self._gather_subdomains(result),
            self._gather_credentials(result),
            self._fingerprint_http(result),
            self._gather_reputation(result),
            self._collect_whois(result),
            self._collect_rdap(result),
        ]

        await asyncio.gather(*tasks)
        return result

    # ------------------------------------------------------------------
    # Subdomains / Passive Sources
    # ------------------------------------------------------------------
    async def _gather_subdomains(self, result: PassiveReconResult) -> None:
        collectors = [
            self._from_passivetotal,
            self._from_certspotter,
            self._from_censys,
            self._from_securitytrails,
            self._from_spyse,
            self._from_leakix,
        ]

        subdomains: Dict[str, List[str]] = {}

        async def run_collector(handler):
            name = handler.__name__.replace("_from_", "")
            try:
                data = await handler()
                if data:
                    subdomains[name] = sorted(set(data))
            except Exception as exc:  # pragma: no cover - tolera falhas pontuais
                logger.debug("passiverecon.source.error", source=name, error=str(exc))

        await asyncio.gather(*(run_collector(c) for c in collectors))
        result.subdomains = subdomains

    async def _from_passivetotal(self) -> List[str]:
        creds = self._get_credentials("passivetotal")
        if not creds or not creds.get("username") or not creds.get("key"):
            return []

        auth = base64.b64encode(f"{creds['username']}:{creds['key']}".encode()).decode()
        url = "https://api.passivetotal.org/v2/enrichment/subdomains"
        params = {"query": self.domain}
        headers = {"Authorization": f"Basic {auth}"}

        response = await self.session.get(url, params=params, headers=headers)
        if response.status_code != 200:
            logger.debug("passiverecon.passivetotal.http", status=response.status_code)
            return []

        payload = response.json()
        return [f"{sub}.{self.domain}" for sub in payload.get("subdomains", [])]

    async def _from_certspotter(self) -> List[str]:
        url = "https://api.certspotter.com/v1/issuances"
        params = {
            "domain": self.domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }

        response = await self.session.get(url, params=params)
        if response.status_code != 200:
            logger.debug("passiverecon.certspotter.http", status=response.status_code)
            return []

        hosts: List[str] = []
        for entry in response.json():
            hosts.extend(entry.get("dns_names", []))
        return [h for h in hosts if h.endswith(self.domain)]

    async def _from_censys(self) -> List[str]:
        creds = self._get_credentials("censys")
        if not creds or not creds.get("id") or not creds.get("secret"):
            return []

        query = f"services.tls.certificates.leaf_data.subject_dn: {self.domain}"
        url = "https://search.censys.io/api/v2/hosts/search"
        auth = (creds["id"], creds["secret"])
        payload = {"q": query, "per_page": 50}

        response = await self.session.post(url, auth=auth, json=payload)
        if response.status_code != 200:
            logger.debug("passiverecon.censys.http", status=response.status_code)
            return []

        hosts = []
        for entry in response.json().get("result", {}).get("hits", []):
            ip = entry.get("ip")
            if ip:
                hosts.append(ip)
            for service in entry.get("services", []):
                hostname = service.get("observed_dns_names") or []
                hosts.extend([h for h in hostname if h.endswith(self.domain)])
        return hosts

    async def _from_securitytrails(self) -> List[str]:
        creds = self._get_credentials("securitytrails")
        if not creds or not creds.get("key"):
            return []

        headers = {"APIKEY": creds["key"]}
        url = f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"
        response = await self.session.get(url, headers=headers)
        if response.status_code != 200:
            logger.debug("passiverecon.securitytrails.http", status=response.status_code)
            return []

        hosts = []
        data = response.json()
        for record in data.get("records", []):
            hosts.extend(record.get("values", []))
        return hosts

    async def _from_spyse(self) -> List[str]:
        creds = self._get_credentials("spyse")
        if not creds or not creds.get("key"):
            return []

        headers = {"Authorization": f"Bearer {creds['key']}"}
        payload = {"search_params": {"domain": {"equals": self.domain}}}
        url = "https://api.spyse.com/v4/data/domain/search"

        response = await self.session.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            logger.debug("passiverecon.spyse.http", status=response.status_code)
            return []

        hosts = []
        for entry in response.json().get("data", {}).get("items", []):
            hosts.extend(entry.get("related_domains", []))
        return [h for h in hosts if h.endswith(self.domain)]

    async def _from_leakix(self) -> List[str]:
        creds = self._get_credentials("leakix")
        if not creds or not creds.get("key"):
            return []

        headers = {"Authorization": f"Bearer {creds['key']}"}
        url = f"https://leakix.net/api/v1/lookup/{self.domain}"
        response = await self.session.get(url, headers=headers)
        if response.status_code != 200:
            logger.debug("passiverecon.leakix.http", status=response.status_code)
            return []

        results = response.json().get("results", [])
        hosts = []
        for entry in results:
            host = entry.get("host")
            if host:
                hosts.append(host)
        return hosts

    # ------------------------------------------------------------------
    # Credenciais e vazamentos
    # ------------------------------------------------------------------
    async def _gather_credentials(self, result: PassiveReconResult) -> None:
        leaks: Dict[str, Any] = {}

        hibp = await self._from_hibp()
        if hibp:
            leaks["haveibeenpwned"] = hibp

        leakpeek = await self._from_leakpeek()
        if leakpeek:
            leaks["leakpeek"] = leakpeek

        result.leaks = leaks

    async def _from_hibp(self) -> Optional[Dict[str, Any]]:
        creds = self._get_credentials("hibp")
        if not creds or not creds.get("key"):
            return None

        headers = {
            "hibp-api-key": creds["key"],
            "user-agent": "moriarty-osint",
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.domain}"

        response = await self.session.get(url, headers=headers)
        if response.status_code == 404:
            return {"breaches": []}
        if response.status_code != 200:
            logger.debug("passiverecon.hibp.http", status=response.status_code)
            return None
        return {"breaches": response.json()}

    async def _from_leakpeek(self) -> Optional[List[Dict[str, Any]]]:
        creds = self._get_credentials("leakpeek")
        if not creds or not creds.get("key"):
            return None

        headers = {"Authorization": f"Bearer {creds['key']}"}
        url = f"https://api.leakpeek.com/v1/leaks/{self.domain}"
        response = await self.session.get(url, headers=headers)
        if response.status_code != 200:
            logger.debug("passiverecon.leakpeek.http", status=response.status_code)
            return None
        return response.json().get("results", [])

    # ------------------------------------------------------------------
    # Fingerprinting HTTP / tecnologia
    # ------------------------------------------------------------------
    async def _fingerprint_http(self, result: PassiveReconResult) -> None:
        try:
            profile = await profile_domain(self.domain, session=self.session)
        except Exception as exc:  # pragma: no cover - tolerate fingerprint failures
            logger.debug("passiverecon.fingerprint.error", domain=self.domain, error=str(exc))
            profile = {}
        result.technologies = profile

    # ------------------------------------------------------------------
    # Reputação / ameaças
    # ------------------------------------------------------------------
    async def _gather_reputation(self, result: PassiveReconResult) -> None:
        rep: Dict[str, Any] = {}

        otx = await self._from_alienvault()
        if otx:
            rep["alienvault"] = otx

        threatfox = await self._from_threatfox()
        if threatfox:
            rep["threatfox"] = threatfox

        urlhaus = await self._from_urlhaus()
        if urlhaus:
            rep["urlhaus"] = urlhaus

        result.reputation = rep

    async def _from_alienvault(self) -> Optional[Dict[str, Any]]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general"
        response = await self.session.get(url)
        if response.status_code != 200:
            logger.debug("passiverecon.alienvault.http", status=response.status_code)
            return None
        data = response.json()
        pulses = [pulse.get("name") for pulse in data.get("pulse_info", {}).get("pulses", [])]
        return {
            "pulses": pulses,
            "alexa": data.get("alexa"),
            "asn": data.get("asn"),
        }

    async def _from_threatfox(self) -> Optional[Dict[str, Any]]:
        """Consulta threat intel da Abuse.ch (ThreatFox)."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": self.domain}
        try:
            response = await self.session.post(url, json=payload)
        except Exception as exc:  # pragma: no cover
            logger.debug("passiverecon.threatfox.error", error=str(exc))
            return None

        if response.status_code != 200:
            logger.debug("passiverecon.threatfox.http", status=response.status_code)
            return None

        data = response.json()
        if data.get("query_status") != "ok":
            return None

        records = data.get("data", [])
        families = sorted({entry.get("malware", "") for entry in records if entry.get("malware")})
        return {
            "count": len(records),
            "malware_families": families,
        }

    async def _from_urlhaus(self) -> Optional[Dict[str, Any]]:
        """Consulta URLs maliciosas hospedadas no domínio (URLHaus)."""
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        data = {"host": self.domain}
        try:
            response = await self.session.post(url, data=data)
        except Exception as exc:  # pragma: no cover
            logger.debug("passiverecon.urlhaus.error", error=str(exc))
            return None

        if response.status_code != 200:
            logger.debug("passiverecon.urlhaus.http", status=response.status_code)
            return None

        payload = response.json()
        if payload.get("query_status") != "ok":
            return None

        entries = payload.get("urls", [])
        latest = None
        if entries:
            latest_record = entries[0]
            latest = {
                "url": latest_record.get("url"),
                "status": latest_record.get("url_status"),
                "threat": latest_record.get("threat"),
                "reporter": latest_record.get("reporter"),
            }

        return {
            "count": len(entries),
            "latest": latest,
        }

    # ------------------------------------------------------------------
    # WHOIS
    # ------------------------------------------------------------------
    async def _collect_whois(self, result: PassiveReconResult) -> None:
        cmd = await asyncio.create_subprocess_exec(
            "whois",
            self.domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await cmd.communicate()
        result.whois = stdout.decode(errors="ignore") if stdout else None

    async def _collect_rdap(self, result: PassiveReconResult) -> None:
        """Consulta RDAP oficial para complementar WHOIS."""
        try:
            client = RDAPClient(timeout=self.timeout, http2=True)
            rdap = await client.fetch(f"domain/{self.domain}")
        except Exception as exc:  # pragma: no cover - RDAP falhas toleradas
            logger.debug("passiverecon.rdap.error", domain=self.domain, error=str(exc))
            return

        payload = rdap.payload.copy()
        result.rdap = {
            "url": rdap.url,
            "status": rdap.status,
            "latency_ms": round(rdap.latency_ms, 2),
            "handle": payload.get("handle"),
            "registrar": payload.get("registrar", {}).get("name")
            if isinstance(payload.get("registrar"), dict)
            else payload.get("registrar"),
            "events": payload.get("events", []),
            "raw": payload,
        }

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def _get_credentials(self, service: str) -> Dict[str, Any]:
        if not self.config:
            return {}

        api_keys = getattr(self.config, "api_keys", None)
        if not api_keys:
            return {}

        data = getattr(api_keys, service, None)
        if isinstance(data, dict):
            return data
        if isinstance(data, str):
            return {"key": data}

        # Suporte a nomes específicos (ex.: censys_id/secret)
        if service == "censys":
            return {
                "id": getattr(api_keys, "censys_id", None),
                "secret": getattr(api_keys, "censys_secret", None),
            }
        if service == "passivetotal":
            return {
                "username": getattr(api_keys, "passivetotal_username", None),
                "key": getattr(api_keys, "passivetotal_key", None),
            }

        return {}


__all__ = ["PassiveRecon", "PassiveReconResult"]
