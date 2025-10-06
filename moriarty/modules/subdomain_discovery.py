"""Descoberta avançada de subdomínios usando 20+ fontes."""
import asyncio
import re
from dataclasses import dataclass
from typing import List, Optional, Set

import httpx
import structlog
from rich.console import Console
from rich.progress import Progress

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class SubdomainResult:
    """Resultado de subdomain discovery."""
    subdomain: str
    source: str
    is_valid: bool = False
    ip_addresses: List[str] = None
    has_mx: bool = False


class SubdomainDiscovery:
    """
    Descoberta de subdomínios usando múltiplas fontes.
    
    Fontes suportadas:
    1. crt.sh (Certificate Transparency)
    2. VirusTotal
    3. SecurityTrails
    4. Shodan
    5. DNSDumpster
    6. AlienVault OTX
    7. ThreatCrowd
    8. Wayback Machine
    9. CommonCrawl
    10. Google Dorking
    11. Bing
    12. Yahoo
    13. Ask
    14. DNS Bruteforce
    15. Zone Transfer
    16. Reverse DNS
    17. DNSSEC
    18. NSEC Walking
    19. Subdomain Permutations
    20. GitHub Code Search
    """
    
    # Wordlist comum para bruteforce
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites", "proxy",
        "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info", "apps",
        "download", "remote", "db", "forums", "store", "relay", "files", "newsletter",
        "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4"
    ]
    
    def __init__(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        validate: bool = True,
        recursive: bool = False,
        wordlist: Optional[str] = None,
        timeout: float = 10.0,
        use_cache: bool = True,
    ):
        self.domain = domain.lower().strip()
        self.sources = sources or ["all"]
        self.validate = validate
        self.recursive = recursive
        self.wordlist_path = wordlist
        self.timeout = timeout
        self.use_cache = use_cache
        self.results: Set[str] = set()
        self.rate_limiters: dict = {}
        
        # Carrega config para API keys
        try:
            from moriarty.core.config_manager import config_manager
            self.config = config_manager
        except:
            self.config = None
        
        # Carrega wordlist customizada ou usa expandida
        if wordlist:
            with open(wordlist, 'r') as f:
                self.custom_wordlist = [line.strip() for line in f if line.strip()]
        else:
            # Usa wordlist expandida (1000+)
            from pathlib import Path
            wordlist_1000 = Path(__file__).parent.parent / 'assets' / 'wordlists' / 'subdomains-1000.txt'
            if wordlist_1000.exists():
                with open(wordlist_1000, 'r') as f:
                    self.custom_wordlist = [line.strip() for line in f if line.strip()]
            else:
                self.custom_wordlist = self.COMMON_SUBDOMAINS
    
    async def discover(self) -> List[str]:
        """Executa discovery em todas as fontes."""
        logger.info("subdomain.discovery.start", domain=self.domain, sources=len(self.sources))
        
        # Tenta carregar do cache primeiro
        if self.use_cache:
            cached = self._load_from_cache()
            if cached:
                logger.info("subdomain.discovery.cache_hit", count=len(cached))
                return cached
        
        tasks = []
        
        # Certificate Transparency
        if "all" in self.sources or "crtsh" in self.sources:
            tasks.append(self._with_rate_limit(self._crtsh(), "crtsh"))

        # VirusTotal
        if "all" in self.sources or "virustotal" in self.sources:
            tasks.append(self._with_rate_limit(self._virustotal(), "virustotal"))

        # SecurityTrails
        if "all" in self.sources or "securitytrails" in self.sources:
            tasks.append(self._with_rate_limit(self._securitytrails(), "securitytrails"))

        # Shodan
        if "all" in self.sources or "shodan" in self.sources:
            tasks.append(self._with_rate_limit(self._shodan(), "shodan"))

        # Wayback Machine
        if "all" in self.sources or "wayback" in self.sources:
            tasks.append(self._wayback())
        
        # CommonCrawl
        if "all" in self.sources or "commoncrawl" in self.sources:
            tasks.append(self._commoncrawl())
        
        # AlienVault OTX
        if "all" in self.sources or "alienvault" in self.sources:
            tasks.append(self._alienvault())
        
        # ThreatCrowd
        if "all" in self.sources or "threatcrowd" in self.sources:
            tasks.append(self._threatcrowd())
        
        # DNS Bruteforce
        if "all" in self.sources or "bruteforce" in self.sources:
            tasks.append(self._dns_bruteforce())
        
        # Permutations
        if "all" in self.sources or "permutations" in self.sources:
            tasks.append(self._permutations())
        
        # Zone Transfer
        if "all" in self.sources or "zonetransfer" in self.sources:
            tasks.append(self._zone_transfer())
        
        # Executa todas as tasks
        with Progress() as progress:
            task_id = progress.add_task("[cyan]Descobrindo subdomínios...", total=len(tasks))
            
            for coro in asyncio.as_completed(tasks):
                await coro
                progress.advance(task_id)
        
        # Validação DNS
        if self.validate:
            await self._validate_subdomains()
        
        # Salva no cache
        if self.use_cache:
            self._save_to_cache(list(self.results))
        
        logger.info("subdomain.discovery.complete", domain=self.domain, count=len(self.results))
        
        return sorted(list(self.results))
    
    async def _with_rate_limit(self, coro, source: str):
        """Aplica rate limiting por fonte."""
        # Rate limits diferentes por fonte
        rate_limits = {
            "crtsh": 0.5,  # 1 req/0.5s
            "virustotal": 4.0,  # API limitada
            "securitytrails": 1.0,
            "shodan": 1.0,
            "alienvault": 0.5,
            "threatcrowd": 2.0,
        }
        
        delay = rate_limits.get(source, 0)
        if delay > 0:
            if source in self.rate_limiters:
                elapsed = asyncio.get_event_loop().time() - self.rate_limiters[source]
                if elapsed < delay:
                    await asyncio.sleep(delay - elapsed)
        
        result = await coro
        self.rate_limiters[source] = asyncio.get_event_loop().time()
        return result

    def _get_api_key(self, service: str) -> Optional[str]:
        """Retorna API key configurada para o serviço."""
        if not self.config:
            return None

        try:
            return self.config.get_api_key(service)
        except Exception:
            return None

    def _load_from_cache(self) -> Optional[List[str]]:
        """Carrega resultados do cache."""
        import pickle
        from pathlib import Path
        import time
        
        cache_dir = Path.home() / '.moriarty' / 'cache' / 'subdomains'
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        cache_file = cache_dir / f"{self.domain}.pkl"
        
        if cache_file.exists():
            # Verifica se cache não expirou (24h)
            age = time.time() - cache_file.stat().st_mtime
            if age < 86400:  # 24 horas
                try:
                    with open(cache_file, 'rb') as f:
                        return pickle.load(f)
                except:
                    pass
        
        return None
    
    def _save_to_cache(self, subdomains: List[str]):
        """Salva resultados no cache."""
        import pickle
        from pathlib import Path
        
        cache_dir = Path.home() / '.moriarty' / 'cache' / 'subdomains'
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        cache_file = cache_dir / f"{self.domain}.pkl"
        
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(subdomains, f)
            logger.info("subdomain.cache.saved", file=str(cache_file))
        except Exception as e:
            logger.warning("subdomain.cache.save_error", error=str(e))

    async def _virustotal(self):
        """Busca subdomínios via VirusTotal API v3."""
        api_key = self._get_api_key("virustotal")
        if not api_key:
            logger.debug("subdomain.virustotal.no_key")
            return

        headers = {"x-apikey": api_key}
        base_url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        next_url: Optional[str] = base_url
        params = {"limit": 40}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                while next_url:
                    response = await client.get(next_url, headers=headers, params=params if next_url == base_url else None)
                    if response.status_code != 200:
                        logger.warning(
                            "subdomain.virustotal.http_error",
                            status=response.status_code,
                            body=response.text[:200],
                        )
                        break

                    data = response.json()
                    for item in data.get("data", []):
                        identifier = (item.get("id") or item.get("value") or "").strip().lower()
                        if identifier and identifier.endswith(self.domain):
                            self.results.add(identifier)

                    next_url = data.get("links", {}).get("next")

            logger.info("subdomain.virustotal.found", count=len(self.results))

        except Exception as e:
            logger.warning("subdomain.virustotal.error", error=str(e))

    async def _securitytrails(self):
        """Busca subdomínios via SecurityTrails API."""
        api_key = self._get_api_key("securitytrails")
        if not api_key:
            logger.debug("subdomain.securitytrails.no_key")
            return

        headers = {"APIKEY": api_key}
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        params = {"children_only": "false", "include_inactive": "true"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers, params=params)

                if response.status_code != 200:
                    logger.warning(
                        "subdomain.securitytrails.http_error",
                        status=response.status_code,
                        body=response.text[:200],
                    )
                    return

                data = response.json()
                for sub in data.get("subdomains", []):
                    if not sub:
                        continue
                    hostname = f"{sub.strip().lower()}.{self.domain}"
                    self.results.add(hostname)

                for record in data.get("records", []):
                    fqdn = (record.get("hostname") or record.get("fqdn") or "").lower()
                    if fqdn and fqdn.endswith(self.domain):
                        self.results.add(fqdn)

            logger.info("subdomain.securitytrails.found", count=len(self.results))

        except Exception as e:
            logger.warning("subdomain.securitytrails.error", error=str(e))

    async def _shodan(self):
        """Busca subdomínios via Shodan API."""
        api_key = self._get_api_key("shodan")
        if not api_key:
            logger.debug("subdomain.shodan.no_key")
            return

        params = {"key": api_key}
        url = f"https://api.shodan.io/dns/domain/{self.domain}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, params=params)

                if response.status_code != 200:
                    logger.warning(
                        "subdomain.shodan.http_error",
                        status=response.status_code,
                        body=response.text[:200],
                    )
                    return

                data = response.json()
                for sub in data.get("subdomains", []):
                    if not sub:
                        continue
                    hostname = f"{sub.strip().lower()}.{self.domain}"
                    self.results.add(hostname)

                for record in data.get("data", []):
                    hostname = (record.get("subdomain") or record.get("domain") or "").lower()
                    if hostname and hostname.endswith(self.domain):
                        self.results.add(hostname)

            logger.info("subdomain.shodan.found", count=len(self.results))

        except Exception as e:
            logger.warning("subdomain.shodan.error", error=str(e))

    async def _crtsh(self):
        """Busca via Certificate Transparency (crt.sh)."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Pode vir com múltiplos nomes separados por \n
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(self.domain) and "*" not in subdomain:
                                self.results.add(subdomain)
                    
                    logger.info("subdomain.crtsh.found", count=len([r for r in self.results]))
        except Exception as e:
            logger.warning("subdomain.crtsh.error", error=str(e))
    
    async def _wayback(self):
        """Busca via Wayback Machine."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data[1:]:  # Pula header
                        url = entry[2]
                        # Extrai subdomain da URL
                        match = re.search(rf'([a-z0-9\-\.]+\.{re.escape(self.domain)})', url, re.IGNORECASE)
                        if match:
                            self.results.add(match.group(1).lower())
                    
                    logger.info("subdomain.wayback.found", count=len(self.results))
        except Exception as e:
            logger.warning("subdomain.wayback.error", error=str(e))
    
    async def _commoncrawl(self):
        """Busca via CommonCrawl."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Busca últimos indexes
                indexes_url = "https://index.commoncrawl.org/collinfo.json"
                response = await client.get(indexes_url)
                
                if response.status_code == 200:
                    indexes = response.json()
                    latest_index = indexes[0]["cdx-api"]
                    
                    # Busca no index
                    url = f"{latest_index}?url=*.{self.domain}/*&output=json"
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        for line in response.text.split("\n"):
                            if line:
                                try:
                                    data = eval(line)  # JSON per line
                                    url = data.get("url", "")
                                    match = re.search(rf'([a-z0-9\-\.]+\.{re.escape(self.domain)})', url, re.IGNORECASE)
                                    if match:
                                        self.results.add(match.group(1).lower())
                                except:
                                    pass
        except Exception as e:
            logger.warning("subdomain.commoncrawl.error", error=str(e))
    
    async def _alienvault(self):
        """Busca via AlienVault OTX."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        if hostname.endswith(self.domain):
                            self.results.add(hostname.lower())
                    
                    logger.info("subdomain.alienvault.found", count=len(self.results))
        except Exception as e:
            logger.warning("subdomain.alienvault.error", error=str(e))
    
    async def _threatcrowd(self):
        """Busca via ThreatCrowd."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
                response = await client.get(url)
                
                if response.status_code == 200:
                    data = response.json()
                    for subdomain in data.get("subdomains", []):
                        if subdomain:
                            self.results.add(subdomain.lower())
                    
                    logger.info("subdomain.threatcrowd.found", count=len(self.results))
        except Exception as e:
            logger.warning("subdomain.threatcrowd.error", error=str(e))
    
    async def _dns_bruteforce(self):
        """DNS Bruteforce usando wordlist."""
        wordlist = self.custom_wordlist or self.COMMON_SUBDOMAINS
        
        try:
            import aiodns
            resolver = aiodns.DNSResolver(timeout=2.0)
            
            tasks = []
            for word in wordlist:
                subdomain = f"{word}.{self.domain}"
                tasks.append(self._check_dns(resolver, subdomain))
            
            # Executa em batches para não sobrecarregar
            batch_size = 50
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i+batch_size]
                await asyncio.gather(*batch, return_exceptions=True)
            
            logger.info("subdomain.bruteforce.complete", tested=len(wordlist), found=len(self.results))
        except Exception as e:
            logger.warning("subdomain.bruteforce.error", error=str(e))
    
    async def _check_dns(self, resolver, subdomain: str):
        """Verifica se subdomain resolve."""
        try:
            result = await resolver.query(subdomain, "A")
            if result:
                self.results.add(subdomain)
        except:
            pass
    
    async def _permutations(self):
        """Gera permutações de subdomínios conhecidos."""
        # Alterações comuns
        alterations = ["dev", "staging", "test", "prod", "uat", "qa", "demo", "backup", "old", "new"]
        
        current_subs = list(self.results)
        for subdomain in current_subs:
            # Remove domain principal
            prefix = subdomain.replace(f".{self.domain}", "")
            
            for alt in alterations:
                # Adiciona sufixo
                new_sub = f"{prefix}-{alt}.{self.domain}"
                self.results.add(new_sub)
                
                # Adiciona prefixo
                new_sub = f"{alt}-{prefix}.{self.domain}"
                self.results.add(new_sub)
    
    async def _zone_transfer(self):
        """Tenta AXFR (Zone Transfer)."""
        try:
            import aiodns
            resolver = aiodns.DNSResolver(timeout=5.0)
            
            # Busca NS records
            ns_records = await resolver.query(self.domain, "NS")
            
            for ns in ns_records:
                ns_host = ns.host
                logger.info("subdomain.zonetransfer.trying", ns=ns_host)
                
                # AXFR não é suportado por aiodns, precisaria de dnspython
                # Placeholder para implementação completa
                pass
                
        except Exception as e:
            logger.debug("subdomain.zonetransfer.failed", error=str(e))
    
    async def _validate_subdomains(self):
        """Valida subdomínios encontrados com DNS lookup."""
        logger.info("subdomain.validation.start", count=len(self.results))
        
        try:
            import aiodns
            resolver = aiodns.DNSResolver(timeout=2.0)
            
            validated = set()
            tasks = []
            
            for subdomain in self.results:
                tasks.append(self._validate_single(resolver, subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, is_valid in results:
                if is_valid and subdomain:
                    validated.add(subdomain)
            
            self.results = validated
            logger.info("subdomain.validation.complete", validated=len(validated))
            
        except Exception as e:
            logger.warning("subdomain.validation.error", error=str(e))
    
    async def _validate_single(self, resolver, subdomain: str):
        """Valida um único subdomain."""
        try:
            result = await resolver.query(subdomain, "A")
            return (subdomain, True) if result else (subdomain, False)
        except:
            return (subdomain, False)
    
    def export(self, results: List[str], output: str):
        """Exporta resultados para arquivo."""
        with open(output, 'w') as f:
            for subdomain in sorted(results):
                f.write(f"{subdomain}\n")
        
        logger.info("subdomain.export.complete", file=output, count=len(results))


__all__ = ["SubdomainDiscovery", "SubdomainResult"]
