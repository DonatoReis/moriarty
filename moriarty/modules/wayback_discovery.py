"""Descoberta de URLs históricas via Wayback Machine."""
import asyncio
from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urlparse

import httpx
import structlog
from rich.progress import Progress

logger = structlog.get_logger(__name__)


@dataclass
class WaybackURL:
    """URL histórica do Wayback Machine."""
    url: str
    timestamp: str
    status_code: int
    is_active: bool = False


class WaybackDiscovery:
    """Descoberta de URLs históricas via Wayback Machine."""
    
    def __init__(
        self,
        domain: str,
        validate: bool = True,
        filter_extensions: Optional[List[str]] = None,
        filter_status_codes: Optional[List[int]] = None,
        years_back: int = 5,
        timeout: float = 10.0,
        extract_params: bool = True,
        detect_admin: bool = True,
    ):
        self.domain = domain.lower().strip()
        self.validate = validate
        self.filter_extensions = filter_extensions
        self.filter_status_codes = filter_status_codes or [200]
        self.years_back = years_back
        self.timeout = timeout
        self.extract_params = extract_params
        self.detect_admin = detect_admin
        self.urls: Set[str] = set()
        self.parameters: Set[str] = set()
        self.admin_urls: Set[str] = set()
    
    async def discover(self) -> List[WaybackURL]:
        """Descobre URLs históricas."""
        logger.info("wayback.discovery.start", domain=self.domain)
        
        # Busca no CDX API
        urls = await self._fetch_cdx()
        
        # Filtra por extensão se especificado
        if self.filter_extensions:
            urls = self._filter_by_extension(urls)
        
        # Extrai parâmetros interessantes
        if self.extract_params:
            self._extract_parameters(urls)
        
        # Detecta páginas admin/login
        if self.detect_admin:
            self._detect_admin_pages(urls)
        
        # Valida URLs ativas
        if self.validate:
            urls = await self._validate_urls(urls)
        
        logger.info("wayback.discovery.complete", 
                   count=len(urls), 
                   params=len(self.parameters),
                   admin_pages=len(self.admin_urls))
        return urls
    
    async def _fetch_cdx(self) -> List[WaybackURL]:
        """Busca URLs no CDX Server."""
        wayback_urls = []
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # CDX API endpoint
                url = f"http://web.archive.org/cdx/search/cdx"
                
                # Monta filtro de status codes
                status_filter = '|'.join(map(str, self.filter_status_codes))
                
                params = {
                    "url": f"{self.domain}/*",
                    "output": "json",
                    "collapse": "urlkey",
                    "fl": "timestamp,original,statuscode",
                    "filter": f"statuscode:{status_filter}",
                    "from": f"{2024 - self.years_back}",
                }
                
                response = await client.get(url, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Primeira linha é header
                    for entry in data[1:]:
                        timestamp, original_url, status_code = entry
                        
                        wayback_url = WaybackURL(
                            url=original_url,
                            timestamp=timestamp,
                            status_code=int(status_code),
                        )
                        wayback_urls.append(wayback_url)
                        self.urls.add(original_url)
                    
                    logger.info("wayback.fetch.success", count=len(wayback_urls))
        
        except Exception as e:
            logger.error("wayback.fetch.error", error=str(e))
        
        return wayback_urls
    
    def _filter_by_extension(self, urls: List[WaybackURL]) -> List[WaybackURL]:
        """Filtra URLs por extensão."""
        filtered = []
        
        for wayback_url in urls:
            parsed = urlparse(wayback_url.url)
            path = parsed.path.lower()
            
            # Verifica se tem alguma extensão desejada
            has_extension = any(path.endswith(f".{ext}") for ext in self.filter_extensions)
            
            if has_extension:
                filtered.append(wayback_url)
        
        logger.info("wayback.filter.complete", before=len(urls), after=len(filtered))
        return filtered
    
    async def _validate_urls(self, urls: List[WaybackURL]) -> List[WaybackURL]:
        """Valida se URLs ainda estão ativas."""
        logger.info("wayback.validation.start", count=len(urls))
        
        validated = []
        
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            tasks = [self._check_url(client, wayback_url) for wayback_url in urls]
            
            with Progress() as progress:
                task_id = progress.add_task("[cyan]Validando URLs...", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    if result:
                        validated.append(result)
                    progress.advance(task_id)
        
        logger.info("wayback.validation.complete", active=len(validated), total=len(urls))
        return validated
    
    async def _check_url(self, client: httpx.AsyncClient, wayback_url: WaybackURL) -> Optional[WaybackURL]:
        """Verifica se URL está ativa."""
        try:
            response = await client.head(wayback_url.url)
            
            if response.status_code < 400:
                wayback_url.is_active = True
                return wayback_url
        except:
            pass
        
        return None
    
    def _extract_parameters(self, urls: List[WaybackURL]):
        """Extrai parâmetros interessantes das URLs."""
        from urllib.parse import urlparse, parse_qs
        
        for wb_url in urls:
            parsed = urlparse(wb_url.url)
            if parsed.query:
                params = parse_qs(parsed.query)
                self.parameters.update(params.keys())
    
    def _detect_admin_pages(self, urls: List[WaybackURL]):
        """Detecta páginas admin/login."""
        admin_patterns = [
            'admin', 'login', 'signin', 'signup', 'register',
            'dashboard', 'panel', 'console', 'manager', 'backend',
            'wp-admin', 'administrator', 'auth', 'user/login',
            'account', 'portal', 'control', 'secure', 'private'
        ]
        
        for wb_url in urls:
            url_lower = wb_url.url.lower()
            for pattern in admin_patterns:
                if pattern in url_lower:
                    self.admin_urls.add(wb_url.url)
                    break
    
    def export(self, urls: List[WaybackURL], output: str):
        """Exporta URLs para arquivo."""
        with open(output, 'w') as f:
            for wayback_url in sorted(urls, key=lambda x: x.timestamp):
                status = "ACTIVE" if wayback_url.is_active else "ARCHIVED"
                f.write(f"{wayback_url.timestamp} [{status}] {wayback_url.url}\n")
        
        logger.info("wayback.export.complete", file=output, count=len(urls))
    
    def export_url_list(self, output: str):
        """Exporta lista simples de URLs para outras ferramentas."""
        with open(output, 'w') as f:
            for url in sorted(self.urls):
                f.write(f"{url}\n")
        
        logger.info("wayback.export.urllist", file=output, count=len(self.urls))
    
    def export_parameters(self, output: str):
        """Exporta lista de parâmetros encontrados."""
        with open(output, 'w') as f:
            for param in sorted(self.parameters):
                f.write(f"{param}\n")
        
        logger.info("wayback.export.params", file=output, count=len(self.parameters))
    
    def export_admin_urls(self, output: str):
        """Exporta URLs de admin/login."""
        with open(output, 'w') as f:
            for url in sorted(self.admin_urls):
                f.write(f"{url}\n")
        
        logger.info("wayback.export.admin", file=output, count=len(self.admin_urls))


__all__ = ["WaybackDiscovery", "WaybackURL"]
