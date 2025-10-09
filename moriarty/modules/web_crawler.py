"""Crawler HTTP avançado para enumeração de rotas e formulários com suporte a redirecionamentos e evasão de bloqueios."""
from __future__ import annotations

import asyncio
import random
import time
import ssl
import certifi
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, TYPE_CHECKING
from urllib.parse import urlparse, urljoin

import httpx
from selectolax.parser import HTMLParser
import structlog

if TYPE_CHECKING:  # pragma: no cover - apenas para type hints
    from moriarty.modules.stealth_mode import StealthMode

logger = structlog.get_logger(__name__)

# Headers realistas de navegador
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

# Lista de user-agents para rotação
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

# Lista de referrers para rotação
REFERRERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://duckduckgo.com/",
    ""
]

@dataclass
class CrawlPage:
    """Representa uma página web rastreada."""
    url: str
    status: int
    title: Optional[str] = None
    forms: List[Dict[str, Any]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    redirect_chain: List[Tuple[str, int]] = field(default_factory=list)
    error: Optional[str] = None


class WebCrawler:
    """Crawler avançado com suporte a redirecionamentos e evasão de bloqueios."""

    def __init__(
        self,
        base_url: str,
        max_pages: int = 100,
        max_depth: int = 2,
        concurrency: int = 5,  # Reduzido para evitar sobrecarga
        follow_subdomains: bool = False,
        user_agent: Optional[str] = None,
        stealth: Optional["StealthMode"] = None,
        request_delay: Tuple[float, float] = (1.0, 3.0),  # Atraso aleatório entre requisições (min, max)
        timeout: float = 30.0,  # Timeout para requisições
        verify_ssl: bool = True,  # Verificar certificados SSL
        max_redirects: int = 5,  # Número máximo de redirecionamentos
        respect_robots: bool = True,  # Respeitar robots.txt
    ):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.follow_subdomains = follow_subdomains
        
        # Configurações de requisição
        self.request_delay = request_delay
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl
        self.respect_robots = respect_robots
        
        # Configurações de stealth
        self.stealth = stealth
        self.user_agent = user_agent or random.choice(USER_AGENTS)
        self.session_cookies: Dict[str, str] = {}
        self.last_request_time: float = 0
        
        # Configurações de domínio
        self.parsed_base_url = self._parse_url(base_url)
        self.base_domain = self._get_base_domain(self.parsed_base_url.hostname or '')
        self.allowed_domains = {self.base_domain}
        if follow_subdomains:
            self.allowed_domains.add(f".{self.base_domain}")
            
        # Estado do crawler
        self.visited: Set[str] = set()
        self.results: Dict[str, CrawlPage] = {}
        self.robots_txt: Optional[Dict[str, Any]] = None
        
        # Configuração do cliente HTTP
        self.session: Optional[httpx.AsyncClient] = None
        self.sem: Optional[asyncio.Semaphore] = None

    async def _init_session(self) -> None:
        """Inicializa a sessão HTTP com configurações de segurança e performance."""
        # Configuração SSL
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        if not self.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
        # Configuração do transporte HTTP
        limits = httpx.Limits(
            max_keepalive_connections=10,
            max_connections=20,
            keepalive_expiry=60.0
        )
        
        # Configuração do cliente HTTP
        self.session = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            max_redirects=self.max_redirects,
            http_versions=["HTTP/1.1", "HTTP/2"],
            limits=limits,
            verify=ssl_context if self.verify_ssl else False,
            headers=DEFAULT_HEADERS.copy(),
            cookies=self.session_cookies
        )
        
        # Atualiza o user-agent
        if self.user_agent:
            self.session.headers["User-Agent"] = self.user_agent
            
        # Adiciona headers adicionais de stealth
        self.session.headers.update({
            "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1"
        })
        
        # Configura o semáforo para limitar concorrência
        self.sem = asyncio.Semaphore(self.concurrency)
        
        # Se necessário, verifica o robots.txt
        if self.respect_robots:
            await self._check_robots_txt()
    
    async def _check_robots_txt(self) -> None:
        """Verifica o arquivo robots.txt e atualiza as regras de acesso."""
        if not self.session:
            return
            
        robots_url = f"{self.parsed_base_url.scheme}://{self.parsed_base_url.netloc}/robots.txt"
        try:
            response = await self.session.get(robots_url)
            if response.status_code == 200:
                # Aqui você pode implementar um parser de robots.txt mais sofisticado
                self.robots_txt = {"content": response.text}
                logger.info("robots_txt_found", url=robots_url)
        except Exception as e:
            logger.warning("robots_txt_error", url=robots_url, error=str(e))
    
    async def _random_delay(self) -> None:
        """Aguarda um tempo aleatório entre requisições para evitar bloqueios."""
        if self.request_delay:
            min_delay, max_delay = self.request_delay
            delay = random.uniform(min_delay, max_delay)
            elapsed = time.time() - self.last_request_time
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self.last_request_time = time.time()
    
    async def crawl(self) -> Dict[str, CrawlPage]:
        """Inicia o processo de rastreamento do site.
        
        Returns:
            Dict[str, CrawlPage]: Dicionário com as páginas encontradas, onde a chave é a URL.
        """
        # Inicializa a sessão HTTP
        if not self.session:
            await self._init_session()
            
        # Inicializa a fila de URLs a serem processadas
        queue: asyncio.Queue = asyncio.Queue()
        initial_url = f"{self.parsed_base_url.scheme}://{self.parsed_base_url.netloc}"
        await queue.put((initial_url, 0))

        # Função worker para processar URLs em paralelo
        async def worker() -> None:
            while True:
                try:
                    url, depth = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                    
                # Verifica os limites de páginas e profundidade
                if len(self.results) >= self.max_pages or depth > self.max_depth:
                    continue
                    
                # Evita processar a mesma URL múltiplas vezes
                if url in self.visited:
                    continue
                    
                # Aguarda um tempo aleatório entre requisições
                await self._random_delay()
                
                # Processa a URL
                await self._fetch(url, depth, queue)
                
                # Atualiza o contador de páginas processadas
                queue.task_done()

        # Inicia os workers
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers)
        return self.results

    def _parse_url(self, url: str) -> httpx.URL:
        """Parseia uma URL e retorna um objeto URL do httpx."""
        try:
            return httpx.URL(url)
        except Exception as e:
            logger.error("url_parse_error", url=url, error=str(e))
            raise ValueError(f"URL inválida: {url}") from e
    
    def _get_base_domain(self, hostname: str) -> str:
        """Extrai o domínio base de um hostname."""
        if not hostname:
            return ""
        parts = hostname.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return hostname
    
    def _is_same_domain(self, url: str) -> bool:
        """Verifica se uma URL pertence ao mesmo domínio do alvo."""
        try:
            parsed = self._parse_url(url)
            if not parsed.host:
                return False
                
            # Verifica se o domínio é o mesmo ou um subdomínio
            if self.follow_subdomains:
                return parsed.host.endswith(self.base_domain) or f".{parsed.host}".endswith(f".{self.base_domain}")
            return parsed.host == self.parsed_base_url.host
        except Exception:
            return False
    
    def _normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        """Normaliza uma URL, resolvendo URLs relativas e removendo fragmentos."""
        try:
            if not url:
                return ""
                
            # Remove fragmentos e espaços em branco
            url = url.split("#")[0].strip()
            if not url:
                return ""
                
            # Se for uma URL relativa, resolve em relação à base_url
            if base_url and not url.startswith(('http://', 'https://')):
                base = self._parse_url(base_url)
                url = str(base.join(url))
            
            # Parseia a URL para normalização
            parsed = self._parse_url(url)
            
            # Remove parâmetros de rastreamento comuns
            if parsed.query:
                query_params = []
                for param in parsed.query.decode().split('&'):
                    if '=' in param and any(t in param.lower() for t in ['utm_', 'ref=', 'source=', 'fbclid=', 'gclid=']):
                        continue
                    query_params.append(param)
                
                # Reconstrói a URL sem os parâmetros de rastreamento
                if query_params:
                    parsed = parsed.copy_with(query='&'.join(query_params))
                else:
                    parsed = parsed.copy_with(query=None)
            
            # Remove barras finais desnecessárias
            path = parsed.path.decode()
            if path.endswith('/'):
                path = path.rstrip('/') or '/'
                parsed = parsed.copy_with(path=path)
            
            return str(parsed)
            
        except Exception as e:
            logger.warning("url_normalize_error", url=url, error=str(e))
            return url
    
    def _build_headers(self, referer: Optional[str] = None) -> Dict[str, str]:
        """Constrói os headers para a requisição HTTP."""
        headers = DEFAULT_HEADERS.copy()
        
        # Rotaciona o User-Agent
        headers["User-Agent"] = random.choice(USER_AGENTS)
        
        # Adiciona o referer se fornecido
        if referer:
            headers["Referer"] = referer
        else:
            headers["Referer"] = random.choice(REFERRERS)
            
        return headers
    
    async def _stealth_delay(self) -> None:
        """Aplica um atraso aleatório para evitar detecção."""
        if self.stealth and hasattr(self.stealth, 'get_delay'):
            delay = self.stealth.get_delay()
            if delay > 0:
                await asyncio.sleep(delay)
    
    async def _fetch(self, url: str, depth: int, queue: asyncio.Queue) -> None:
        """
        Faz o fetch de uma URL e processa os links encontrados.
        
        Args:
            url: URL a ser acessada
            depth: Profundidade atual do rastreamento
            queue: Fila de URLs para processamento
        """
        if not self.session:
            logger.error("session_not_initialized")
            return
            
        # Marca a URL como visitada
        self.visited.add(url)
        
        try:
            # Aplica atraso de stealth, se necessário
            await self._stealth_delay()
            
            # Prepara os headers para a requisição
            headers = self._build_headers()
            
            # Tenta fazer a requisição com tratamento de erros
            try:
                response = await self.session.get(
                    url,
                    headers=headers,
                    follow_redirects=True,
                    timeout=self.timeout
                )
                
                # Registra o tempo da última requisição
                self.last_request_time = time.time()
                
            except httpx.HTTPStatusError as e:
                logger.warning("http_status_error", url=url, status_code=e.response.status_code)
                self.results[url] = CrawlPage(
                    url=url,
                    status=e.response.status_code,
                    error=f"HTTP Error: {e.response.status_code}"
                )
                return
                
            except httpx.RequestError as e:
                logger.warning("request_error", url=url, error=str(e))
                self.results[url] = CrawlPage(
                    url=url,
                    status=0,
                    error=f"Request Error: {str(e)}"
                )
                return
                
            except Exception as e:
                logger.error("unexpected_error", url=url, error=str(e))
                self.results[url] = CrawlPage(
                    url=url,
                    status=0,
                    error=f"Unexpected Error: {str(e)}"
                )
                return
                
            # Processa a resposta
            await self._process_response(url, response, depth, queue)
            
        except Exception as e:
            logger.error("fetch_error", url=url, error=str(e))
            self.results[url] = CrawlPage(
                url=url,
                status=0,
                error=f"Processing Error: {str(e)}"
            )
    
    async def _process_response(self, url: str, response: httpx.Response, depth: int, queue: asyncio.Queue) -> None:
        """
        Processa a resposta HTTP e extrai links para continuar o rastreamento.
        
        Args:
            url: URL que foi acessada
            response: Resposta HTTP
            depth: Profundidade atual do rastreamento
            queue: Fila de URLs para processamento
        """
        # Cria o objeto da página com os dados básicos
        page = CrawlPage(
            url=url,
            status=response.status_code,
            redirect_chain=[(str(r.url), r.status_code) for r in response.history]
        )
        
        # Se não for uma resposta de sucesso ou não for HTML, retorna
        if response.status_code >= 400 or not response.headers.get("content-type", "").startswith("text"):
            self.results[url] = page
            return
            
        try:
            # Parseia o HTML
            parser = HTMLParser(response.text)
            
            # Extrai o título da página
            title = parser.css_first("title")
            if title and hasattr(title, 'text') and callable(title.text):
                page.title = title.text(strip=True)
            
            # Extrai os links da página
            await self._extract_links(parser, url, depth, queue)
            
            # Extrai os formulários da página
            self._extract_forms(parser, page)
            
            # Adiciona a página aos resultados
            self.results[url] = page
            
        except Exception as e:
            logger.error("process_response_error", url=url, error=str(e))
            page.error = f"Error processing response: {str(e)}"
            self.results[url] = page
    
    async def _extract_links(self, parser: HTMLParser, base_url: str, depth: int, queue: asyncio.Queue) -> None:
        """Extrai links do HTML e os adiciona à fila de processamento."""
        for link in parser.css("a[href]"):
            try:
                href = link.attributes.get("href", "").strip()
                if not href or href.startswith("#") or href.startswith("javascript:"):
                    continue
                    
                # Normaliza a URL
                url = self._normalize_url(href, base_url)
                if not url:
                    continue
                    
                # Verifica se a URL pertence ao mesmo domínio
                if not self._is_same_domain(url):
                    continue
                    
                # Adiciona à fila se ainda não foi visitada
                if url not in self.visited and url not in self.results:
                    queue.put_nowait((url, depth + 1))
                    
            except Exception as e:
                logger.warning("link_extraction_error", href=href, error=str(e))
    
    def _extract_forms(self, parser: HTMLParser, page: CrawlPage) -> None:
        """Extrai formulários do HTML."""
        for form in parser.css("form"):
            try:
                form_data = {"method": form.attributes.get("method", "GET").upper()}
                
                # Obtém a ação do formulário
                action = form.attributes.get("action", "").strip()
                if action:
                    form_data["action"] = self._normalize_url(action, page.url)
                else:
                    form_data["action"] = page.url
                
                # Extrai os campos do formulário
                form_data["fields"] = []
                for field in form.css("input, textarea, select"):
                    field_data = {
                        "name": field.attributes.get("name", ""),
                        "type": field.attributes.get("type", "text"),
                        "value": field.attributes.get("value", ""),
                        "required": "required" in field.attributes
                    }
                    form_data["fields"].append(field_data)
                
                page.forms.append(form_data)
                
            except Exception as e:
                logger.warning("form_extraction_error", error=str(e))
    
    async def close(self) -> None:
        """Fecha a sessão HTTP."""
        if self.session:
            await self.session.aclose()
            self.session = None

    async def __aenter__(self):
        await self._init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Para compatibilidade com código existente
__all__ = ["WebCrawler", "CrawlPage"]
