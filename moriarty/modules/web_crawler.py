"""Crawler HTTP avançado para enumeração de rotas e formulários com suporte a redirecionamentos e evasão de bloqueios."""
from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING
import re
import socket
import ssl
import time
import types
import certifi
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union
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
        # Garante que a URL base seja uma string
        self.base_url_str = str(self.parsed_base_url).rstrip("/")
        # Obtém o host e domínio base como strings
        host = self.parsed_base_url.host
        if isinstance(host, (bytes, bytearray)):
            self.base_host = host.decode("utf-8")
        else:
            self.base_host = str(host or "")
        self.base_domain = self._get_base_domain(self.base_host)
        
        # Domínios permitidos
        self.allowed_domains = {self.base_domain}
        if follow_subdomains:
            self.allowed_domains.add(f".{self.base_domain}")
            
        # Configuração do parser de robots.txt
        self.robots: Optional[urllib.robotparser.RobotFileParser] = None
            
        # Estado do crawler
        self.visited: Set[str] = set()
        self.results: Dict[str, CrawlPage] = {}
        self.robots_txt: Optional[Dict[str, Any]] = None
        
        # Configuração do cliente HTTP
        self.session: Optional[httpx.AsyncClient] = None
        self.sem: Optional[asyncio.Semaphore] = None

    async def _init_session(self) -> None:
        """Inicializa a sessão HTTP com configurações de segurança e performance.
        
        Esta função configura o cliente HTTP com:
        - Suporte a HTTP/1.1 e HTTP/2
        - Timeout personalizado
        - Limites de conexão
        - Verificação SSL configurável
        - Headers padrão
        - Cookies de sessão
        """
        try:
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
            transport = httpx.AsyncHTTPTransport(
                verify=ssl_context if self.verify_ssl else False,
                retries=3,  # Número de tentativas de reconexão
                http2=True,  # Habilita HTTP/2
                limits=limits
            )
            
            # Configuração do cliente HTTP
            self.session = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects,
                transport=transport,
                headers=DEFAULT_HEADERS.copy(),
                cookies=self.session_cookies,
                trust_env=False  # Ignora variáveis de ambiente como HTTP_PROXY
            )
            
            # Atualiza o user-agent
            if self.user_agent:
                self.session.headers["User-Agent"] = self.user_agent
                
            # Adiciona headers adicionais para evitar detecção
            self.session.headers.update({
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Upgrade-Insecure-Requests": "1"
            })
            
            logger.info("session_initialized", 
                      verify_ssl=self.verify_ssl, 
                      timeout=self.timeout,
                      max_redirects=self.max_redirects)
            
        except Exception as e:
            logger.error("session_initialization_error", 
                        error=str(e), 
                        exc_info=True)
            raise RuntimeError(f"Falha ao inicializar a sessão HTTP: {str(e)}") from e
            
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
            
        robots_url = f"{self.parsed_base_url.scheme.decode() if isinstance(self.parsed_base_url.scheme, (bytes, bytearray)) else self.parsed_base_url.scheme}://{self.base_host}/robots.txt"
        try:
            response = await self.session.get(robots_url)
            if response.status_code == 200 and response.text:
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(response.text.splitlines())
                self.robots = rp
                logger.info("robots_txt_parsed", url=robots_url)
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
        # Usa a URL base já normalizada
        initial_url = self.base_url_str
        await queue.put((initial_url, 0))
        logger.info("crawl_started", initial_url=initial_url, max_pages=self.max_pages, max_depth=self.max_depth)

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
        """Parseia uma URL e retorna um objeto URL do httpx.
        
        Args:
            url: URL a ser parseada (pode ser string, bytes ou qualquer objeto que possa ser convertido para string)
            
        Returns:
            httpx.URL: Objeto URL parseado
            
        Raises:
            ValueError: Se a URL for inválida ou não puder ser parseada
        """
        try:
            # Garante que a URL seja uma string
            if isinstance(url, bytes):
                url = url.decode('utf-8', errors='replace').strip()
            elif not isinstance(url, str):
                url = str(url).strip()
            else:
                url = url.strip()
                
            # Se a URL estiver vazia, levanta um erro
            if not url:
                raise ValueError("URL não pode ser vazia")
                
            # Remove espaços em branco e caracteres de controle
            url = ''.join(char for char in url if ord(char) >= 32 or char in '\t\n\r')
            
            # Remove caracteres de nova linha e tabulação
            url = url.replace('\n', '').replace('\r', '').replace('\t', '')
            
            # Adiciona o esquema se não existir
            if not url.startswith(('http://', 'https://')):
                # Se a URL começar com //, adiciona https:
                if url.startswith('//'):
                    url = f'https:{url}'
                # Se parecer um domínio ou IP, adiciona https://
                elif '://' not in url and ('.' in url or 'localhost' in url):
                    url = f'https://{url}'
                else:
                    # Se não for possível determinar o esquema, usa https por padrão
                    url = f'https://{url}'
            
            # Parseia a URL para garantir que é válida
            parsed = httpx.URL(url)
            
            # Garante que o host não está vazio
            if not parsed.host:
                raise ValueError(f"URL inválida: host não especificado em '{url}'")
                
            return parsed
            
        except Exception as e:
            logger.error("url_parse_error", url=url, error=str(e), exc_info=True)
            raise ValueError(f"URL inválida: {url} - {str(e)}") from e
    
    def _get_base_domain(self, hostname: Union[str, bytes]) -> str:
        """Extrai o domínio base de um hostname.
        
        Args:
            hostname: Hostname como string ou bytes
            
        Returns:
            str: Domínio base extraído
        """
        if isinstance(hostname, (bytes, bytearray)):
            hostname = hostname.decode("utf-8", "ignore")
        if not hostname:
            return ""
            
        # Remove porta se presente
        if ":" in hostname:
            hostname = hostname.split(":")[0]
            
        parts = hostname.split(".")
        # Se tiver menos de 3 partes, retorna o hostname completo
        if len(parts) <= 2:
            return hostname
            
        # Para domínios como .co.uk, .com.br, etc.
        tlds = ["co", "com", "org", "net", "gov", "edu", "mil"]
        if len(parts) > 2 and parts[-2] in tlds:
            return ".".join(parts[-3:])
            
        return ".".join(parts[-2:])
    
    def _is_same_domain(self, url: str) -> bool:
        """Verifica se uma URL pertence ao mesmo domínio do alvo.
        
        Args:
            url: URL a ser verificada
            
        Returns:
            bool: True se a URL pertencer ao mesmo domínio (ou subdomínio, se permitido)
        """
        try:
            # Parseia a URL para extrair o host
            parsed = self._parse_url(url)
            host = (parsed.host or b"").decode("utf-8")
            if not host:
                logger.warning("no_host_in_url", url=url)
                return False

            # Se não estivermos seguindo subdomínios, verifica se o host é exatamente o mesmo
            if not self.follow_subdomains:
                return host == self.base_host
                
            # Se estivermos seguindo subdomínios, verifica se o domínio base é o mesmo
            base = self.base_domain.lstrip(".")
            
            # Verifica se o host é exatamente o domínio base
            if host == base:
                return True
                
            # Verifica se o host termina com .domínio_base
            if host.endswith(f".{base}"):
                return True
                
            # Verifica se o domínio base do host é o mesmo do domínio base alvo
            return self._get_base_domain(host) == self.base_domain
            
        except Exception as e:
            logger.warning("domain_check_error", url=url, error=str(e), exc_info=True)
            return False
    
    def _normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        """Normaliza uma URL, resolvendo URLs relativas e removendo fragmentos.
        
        Args:
            url: URL a ser normalizada
            base_url: URL base para resolver URLs relativas (opcional)
            
        Returns:
            str: URL normalizada ou string vazia em caso de erro
        """
        try:
            # Se a URL for vazia, retorna vazio
            if not url or not isinstance(url, (str, bytes)):
                return ""
                
            # Converte para string se for bytes
            if isinstance(url, bytes):
                url = url.decode('utf-8', errors='replace')
                
            # Remove espaços em branco e caracteres de controle
            url = url.strip()
            url = ''.join(char for char in url if ord(char) >= 32 or char in '\t\n\r')
            
            # Remove fragmentos e espaços em branco
            url = url.split("#")[0].strip()
            if not url:
                return ""
                
            # Se for uma URL relativa e tivermos uma URL base, resolve em relação a ela
            if base_url and not url.startswith(('http://', 'https://', '//')):
                try:
                    # Remove parâmetros de consulta e fragmentos da URL base
                    base = str(base_url).split("?")[0].split("#")[0]
                    # Garante que a base termine com / se for um diretório
                    if not base.endswith("/"):
                        base = f"{base}/"
                    # Resolve a URL relativa
                    url = urljoin(base, url)
                except Exception as e:
                    logger.warning("url_join_error", base=base_url, url=url, error=str(e), exc_info=True)
                    return ""
            
            # Se a URL começar com //, adiciona o esquema
            if url.startswith("//"):
                url = f"https:{url}"
            
            # Se ainda não tiver esquema, adiciona https://
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            
            # Parseia a URL para normalização
            try:
                parsed = self._parse_url(url)
                
                # Remove parâmetros de rastreamento comuns
                if parsed.query:
                    query_params = []
                    for param in parsed.query.decode('utf-8', errors='replace').split('&'):
                        if '=' in param and any(t in param.lower() for t in ['utm_', 'ref=', 'source=', 'fbclid=', 'gclid=']):
                            continue
                        query_params.append(param)
                    
                    # Reconstrói a URL sem os parâmetros de rastreamento
                    if query_params:
                        parsed = parsed.copy_with(query='&'.join(query_params).encode('utf-8'))
                    else:
                        parsed = parsed.copy_with(query=None)
                
                # Remove barras finais desnecessárias
                path = parsed.path.decode('utf-8', errors='replace')
                if path.endswith('/'):
                    path = path.rstrip('/') or '/'
                    parsed = parsed.copy_with(path=path.encode('utf-8'))
                
                # Remove a porta padrão se for a porta 443 (HTTPS) ou 80 (HTTP)
                netloc = parsed.host.decode('utf-8', errors='replace')
                if ":443" in netloc and parsed.scheme == b'https':
                    netloc = netloc.replace(":443", "")
                    parsed = parsed.copy_with(host=netloc.encode('utf-8'))
                elif ":80" in netloc and parsed.scheme == b'http':
                    netloc = netloc.replace(":80", "")
                    parsed = parsed.copy_with(host=netloc.encode('utf-8'))
                
                # Remove www. se existir para normalização
                if netloc.startswith("www."):
                    netloc = netloc[4:]
                    parsed = parsed.copy_with(host=netloc.encode('utf-8'))
                
                return str(parsed)
                
            except Exception as e:
                logger.warning("url_parsing_error", url=url, error=str(e), exc_info=True)
                return ""
            
        except Exception as e:
            logger.warning("url_normalization_error", url=url, error=str(e), exc_info=True)
            return ""
    
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
        try:
            # Registra informações de depuração
            logger.debug("processing_response", 
                        url=url, 
                        status=response.status_code,
                        content_type=response.headers.get("content-type"),
                        content_length=len(response.content) if response.content else 0)
            
            # Cria o objeto da página com os dados básicos
            page = CrawlPage(
                url=url,
                status=response.status_code,
                redirect_chain=[(str(r.url), r.status_code) for r in response.history]
            )
            
            # Se não for uma resposta de sucesso, adiciona aos resultados e retorna
            if response.status_code >= 400:
                page.error = f"HTTP Error: {response.status_code}"
                self.results[url] = page
                logger.warning("http_error_response", 
                             url=url, 
                             status=response.status_code,
                             error=page.error)
                return
                
            # Obtém o tipo de conteúdo
            content_type = response.headers.get("content-type", "").lower()
            
            # Se não for HTML, adiciona aos resultados e retorna
            if not any(ct in content_type for ct in ["text/html", "application/xhtml+xml"]):
                self.results[url] = page
                logger.debug("non_html_response", 
                           url=url, 
                           content_type=content_type)
                return
                
            try:
                # Tenta decodificar o conteúdo da resposta
                try:
                    # Tenta decodificar como UTF-8 primeiro
                    html_content = response.text
                except UnicodeDecodeError:
                    # Se falhar, tenta com diferentes codificações comuns
                    encodings = ['latin-1', 'iso-8859-1', 'windows-1252', 'utf-8']
                    for encoding in encodings:
                        try:
                            html_content = response.content.decode(encoding, errors='replace')
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        # Se nenhuma codificação funcionar, usa replace para caracteres inválidos
                        html_content = response.content.decode('utf-8', errors='replace')
                
                # Parseia o HTML
                parser = HTMLParser(html_content)
                
                # Extrai o título da página
                title = parser.css_first("title")
                if title and hasattr(title, 'text'):
                    try:
                        page.title = title.text(strip=True)[:500]  # Limita o tamanho do título
                    except Exception as e:
                        logger.warning("title_extraction_error", url=url, error=str(e))
                        page.title = "[Título não disponível]"
                
                # Extrai os links da página
                try:
                    await self._extract_links(parser, url, depth, queue, page)
                except Exception as e:
                    logger.error("link_extraction_failed", 
                                url=url, 
                                error=str(e), 
                                exc_info=True)
                
                # Extrai os formulários da página
                try:
                    self._extract_forms(parser, page)
                except Exception as e:
                    logger.error("form_extraction_failed", 
                                url=url, 
                                error=str(e), 
                                exc_info=True)
                
                # Adiciona a página aos resultados
                self.results[url] = page
                
                # Log de sucesso
                logger.info("page_processed", 
                          url=url, 
                          status=response.status_code,
                          title=page.title[:100] if page.title else "",
                          links_count=len(page.links),
                          forms_count=len(page.forms))
                
            except Exception as e:
                error_msg = f"Error processing HTML content: {str(e)}"
                logger.error("html_processing_error", 
                            url=url, 
                            error=error_msg, 
                            exc_info=True)
                page.error = error_msg
                self.results[url] = page
                
        except Exception as e:
            error_msg = f"Unexpected error in _process_response: {str(e)}"
            logger.error("process_response_error", 
                        url=url, 
                        error=error_msg, 
                        exc_info=True)
            
            # Cria uma página de erro se ainda não existir
            if url not in self.results:
                self.results[url] = CrawlPage(
                    url=url,
                    status=response.status_code if 'response' in locals() else 0,
                    error=error_msg,
                    redirect_chain=[(str(r.url), r.status_code) for r in response.history] if 'response' in locals() else []
                )
    
    async def _extract_links(self, parser: HTMLParser, base_url: str, depth: int, queue: asyncio.Queue, page: CrawlPage) -> None:
        """Extrai links do HTML e os adiciona à fila de processamento.
        
        Args:
            parser: Objeto HTMLParser com o conteúdo da página
            base_url: URL base para resolver URLs relativas
            depth: Profundidade atual do rastreamento
            queue: Fila de URLs para processamento
            
        Este método:
        1. Extrai todos os links <a href> da página
        2. Filtra e normaliza as URLs
        3. Verifica se as URLs são válidas e seguras para rastreamento
        4. Adiciona as URLs válidas à fila de processamento
        """
        if depth >= self.max_depth:
            logger.debug("max_depth_reached", 
                        base_url=base_url, 
                        current_depth=depth,
                        max_depth=self.max_depth)
            return
            
        try:
            # Contadores para métricas
            total_links = 0
            valid_links = 0
            queued_links = 0
            
            # Extrai todos os links de uma vez para melhor desempenho
            for link in parser.css("a[href]"):
                try:
                    total_links += 1
                    href = link.attributes.get("href", "").strip()
                    
                    # Ignora links vazios, âncoras e javascript
                    if not href or href.startswith("#") or href.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "about:", "blob:")):
                        continue
                    
                    # Normaliza a URL
                    url = self._normalize_url(href, base_url)
                    if not url:
                        continue
                        
                    # Adiciona o link à lista de links da página
                    if page and url not in page.links:
                        page.links.append(url)
                        
                    # Verifica se a URL é válida e segura para rastreamento
                    if not self.is_valid_url(url):
                        continue
                        
                    valid_links += 1
                    
                    # Verifica se a URL já foi processada ou está na fila
                    if self.is_url_queued_or_processed(url, queue):
                        continue
                    
                    # Adiciona à fila de processamento
                    # Verifica se ainda não atingimos o limite de páginas
                    if len(self.results) + queue.qsize() < self.max_pages:
                        queue.put_nowait((url, depth + 1))
                        queued_links += 1
                        
                        # Log detalhado para depuração
                        logger.debug("link_queued",
                                    source_url=base_url,
                                    target_url=url,
                                    depth=depth,
                                    queue_size=queue.qsize())
                        
                        # Verifica se atingimos o limite de páginas
                        if len(self.results) + queue.qsize() >= self.max_pages:
                            logger.debug("max_pages_reached_during_extraction",
                                        base_url=base_url,
                                        max_pages=self.max_pages)
                            break
                        
                except asyncio.QueueFull:
                    logger.warning("queue_full_during_extraction",
                                 queue_size=queue.qsize(),
                                 max_pages=self.max_pages)
                    break
                    
                except Exception as e:
                    logger.warning("link_processing_error",
                                 href=href[:200] if href else "",
                                 base_url=base_url,
                                 error=str(e),
                                 exc_info=True)
            
            # Log de resumo da extração de links
            logger.debug("links_extraction_summary",
                        base_url=base_url,
                        total_links_processed=total_links,
                        valid_links=valid_links,
                        links_queued=queued_links,
                        queue_size=queue.qsize(),
                        visited_count=len(self.visited),
                        max_depth=self.max_depth,
                        current_depth=depth)
                        
        except Exception as e:
            logger.error("extract_links_error",
                       base_url=base_url,
                       error=str(e),
                       exc_info=True)
        
        # Verifica se devemos continuar processando
        if queue.qsize() == 0 and len(self.visited) > 0:
            logger.info("no_more_links_to_process",
                      base_url=base_url,
                      total_visited=len(self.visited),
                      max_pages=self.max_pages)
    
    def _extract_forms(self, parser: HTMLParser, page: CrawlPage) -> None:
        """Extrai formulários HTML da página para análise.
        
        Args:
            parser: Objeto HTMLParser com o conteúdo da página
            page: Objeto CrawlPage onde os formulários serão armazenados
            
        Este método extrai todos os formulários da página, incluindo:
        - Método (GET/POST)
        - URL de ação
        - Campos de entrada (inputs, textareas, selects)
        - Valores padrão
        - Atributos importantes (required, type, etc.)
        """
        try:
            forms = parser.css("form")
            logger.debug("extracting_forms", 
                       url=page.url, 
                       form_count=len(forms))
            
            for form in forms:
                try:
                    form_data = {
                        "method": form.attributes.get("method", "GET").upper(),
                        "enctype": form.attributes.get("enctype", "application/x-www-form-urlencoded"),
                        "inputs": []
                    }
                    
                    # Obtém a ação do formulário
                    action = form.attributes.get("action", "").strip()
                    if action:
                        form_data["action"] = self._normalize_url(action, page.url)
                    else:
                        form_data["action"] = page.url
                    
                    # Extrai os campos do formulário
                    self._extract_form_fields(form, form_data)
                    
                    # Extrai botões de submit
                    self._extract_buttons(form, form_data)
                    
                    # Verifica se o formulário tem campos relevantes
                    if form_data["inputs"]:
                        # Adiciona metadados adicionais
                        form_data["id"] = form.attributes.get("id", "")
                        form_data["class"] = form.attributes.get("class", "").split()
                        
                        # Adiciona o formulário à página
                        page.forms.append(form_data)
                        
                        logger.debug("form_extracted",
                                   url=page.url,
                                   form_action=form_data["action"],
                                   method=form_data["method"],
                                   input_count=len(form_data["inputs"]))
                    
                except Exception as e:
                    logger.error("form_processing_error",
                               url=page.url,
                               error=str(e),
                               exc_info=True)
            
            # Log de resumo
            if page.forms:
                logger.info("forms_extracted",
                          url=page.url,
                          total_forms=len(page.forms),
                          total_inputs=sum(len(f["inputs"]) for f in page.forms))
                        
        except Exception as e:
            logger.error("form_extraction_error",
                       url=page.url if hasattr(page, 'url') else 'unknown',
                       error=str(e),
                       exc_info=True)
    
    def _extract_form_fields(self, form: Any, form_data: Dict[str, Any]) -> None:
        """Extrai campos de um formulário HTML.
        
        Args:
            form: Elemento HTML do formulário
            form_data: Dicionário onde os campos serão armazenados
        """
        # Processa inputs padrão
        for input_elem in form.css("input, textarea, select"):
            try:
                input_type = input_elem.attributes.get("type", "text").lower()
                input_name = input_elem.attributes.get("name", "")
                
                # Ignora inputs sem nome, a menos que sejam especiais
                if not input_name and input_type not in ["submit", "button", "image"]:
                    continue
                
                # Cria o objeto de input
                input_data = {
                    "tag": input_elem.tag.lower(),
                    "type": input_type,
                    "name": input_name,
                    "value": input_elem.attributes.get("value", ""),
                    "required": "required" in input_elem.attributes,
                    "disabled": "disabled" in input_elem.attributes,
                    "readonly": "readonly" in input_elem.attributes,
                    "id": input_elem.attributes.get("id", ""),
                    "class": input_elem.attributes.get("class", "").split(),
                    "placeholder": input_elem.attributes.get("placeholder", ""),
                    "pattern": input_elem.attributes.get("pattern", ""),
                    "minlength": input_elem.attributes.get("minlength", ""),
                    "maxlength": input_elem.attributes.get("maxlength", ""),
                    "autocomplete": input_elem.attributes.get("autocomplete", ""),
                }
                
                # Processa tipos especiais de input
                if input_elem.tag.lower() == "select":
                    input_data["options"] = [
                        {
                            "value": option.attributes.get("value", ""),
                            "text": option.text.strip(),
                            "selected": "selected" in option.attributes
                        }
                        for option in input_elem.css("option")
                    ]
                elif input_type == "radio" or input_type == "checkbox":
                    input_data["checked"] = "checked" in input_elem.attributes
                
                form_data["inputs"].append(input_data)
                
            except Exception as e:
                logger.warning("input_processing_error",
                             tag=input_elem.tag if hasattr(input_elem, 'tag') else 'unknown',
                             error=str(e))
    
    def _extract_buttons(self, form: Any, form_data: Dict[str, Any]) -> None:
        """Extrai botões de um formulário HTML.
        
        Args:
            form: Elemento HTML do formulário
            form_data: Dicionário onde os botões serão armazenados
        """
        # Adiciona botões de submit como inputs especiais
        for button in form.css("button, input[type='submit'], input[type='button'], input[type='image']"):
            try:
                button_type = button.attributes.get("type", "submit" if button.tag == "button" else button.attributes.get("type", "")).lower()
                button_name = button.attributes.get("name", "")
                button_value = button.attributes.get("value", "")
                
                # Se for um botão sem nome, usa o texto como valor
                if not button_name and button.tag == "button":
                    button_value = button.text.strip() or button_value
                
                button_data = {
                    "tag": button.tag,
                    "type": button_type,
                    "name": button_name,
                    "value": button_value,
                    "id": button.attributes.get("id", ""),
                    "class": button.attributes.get("class", "").split(),
                }
                
                form_data["inputs"].append(button_data)
                
            except Exception as e:
                logger.warning("button_processing_error",
                             tag=button.tag if hasattr(button, 'tag') else 'unknown',
                             error=str(e))
    
    def is_url_queued_or_processed(self, url: str, queue: Optional[asyncio.Queue] = None) -> bool:
        """Verifica se uma URL já foi processada ou está na fila de processamento.
        
        Args:
            url: URL a ser verificada
            queue: Fila de processamento (opcional)
            
        Returns:
            bool: True se a URL já foi processada ou está na fila
        """
        # Verifica se a URL está na lista de visitadas
        if url in self.visited:
            return True
            
        # Verifica se a URL está nos resultados
        if url in self.results:
            return True
            
        # Verifica se a URL está na fila de processamento
        if queue is not None:
            # Cria uma lista temporária para armazenar os itens da fila
            items = []
            
            # Esvazia a fila temporariamente
            while not queue.empty():
                try:
                    item = queue.get_nowait()
                    items.append(item)
                    # Verifica se a URL atual está na fila
                    if item[0] == url:
                        # Recoloca os itens na fila
                        for i in items:
                            queue.put_nowait(i)
                        return True
                except asyncio.QueueEmpty:
                    break
            
            # Recoloca os itens na fila
            for item in items:
                queue.put_nowait(item)
        
        return False
    
    def is_valid_url(self, url: str) -> bool:
        """Verifica se uma URL é válida e segura para rastreamento.
        
        Args:
            url: URL a ser validada
            
        Returns:
            bool: True se a URL for válida e segura para rastreamento
        """
        try:
            # Parseia a URL para verificar se é válida
            parsed = self._parse_url(url)
            
            # Verifica o esquema
            if parsed.scheme not in (b'http', b'https'):
                return False
                
            # Obtém o host como string
            host = (parsed.host or b'').decode('utf-8')
            if not host:
                return False
                
            # Verifica se o domínio é permitido
            if not self._is_same_domain(url):
                return False
                
            # Verifica o robots.txt se estiver habilitado
            if self.respect_robots and self.robots:
                # Obtém o user-agent da sessão ou usa um padrão
                ua = (self.session.headers.get("User-Agent") if self.session else None) or "*"
                if not self.robots.can_fetch(ua, url):
                    logger.debug("blocked_by_robots", url=url)
                    return False
                    
            return True
            
        except Exception as e:
            logger.debug("invalid_url", url=url, error=str(e))
            return False
    
    async def close(self) -> None:
        """Fecha a sessão HTTP."""
        if self.session:
            await self.session.aclose()
            self.session = None

    async def __aenter__(self) -> 'WebCrawler':
        """Método de entrada para gerenciamento de contexto assíncrono.
        
        Este método é chamado quando o bloco 'async with' é iniciado.
        Inicializa a sessão HTTP automaticamente.
        
        Returns:
            WebCrawler: A própria instância do WebCrawler
            
        Example:
            async with WebCrawler("https://example.com") as crawler:
                results = await crawler.crawl()
        """
        await self._init_session()
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]], 
                       exc_val: Optional[BaseException], 
                       exc_tb: Optional[types.TracebackType]) -> None:
        """Método de saída para gerenciamento de contexto assíncrono.
        
        Este método é chamado quando o bloco 'async with' é finalizado,
        garantindo que os recursos sejam liberados corretamente.
        
        Args:
            exc_type: Tipo da exceção, se ocorreu alguma
            exc_val: Instância da exceção, se ocorreu alguma
            exc_tb: Objeto de traceback, se ocorreu alguma exceção
        """
        await self.close()


# Para compatibilidade com código existente
__all__ = ["WebCrawler", "CrawlPage"]
