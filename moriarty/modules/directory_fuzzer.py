"""Directory Fuzzer avançado para descoberta de diretórios e arquivos."""
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

import httpx
import structlog
from rich.console import Console
from rich.progress import Progress

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class FuzzResult:
    """Resultado de fuzzing."""
    url: str
    status_code: int
    size: int
    redirect_url: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None


class DirectoryFuzzer:
    """
    Directory/File fuzzer avançado.
    
    Features:
    - Wordlists (small, medium, large)
    - Fuzzing de extensões
    - Recursive fuzzing
    - Status code filtering
    - Rate limiting
    - Stealth mode integration
    - Smart filtering (tamanho, tipo)
    """
    
    # Wordlists embutidas
    SMALL_WORDLIST = [
        'admin', 'administrator', 'login', 'wp-admin', 'dashboard', 'panel',
        'api', 'v1', 'v2', 'test', 'dev', 'staging', 'backup', 'old',
        'config', 'conf', 'settings', 'setup', 'install', 'debug',
        'logs', 'log', 'tmp', 'temp', 'cache', 'uploads', 'upload',
        'files', 'file', 'download', 'downloads', 'assets', 'static',
        'images', 'img', 'css', 'js', 'scripts', 'includes', 'inc',
        'vendor', 'node_modules', 'lib', 'libs', 'bin', 'src', 'source',
        'public', 'private', 'secure', 'backup', 'backups', 'db', 'database',
        'sql', 'data', 'users', 'user', 'accounts', 'account', 'profile',
        'profiles', 'settings', 'preferences', 'config', 'configuration',
        'admin', 'administrator', 'root', 'superuser', 'sudo', 'manager',
        'staff', 'employee', 'member', 'members', 'reports', 'report',
        'analytics', 'stats', 'statistics', 'monitor', 'monitoring',
        'metrics', 'health', 'status', 'info', 'information', 'about',
        'contact', 'support', 'help', 'docs', 'documentation', 'api-docs',
        'swagger', 'graphql', 'rest', 'soap', 'xml-rpc', 'json-rpc'
    ]
    
    COMMON_EXTENSIONS = [
        '', '.html', '.php', '.asp', '.aspx', '.jsp', '.jspx',
        '.txt', '.xml', '.json', '.yml', '.yaml', '.conf', '.config',
        '.bak', '.backup', '.old', '.orig', '.tmp', '.temp', '.swp',
        '.log', '.sql', '.db', '.sqlite', '.mdb',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.env', '.git', '.svn', '.hg', '.DS_Store',
    ]
    
    INTERESTING_STATUS = [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500]
    
    def __init__(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        wordlist_file: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        max_depth: int = 2,
        threads: int = 50,
        timeout: float = 5.0,
        status_filter: Optional[List[int]] = None,
        size_filter: Optional[int] = None,
        stealth_level: int = 0,
    ):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist or self._load_wordlist(wordlist_file)
        self.extensions = extensions or self.COMMON_EXTENSIONS
        self.recursive = recursive
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.status_filter = status_filter or self.INTERESTING_STATUS
        self.size_filter = size_filter
        self.stealth_level = stealth_level
        
        self.results: List[FuzzResult] = []
        self.found_dirs: Set[str] = set()
        self.baseline_sizes: dict = {}
    
    def _load_wordlist(self, wordlist_file: Optional[str]) -> List[str]:
        """Carrega wordlist de arquivo ou usa embutida."""
        if wordlist_file and Path(wordlist_file).exists():
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        
        # Usa wordlist pequena embutida
        return self.SMALL_WORDLIST
    
    async def fuzz(self) -> List[FuzzResult]:
        """Executa fuzzing."""
        logger.info("fuzzer.start", url=self.base_url, words=len(self.wordlist))
        
        # Calibração inicial (baseline)
        await self._calibrate()
        
        # Fuzz inicial
        await self._fuzz_directory(self.base_url, depth=0)
        
        logger.info("fuzzer.complete", results=len(self.results))
        return self.results
    
    async def _calibrate(self):
        """Calibra fuzzer com requests de baseline."""
        console.print("[dim]Calibrating fuzzer...[/dim]")
        
        baseline_paths = [
            f"/{self._generate_random_string(10)}",
            f"/{self._generate_random_string(15)}.{self._generate_random_string(3)}",
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            for path in baseline_paths:
                try:
                    response = await client.get(f"{self.base_url}{path}")
                    self.baseline_sizes[response.status_code] = len(response.content)
                except:
                    pass
        
        logger.debug("fuzzer.calibrated", baseline_sizes=self.baseline_sizes)
    
    async def _fuzz_directory(self, base_url: str, depth: int):
        """Fuzz um diretório."""
        if depth > self.max_depth:
            return
        
        # Cria lista de URLs para testar
        urls_to_test = []
        for word in self.wordlist:
            for ext in self.extensions:
                url = f"{base_url}/{word}{ext}"
                urls_to_test.append(url)
        
        # Semaphore para controlar concorrência
        semaphore = asyncio.Semaphore(self.threads)
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False
        ) as client:
            
            with Progress() as progress:
                task_id = progress.add_task(
                    f"[cyan]Fuzzing {base_url.split('/')[-1] or 'root'}...",
                    total=len(urls_to_test)
                )
                
                tasks = [
                    self._test_url(client, semaphore, url, progress, task_id)
                    for url in urls_to_test
                ]
                
                await asyncio.gather(*tasks, return_exceptions=True)
        
        # Recursive fuzzing em diretórios encontrados
        if self.recursive and depth < self.max_depth:
            for dir_url in list(self.found_dirs):
                if dir_url.startswith(base_url):
                    await self._fuzz_directory(dir_url, depth + 1)
    
    async def _test_url(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
        progress: Progress,
        task_id: int
    ):
        """Testa uma URL."""
        async with semaphore:
            try:
                # Stealth delay
                if self.stealth_level > 0:
                    await asyncio.sleep(self.stealth_level * 0.1)
                
                headers = self._get_headers()
                response = await client.get(url, headers=headers)
                
                progress.update(task_id, advance=1)
                
                # Filtra por status code
                if response.status_code not in self.status_filter:
                    return
                
                # Filtra por tamanho (baseline)
                content_size = len(response.content)
                if self._is_baseline_size(response.status_code, content_size):
                    return
                
                # Filtra por tamanho customizado
                if self.size_filter and content_size > self.size_filter:
                    return
                
                # Cria resultado
                result = FuzzResult(
                    url=url,
                    status_code=response.status_code,
                    size=content_size,
                    redirect_url=response.headers.get('location'),
                    server=response.headers.get('server'),
                    content_type=response.headers.get('content-type'),
                )
                
                self.results.append(result)
                
                # Se é diretório, adiciona para recursive fuzzing
                if response.status_code in [301, 302, 307, 308]:
                    if result.redirect_url and result.redirect_url.endswith('/'):
                        self.found_dirs.add(result.redirect_url.rstrip('/'))
                elif url.endswith('/'):
                    self.found_dirs.add(url.rstrip('/'))
                
                # Log descoberta
                color = self._get_status_color(response.status_code)
                console.print(
                    f"  [{color}]{response.status_code}[/{color}] "
                    f"[cyan]{url.replace(self.base_url, '')}[/cyan] "
                    f"[dim]({content_size} bytes)[/dim]"
                )
                
                logger.info(
                    "fuzzer.found",
                    url=url,
                    status=response.status_code,
                    size=content_size
                )
                
            except httpx.TimeoutException:
                pass
            except Exception as e:
                logger.debug("fuzzer.error", url=url, error=str(e))
    
    def _is_baseline_size(self, status_code: int, size: int) -> bool:
        """Verifica se tamanho é baseline (falso positivo)."""
        baseline = self.baseline_sizes.get(status_code)
        if baseline is None:
            return False
        
        # Permite variação de 5%
        tolerance = baseline * 0.05
        return abs(size - baseline) <= tolerance
    
    def _get_headers(self) -> dict:
        """Retorna headers com stealth."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }
        
        if self.stealth_level > 1:
            headers.update({
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
            })
        
        return headers
    
    def _get_status_color(self, status_code: int) -> str:
        """Retorna cor baseada no status code."""
        if status_code < 300:
            return "green"
        elif status_code < 400:
            return "yellow"
        elif status_code == 401 or status_code == 403:
            return "red"
        elif status_code < 500:
            return "blue"
        else:
            return "magenta"
    
    def _generate_random_string(self, length: int) -> str:
        """Gera string aleatória."""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def export(self, output: str):
        """Exporta resultados."""
        import json
        
        data = [
            {
                'url': r.url,
                'status_code': r.status_code,
                'size': r.size,
                'redirect_url': r.redirect_url,
                'server': r.server,
                'content_type': r.content_type,
            }
            for r in self.results
        ]
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info("fuzzer.export", file=output, count=len(self.results))


__all__ = ["DirectoryFuzzer", "FuzzResult"]
