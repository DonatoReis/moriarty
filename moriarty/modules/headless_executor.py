"""Executor headless para sites que requerem JavaScript."""
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HeadlessResult:
    """Resultado de execução headless."""
    url: str
    html: str
    status_code: int
    screenshot: Optional[bytes] = None
    console_logs: List[str] = None
    network_requests: List[Dict[str, Any]] = None


class HeadlessExecutor:
    """
    Executor headless usando Playwright.
    
    Para sites que requerem JavaScript para renderizar conteúdo.
    """
    
    def __init__(
        self,
        timeout: float = 30.0,
        headless: bool = True,
        user_agent: Optional[str] = None,
    ):
        self._timeout = timeout
        self._headless = headless
        self._user_agent = user_agent
        self._playwright = None
        self._browser = None
    
    async def initialize(self):
        """Inicializa Playwright e browser."""
        try:
            from playwright.async_api import async_playwright
            
            logger.info("headless.init.start")
            
            self._playwright = await async_playwright().start()
            
            # Lança browser (Chromium por padrão)
            self._browser = await self._playwright.chromium.launch(
                headless=self._headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            
            logger.info("headless.init.complete")
            
        except ImportError:
            logger.error("headless.init.error", error="Playwright not installed. Run: pip install playwright && playwright install chromium")
            raise
    
    async def execute(
        self,
        url: str,
        wait_for: Optional[str] = None,
        screenshot: bool = False,
    ) -> Optional[HeadlessResult]:
        """
        Executa uma página com headless browser.
        
        Args:
            url: URL para visitar
            wait_for: Seletor CSS para aguardar antes de extrair
            screenshot: Se deve capturar screenshot
        """
        if not self._browser:
            await self.initialize()
        
        logger.info("headless.execute.start", url=url)
        
        try:
            # Cria contexto isolado
            context = await self._browser.new_context(
                user_agent=self._user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                viewport={"width": 1920, "height": 1080},
            )
            
            page = await context.new_page()
            
            # Captura console logs
            console_logs = []
            page.on("console", lambda msg: console_logs.append(msg.text))
            
            # Captura network requests
            network_requests = []
            
            def handle_request(request):
                network_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                })
            
            page.on("request", handle_request)
            
            # Navega
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self._timeout * 1000)
            
            # Aguarda seletor específico se fornecido
            if wait_for:
                try:
                    await page.wait_for_selector(wait_for, timeout=5000)
                except Exception:
                    logger.warning("headless.wait_for.timeout", selector=wait_for)
            
            # Aguarda JavaScript render
            await page.wait_for_load_state("networkidle", timeout=10000)
            
            # Extrai HTML
            html = await page.content()
            
            # Screenshot opcional
            screenshot_data = None
            if screenshot:
                screenshot_data = await page.screenshot(full_page=True)
            
            status_code = response.status if response else 0
            
            await context.close()
            
            logger.info("headless.execute.complete", url=url, status=status_code, html_len=len(html))
            
            return HeadlessResult(
                url=url,
                html=html,
                status_code=status_code,
                screenshot=screenshot_data,
                console_logs=console_logs,
                network_requests=network_requests,
            )
            
        except Exception as e:
            logger.error("headless.execute.error", url=url, error=str(e))
            return None
    
    async def close(self):
        """Fecha browser e Playwright."""
        if self._browser:
            await self._browser.close()
        
        if self._playwright:
            await self._playwright.stop()
        
        logger.info("headless.closed")


class HeadlessPool:
    """Pool de browsers headless para uso concorrente."""
    
    def __init__(self, pool_size: int = 3, timeout: float = 30.0):
        self._pool_size = pool_size
        self._timeout = timeout
        self._executors: List[HeadlessExecutor] = []
        self._semaphore = asyncio.Semaphore(pool_size)
    
    async def initialize(self):
        """Inicializa pool de executors."""
        logger.info("headless.pool.init", size=self._pool_size)
        
        for _ in range(self._pool_size):
            executor = HeadlessExecutor(timeout=self._timeout)
            await executor.initialize()
            self._executors.append(executor)
        
        logger.info("headless.pool.ready", size=self._pool_size)
    
    async def execute(self, url: str, **kwargs) -> Optional[HeadlessResult]:
        """Executa usando um executor do pool."""
        async with self._semaphore:
            # Pega próximo executor disponível (round-robin simplificado)
            executor = self._executors[0]
            return await executor.execute(url, **kwargs)
    
    async def close(self):
        """Fecha todos os executors."""
        for executor in self._executors:
            await executor.close()
        
        self._executors.clear()
        logger.info("headless.pool.closed")


__all__ = [
    "HeadlessExecutor",
    "HeadlessPool",
    "HeadlessResult",
]
