"""Crawler HTTP leve focado em enumeração de rotas e formulários."""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, TYPE_CHECKING

import httpx
from selectolax.parser import HTMLParser
import structlog

if TYPE_CHECKING:  # pragma: no cover - apenas para type hints
    from moriarty.modules.stealth_mode import StealthMode

logger = structlog.get_logger(__name__)


@dataclass
class CrawlPage:
    url: str
    status: int
    title: Optional[str] = None
    forms: List[Dict[str, str]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)


class WebCrawler:
    """Crawler simples limitado a um domínio, ideal para pré-enumeração."""

    def __init__(
        self,
        base_url: str,
        max_pages: int = 100,
        max_depth: int = 2,
        concurrency: int = 10,
        follow_subdomains: bool = False,
        user_agent: str = "Mozilla/5.0 (Moriarty Recon)",
        stealth: Optional["StealthMode"] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.follow_subdomains = follow_subdomains
        self.visited: Set[str] = set()
        self.results: Dict[str, CrawlPage] = {}
        self.stealth = stealth
        self.user_agent = user_agent

        effective_concurrency = concurrency
        if self.stealth and getattr(self.stealth.config, "timing_randomization", False):
            # Reduz concorrência para modos stealth altos
            effective_concurrency = max(2, min(concurrency, int(concurrency / (self.stealth.level or 1))))

        self.sem = asyncio.Semaphore(effective_concurrency)
        self.session = httpx.AsyncClient(timeout=10.0, follow_redirects=True)

        parsed = httpx.URL(self.base_url)
        self._host = parsed.host
        self._scheme = parsed.scheme

    async def close(self) -> None:
        await self.session.aclose()

    async def crawl(self) -> Dict[str, CrawlPage]:
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put((self.base_url, 0))

        async def worker():
            while True:
                try:
                    url, depth = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if len(self.results) >= self.max_pages or depth > self.max_depth:
                    continue
                if url in self.visited:
                    continue
                self.visited.add(url)
                await self._fetch(url, depth, queue)

        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        await asyncio.gather(*workers)
        return self.results

    async def _fetch(self, url: str, depth: int, queue: asyncio.Queue) -> None:
        async with self.sem:
            try:
                await self._stealth_delay()
                response = await self.session.get(url, headers=self._build_headers())
            except Exception as exc:
                logger.debug("crawler.fetch.error", url=url, error=str(exc))
                return

        page = CrawlPage(url=url, status=response.status_code)
        if response.status_code >= 400 or not response.headers.get("content-type", "").startswith("text"):
            self.results[url] = page
            return

        parser = HTMLParser(response.text)
        title = parser.css_first("title")
        page.title = title.text(strip=True) if title else None

        # Forms
        for form in parser.css("form"):
            action = form.attributes.get("action", url)
            method = form.attributes.get("method", "GET").upper()
            inputs = [inp.attributes.get("name") for inp in form.css("input") if inp.attributes.get("name")]
            page.forms.append(
                {
                    "action": action,
                    "method": method,
                    "inputs": ",".join(inputs),
                }
            )

        # Links
        links: Set[str] = set()
        for anchor in parser.css("a"):
            href = anchor.attributes.get("href")
            if not href:
                continue
            href = href.strip()
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            absolute = httpx.URL(href, base=httpx.URL(url)).human_repr()
            if not self._should_follow(absolute):
                continue
            links.add(absolute)
            if absolute not in self.visited and len(self.results) < self.max_pages:
                await queue.put((absolute, depth + 1))
        page.links = sorted(links)
        self.results[url] = page

    def _should_follow(self, url: str) -> bool:
        parsed = httpx.URL(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not self.follow_subdomains and parsed.host != self._host:
            return False
        if not parsed.host.endswith(self._host):
            return False
        return True

    def _build_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if self.stealth:
            stealth_headers = self.stealth.get_random_headers()
            headers.update(stealth_headers)
            headers.setdefault("User-Agent", stealth_headers.get("User-Agent", self.user_agent))
        return headers

    async def _stealth_delay(self) -> None:
        if not self.stealth:
            return
        config = getattr(self.stealth, "config", None)
        if not config or not getattr(config, "timing_randomization", False):
            return
        await asyncio.sleep(random.uniform(0.05, 0.2) * max(1, self.stealth.level))


__all__ = ["WebCrawler", "CrawlPage"]
