from __future__ import annotations

import hashlib
from dataclasses import dataclass
from time import perf_counter
from typing import Any, Dict, List, Optional

import httpx
import structlog

from ..dsl.schema import TemplateSpec
from ..parsers.html_parser import HTMLExtractor

logger = structlog.get_logger(__name__)


@dataclass(slots=True)
class ExecutionResult:
    """Resultado da execução de um template."""

    site: str
    url: str
    exists: bool
    confidence: float
    extracted: Dict[str, Any]
    page_hash: str
    latency_ms: float
    status_code: int
    error: Optional[str] = None


class TemplateExecutor:
    """Executa templates contra alvos."""

    def __init__(
        self,
        timeout: float = 8.0,
        user_agent: Optional[str] = None,
        cookie_store: Optional[Dict[str, httpx.Cookies]] = None,
    ) -> None:
        self._timeout = timeout
        self._user_agent = user_agent or "Moriarty/0.1.0 (OSINT Client)"
        self._cookie_store = cookie_store if cookie_store is not None else {}

    async def execute(
        self, template: TemplateSpec, variables: Dict[str, str]
    ) -> ExecutionResult:
        """Executa um template com as variáveis fornecidas."""
        start = perf_counter()
        
        # Renderiza URL
        url = template.url_template.format(**variables)
        
        logger.info(
            "template.execute.start",
            site=template.site,
            url=url,
            method=template.method,
        )

        # Prepara headers
        headers = {
            "User-Agent": self._user_agent,
            **template.headers,
        }

        target_host = httpx.URL(url).host
        cookies = self._cookie_store.get(target_host)

        request_body = None
        request_json = None
        if isinstance(template.body, dict):
            # Permite templates explicitarem JSON ou form-encoded
            if template.method.upper() == "POST" and template.headers.get("Content-Type", "").lower() == "application/x-www-form-urlencoded":
                request_body = template.body
            else:
                request_json = template.body
        elif template.body is not None:
            request_body = template.body

        # Faz requisição
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                http2=True,
                cookies=cookies,
            ) as client:
                if template.method.upper() == "GET":
                    response = await client.get(url, headers=headers)
                elif template.method.upper() == "HEAD":
                    response = await client.head(url, headers=headers)
                elif template.method.upper() == "POST":
                    response = await client.post(url, headers=headers, json=request_json, data=request_body)
                else:
                    response = await client.request(
                        template.method.upper(),
                        url,
                        headers=headers,
                        json=request_json,
                        data=request_body,
                    )

                # Armazena cookies retornados
                if response.cookies:
                    merged = httpx.Cookies()
                    if cookies:
                        for cookie in cookies.jar:
                            merged.set(cookie[0], cookie[1], domain=cookie[2]["domain"], path=cookie[2]["path"])
                    for cookie in response.cookies.jar:
                        merged.set(cookie[0], cookie[1], domain=cookie[2]["domain"], path=cookie[2]["path"])
                    self._cookie_store[target_host] = merged

            status_code = response.status_code
            html = response.text
            
        except Exception as exc:
            latency_ms = (perf_counter() - start) * 1000
            logger.warning(
                "template.execute.error",
                site=template.site,
                url=url,
                error=str(exc),
                latency_ms=round(latency_ms, 2),
            )
            return ExecutionResult(
                site=template.site,
                url=url,
                exists=False,
                confidence=0.0,
                extracted={},
                page_hash="",
                latency_ms=latency_ms,
                status_code=0,
                error=str(exc),
            )

        # Parse HTML
        extractor = HTMLExtractor(html)
        
        # Verifica existência
        exists = self._check_exists(extractor, template)
        
        # Extrai dados
        extracted = self._extract_data(extractor, template)
        
        # Calcula hash da página
        page_hash = hashlib.sha256(html.encode("utf-8")).hexdigest()[:16]
        
        # Calcula confidence
        confidence = self._calculate_confidence(exists, extracted, template, status_code)
        
        latency_ms = (perf_counter() - start) * 1000
        
        logger.info(
            "template.execute.success",
            site=template.site,
            url=url,
            exists=exists,
            confidence=confidence,
            status=status_code,
            latency_ms=round(latency_ms, 2),
        )

        return ExecutionResult(
            site=template.site,
            url=url,
            exists=exists,
            confidence=confidence,
            extracted=extracted,
            page_hash=page_hash,
            latency_ms=latency_ms,
            status_code=status_code,
        )

    def _check_exists(self, extractor: HTMLExtractor, template: TemplateSpec) -> bool:
        """Verifica se o perfil existe."""
        # Se encontrar "not found", não existe
        for selector in template.not_found_selectors:
            if extractor.exists(selector):
                return False
        
        # Se não tiver "exists" selectors, assume que existe se status 200
        if not template.exists_selectors:
            return True
        
        # Precisa encontrar pelo menos um "exists" selector
        for selector in template.exists_selectors:
            if extractor.exists(selector):
                return True
        
        return False

    def _extract_data(
        self, extractor: HTMLExtractor, template: TemplateSpec
    ) -> Dict[str, Any]:
        """Extrai dados usando extractors."""
        data: Dict[str, Any] = {}
        
        for ext in template.extractors:
            value = extractor.extract(ext.selector)
            
            if value is None and ext.required:
                value = ext.default
            
            if value is not None:
                data[ext.name] = value
        
        return data

    def _calculate_confidence(
        self,
        exists: bool,
        extracted: Dict[str, Any],
        template: TemplateSpec,
        status_code: int,
    ) -> float:
        """Calcula confidence score (0.0 - 1.0)."""
        if not exists:
            return 0.0
        
        if status_code != 200:
            return 0.3
        
        # Base confidence
        confidence = 0.7
        
        # Aumenta se extraiu dados
        if extracted:
            confidence += 0.2 * (len(extracted) / max(len(template.extractors), 1))
        
        # Aumenta se tem "exists" selectors
        if template.exists_selectors:
            confidence += 0.1
        
        return min(confidence, 1.0)


__all__ = ["TemplateExecutor", "ExecutionResult"]
