from __future__ import annotations

import re
from typing import Any, List, Optional

from selectolax.parser import HTMLParser

from ..dsl.schema import SelectorSpec


class ParserError(Exception):
    """Erro ao fazer parsing."""


class HTMLExtractor:
    """Extrai dados de HTML usando selectores."""

    def __init__(self, html: str) -> None:
        self._parser = HTMLParser(html)
        self._raw_html = html

    def extract(self, selector: SelectorSpec) -> Optional[str]:
        """Extrai um único valor usando um seletor."""
        if selector.type == "css":
            return self._extract_css(selector)
        elif selector.type == "xpath":
            # selectolax não suporta XPath nativamente, fallback para lxml se necessário
            return self._extract_xpath(selector)
        elif selector.type == "regex":
            return self._extract_regex(selector)
        elif selector.type == "json":
            # JSON path sobre o HTML bruto
            return None
        return None

    def extract_all(self, selector: SelectorSpec) -> List[str]:
        """Extrai múltiplos valores."""
        if selector.type == "css":
            return self._extract_css_all(selector)
        elif selector.type == "regex":
            return self._extract_regex_all(selector)
        return []

    def exists(self, selector: SelectorSpec) -> bool:
        """Verifica se um seletor encontra algo."""
        result = self.extract(selector)
        return result is not None and len(result) > 0

    def _extract_css(self, selector: SelectorSpec) -> Optional[str]:
        """Extrai usando CSS selector."""
        node = self._parser.css_first(selector.query)
        if node is None:
            return None

        if selector.attribute:
            return node.attributes.get(selector.attribute)
        
        return node.text(strip=True)

    def _extract_css_all(self, selector: SelectorSpec) -> List[str]:
        """Extrai todos os matches de um CSS selector."""
        nodes = self._parser.css(selector.query)
        results: List[str] = []

        for node in nodes:
            if selector.attribute:
                value = node.attributes.get(selector.attribute)
                if value:
                    results.append(value)
            else:
                text = node.text(strip=True)
                if text:
                    results.append(text)

        return results

    def _extract_xpath(self, selector: SelectorSpec) -> Optional[str]:
        """Extrai usando XPath (requer lxml)."""
        try:
            from lxml import etree, html
        except ImportError:
            raise ParserError("lxml required for XPath selectors")

        try:
            tree = html.fromstring(self._raw_html)
            result = tree.xpath(selector.query)
            
            if not result:
                return None
            
            if isinstance(result, list) and len(result) > 0:
                element = result[0]
                if selector.attribute and hasattr(element, "get"):
                    return element.get(selector.attribute)
                if hasattr(element, "text"):
                    return element.text
                return str(element)
            
            return str(result)
        except Exception:
            return None

    def _extract_regex(self, selector: SelectorSpec) -> Optional[str]:
        """Extrai usando regex."""
        pattern = re.compile(selector.query, re.IGNORECASE | re.DOTALL)
        match = pattern.search(self._raw_html)
        
        if match:
            group = selector.group if selector.group is not None else 0
            try:
                return match.group(group)
            except IndexError:
                return None
        
        return None

    def _extract_regex_all(self, selector: SelectorSpec) -> List[str]:
        """Extrai todos os matches de regex."""
        pattern = re.compile(selector.query, re.IGNORECASE | re.DOTALL)
        matches = pattern.finditer(self._raw_html)
        
        results: List[str] = []
        group = selector.group if selector.group is not None else 0
        
        for match in matches:
            try:
                value = match.group(group)
                if value:
                    results.append(value)
            except IndexError:
                continue
        
        return results


__all__ = ["HTMLExtractor", "ParserError"]
