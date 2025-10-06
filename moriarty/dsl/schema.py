from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class SelectorSpec(BaseModel):
    """Define como extrair dados de uma resposta."""

    type: Literal["css", "xpath", "json", "regex"] = "css"
    query: str
    attribute: Optional[str] = None  # Para CSS/XPath: qual atributo extrair
    group: Optional[int] = None  # Para regex: qual grupo capturar


class ExtractorSpec(BaseModel):
    """Define um campo a ser extraído."""

    name: str
    selector: SelectorSpec
    required: bool = False
    default: Optional[Any] = None


class TemplateSpec(BaseModel):
    """Especificação completa de um template de site."""

    site: str
    name: str
    category: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    url_template: str  # Ex: "https://github.com/{username}"
    method: Literal["GET", "POST"] = "GET"
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    exists_selectors: List[SelectorSpec] = Field(default_factory=list)
    not_found_selectors: List[SelectorSpec] = Field(default_factory=list)
    extractors: List[ExtractorSpec] = Field(default_factory=list)
    require_headless: bool = False
    rate_limit_per_second: float = 2.0
    page_hash_baseline: Optional[str] = None  # Para canary/auto-heal
    enabled: bool = True
    nsfw: bool = False  # NSFW content flag


__all__ = ["TemplateSpec", "ExtractorSpec", "SelectorSpec"]
