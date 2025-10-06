from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import ValidationError

from .schema import TemplateSpec


class TemplateLoadError(Exception):
    """Erro ao carregar template."""


class TemplateLoader:
    """Carrega e valida templates YAML."""

    def __init__(self) -> None:
        self._templates: dict[str, TemplateSpec] = {}

    def load_from_path(self, path: Path) -> TemplateSpec:
        """Carrega um template de um arquivo."""
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as exc:
            raise TemplateLoadError(f"Failed to read {path}: {exc}") from exc

        try:
            return TemplateSpec(**data)
        except ValidationError as exc:
            raise TemplateLoadError(f"Invalid template in {path}: {exc}") from exc

    def load_from_directory(self, directory: Path) -> List[TemplateSpec]:
        """Carrega todos os templates de um diretório."""
        templates: List[TemplateSpec] = []
        if not directory.exists():
            return templates

        for yaml_file in directory.glob("*.yaml"):
            try:
                template = self.load_from_path(yaml_file)
                templates.append(template)
                self._templates[template.site] = template
            except TemplateLoadError:
                continue

        return templates

    def load_builtin(self) -> List[TemplateSpec]:
        """Carrega templates embutidos da pasta assets/modules (recursivamente)."""
        try:
            root = importlib.resources.files("moriarty.assets.modules")
        except (AttributeError, ModuleNotFoundError):
            return []

        templates: List[TemplateSpec] = []

        def _load_entry(entry) -> None:
            if entry.is_file() and entry.name.endswith(".yaml"):
                try:
                    content = entry.read_text(encoding="utf-8")
                    data = yaml.safe_load(content)
                    template = TemplateSpec(**data)
                    templates.append(template)
                    self._templates[template.site] = template
                except (ValidationError, Exception):
                    return
            elif entry.is_dir():
                for child in entry.iterdir():
                    _load_entry(child)

        for entry in root.iterdir():
            _load_entry(entry)

        return templates

    def get_template(self, site: str) -> Optional[TemplateSpec]:
        """Retorna um template pelo nome do site."""
        return self._templates.get(site)

    def list_templates(
        self, tag: Optional[str] = None, category: Optional[str] = None
    ) -> List[TemplateSpec]:
        """Lista templates, opcionalmente filtrados por tag ou categoria."""
        results = list(self._templates.values())

        if tag:
            results = [t for t in results if tag in t.tags]

        if category:
            results = [t for t in results if category in t.category]

        return results


__all__ = ["TemplateLoader", "TemplateLoadError"]
