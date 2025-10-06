from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
import re

import typer
import httpx
from rich import box
from rich.table import Table

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from ..dsl.loader import TemplateLoader
from ..modules.template_executor import ExecutionResult, TemplateExecutor

app = typer.Typer(add_completion=False, help="Enumeração de usernames.")


@app.command("enum")
def enum(
    ctx: typer.Context,
    username: str = typer.Option(..., "--username", "-u", help="Username a pesquisar."),
    sites: str = typer.Option("top20", help="Sites: top20, all, tag:X, ou caminho para .yml"),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
    retry: int = typer.Option(0, min=0, help="Tentativas de retry por site."),
    nsfw: bool = typer.Option(False, "--nsfw", help="Include checking of NSFW sites from default list."),
    print_all: bool = typer.Option(False, "--print-all", help="Output sites where the username was not found."),
    print_found: bool = typer.Option(False, "--print-found", help="Output sites where the username was found."),
    timeout_override: Optional[float] = typer.Option(None, "--timeout", help="Time (in seconds) to wait for response to requests."),
) -> None:
    """Enumera username em múltiplos sites."""
    import logging
    
    state = ensure_state(ctx)
    
    # Override timeout se especificado
    if timeout_override is not None:
        state.options.timeout = timeout_override
    
    # Suprime logs INFO/WARNING de bibliotecas externas
    if not state.options.verbose:
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("httpcore").setLevel(logging.ERROR)
        logging.getLogger("moriarty.modules.template_executor").setLevel(logging.ERROR)
    
    # Carrega templates
    loader = TemplateLoader()
    loader.load_builtin()
    
    # Filtra templates
    if sites == "all":
        templates = loader.list_templates()
    elif sites == "top20":
        templates = loader.list_templates(tag="top20")
    elif sites.startswith("tag:"):
        tag = sites[4:]
        templates = loader.list_templates(tag=tag)
    else:
        # Caminho para arquivo/diretório
        from pathlib import Path
        path = Path(sites)
        if path.is_file():
            templates = [loader.load_from_path(path)]
        elif path.is_dir():
            templates = loader.load_from_directory(path)
        else:
            raise typer.BadParameter(f"Invalid sites specification: {sites}")
    
    # Filtra templates
    # 1. Filtra habilitados
    templates = [t for t in templates if t.enabled]
    
    # 2. Filtra headless se necessário
    if state.options.headless == "never":
        templates = [t for t in templates if not t.require_headless]
    
    # 3. Filtra NSFW se não solicitado
    if not nsfw:
        templates = [t for t in templates if not t.nsfw]
    
    if not templates:
        console.print("[warning]Nenhum template encontrado para executar.")
        return
    
    allowed_vars = {"username"}
    templates = _filter_templates_by_variables(templates, allowed_vars)

    console.print(f"[info]🔎 Buscando username em {len(templates)} sites...")
    console.print()
    
    # Executa com spinner
    with console.status("[cyan]Verificando perfis...", spinner="dots"):
        cookie_store: Dict[str, httpx.Cookies] = {}
        executor = TemplateExecutor(timeout=state.options.timeout, cookie_store=cookie_store)
        results = run_async(_execute_all(executor, templates, username, state.options.concurrency))
    
    # Saída
    output_format = ("json" if json_output else state.options.format).lower()
    
    # Filtra resultados para exibição
    if print_found:
        # Mostra apenas encontrados
        filtered_results = [r for r in results if r.exists]
    elif print_all:
        # Mostra todos (padrão se nenhum filtro)
        filtered_results = results
    else:
        # Mostra todos por padrão
        filtered_results = results
    
    if output_format == "json":
        payload = _results_to_dict(filtered_results, username)
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        payload = _results_to_dict(filtered_results, username)
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_table(filtered_results, username, show_not_found=print_all or not print_found)


async def _execute_all(
    executor: TemplateExecutor,
    templates: List[Any],
    username: str,
    concurrency: int,
) -> List[ExecutionResult]:
    """Executa todos os templates concorrentemente."""
    semaphore = asyncio.Semaphore(concurrency)
    
    async def bounded_execute(template: Any) -> ExecutionResult:
        async with semaphore:
            return await executor.execute(template, {"username": username})
    
    tasks = [bounded_execute(t) for t in templates]
    return await asyncio.gather(*tasks)


def _render_table(results: List[ExecutionResult], username: str, show_not_found: bool = True) -> None:
    """Renderiza resultados em tabela."""
    table = Table(title=f"Username Enumeration · {username}", box=box.SIMPLE_HEAVY)
    table.add_column("Site", style="cyan", no_wrap=True)
    table.add_column("Exists", style="white", no_wrap=True)
    table.add_column("Confidence", style="white", no_wrap=True)
    table.add_column("Extracted", style="dim")
    table.add_column("URL", style="blue", overflow="fold")
    
    # Ordena por exists e confidence
    sorted_results = sorted(results, key=lambda r: (r.exists, r.confidence), reverse=True)
    
    for result in sorted_results:
        # Pula não encontrados se show_not_found=False
        if not show_not_found and not result.exists:
            continue
        
        exists_icon = "✓" if result.exists else "✗"
        exists_color = "green" if result.exists else "dim"
        
        confidence_str = f"{result.confidence:.2f}"
        
        extracted_str = ", ".join(f"{k}={v}" for k, v in result.extracted.items()) if result.extracted else "—"
        
        table.add_row(
            result.site,
            f"[{exists_color}]{exists_icon}[/{exists_color}]",
            confidence_str,
            extracted_str,
            result.url,
        )
    
    console.print(table)
    
    # Estatísticas
    total = len(results)
    found = sum(1 for r in results if r.exists)
    console.print(f"\n[info]Total: {total} sites · Found: {found} ({found/total*100:.1f}%)")


def _results_to_dict(results: List[ExecutionResult], username: str) -> Dict[str, Any]:
    """Converte resultados para dict."""
    return {
        "username": username,
        "total_sites": len(results),
        "found_count": sum(1 for r in results if r.exists),
        "results": [
            {
                "site": r.site,
                "url": r.url,
                "exists": r.exists,
                "confidence": r.confidence,
                "extracted": r.extracted,
                "page_hash": r.page_hash,
                "latency_ms": r.latency_ms,
                "status_code": r.status_code,
                "error": r.error,
            }
            for r in results
        ],
    }


_PLACEHOLDER_PATTERN = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def _filter_templates_by_variables(templates: List[Any], allowed: set[str]) -> List[Any]:
    filtered: List[Any] = []
    for template in templates:
        placeholders = _collect_placeholders(template)
        if placeholders - allowed:
            continue
        filtered.append(template)
    return filtered


def _collect_placeholders(template: Any) -> set[str]:
    values = [template.url_template]
    values.extend(template.headers.values())
    if template.body:
        values.append(str(template.body))
    placeholders: set[str] = set()
    for value in values:
        for match in _PLACEHOLDER_PATTERN.findall(str(value)):
            placeholders.add(match)
    return placeholders


__all__ = ["app"]
