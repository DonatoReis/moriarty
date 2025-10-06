from __future__ import annotations

from typing import Any, Dict, Optional

import typer
from rich import box
from rich.table import Table

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from ..modules.orchestrator import Orchestrator
from ..modules.rdap import RDAPResult, RDAPService
from ..net.rdap_client import RDAPClient

app = typer.Typer(add_completion=False, help="Consultas RDAP.")


@app.command("domain")
def domain(
    ctx: typer.Context,
    domain: str = typer.Option(..., "--domain", "-d", help="Domínio a consultar."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
) -> None:
    _execute_rdap(ctx, query=domain, path="domain", json_output=json_output)


@app.command("ip")
def ip(
    ctx: typer.Context,
    ip_value: str = typer.Option(..., "--ip", "-i", help="Endereço IP ou prefixo."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
) -> None:
    _execute_rdap(ctx, query=ip_value, path="ip", json_output=json_output)


def _execute_rdap(ctx: typer.Context, query: str, path: str, json_output: Optional[str]) -> None:
    state = ensure_state(ctx)
    orchestrator: Orchestrator = Orchestrator(
        concurrency=state.options.concurrency,
        timeout=state.options.timeout,
    )
    service = RDAPService(
        client=RDAPClient(timeout=state.options.timeout, http2=True),
        orchestrator=orchestrator,
    )

    if path == "domain":
        result = run_async(service.domain(query))
    else:
        result = run_async(service.ip(query))

    payload = _result_to_dict(result)
    output_format = ("json" if json_output else state.options.format).lower()

    if output_format == "json":
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_table(result)


def _render_table(result: RDAPResult) -> None:
    table = Table(title=f"RDAP · {result.query}", box=box.SIMPLE_HEAVY)
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("URL", result.url)
    table.add_row("Status", str(result.status))
    table.add_row("Latência (ms)", f"{result.latency_ms:.2f}")
    handle = result.response.get("handle")
    if handle:
        table.add_row("Handle", str(handle))
    entity_type = result.response.get("objectClassName")
    if entity_type:
        table.add_row("Objeto", str(entity_type))
    events = result.response.get("events", [])
    if events:
        table.add_row("Eventos", "\n".join(f"{e.get('eventAction')}: {e.get('eventDate')}" for e in events))

    console.print(table)


def _result_to_dict(result: RDAPResult) -> Dict[str, Any]:
    return {
        "query": result.query,
        "url": result.url,
        "status": result.status,
        "latency_ms": result.latency_ms,
        "response": result.response,
    }


__all__ = ["app"]
