from __future__ import annotations

from typing import Any, Dict, Optional

import typer
from rich import box
from rich.table import Table

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from ..modules.dns_scan import DNSScanService
from ..modules.orchestrator import Orchestrator
from ..net.dns_client import DNSClient, DNSLookupResult

app = typer.Typer(add_completion=False, help="Consultas de DNS.")


@app.command("scan")
def scan(
    ctx: typer.Context,
    domain: str = typer.Option(..., "--domain", "-d", help="Domínio alvo."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
) -> None:
    """Executa varredura de registros DNS (A/AAAA/MX/TXT/SPF/DMARC)."""
    state = ensure_state(ctx)
    orchestrator: Orchestrator[DNSLookupResult] = Orchestrator(
        concurrency=state.options.concurrency,
        timeout=state.options.timeout,
    )
    service = DNSScanService(
        domain=domain,
        orchestrator=orchestrator,
        dns_client=DNSClient(timeout=state.options.timeout),
    )

    result = run_async(service.run())

    payload = _result_to_dict(result.records, domain)
    output_format = ("json" if json_output else state.options.format).lower()

    if output_format == "json":
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_table(domain, result.records)


def _render_table(domain: str, records: DNSLookupResult) -> None:
    table = Table(title=f"DNS Scan · {domain}", box=box.SIMPLE_HEAVY)
    table.add_column("Tipo", style="cyan", no_wrap=True)
    table.add_column("Valores", style="white")

    table.add_row("A", ", ".join(records.a) or "—")
    table.add_row("AAAA", ", ".join(records.aaaa) or "—")
    table.add_row("MX", ", ".join(f"{mx.exchange} (prio {mx.priority})" for mx in records.mx) or "—")
    table.add_row("SPF", "; ".join(records.spf) or "—")
    table.add_row("DMARC", "; ".join(records.dmarc) or "—")
    if records.txt:
        table.add_row("TXT", "\n".join(record.text for record in records.txt))

    console.print(table)


def _result_to_dict(records: DNSLookupResult, domain: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "a": records.a,
        "aaaa": records.aaaa,
        "mx": [
            {
                "priority": mx.priority,
                "exchange": mx.exchange,
            }
            for mx in records.mx
        ],
        "spf": records.spf,
        "dmarc": records.dmarc,
        "txt": [record.text for record in records.txt],
    }


__all__ = ["app"]
