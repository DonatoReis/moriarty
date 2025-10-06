from __future__ import annotations

from typing import Any, Dict, Optional

import typer
from rich import box
from rich.table import Table

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from ..modules.orchestrator import Orchestrator
from ..modules.tls_scan import TLSScanService
from ..net.tls_client import TLSClient, TLSInspection

app = typer.Typer(add_completion=False, help="Inspeção de certificados TLS.")


@app.command("certs")
def certs(
    ctx: typer.Context,
    domain: str = typer.Option(..., "--domain", "-d", help="Host a ser inspecionado."),
    port: int = typer.Option(443, help="Porta TLS."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
) -> None:
    state = ensure_state(ctx)
    orchestrator: Orchestrator[TLSInspection] = Orchestrator(
        concurrency=state.options.concurrency,
        timeout=state.options.timeout,
    )

    service = TLSScanService(
        client=TLSClient(timeout=state.options.timeout),
        orchestrator=orchestrator,
        host=domain,
        port=port,
    )

    result = run_async(service.run())
    payload = _result_to_dict(result.inspection)

    output_format = ("json" if json_output else state.options.format).lower()
    if output_format == "json":
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_table(result.inspection)


def _render_table(inspection: TLSInspection) -> None:
    table = Table(title=f"TLS Certs · {inspection.host}:{inspection.port}", box=box.SIMPLE_HEAVY)
    table.add_column("Campo", style="cyan", no_wrap=True)
    table.add_column("Valor", style="white")

    table.add_row("Protocolo", inspection.protocol or "—")
    table.add_row("Cipher", inspection.cipher or "—")
    table.add_row("Latência (ms)", f"{inspection.latency_ms:.2f}")

    for idx, cert in enumerate(inspection.certificates, start=1):
        table.add_row(f"Certificado {idx} - Subject", cert.subject or "—")
        table.add_row(f"Certificado {idx} - Issuer", cert.issuer or "—")
        table.add_row(f"Certificado {idx} - Validade", f"{cert.not_before} → {cert.not_after}")
        table.add_row(f"Certificado {idx} - SHA256", cert.fingerprint_sha256)
        if cert.subject_alt_names:
            table.add_row(f"Certificado {idx} - SANs", ", ".join(cert.subject_alt_names))

    console.print(table)


def _result_to_dict(inspection: TLSInspection) -> Dict[str, Any]:
    return {
        "host": inspection.host,
        "port": inspection.port,
        "protocol": inspection.protocol,
        "cipher": inspection.cipher,
        "latency_ms": inspection.latency_ms,
        "certificates": [
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "fingerprint_sha256": cert.fingerprint_sha256,
                "subject_alt_names": cert.subject_alt_names,
            }
            for cert in inspection.certificates
        ],
    }


__all__ = ["app"]
