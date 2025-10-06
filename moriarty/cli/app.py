from __future__ import annotations

import logging
from typing import cast

import typer
from rich.console import Console
from rich.theme import Theme

from ..logging.config import LogStyle, configure_logging
from . import dns, email, rdap, tls, user, domain_cmd, intelligence
from .state import CLIState, GlobalOptions

console = Console(theme=Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "green",
}))

app = typer.Typer(
    add_completion=False,
    help="Moriarty — client-side OSINT investigations."
)


@app.callback()
def main(
    ctx: typer.Context,
    concurrency: int = typer.Option(50, min=1, help="Maximum concurrent tasks."),
    timeout: float = typer.Option(8.0, min=0.1, help="Per-request timeout in seconds."),
    proxy: str | None = typer.Option(None, help="HTTP/SOCKS proxy URI."),
    headless: str = typer.Option(
        "auto",
        case_sensitive=False,
        help="Headless mode: auto, never, or force.",
    ),
    allowlist_domain: str | None = typer.Option(
        None,
        help="Comma-separated domains allowed for headless browsing.",
    ),
    format_: str = typer.Option(
        "table",
        "--format",
        help="Output format: table, json, yaml.",
    ),
    output: str | None = typer.Option(None, help="Path to export artifacts."),
    redact: bool = typer.Option(True, "--redact/--no-redact", help="Redact PII in output."),
    verbose: bool = typer.Option(False, help="Enable verbose logging."),
    quiet: bool = typer.Option(False, help="Suppress non-critical output."),
    professional_mode: bool = typer.Option(False, help="Enable professional mode safeguards."),
    seed: int | None = typer.Option(None, help="Deterministic seed for planners."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Execute planning without side-effects."),
    plan_only: bool = typer.Option(False, help="Emit planned actions without execution."),
    sign: bool = typer.Option(False, help="Sign artifacts using Sigstore (requires --output)."),
    resume: str | None = typer.Option(None, help="Resume a stored plan from JSON."),
    http3: bool = typer.Option(False, help="Enable HTTP/3 (requires aioquic extra)."),
    doh: str | None = typer.Option(None, help="Use DNS-over-HTTPS with the provided endpoint."),
    dot: str | None = typer.Option(None, help="Use DNS-over-TLS host:port."),
    logs: str = typer.Option("structured", help="Logging style: structured or pretty."),
) -> None:
    """Configure global CLI options."""
    if quiet and verbose:
        raise typer.BadParameter("Use either --verbose or --quiet, not both.")

    log_style_value = logs.lower()
    if log_style_value not in ("structured", "pretty"):
        raise typer.BadParameter("Logging style must be 'structured' or 'pretty'.")

    log_style = cast(LogStyle, log_style_value)
    configure_logging(style=log_style, verbose=verbose)
    if quiet:
        logging.getLogger().setLevel(logging.WARNING)

    ctx.obj = CLIState(
        options=GlobalOptions(
            concurrency=concurrency,
            timeout=timeout,
            proxy=proxy,
            headless=headless.lower(),
            allowlist_domain=allowlist_domain,
            format=format_,
            output=output,
            redact=redact,
            verbose=verbose,
            quiet=quiet,
            professional_mode=professional_mode,
            seed=seed,
            dry_run=dry_run,
            plan_only=plan_only,
            sign=sign,
            resume_path=resume,
            http3=http3,
            doh=doh,
            dot=dot,
            logs=log_style,
        )
    )


app.add_typer(email.app, name="email", help="Email reconnaissance primitives.")
app.add_typer(dns.app, name="dns", help="Consultas DNS.")
app.add_typer(rdap.app, name="rdap", help="Consultas RDAP.")
app.add_typer(tls.app, name="tls", help="Inspeções TLS.")
app.add_typer(user.app, name="user", help="Enumeração de usernames.")
app.add_typer(domain_cmd.app, name="domain", help="🌐 Domain/IP reconnaissance and scanning.")

# Registra os comandos de inteligência
intelligence.register_app(app)


def main_entry() -> None:
    app()


def main() -> None:  # Console script compatibility
    main_entry()


__all__ = ["app", "main"]
