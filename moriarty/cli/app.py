from __future__ import annotations

import logging
from typing import cast

import typer
from rich.console import Console
from rich.theme import Theme

from ..logging.config import LogStyle, configure_logging
from . import dns, email, rdap, tls, user, domain_cmd, intelligence
# Temporariamente removido para testes: wifippler
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


def version_callback(value: bool):
    if value:
        from .. import __version__
        console.print(f"Moriarty OSINT Toolkit v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, 
        "--version", 
        "-V",  # Mudando de -v para -V para evitar conflito com --verbose
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
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
    verbose: bool = typer.Option(False, "--verbose", help="Enable verbose logging."),  # Removendo o atalho -v para evitar duplicação
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
app.add_typer(intelligence.app, name="intelligence", help="Inteligência de ameaças.")
app.add_typer(domain_cmd.app, name="domain", help="Análise de domínios.")
# Temporariamente removido: wifippler.app
app.add_typer(user.app, name="user", help="User/IP reconnaissance and scanning.")

# Registra os comandos de inteligência
intelligence.register_app(app)


if __name__ == "__main__":
    app()


def main() -> None:  # Console script compatibility
    app()


def check_pipx_installed() -> bool:
    """Verifica se o pipx está instalado."""
    try:
        import subprocess
        subprocess.run(["pipx", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def self_update():
    """Atualiza o Moriarty para a versão mais recente."""
    import subprocess
    import sys
    from rich.console import Console
    from rich.panel import Panel
    from rich import print
    
    console = Console()
    
    try:
        # Verifica se está instalado com pipx
        if check_pipx_installed():
            console.print("🔄 Atualizando via pipx...", style="bold blue")
            result = subprocess.run(
                ["pipx", "install", "--upgrade", "moriarty-project"],
                capture_output=True,
                text=True
            )
        else:
            console.print("🔄 Atualizando via pip...", style="bold blue")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "moriarty-project"],
                capture_output=True,
                text=True
            )
        
        if result.returncode == 0:
            console.print("✅ [bold green]Atualização concluída com sucesso![/]")
            if result.stdout:
                console.print(Panel(
                    result.stdout.strip(),
                    title="[bold]Saída do comando[/]",
                    border_style="green"
                ))
            console.print("\nReinicie o terminal para aplicar as alterações.", style="yellow")
        else:
            console.print("❌ [bold red]Erro durante a atualização:[/]")
            if result.stderr:
                console.print(Panel(
                    result.stderr.strip(),
                    title="[bold]Mensagem de erro[/]",
                    border_style="red"
                ))
            console.print("\nTente executar manualmente:")
            if check_pipx_installed():
                console.print("  [cyan]pipx install --upgrade moriarty-project[/]")
            else:
                console.print(f"  [cyan]{sys.executable} -m pip install --upgrade moriarty-project[/]")
    except Exception as e:
        console.print(f"❌ [bold red]Erro inesperado:[/] {str(e)}")
        console.print("\nTente atualizar manualmente usando:")
        if check_pipx_installed():
            console.print("  [cyan]pipx install --upgrade moriarty-project[/]")
        else:
            console.print(f"  [cyan]{sys.executable} -m pip install --upgrade moriarty-project[/]")


# Adiciona o comando self-update
@app.command("self-update", help="Atualiza o Moriarty para a versão mais recente.")
def self_update_command():
    """Atualiza o Moriarty para a versão mais recente."""
    self_update()


# Adiciona um alias mais curto
@app.command("update", hidden=True)
def update_alias():
    """Alias para 'self-update'."""
    self_update()


__all__ = ["app", "main", "self_update"]
