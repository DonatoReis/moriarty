from __future__ import annotations

from typing import Any, Dict, Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from .state import GlobalOptions
from ..modules.email_check import EmailCheckOptions, EmailCheckResult, EmailCheckService
from ..modules.email_investigate import EmailInvestigator, EmailInvestigationResult

app = typer.Typer(add_completion=False, help="Email reconnaissance primitives.")


@app.command("check")
def check(  # noqa: PLR0913 - CLI interface requires multiple parameters
    ctx: typer.Context,
    email: str = typer.Option(..., "--email", "-e", help="Target email address."),
    dns: bool = typer.Option(True, "--dns/--no-dns", help="Run DNS lookups (MX/SPF/DMARC)."),
    smtp: bool = typer.Option(False, "--smtp/--no-smtp", help="Attempt SMTP RCPT TO verification."),
    from_address: str = typer.Option("postmaster@localhost", "--from", help="Envelope MAIL FROM address."),
    retries: int = typer.Option(1, min=0, help="SMTP retry attempts after the first try."),
    wait: float = typer.Option(1.0, min=0.0, help="Seconds to wait between SMTP retries."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Write JSON output to path or '-' for stdout."),
) -> None:
    """Validate an email address using DNS and SMTP heuristics."""
    state = ensure_state(ctx)

    options = EmailCheckOptions(
        check_dns=dns,
        check_smtp=smtp,
        from_address=from_address,
        retries=retries,
        wait=wait,
    )

    service = EmailCheckService(email=email, options=options, timeout=state.options.timeout)

    try:
        result = run_async(service.run())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if state.options.professional_mode:
        _render_professional_banner(state.options)

    output_format = ("json" if json_output else state.options.format).lower()

    if output_format == "json":
        payload = _result_to_dict(result)
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        payload = _result_to_dict(result)
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_table(result, state.options)

    for warning in result.warnings:
        console.print(f"[warning]⚠️  {warning}")


def _render_professional_banner(options: GlobalOptions) -> None:
    notice = (
        "⚠️ Professional Mode\n"
        "Consent required. Ensure investigative actions comply with policy."
    )
    console.print(
        Panel(
            notice,
            title="MORIARTY",
            border_style="yellow",
        )
    )


def _render_table(result: EmailCheckResult, options: GlobalOptions) -> None:
    table = Table(title=f"Email Check · {result.normalized_email}", box=box.SIMPLE_HEAVY)
    table.add_column("Attribute", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Input", result.input_email)
    table.add_row("Normalized", result.normalized_email)
    table.add_row("Local Part", result.local_part)
    table.add_row("Domain", result.domain)

    if result.dns:
        mx_summary = ", ".join(f"{mx.exchange} (prio {mx.priority})" for mx in result.dns.mx) or "—"
        spf_summary = "; ".join(result.dns.spf) or "—"
        dmarc_summary = "; ".join(result.dns.dmarc) or "—"
        table.add_row("A", ", ".join(result.dns.a) or "—")
        table.add_row("AAAA", ", ".join(result.dns.aaaa) or "—")
        table.add_row("MX", mx_summary)
        table.add_row("SPF", spf_summary)
        table.add_row("DMARC", dmarc_summary)

    if result.smtp:
        status = "deliverable" if result.smtp.deliverable else "undeliverable"
        attempt_lines = []
        for attempt in result.smtp.attempts:
            if attempt.result_code is not None:
                message = attempt.result_message or ""
                attempt_lines.append(f"{attempt.host}: {attempt.result_code} {message}".strip())
            elif attempt.error:
                attempt_lines.append(f"{attempt.host}: error {attempt.error}")
        table.add_row("SMTP", f"{status}\n" + "\n".join(attempt_lines) if attempt_lines else status)

    console.print(table)


def _result_to_dict(result: EmailCheckResult) -> Dict[str, Any]:
    return {
        "input_email": result.input_email,
        "normalized_email": result.normalized_email,
        "local_part": result.local_part,
        "domain": result.domain,
        "dns": _dns_to_dict(result.dns) if result.dns else None,
        "smtp": _smtp_to_dict(result.smtp) if result.smtp else None,
        "warnings": result.warnings,
    }


def _dns_to_dict(dns_result: Optional[Any]) -> Optional[Dict[str, Any]]:
    if dns_result is None:
        return None
    return {
        "a": dns_result.a,
        "aaaa": dns_result.aaaa,
        "mx": [
            {
                "priority": record.priority,
                "exchange": record.exchange,
            }
            for record in dns_result.mx
        ],
        "spf": dns_result.spf,
        "dmarc": dns_result.dmarc,
        "txt": [record.text for record in dns_result.txt],
    }


def _smtp_to_dict(smtp_result: Optional[Any]) -> Optional[Dict[str, Any]]:
    if smtp_result is None:
        return None
    return {
        "deliverable": smtp_result.deliverable,
        "attempts": [
            {
                "host": attempt.host,
                "port": attempt.port,
                "code": attempt.result_code,
                "message": attempt.result_message,
                "success": attempt.success,
                "error": attempt.error,
            }
            for attempt in smtp_result.attempts
        ],
    }


@app.command("investigate")
def investigate(
    ctx: typer.Context,
    email: str = typer.Option(..., "--email", "-e", help="Email a investigar."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
    include_breaches: bool = typer.Option(True, "--breaches/--no-breaches", help="Verificar data breaches."),
) -> None:
    """Investiga email em múltiplas fontes (Gravatar, social, breaches)."""
    import logging
    from rich.tree import Tree
    
    state = ensure_state(ctx)
    
    # Suprime logs INFO/WARNING de bibliotecas externas - apenas durante investigate
    if not state.options.verbose:
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("httpcore").setLevel(logging.ERROR)
        logging.getLogger("moriarty.modules.email_investigate").setLevel(logging.ERROR)
        logging.getLogger("moriarty.modules.template_executor").setLevel(logging.ERROR)
    
    if state.options.professional_mode:
        notice = (
            "⚠️ Investigação Profunda\n\n"
            "Esta ferramenta consulta fontes públicas. Respeite a privacidade e "
            "use apenas para fins legítimos de segurança e investigação autorizada."
        )
        console.print(
            Panel(
                notice,
                title="MORIARTY · Professional Mode",
                border_style="yellow",
                padding=(1, 2),
            )
        )
        console.print()
    
    console.print(f"[info]🔎 Investigando: {email}")
    console.print()
    
    with console.status("[cyan]Buscando em múltiplas fontes...", spinner="dots"):
        investigator = EmailInvestigator(timeout=state.options.timeout)
        result = run_async(investigator.investigate(email))
    
    # Saída
    output_format = ("json" if json_output else state.options.format).lower()
    
    if output_format == "json":
        payload = _investigation_to_dict(result)
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        payload = _investigation_to_dict(result)
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_investigation(result, state.options.redact)
        
        if not include_breaches:
            console.print("\n[dim]Verificação de breaches desabilitada (use --breaches para habilitar)")


def _render_investigation(result: EmailInvestigationResult, redact: bool) -> None:
    """Renderiza resultado da investigação."""
    from rich.tree import Tree
    
    # Painel principal
    email_display = _redact_email(result.email) if redact else result.email
    
    tree = Tree(f"[bold cyan]📧 {email_display}[/bold cyan]")
    
    # Informações básicas
    basic_node = tree.add("[bold]Informações Básicas[/bold]")
    basic_node.add(f"Local Part: {result.local_part}")
    basic_node.add(f"Domínio: {result.domain}")
    basic_node.add(f"Normalizado: {result.normalized_email}")
    
    # Gravatar
    gravatar_node = tree.add("[bold]Gravatar[/bold]")
    if result.gravatar_profile:
        gravatar_node.add("✓ Perfil encontrado")
        gravatar_node.add(f"Hash: {result.gravatar_hash[:16]}...")
        if result.gravatar_avatar:
            gravatar_node.add(f"Avatar: {result.gravatar_avatar}")
        
        # Dados do perfil
        profile = result.gravatar_profile
        if profile.get("displayName"):
            gravatar_node.add(f"Nome: {profile['displayName']}")
        if profile.get("profileUrl"):
            gravatar_node.add(f"URL: {profile['profileUrl']}")
    else:
        gravatar_node.add("[dim]✗ Nenhum perfil Gravatar encontrado[/dim]")
    
    # Perfis sociais
    social_node = tree.add(f"[bold]Perfis Sociais ({len(result.social_profiles)})[/bold]")
    if result.social_profiles:
        for profile in result.social_profiles:
            platform_node = social_node.add(f"[green]✓[/green] [cyan]{profile.platform.title()}[/cyan]")
            platform_node.add(f"🔗 {profile.url}")
            if profile.display_name:
                platform_node.add(f"👤 {profile.display_name}")
            if profile.bio:
                bio_preview = profile.bio[:80] + "..." if len(profile.bio) > 80 else profile.bio
                platform_node.add(f"📝 {bio_preview}")
            if profile.metadata.get("location"):
                platform_node.add(f"📍 {profile.metadata['location']}")
            if profile.metadata.get("website"):
                platform_node.add(f"🌐 {profile.metadata['website']}")
            platform_node.add(f"💯 Confidence: {profile.confidence:.0%}")
    else:
        social_node.add("[dim]✗ Nenhum perfil encontrado com o username '{local_part}'[/dim]".format(local_part=result.local_part))
    
    # Usernames extraídos
    if result.usernames:
        usernames_node = tree.add(f"[bold]Usernames Encontrados ({len(result.usernames)})[/bold]")
        for username in result.usernames:
            usernames_node.add(f"• {username}")
    
    # Websites
    if result.websites:
        websites_node = tree.add(f"[bold]Websites Vinculados ({len(result.websites)})[/bold]")
        for website in result.websites:
            websites_node.add(f"🔗 {website}")
    
    # Data Breaches
    breach_node = tree.add("[bold]Data Breaches[/bold]")
    if result.breached:
        breach_node.add(f"[red]⚠️  Email encontrado em {result.breach_count} breach(es)[/red]")
        for breach in result.breaches:
            breach_node.add(f"• {breach.get('source', 'Unknown')}: {breach.get('occurrences', 0)} ocorrências")
    else:
        breach_node.add("[green]✓ Nenhum breach conhecido[/green]")
    
    console.print(tree)
    console.print()
    
    # Estatísticas
    stats_table = Table(title="Resumo da Investigação", box=box.SIMPLE)
    stats_table.add_column("Métrica", style="cyan")
    stats_table.add_column("Valor", style="white")
    
    stats_table.add_row("Email", email_display)
    stats_table.add_row("Plataformas encontradas", str(result.total_platforms_found))
    stats_table.add_row("Usernames únicos", str(len(result.usernames)))
    stats_table.add_row("Websites vinculados", str(len(result.websites)))
    stats_table.add_row("Gravatar", "✓ Sim" if result.gravatar_profile else "✗ Não")
    stats_table.add_row("Breaches", f"{'✗ Sim (' + str(result.breach_count) + ')' if result.breached else '✓ Não'}")
    stats_table.add_row("Timestamp", result.search_timestamp)
    
    console.print(stats_table)
    
    # Recomendações
    if result.breached:
        console.print()
        console.print(
            Panel(
                "[red]⚠️  Este email foi encontrado em data breaches.\n"
                "Recomendações:\n"
                "• Alterar senhas imediatamente\n"
                "• Habilitar autenticação de dois fatores\n"
                "• Verificar atividades suspeitas nas contas[/red]",
                title="Alerta de Segurança",
                border_style="red",
            )
        )


def _redact_email(email: str) -> str:
    """Redige email para exibição."""
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        redacted_local = local[0] + "*"
    else:
        redacted_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{redacted_local}@{domain}"


def _investigation_to_dict(result: EmailInvestigationResult) -> Dict[str, Any]:
    """Converte resultado para dict."""
    return {
        "email": result.email,
        "normalized_email": result.normalized_email,
        "domain": result.domain,
        "local_part": result.local_part,
        "gravatar": {
            "hash": result.gravatar_hash,
            "profile": result.gravatar_profile,
            "avatar_url": result.gravatar_avatar,
        },
        "social_profiles": [
            {
                "platform": p.platform,
                "url": p.url,
                "username": p.username,
                "user_id": p.user_id,
                "display_name": p.display_name,
                "avatar_url": p.avatar_url,
                "bio": p.bio,
                "verified": p.verified,
                "confidence": p.confidence,
                "metadata": p.metadata,
            }
            for p in result.social_profiles
        ],
        "breaches": {
            "breached": result.breached,
            "count": result.breach_count,
            "details": result.breaches,
        },
        "extracted_data": {
            "usernames": result.usernames,
            "websites": result.websites,
            "phone_numbers": result.phone_numbers,
        },
        "metadata": {
            "total_platforms_found": result.total_platforms_found,
            "search_timestamp": result.search_timestamp,
        },
    }


__all__ = ["app"]
