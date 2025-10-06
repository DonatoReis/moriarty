from __future__ import annotations

from typing import Any, Dict, List, Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .async_utils import run_async
from .output import console, emit_json, emit_yaml, ensure_state
from ..modules.email_investigate import EmailInvestigator, SocialProfile

app = typer.Typer(add_completion=False, help="Investigação profunda de emails.")


@app.command("investigate")
def investigate(
    ctx: typer.Context,
    email: str = typer.Option(..., "--email", "-e", help="Email a investigar."),
    json_output: Optional[str] = typer.Option(None, "--json", help="Escreve saída JSON no caminho ou '-'"),
    include_breaches: bool = typer.Option(True, "--breaches/--no-breaches", help="Verificar data breaches."),
) -> None:
    """Investiga email em múltiplas fontes (Gravatar, social, breaches)."""
    state = ensure_state(ctx)
    
    if state.options.professional_mode:
        _render_professional_banner()
    
    console.print(f"[info]🔎 Investigando: {email}")
    console.print()
    
    investigator = EmailInvestigator(timeout=state.options.timeout)
    result = run_async(investigator.investigate(email))
    
    # Saída
    output_format = ("json" if json_output else state.options.format).lower()
    
    if output_format == "json":
        payload = _result_to_dict(result)
        emit_json(payload, json_output, state.options.output)
    elif output_format == "yaml":
        payload = _result_to_dict(result)
        emit_yaml(payload, json_output, state.options.output)
    else:
        _render_investigation(result, state.options.redact)
        
        if not include_breaches:
            console.print("\n[dim]Verificação de breaches desabilitada (use --breaches para habilitar)")


def _render_professional_banner() -> None:
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


def _render_investigation(result: Any, redact: bool) -> None:
    """Renderiza resultado da investigação."""
    
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
        gravatar_node.add(f"✓ Perfil encontrado")
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
            platform_node = social_node.add(f"[cyan]{profile.platform}[/cyan]")
            platform_node.add(f"URL: {profile.url}")
            if profile.username:
                platform_node.add(f"Username: {profile.username}")
            if profile.display_name:
                platform_node.add(f"Nome: {profile.display_name}")
            platform_node.add(f"Confidence: {profile.confidence:.2f}")
    else:
        social_node.add("[dim]Nenhum perfil encontrado (use local_part como username)[/dim]")
    
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


def _result_to_dict(result: Any) -> Dict[str, Any]:
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
