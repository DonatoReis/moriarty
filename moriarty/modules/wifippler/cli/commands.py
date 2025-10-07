"""
Interface de linha de comando (CLI) para o WiFiPPLER.

Utiliza Typer para criar uma interface de linha de comando amigável.
"""
import typer
from typing import Optional, List
from rich.console import Console
from rich.table import Table

# Importa o scanner e o registro de ataques
from ..core.scanner import WiFiScanner
from ..core.attacks import list_attacks, get_attack, Attack

# Cria a aplicação Typer
app = typer.Typer(help="WiFiPPLER - Ferramenta Avançada de Análise de Segurança WiFi")
console = Console()

# Instância do scanner
scanner = WiFiScanner()

@app.command()
def list_attacks():
    """Lista todos os ataques disponíveis."""
    attacks = scanner.list_attacks()
    
    if not attacks:
        console.print("[yellow]Nenhum ataque registrado.[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Nome", style="cyan")
    table.add_column("Descrição")
    
    for name, attack_cls in attacks.items():
        table.add_row(name, attack_cls.description)
    
    console.print("\n[bold]Ataques disponíveis:[/bold]")
    console.print(table)

@app.command()
def scan(iface: str = typer.Option(..., "--iface", "-i", help="Interface de rede a ser usada")):
    """Escaneia redes WiFi próximas."""
    try:
        console.print(f"[bold]Escaneando redes na interface {iface}...[/bold]")
        # Implementar lógica de escaneamento aqui
        networks = scanner.scan(iface=iface)
        
        if not networks:
            console.print("[yellow]Nenhuma rede encontrada.[/yellow]")
            return
        
        table = Table(show_header=True, header_style="bold green")
        table.add_column("BSSID", style="cyan")
        table.add_column("SSID", style="green")
        table.add_column("Canal")
        table.add_column("Sinal")
        table.add_column("Segurança")
        
        for net in networks:
            table.add_row(
                net.bssid,
                net.ssid or "[dim](oculto)[/dim]",
                str(net.channel),
                f"{net.signal} dBm",
                ", ".join(net.security) if net.security else "Aberta"
            )
        
        console.print("\n[bold]Redes encontradas:[/bold]")
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Erro ao escanear redes: {e}[/red]")
        raise typer.Exit(1)

@app.command()
def run(
    attack: str = typer.Argument(..., help="Nome do ataque a ser executado"),
    iface: str = typer.Option(..., "--iface", "-i", help="Interface de rede a ser usada"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Alvo do ataque (opcional)"),
    channel: Optional[int] = typer.Option(None, "--channel", "-c", help="Canal a ser monitorado (opcional)"),
):
    """Executa um ataque específico."""
    try:
        console.print(f"[bold]Preparando para executar o ataque: {attack}[/bold]")
        
        # Verifica se o ataque existe
        attack_cls = get_attack(attack)
        if not attack_cls:
            available = ", ".join(scanner.list_attacks().keys())
            console.print(f"[red]Ataque '{attack}' não encontrado. Ataques disponíveis: {available}[/red]")
            raise typer.Exit(1)
        
        # Cria e executa o ataque
        attack_instance = attack_cls()
        
        # Configura parâmetros comuns
        params = {
            'iface': iface,
            'target': target
        }
        
        if channel is not None:
            params['channel'] = channel
        
        console.print(f"[bold]Iniciando ataque {attack}...[/]")
        console.print("[yellow]Pressione Ctrl+C para interromper[/yellow]")
        
        # Executa o ataque
        attack_instance.run(**params)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Ataque interrompido pelo usuário.[/yellow]")
        raise typer.Exit(0)
    except Exception as e:
        console.print(f"[red]Erro ao executar o ataque: {e}[/red]")
        if typer.get_app_dir("wifippler").startswith("DEBUG"):
            import traceback
            console.print(traceback.format_exc())
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
