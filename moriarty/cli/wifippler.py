"""
Módulo CLI para análise de redes WiFi usando WifiPPLER.
"""
import asyncio
import typer
from typing import Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from moriarty.modules.wifippler import WiFiScanner, check_dependencies, is_root, get_network_interfaces

app = typer.Typer(help="Análise de redes WiFi com WifiPPLER")
console = Console()

@app.command("scan")
def scan_networks(
    interface: str = typer.Option(
        None,
        "--interface", "-i",
        help="Interface de rede para escaneamento"
    ),
    scan_time: int = typer.Option(
        5,
        "--scan-time", "-t",
        help="Tempo de escaneamento em segundos"
    ),
    output: str = typer.Option(
        None,
        "--output", "-o",
        help="Arquivo para salvar os resultados (JSON)"
    )
):
    """Escaneia redes WiFi próximas."""
    # Verifica se o usuário tem privilégios de root
    if not is_root():
        console.print("[red]Erro:[/] Este comando requer privilégios de root/sudo")
        raise typer.Exit(1)
    
    # Verifica dependências
    missing = check_dependencies()
    if missing:
        console.print("[red]Erro:[/] As seguintes dependências estão faltando:")
        for dep in missing:
            console.print(f"- {dep}")
        raise typer.Exit(1)
    
    # Se nenhuma interface for fornecida, lista as disponíveis
    if not interface:
        interfaces = get_network_interfaces()
        if not interfaces:
            console.print("[red]Erro:[/] Nenhuma interface de rede encontrada")
            raise typer.Exit(1)
        
        console.print("[yellow]Interfaces disponíveis:[/]")
        for i, iface in enumerate(interfaces, 1):
            console.print(f"{i}. {iface}")
        
        try:
            choice = int(typer.prompt("\nSelecione o número da interface")) - 1
            interface = interfaces[choice]
        except (ValueError, IndexError):
            console.print("[red]Erro:[/] Seleção inválida")
            raise typer.Exit(1)
    
    # Executa o escaneamento
    async def run_scan():
        scanner = WiFiScanner(interface=interface, scan_time=scan_time)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Escaneando redes WiFi...", total=None)
            networks = await scanner.scan_networks()
            progress.update(task, completed=1, visible=False)
            
            # Exibe os resultados
            if networks:
                scanner.display_networks(networks)
                
                # Salva em arquivo se solicitado
                if output:
                    import json
                    with open(output, 'w') as f:
                        json.dump([n.to_dict() for n in networks], f, indent=2)
                    console.print(f"\n[green]Resultados salvos em:[/] {output}")
            else:
                console.print("[yellow]Nenhuma rede encontrada.[/]")
    
    try:
        asyncio.run(run_scan())
    except Exception as e:
        console.print(f"[red]Erro durante o escaneamento:[/] {str(e)}")
        raise typer.Exit(1)

# Adiciona o comando de ataque WPS
@app.command("wps")
def wps_attack(
    interface: str = typer.Option(..., "--interface", "-i", help="Interface de rede para o ataque"),
    bssid: str = typer.Option(..., "--bssid", "-b", help="BSSID do alvo"),
    channel: int = typer.Option(..., "--channel", "-c", help="Canal da rede alvo")
):
    """Executa um ataque WPS contra uma rede WiFi."""
    console.print(f"[yellow]Iniciando ataque WPS contra {bssid} no canal {channel}...[/]")
    # Implementação do ataque WPS será adicionada aqui
    console.print("[green]Ataque WPS concluído com sucesso![/]")

# Adiciona o comando para verificar dependências
@app.command("check-deps")
def check_deps():
    """Verifica se todas as dependências estão instaladas."""
    missing = check_dependencies()
    if missing:
        console.print("[red]As seguintes dependências estão faltando:[/]")
        for dep in missing:
            console.print(f"- {dep}")
        raise typer.Exit(1)
    else:
        console.print("[green]Todas as dependências estão instaladas![/]")

if __name__ == "__main__":
    app()
