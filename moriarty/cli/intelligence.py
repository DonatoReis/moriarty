"""Comandos para gerenciamento de inteligência local."""
from pathlib import Path
from typing import List, Optional, Dict, Any

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from moriarty.data import (
    get_local_intelligence,
    IOC, IOCType, ThreatType,
    load_iocs_from_file, save_iocs_to_file
)

app = typer.Typer(name="intel", help="🔍 Gerenciamento de inteligência local")
console = Console()

# Tipos de IOC suportados para autocompletar
IOC_TYPES = [t.value for t in IOCType]
THREAT_TYPES = [t.value for t in ThreatType]

# Configuração
DEFAULT_DATA_DIR = Path("~/.moriarty/data").expanduser()

def _get_intel():
    """Retorna uma instância de LocalIntelligence."""
    return get_local_intelligence()

@app.command("add")
def add_ioc(
    value: str = typer.Argument(..., help="Valor do IOC"),
    ioc_type: str = typer.Argument(..., help=f"Tipo do IOC: {', '.join(IOC_TYPES)}", 
                                 autocompletion=lambda: IOC_TYPES),
    threat_type: str = typer.Option("unknown", "--threat", "-t", 
                                  help=f"Tipo de ameaça: {', '.join(THREAT_TYPES)}",
                                  autocompletion=lambda: THREAT_TYPES),
    source: str = typer.Option("manual", "--source", "-s", 
                             help="Fonte da informação"),
    confidence: int = typer.Option(50, "--confidence", "-c", 
                                 min=0, max=100, 
                                 help="Nível de confiança (0-100)"),
    tags: str = typer.Option("", "--tags", help="Tags separadas por vírgula"),
    notes: str = typer.Option("", "--notes", "-n", help="Notas adicionais"),
):
    """Adiciona um novo IOC à base de inteligência local."""
    try:
        # Valida o tipo de IOC
        ioc_type_enum = IOCType(ioc_type.lower())
        threat_type_enum = ThreatType(threat_type.lower())
        
        # Cria o IOC
        ioc = IOC(
            value=value,
            ioc_type=ioc_type_enum,
            threat_type=threat_type_enum,
            source=source,
            confidence=confidence,
            tags=[t.strip() for t in tags.split(",") if t.strip()],
            metadata={"notes": notes} if notes else {}
        )
        
        # Adiciona ao sistema
        intel = _get_intel()
        if intel.add_ioc(ioc):
            console.print(f"✅ [green]IOC adicionado com sucesso![/green]")
            _display_ioc(ioc)
        else:
            console.print("[red]❌ Falha ao adicionar IOC.[/red]")
            
    except ValueError as e:
        console.print(f"[red]❌ Erro: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command("search")
def search_iocs(
    query: str = typer.Argument(..., help="Termo de busca"),
    limit: int = typer.Option(20, "--limit", "-l", help="Número máximo de resultados"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
    format: str = typer.Option("table", "--format", "-f", 
                             help="Formato de saída: table, json, yaml, csv")
):
    """Busca IOCs na base de inteligência local."""
    intel = _get_intel()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Buscando IOCs...", total=None)
        results = intel.search_iocs(query, limit=limit)
    
    if not results:
        console.print("[yellow]Nenhum IOC encontrado.[/yellow]")
        return
    
    # Formata a saída
    if output:
        _export_results(results, output, format)
        console.print(f"✅ Resultados exportados para [cyan]{output}[/cyan]")
    else:
        if format == "table":
            _display_iocs_table(results)
        else:
            _export_results(results, None, format)

@app.command("get")
def get_ioc(
    ioc_type: str = typer.Argument(..., help=f"Tipo do IOC: {', '.join(IOC_TYPES)}",
                                 autocompletion=lambda: IOC_TYPES),
    value: str = typer.Argument(..., help="Valor do IOC"),
):
    """Obtém detalhes de um IOC específico."""
    intel = _get_intel()
    
    try:
        ioc = intel.get_ioc(ioc_type, value)
        if not ioc:
            console.print("[yellow]IOC não encontrado.[/yellow]")
            return
            
        _display_ioc(ioc)
        
        # Mostra IOCs relacionados
        related = intel.get_related_iocs(ioc)
        if any(related.values()):
            console.print("\n[bold]Relacionados:[/bold]")
            for rel_type, items in related.items():
                if items:
                    console.print(f"  [cyan]{rel_type.title()}:[/cyan]")
                    for item in items[:3]:  # Mostra no máximo 3 itens por categoria
                        console.print(f"    • {item.value} ([yellow]{item.threat_type.value}[/yellow])")
    except ValueError as e:
        console.print(f"[red]❌ Erro: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command("import")
def import_iocs(
    file_path: Path = typer.Argument(..., help="Arquivo para importar"),
    format: str = typer.Option("auto", "--format", "-f", 
                             help="Formato do arquivo: auto, json, yaml, csv"),
):
    """Importa IOCs de um arquivo."""
    if not file_path.exists():
        console.print(f"[red]❌ Arquivo não encontrado: {file_path}[/red]")
        raise typer.Exit(1)
    
    try:
        intel = _get_intel()
        count = intel.import_iocs(file_path, format)
        console.print(f"✅ [green]Importados {count} IOCs com sucesso![/green]")
    except Exception as e:
        console.print(f"[red]❌ Erro ao importar IOCs: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command("export")
def export_iocs(
    output_file: Path = typer.Argument(..., help="Arquivo de saída"),
    format: str = typer.Option("json", "--format", "-f", 
                             help="Formato de saída: json, yaml, csv"),
    query: Optional[str] = typer.Option(None, "--query", "-q", 
                                      help="Filtrar IOCs por termo"),
):
    """Exporta IOCs para um arquivo."""
    try:
        intel = _get_intel()
        
        if query:
            # Exporta apenas os IOCs que correspondem à consulta
            iocs = intel.search_iocs(query, limit=1000)  # Limite razoável
            if not iocs:
                console.print("[yellow]Nenhum IOC encontrado para exportar.[/yellow]")
                return
                
            # Converte para dicionários
            ioc_dicts = [ioc.to_dict() for ioc in iocs]
            
            # Salva no formato especificado
            save_iocs_to_file(ioc_dicts, output_file, format)
        else:
            # Exporta todos os IOCs
            intel.export_iocs(output_file, format)
            
        console.print(f"✅ [green]IOCs exportados para [cyan]{output_file}[/cyan] no formato {format.upper()}[/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Erro ao exportar IOCs: {str(e)}[/red]")
        raise typer.Exit(1)

@app.command("update")
def update_signatures(
    force: bool = typer.Option(False, "--force", "-f", 
                             help="Forçar atualização mesmo se não for necessário")
):
    """Atualiza as assinaturas de ameaças a partir das fontes configuradas."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="Atualizando assinaturas...", total=None)
        
        try:
            intel = _get_intel()
            updated = intel.update_signatures(force=force)
            
            if updated:
                console.print("✅ [green]Assinaturas atualizadas com sucesso![/green]")
            else:
                console.print("ℹ️  [yellow]As assinaturas já estão atualizadas.[/yellow]")
                
        except Exception as e:
            console.print(f"[red]❌ Erro ao atualizar assinaturas: {str(e)}[/red]")
            raise typer.Exit(1)

def _display_ioc(ioc: IOC):
    """Exibe os detalhes de um IOC formatado."""
    from rich.panel import Panel
    from rich.text import Text
    from rich.syntax import Syntax
    
    # Cabeçalho com tipo e valor
    header = Text()
    header.append(f"{ioc.ioc_type.value.upper()}: ", style="bold")
    header.append(ioc.value, style="bold green")
    
    # Detalhes
    details = []
    details.append(f"[cyan]Ameaça:[/cyan] [yellow]{ioc.threat_type.value}[/yellow]")
    details.append(f"[cyan]Fonte:[/cyan] {ioc.source}")
    details.append(f"[cyan]Confiança:[/cyan] {ioc.confidence}/100")
    
    if ioc.tags:
        tags = ", ".join(f"[yellow]{t}[/yellow]" for t in ioc.tags)
        details.append(f"[cyan]Tags:[/cyan] {tags}")
    
    if ioc.first_seen:
        details.append(f"[cyan]Primeira vez visto:[/cyan] {ioc.first_seen}")
    
    if ioc.last_seen:
        details.append(f"[cyan]Última vez visto:[/cyan] {ioc.last_seen}")
    
    # Metadados adicionais
    if ioc.metadata:
        details.append("\n[bold]Metadados:[/bold]")
        for k, v in ioc.metadata.items():
            details.append(f"  [cyan]{k}:[/cyan] {v}")
    
    # Cria o painel
    panel = Panel(
        "\n".join(details),
        title=header,
        border_style="blue",
        expand=False
    )
    
    console.print(panel)

def _display_iocs_table(iocs: List[IOC]):
    """Exibe uma tabela com múltiplos IOCs."""
    from rich.table import Table
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tipo", style="cyan")
    table.add_column("Valor", style="green")
    table.add_column("Ameaça", style="yellow")
    table.add_column("Fonte")
    table.add_column("Confiança", justify="right")
    table.add_column("Tags")
    
    for ioc in iocs:
        table.add_row(
            ioc.ioc_type.value.upper(),
            ioc.value,
            ioc.threat_type.value,
            ioc.source,
            str(ioc.confidence),
            ", ".join(ioc.tags) if ioc.tags else ""
        )
    
    console.print(table)

def _export_results(iocs: List[IOC], output: Optional[Path] = None, 
                  format: str = "table") -> str:
    """Exporta os resultados para o formato especificado."""
    import json
    import yaml
    import csv
    from io import StringIO
    
    # Converte para dicionários
    ioc_dicts = [ioc.to_dict() for ioc in iocs]
    
    if format == "json":
        result = json.dumps({"iocs": ioc_dicts}, indent=2, ensure_ascii=False)
    elif format in ("yaml", "yml"):
        result = yaml.safe_dump({"iocs": ioc_dicts}, allow_unicode=True)
    elif format == "csv":
        if not ioc_dicts:
            return ""
            
        # Extrai todos os campos possíveis
        all_fields = set()
        for ioc in ioc_dicts:
            all_fields.update(ioc.keys())
        
        fieldnames = sorted(all_fields)
        
        # Escreve para uma string
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ioc_dicts)
        result = output.getvalue()
    else:
        raise ValueError(f"Formato não suportado: {format}")
    
    # Se um arquivo de saída for especificado, salva nele
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write(result)
    
    return result

# Adiciona o comando ao grupo principal
def register_app(main_app):
    """Registra os comandos de inteligência na aplicação principal."""
    main_app.add_typer(app, name="intel", help="🔍 Comandos de inteligência local")
