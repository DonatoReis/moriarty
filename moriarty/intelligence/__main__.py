"""Ponto de entrada principal para o módulo de inteligência."""

import sys
import logging
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.logging import RichHandler

from . import __version__
from .config import init_config, get_config
from .cli import app as cli_app

# Configura o logger
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

# Desativa logs de bibliotecas de terceiros
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

# Cria o logger para este módulo
logger = logging.getLogger("moriarty.intelligence")

# Cria a aplicação principal
app = typer.Typer(
    name="moriarty-intel",
    help="Ferramenta de inteligência de ameaças do Moriarty",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# Adiciona os comandos da CLI
app.add_typer(cli_app, name="cli")

# Console rico para saída formatada
console = Console()

def version_callback(value: bool):
    """Mostra a versão e sai."""
    if value:
        console.print(f"[bold blue]Moriarty Intelligence[/] [green]v{__version__}[/]")
        raise typer.Exit()

@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Mostra a versão e sai.",
        callback=version_callback,
        is_eager=True
    ),
    config: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Caminho para o arquivo de configuração.",
        envvar="MORIARTY_CONFIG"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Ativa o modo verboso."
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Ativa o modo de depuração."
    )
):
    """Ferramenta de inteligência de ameaças do Moriarty.
    
    Uma ferramenta poderosa para coleta, análise e gerenciamento de 
    inteligência sobre ameaças cibernéticas.
    """
    # Configura o nível de log
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    elif verbose:
        logging.getLogger().setLevel(logging.INFO)
        logger.setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
        logger.setLevel(logging.WARNING)
    
    # Inicializa a configuração
    try:
        init_config(config)
        logger.debug("Configuração carregada com sucesso")
    except Exception as e:
        logger.error(f"Erro ao carregar a configuração: {e}")
        if debug:
            logger.exception("Detalhes do erro:")
        raise typer.Exit(1)

# Comandos principais
@app.command()
def init():
    """Inicializa o ambiente do Moriarty Intelligence."""
    from rich.panel import Panel
    from rich.text import Text
    
    config = get_config()
    config_dir = Path(config['storage.path']).parent
    
    console.print(Panel.fit(
        "[bold blue]Inicializando o ambiente do Moriarty Intelligence[/]\n\n"
        f"[bold]Diretório de configuração:[/] {config_dir}\n"
        f"[bold]Banco de dados:[/] {config['storage.path']}\n"
        f"[bold]Arquivo de log:[/] {config['logging.file']}",
        title="Moriarty Intelligence",
        border_style="blue"
    ))
    
    # Cria o diretório de configuração se não existir
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Cria o diretório de assinaturas se não existir
    sig_dir = Path(config['signatures.sources[0].path'])
    sig_dir.mkdir(parents=True, exist_ok=True)
    
    # Salva a configuração padrão se o arquivo não existir
    config_file = config_dir / 'intelligence_config.json'
    if not config_file.exists():
        config.save(config_file)
        console.print(f"[green]✓[/] Arquivo de configuração criado em {config_file}")
    
    console.print("\n[bold]Configuração concluída com sucesso![/]")
    console.print("\nUse [bold]moriarty-intel --help[/] para ver os comandos disponíveis.")

# Ponto de entrada
if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        logger.error(f"Erro inesperado: {e}", exc_info=True)
        raise typer.Exit(1)
