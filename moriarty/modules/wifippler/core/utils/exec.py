"""
Módulo de execução de comandos para o WiFiPPLER.

Fornece funções para execução segura de comandos de sistema.
"""
import asyncio
import shlex
import logging
import subprocess
from typing import List, Optional, Union, Dict, Any, Tuple

logger = logging.getLogger(__name__)

def run_command(
    cmd: Union[str, List[str]],
    capture_output: bool = False,
    check: bool = True,
    **kwargs
) -> subprocess.CompletedProcess:
    """Executa um comando no shell com tratamento de erros.
    
    Args:
        cmd: Comando a ser executado (string ou lista)
        capture_output: Se deve capturar a saída padrão e de erro
        check: Se deve lançar uma exceção em caso de código de saída diferente de zero
        **kwargs: Argumentos adicionais para subprocess.run()
        
    Returns:
        subprocess.CompletedProcess: Resultado da execução do comando
        
    Raises:
        subprocess.CalledProcessError: Se check=True e o comando retornar código de saída não zero
    """
    # Configura os argumentos padrão
    kwargs.setdefault('stdout', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('stderr', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('text', True)
    
    # Converte o comando para lista se for string
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    
    # Executa o comando
    try:
        logger.debug(f"Executando comando: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=check, **kwargs)
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar comando: {e}")
        if capture_output:
            logger.error(f"Saída de erro: {e.stderr}")
        raise
    except Exception as e:
        logger.error(f"Erro inesperado ao executar comando: {e}")
        raise

async def run_command_async(
    cmd: Union[str, List[str]],
    **kwargs
) -> subprocess.CompletedProcess:
    """Executa um comando de forma assíncrona.
    
    Args:
        cmd: Comando a ser executado (string ou lista)
        **kwargs: Argumentos adicionais para asyncio.create_subprocess_exec()
        
    Returns:
        subprocess.CompletedProcess: Resultado da execução do comando
    """
    # Converte o comando para lista se for string
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    
    # Configura os argumentos padrão
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)
    kwargs.setdefault('text', True)
    
    logger.debug(f"Executando comando assíncrono: {' '.join(cmd)}")
    
    try:
        # Cria o processo assíncrono
        process = await asyncio.create_subprocess_exec(
            cmd[0],
            *cmd[1:],
            **kwargs
        )
        
        # Aguarda a conclusão do processo
        stdout, stderr = await process.communicate()
        
        # Cria um objeto CompletedProcess com o resultado
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr
        )
    except Exception as e:
        logger.error(f"Erro ao executar comando assíncrono: {e}")
        raise

def run_sudo_command(
    cmd: Union[str, List[str]],
    password: Optional[str] = None,
    **kwargs
) -> subprocess.CompletedProcess:
    """Executa um comando com privilégios de superusuário.
    
    Args:
        cmd: Comando a ser executado (sem o 'sudo')
        password: Senha do usuário (opcional, pode ser solicitada interativamente)
        **kwargs: Argumentos adicionais para run_command()
        
    Returns:
        subprocess.CompletedProcess: Resultado da execução do comando
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    
    # Adiciona o sudo ao início do comando
    sudo_cmd = ['sudo']
    
    # Se uma senha for fornecida, usa o -S para ler do stdin
    if password is not None:
        sudo_cmd.extend(['-S'])
    
    sudo_cmd.extend(cmd)
    
    # Se uma senha for fornecida, envia pelo stdin
    if password is not None:
        kwargs['input'] = f"{password}\n"
    
    return run_command(sudo_cmd, **kwargs)

def command_success(cmd: str) -> bool:
    """Verifica se um comando é executado com sucesso.
    
    Args:
        cmd: Comando a ser verificado
        
    Returns:
        bool: True se o comando for executado com sucesso, False caso contrário
    """
    try:
        run_command(cmd, capture_output=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_command_output(cmd: Union[str, List[str]], **kwargs) -> str:
    """Executa um comando e retorna sua saída padrão.
    
    Args:
        cmd: Comando a ser executado
        **kwargs: Argumentos adicionais para run_command()
        
    Returns:
        str: Saída padrão do comando
        
    Raises:
        subprocess.CalledProcessError: Se o comando retornar código de saída não zero
    """
    kwargs['capture_output'] = True
    result = run_command(cmd, **kwargs)
    return result.stdout.strip()

def get_command_output_safe(cmd: Union[str, List[str]], default: str = "", **kwargs) -> str:
    """Executa um comando e retorna sua saída padrão ou um valor padrão em caso de erro.
    
    Args:
        cmd: Comando a ser executado
        default: Valor padrão a ser retornado em caso de erro
        **kwargs: Argumentos adicionais para run_command()
        
    Returns:
        str: Saída padrão do comando ou o valor padrão em caso de erro
    """
    try:
        return get_command_output(cmd, **kwargs)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return default
