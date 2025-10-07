"""
Módulo de utilidades do sistema para o WiFiPPLER.

Fornece funções para verificação de permissões, dependências e outras operações do sistema.
"""
import os
import sys
import subprocess
import shutil
from typing import List, Optional, Union, Dict, Any

def is_root() -> bool:
    """Verifica se o script está sendo executado como root.
    
    Returns:
        bool: True se for root, False caso contrário
    """
    return os.geteuid() == 0

def command_exists(cmd: str) -> bool:
    """Verifica se um comando existe no sistema.
    
    Args:
        cmd: Nome do comando a ser verificado
        
    Returns:
        bool: True se o comando existir, False caso contrário
    """
    return shutil.which(cmd) is not None

def check_dependencies() -> List[str]:
    """Verifica as dependências necessárias para o funcionamento do WiFiPPLER.
    
    Returns:
        List[str]: Lista de dependências ausentes
    """
    required_commands = [
        'iwconfig',
        'ifconfig',
        'iw',
        'aircrack-ng',
        'airodump-ng',
        'aireplay-ng',
        'airmon-ng',
        'macchanger'
    ]
    
    missing = []
    for cmd in required_commands:
        if not command_exists(cmd):
            missing.append(cmd)
    
    return missing

def get_os_info() -> Dict[str, str]:
    """Obtém informações sobre o sistema operacional.
    
    Returns:
        Dict[str, str]: Dicionário com informações do sistema
    """
    import platform
    
    return {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version()
    }

def ensure_root() -> None:
    """Verifica se o script está sendo executado como root.
    
    Raises:
        RuntimeError: Se não estiver sendo executado como root
    """
    if not is_root():
        raise RuntimeError("Este script requer privilégios de superusuário (root). Execute com sudo.")

def ensure_dependencies() -> None:
    """Verifica se todas as dependências estão instaladas.
    
    Raises:
        RuntimeError: Se alguma dependência estiver faltando
    """
    missing = check_dependencies()
    if missing:
        raise RuntimeError(
            f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
            "Por favor, instale-as antes de continuar."
        )

def get_available_interfaces() -> List[str]:
    """Obtém uma lista de interfaces de rede disponíveis.
    
    Returns:
        List[str]: Lista de nomes de interfaces de rede
    """
    try:
        return [
            iface for iface in os.listdir('/sys/class/net/')
            if iface != 'lo'  # Ignora interface de loopback
        ]
    except (OSError, IOError):
        return []

def get_wireless_interfaces() -> List[str]:
    """Obtém uma lista de interfaces de rede sem fio disponíveis.
    
    Returns:
        List[str]: Lista de nomes de interfaces sem fio
    """
    try:
        return [
            iface for iface in os.listdir('/sys/class/net/')
            if os.path.exists(f'/sys/class/net/{iface}/wireless')
        ]
    except (OSError, IOError):
        return []

def get_interface_info(interface: str) -> Dict[str, Any]:
    """Obtém informações detalhadas sobre uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        Dict[str, Any]: Dicionário com informações da interface
    """
    return {
        'name': interface,
        'wireless': os.path.exists(f'/sys/class/net/{interface}/wireless'),
        'state': get_interface_state(interface),
        'mac_address': get_interface_mac(interface),
        'ip_address': get_interface_ip(interface)
    }

def get_interface_state(interface: str) -> str:
    """Obtém o estado atual de uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        str: Estado da interface (up/down/unknown)
    """
    try:
        with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
            return f.read().strip()
    except (OSError, IOError):
        return 'unknown'
