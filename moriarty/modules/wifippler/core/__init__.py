"""
Módulo principal do WiFiPPLER.

Este pacote contém a funcionalidade central da ferramenta WiFiPPLER,
incluindo escaneamento de rede, análise de pacotes e módulos de ataque.
"""

# Importações principais
from .scanner import WiFiScanner

# Sistema de registro de ataques
from .attacks import (
    Attack,
    register_attack,
    get_attack,
    list_attacks,
    
    # Ataques padrão
    WPSAttack,
    WPAHandshakeAttack,
    PMKIDAttack,
    WEPAttack,
    DeauthAttack,
    HandshakeCapture
)

# Importar apenas o necessário do módulo utils
from .utils import (
    # Funções básicas
    is_root,
    check_dependencies,
    
    # Funções de rede
    get_network_interfaces,
    get_wireless_interfaces,
    get_monitor_interfaces,
    
    # Controle de modo monitor
    set_monitor_mode,
    restore_network_interface,
    start_monitor_mode,
    stop_monitor_mode,
    
    # Funções de interface
    get_interface_mac,
    get_interface_ip,
    get_interface_netmask,
    get_interface_gateway,
    is_wireless_interface,
    
    # Utilitários de linha de comando
    run_command,
    run_command_async,
    command_exists,
)

# Exportar apenas a API pública
__all__ = [
    # Scanner
    'WiFiScanner',
    
    # Sistema de ataques
    'Attack',
    'register_attack',
    'get_attack',
    'list_attacks',
    
    # Ataques
    'WPSAttack',
    'WPAHandshakeAttack',
    'PMKIDAttack',
    'WEPAttack',
    'DeauthAttack',
    'HandshakeCapture',
    
    # Funções de utilidade
    'is_root',
    'check_dependencies',
    'get_network_interfaces',
    'get_wireless_interfaces',
    'get_monitor_interfaces',
    'set_monitor_mode',
    'restore_network_interface',
    'start_monitor_mode',
    'stop_monitor_mode',
    'get_interface_mac',
    'get_interface_ip',
    'get_interface_netmask',
    'get_interface_gateway',
    'is_wireless_interface',
    'run_command',
    'run_command_async',
    'command_exists',
]
