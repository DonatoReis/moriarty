"""
WifiPPLER - Ferramenta Avançada de Análise de Segurança WiFi

Uma ferramenta abrangente de auditoria de segurança WiFi que combina os melhores
recursos de ferramentas existentes com técnicas modernas e uma interface limpa.

Módulos principais:
- scanner: Escaneamento de redes WiFi
- attacks: Implementações de ataques de segurança
- models: Modelos de dados
- utils: Funções utilitárias
- cli: Interface de linha de comando
"""

__version__ = "1.0.0"
__author__ = "Moriarty Team"
__license__ = "MIT"

# Importações principais
from .core.scanner import WiFiScanner
from .core.attacks import (
    Attack,  # Interface base para ataques
    register_attack,  # Decorador para registrar novos ataques
    get_attack,  # Obter um ataque pelo nome
    list_attacks,  # Listar todos os ataques disponíveis
)

# Importar ataques padrão para registro
from .core.attacks import (
    WPSAttack,
    WPAHandshakeAttack,
    PMKIDAttack,
    WEPAttack,
    DeauthAttack,
    HandshakeCapture
)

# Utilitários comuns
from .core.utils import (
    is_root,
    check_dependencies,
    get_network_interfaces,
    get_wireless_interfaces,
    set_monitor_mode,
    restore_network_interface,
    start_monitor_mode,
    stop_monitor_mode,
    get_monitor_interfaces,
)

# Modelos de dados
from .core.models.network import WiFiNetwork, WiFiClient

# Interface CLI
from .cli.commands import app as cli_app

__all__ = [
    # Classes principais
    'WiFiScanner',
    
    # Sistema de ataques
    'Attack',
    'register_attack',
    'get_attack',
    'list_attacks',
    
    # Ataques específicos
    'WPSAttack',
    'WPAHandshakeAttack',
    'PMKIDAttack',
    'WEPAttack',
    'DeauthAttack',
    'HandshakeCapture',
    
    # Utilitários
    'is_root',
    'check_dependencies',
    'get_network_interfaces',
    'get_wireless_interfaces',
    'set_monitor_mode',
    'restore_network_interface',
    'start_monitor_mode',
    'stop_monitor_mode',
    'get_monitor_interfaces',
    
    # Modelos
    'WiFiNetwork',
    'WiFiClient',
    
    # CLI
    'cli_app'
]
