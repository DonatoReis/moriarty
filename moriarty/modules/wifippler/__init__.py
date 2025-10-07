"""
WifiPPLER - Ferramenta Avançada de Análise de Segurança WiFi

Uma ferramenta abrangente de auditoria de segurança WiFi que combina os melhores
recursos de ferramentas existentes com técnicas modernas e uma interface limpa.
"""

__version__ = "1.0.0"
__author__ = "Moriarty Team"
__license__ = "MIT"

# Importações principais
from .core.scanner import WiFiScanner
from .core.attacks import (
    WPSAttack,
    WPAHandshakeAttack,
    PMKIDAttack,
    WEPAttack,
    DeauthAttack,
    HandshakeCapture
)

# Utilitários
from .core.utils import (
    is_root,
    check_dependencies,
    get_network_interfaces,
    set_monitor_mode,
    restore_network_interface,
    get_monitor_interfaces,
    start_monitor_mode,
    stop_monitor_mode
)

# Modelos de dados
from .core.models.network import WiFiNetwork, WiFiClient

__all__ = [
    # Classes principais
    'WiFiScanner',
    
    # Ataques
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
    'set_monitor_mode',
    'restore_network_interface',
    'get_monitor_interfaces',
    'start_monitor_mode',
    'stop_monitor_mode',
    
    # Modelos
    'WiFiNetwork',
    'WiFiClient'
]
