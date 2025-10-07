"""
Modelos de dados para redes e clientes WiFi.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum, auto
import json


class WiFiSecurityType(Enum):
    """Tipos de segurança WiFi suportados."""
    NONE = auto()
    WEP = auto()
    WPA = auto()
    WPA2 = auto()
    WPA3 = auto()
    WPA2_ENTERPRISE = auto()
    WPA3_ENTERPRISE = auto()
    OWE = auto()  # Opportunistic Wireless Encryption (OWE)
    WPS = auto()   # WiFi Protected Setup


# Mapeamento de códigos de segurança para WiFiSecurityType
SECURITY_MAP = {
    'WPA2': WiFiSecurityType.WPA2,
    'WPA3': WiFiSecurityType.WPA3,
    'WPA2-EAP': WiFiSecurityType.WPA2_ENTERPRISE,
    'WPA3-EAP': WiFiSecurityType.WPA3_ENTERPRISE,
    'WEP': WiFiSecurityType.WEP,
    'OPEN': WiFiSecurityType.NONE,
    'NONE': WiFiSecurityType.NONE,
    'WPA': WiFiSecurityType.WPA,
    'WPA2-PSK': WiFiSecurityType.WPA2,
    'WPA3-PSK': WiFiSecurityType.WPA3,
    'WPA2-PSK-CCMP': WiFiSecurityType.WPA2,
    'WPA2-PSK-TKIP': WiFiSecurityType.WPA2,
    'WPA-PSK': WiFiSecurityType.WPA,
    'WPA-PSK-CCMP': WiFiSecurityType.WPA,
    'WPA-PSK-TKIP': WiFiSecurityType.WPA,
    'WPA2-ENTERPRISE': WiFiSecurityType.WPA2_ENTERPRISE,
    'WPA3-ENTERPRISE': WiFiSecurityType.WPA3_ENTERPRISE,
    'OWE': WiFiSecurityType.OWE,
    'WPS': WiFiSecurityType.WPS,
}


class WiFiCipherType(Enum):
    """Tipos de cifra suportados."""
    NONE = auto()
    WEP_40 = auto()
    WEP_104 = auto()
    TKIP = auto()
    CCMP = auto()
    GCMP = auto()


class WiFiAuthType(Enum):
    """Tipos de autenticação suportados."""
    OPEN = auto()
    SHARED = auto()
    WPA_PSK = auto()
    WPA_EAP = auto()
    WPA2_PSK = auto()
    WPA2_EAP = auto()
    WPA3_SAE = auto()
    WPA3_EAP = auto()
    OWE = auto()


@dataclass
class WiFiNetwork:
    """Representa uma rede WiFi descoberta."""
    # Identificação
    bssid: str
    ssid: str
    channel: int
    frequency: int  # Em MHz
    band: str  # 2.4GHz, 5GHz, 6GHz, etc.
    
    # Sinal e qualidade
    signal_dbm: int  # Potência do sinal em dBm
    signal_percent: int  # Porcentagem de qualidade do sinal (0-100%)
    noise_dbm: int  # Nível de ruído em dBm
    
    # Segurança
    security: WiFiSecurityType
    encryption: str  # Ex: WPA2, WPA3, WEP, etc.
    cipher: WiFiCipherType
    auth: WiFiAuthType
    
    # WPS (WiFi Protected Setup)
    wps: bool = False
    wps_locked: bool = False
    wps_version: str = ""
    wps_state: str = ""
    
    # Clientes conectados
    clients: List['WiFiClient'] = field(default_factory=list)
    
    # Metadados
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    vendor: str = ""  # Fabricante do roteador baseado no OUI do BSSID
    country: str = ""  # Código do país
    
    # Flags adicionais
    is_hidden: bool = False
    is_associated: bool = False
    is_internet: bool = False  # Se a rede tem acesso à internet
    
    # Estatísticas
    beacon: int = 0
    data: int = 0
    data_rate: float = 0.0  # Em Mbps
    
    # Informações adicionais
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o objeto para dicionário."""
        data = asdict(self)
        # Converte enums para strings
        data['security'] = self.security.name
        data['cipher'] = self.cipher.name
        data['auth'] = self.auth.name
        # Converte datetimes para strings ISO
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        # Converte clientes para dicionários
        data['clients'] = [client.to_dict() for client in self.clients]
        return data
    
    def to_json(self, indent: int = 2) -> str:
        """Converte o objeto para JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def update_signal(self, signal_dbm: int, noise_dbm: int):
        """Atualiza as métricas de sinal."""
        self.signal_dbm = signal_dbm
        self.noise_dbm = noise_dbm
        self.signal_percent = self._calculate_signal_percentage(signal_dbm, noise_dbm)
        self.last_seen = datetime.utcnow()
    
    def add_client(self, client: 'WiFiClient'):
        """Adiciona um cliente à rede."""
        # Verifica se o cliente já existe
        for idx, c in enumerate(self.clients):
            if c.mac == client.mac:
                self.clients[idx] = client
                return
        self.clients.append(client)
    
    def remove_client(self, mac: str) -> bool:
        """Remove um cliente da rede."""
        for idx, client in enumerate(self.clients):
            if client.mac == mac:
                self.clients.pop(idx)
                return True
        return False
    
    @staticmethod
    def _calculate_signal_percentage(signal_dbm: int, noise_dbm: int) -> int:
        """Calcula a porcentagem de qualidade do sinal."""
        # Se não houver sinal, retorna 0%
        if signal_dbm == 0 or signal_dbm <= -100:
            return 0
        
        # Se o sinal for maior que -50dBm, retorna 100%
        if signal_dbm >= -50:
            return 100
        
        # Calcula a porcentagem baseada na força do sinal
        # Considerando -100dBm como 0% e -50dBm como 100%
        return 2 * (signal_dbm + 100)


@dataclass
class WiFiClient:
    """Representa um cliente conectado a uma rede WiFi."""
    # Identificação
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""  # Fabricante baseado no OUI do MAC
    
    # Sinal e conexão
    signal_dbm: int = 0
    signal_percent: int = 0
    rx_rate: float = 0.0  # Em Mbps
    tx_rate: float = 0.0  # Em Mbps
    
    # Metadados
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    
    # Informações adicionais
    is_associated: bool = False
    is_authenticated: bool = False
    is_wps: bool = False
    
    # Estatísticas
    packets: int = 0
    data: int = 0  # Em bytes
    
    # Informações adicionais
    extra: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o objeto para dicionário."""
        data = asdict(self)
        # Converte datetimes para strings ISO
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        return data
    
    def to_json(self, indent: int = 2) -> str:
        """Converte o objeto para JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    def update_signal(self, signal_dbm: int):
        """Atualiza as métricas de sinal."""
        self.signal_dbm = signal_dbm
        self.signal_percent = self._calculate_signal_percentage(signal_dbm)
        self.last_seen = datetime.utcnow()
    
    @staticmethod
    def _calculate_signal_percentage(signal_dbm: int) -> int:
        """Calcula a porcentagem de qualidade do sinal."""
        # Se não houver sinal, retorna 0%
        if signal_dbm == 0 or signal_dbm <= -100:
            return 0
        
        # Se o sinal for maior que -50dBm, retorna 100%
        if signal_dbm >= -50:
            return 100
        
        # Calcula a porcentagem baseada na força do sinal
        # Considerando -100dBm como 0% e -50dBm como 100%
        return 2 * (signal_dbm + 100)
