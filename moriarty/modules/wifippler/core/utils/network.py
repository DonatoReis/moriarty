"""
Módulo de utilidades de rede para o WiFiPPLER.

Fornece funções para manipulação de interfaces de rede, endereçamento e operações relacionadas.
"""
import os
import re
import socket
import fcntl
import struct
import array
import platform
from typing import Dict, List, Optional, Union, Any

# Constantes para chamadas de sistema
SIOCGIFHWADDR = 0x8927  # Get hardware address
SIOCGIFADDR = 0x8915    # Get IP address
SIOCGIFNETMASK = 0x891B  # Get netmask
SIOCGIFBRDADDR = 0x8919  # Get broadcast address
SIOCGIFMTU = 0x8921     # Get MTU
SIOCGIFINDEX = 0x8933   # Get interface index
SIOCGIFNAME = 0x8910    # Get interface name
SIOCGIFFLAGS = 0x8913   # Get interface flags
SIOCSIFFLAGS = 0x8914   # Set interface flags

# Flags de interface
IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_DEBUG = 0x4
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10
IFF_NOTRAILERS = 0x20
IFF_RUNNING = 0x40
IFF_NOARP = 0x80
IFF_PROMISC = 0x100
IFF_ALLMULTI = 0x200
IFF_MASTER = 0x400
IFF_SLAVE = 0x800
IFF_MULTICAST = 0x1000
IFF_PORTSEL = 0x2000
IFF_AUTOMEDIA = 0x4000
IFF_DYNAMIC = 0x8000
IFF_LOWER_UP = 0x10000
IFF_DORMANT = 0x20000
IFF_ECHO = 0x40000

def get_interface_mac(interface: str) -> Optional[str]:
    """Obtém o endereço MAC de uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        str: Endereço MAC formatado ou None se não encontrado
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', interface[:15].encode('utf-8')))
        return ':'.join(f'{b:02x}' for b in info[18:24])
    except (IOError, OSError):
        return None

def get_interface_ip(interface: str) -> Optional[str]:
    """Obtém o endereço IP de uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        str: Endereço IP ou None se não encontrado
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            SIOCGIFADDR,
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24])
    except (IOError, OSError):
        return None

def get_interface_netmask(interface: str) -> Optional[str]:
    """Obtém a máscara de rede de uma interface.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        str: Máscara de rede ou None se não encontrada
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            SIOCGIFNETMASK,
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[20:24])
    except (IOError, OSError):
        return None

def get_interface_gateway(interface: str) -> Optional[str]:
    """Obtém o gateway padrão de uma interface.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        str: Endereço do gateway ou None se não encontrado
    """
    try:
        # Lê a tabela de roteamento
        with open('/proc/net/route') as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 2 and fields[0] == interface and fields[1] == '00000000':
                    # Converte o endereço hex para IP
                    return socket.inet_ntoa(struct.pack('<L', int(fields[2], 16)))
    except (IOError, OSError):
        pass
    return None

def is_wireless_interface(interface: str) -> bool:
    """Verifica se uma interface é sem fio.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        bool: True se for uma interface sem fio, False caso contrário
    """
    # Verifica se a interface existe em /sys/class/net/
    if not os.path.exists(f'/sys/class/net/{interface}'):
        return False
    
    # Verifica se é uma interface wireless
    wireless_path = f'/sys/class/net/{interface}/wireless'
    return os.path.exists(wireless_path)

def get_wireless_interfaces() -> List[Dict[str, Any]]:
    """Obtém uma lista de interfaces de rede sem fio.
    
    Returns:
        List[Dict[str, Any]]: Lista de dicionários com informações das interfaces
    """
    interfaces = []
    
    # Lista todos os diretórios em /sys/class/net
    for iface in os.listdir('/sys/class/net'):
        if is_wireless_interface(iface):
            interfaces.append({
                'name': iface,
                'mac': get_interface_mac(iface),
                'ip': get_interface_ip(iface),
                'wireless': True,
                'up': is_interface_up(iface),
                'mtu': get_interface_mtu(iface)
            })
    
    return interfaces

def is_interface_up(interface: str) -> bool:
    """Verifica se uma interface de rede está ativa.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        bool: True se a interface estiver ativa, False caso contrário
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        flags = struct.unpack('H', fcntl.ioctl(
            s.fileno(),
            SIOCGIFFLAGS,
            struct.pack('256s', interface[:15].encode('utf-8'))
        )[16:18])[0]
        return bool(flags & IFF_UP)
    except (IOError, OSError):
        return False

def get_interface_mtu(interface: str) -> int:
    """Obtém o MTU de uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        int: Valor do MTU ou 1500 (padrão) se não for possível obter
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('256s', interface.encode('utf-8')[:15])
        mtu = fcntl.ioctl(s.fileno(), SIOCGIFMTU, ifreq)
        return struct.unpack('H', mtu[16:18])[0]
    except (IOError, OSError, struct.error):
        return 1500  # Valor padrão para MTU


def get_network_interfaces() -> List[Dict[str, Any]]:
    """Obtém uma lista de todas as interfaces de rede.
    
    Returns:
        List[Dict[str, Any]]: Lista de dicionários com informações das interfaces
    """
    interfaces = []
    
    try:
        # Lista todos os diretórios em /sys/class/net
        for iface in os.listdir('/sys/class/net'):
            if iface == 'lo':  # Ignora a interface de loopback
                continue
                
            # Verifica se é uma interface wireless
            is_wireless = is_wireless_interface(iface)
            
            interfaces.append({
                'name': iface,
                'mac': get_interface_mac(iface),
                'ip': get_interface_ip(iface),
                'wireless': is_wireless,
                'up': is_interface_up(iface),
                'mtu': get_interface_mtu(iface)
            })
    except Exception as e:
        print(f"Erro ao listar interfaces de rede: {e}")
    
    return interfaces


def get_monitor_interfaces() -> List[Dict[str, Any]]:
    """Obtém uma lista de interfaces de rede em modo monitor.
    
    Returns:
        List[Dict[str, Any]]: Lista de dicionários com informações das interfaces em modo monitor
    """
    monitor_interfaces = []
    
    try:
        # Obtém todas as interfaces de rede
        interfaces = get_network_interfaces()
        
        # Filtra apenas as interfaces sem fio
        wireless_interfaces = [iface for iface in interfaces if iface.get('wireless')]
        
        # Verifica quais interfaces estão em modo monitor
        for iface in wireless_interfaces:
            ifname = iface['name']
            
            # Verifica se a interface está em modo monitor
            try:
                with open(f'/sys/class/net/{ifname}/type', 'r') as f:
                    iftype = int(f.read().strip())
                    # O tipo 803 indica modo monitor (IEEE80211_IF_TYPE_MONITOR)
                    if iftype == 803:
                        monitor_interfaces.append(iface)
            except (IOError, ValueError):
                continue
                
    except Exception as e:
        print(f"Erro ao listar interfaces em modo monitor: {e}")
    
    return monitor_interfaces
