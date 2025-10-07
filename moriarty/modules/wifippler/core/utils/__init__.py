"""
Módulo de utilidades do WiFiPPLER.

Este módulo fornece funções auxiliares para operações comuns de rede e sistema.
"""
import os
import subprocess
from typing import Optional, List, Dict, Any, Union

# Importações principais
from ..models.network import WiFiCipherType, WiFiAuthType, WiFiNetwork, WiFiClient

from .network import (
    get_interface_ip,
    get_interface_netmask,
    get_interface_gateway,
    is_wireless_interface,
    get_network_interfaces,
    is_interface_up,
    get_interface_mac,
    get_monitor_interfaces
)

from .system import (
    is_root,
    check_dependencies,
    command_exists,
    ensure_root,
    ensure_dependencies,
    get_available_interfaces,
    get_wireless_interfaces
)

from .exec import (
    run_command,
    run_command_async,
    run_sudo_command,
    command_success,
    get_command_output,
    get_command_output_safe
)

# Configuração de logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Exporta apenas o que é necessário para uso externo
__all__ = [
    # Funções de rede
    'get_interface_ip',
    'get_interface_netmask',
    'get_interface_gateway',
    'is_wireless_interface',
    'get_network_interfaces',
    'is_interface_up',
    'get_interface_mac',
    
    # Funções do sistema
    'is_root',
    'check_dependencies',
    'command_exists',
    'ensure_root',
    'ensure_dependencies',
    'get_available_interfaces',
    'get_wireless_interfaces',
    
    # Funções de execução de comandos
    'run_command',
    'run_command_async',
    'run_sudo_command',
    'command_success',
    'get_command_output',
    'get_command_output_safe',
    
    # Logger
    'logger'
]
SIOCGIFNETMASK = 0x891B
SIOCGIFBRDADDR = 0x8919
SIOCGIFMTU = 0x8921
SIOCGIFINDEX = 0x8933
SIOCGIFNAME = 0x8910
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

# O mapeamento de códigos de segurança foi movido para core/models/network.py

# Mapeamento de cifras
CIPHER_MAP = {
    'CCMP': WiFiCipherType.CCMP,
    'TKIP': WiFiCipherType.TKIP,
    'WEP': WiFiCipherType.WEP_40,  # Usando WEP_40 como padrão para WEP
    'WEP-40': WiFiCipherType.WEP_40,
    'WEP-104': WiFiCipherType.WEP_104,
    'WEP-128': WiFiCipherType.WEP_104,  # WEP-128 não está definido, usando WEP_104 como alternativa
    'NONE': WiFiCipherType.NONE,
    'GCMP': WiFiCipherType.GCMP
}

# Mapeamento de autenticação
AUTH_MAP = {
    'PSK': WiFiAuthType.WPA_PSK,  # Usando WPA_PSK para PSK
    'WPA-PSK': WiFiAuthType.WPA_PSK,
    'WPA2-PSK': WiFiAuthType.WPA2_PSK,
    'WPA3-SAE': WiFiAuthType.WPA3_SAE,
    'EAP': WiFiAuthType.WPA_EAP,  # Usando WPA_EAP para EAP
    'WPA-EAP': WiFiAuthType.WPA_EAP,
    'WPA2-EAP': WiFiAuthType.WPA2_EAP,
    'WPA3-EAP': WiFiAuthType.WPA3_EAP,
    'OPEN': WiFiAuthType.OPEN,
    'SHARED': WiFiAuthType.SHARED,
    'OWE': WiFiAuthType.OWE,
    'NONE': WiFiAuthType.OPEN,
}

def is_root() -> bool:
    """Verifica se o script está sendo executado como root."""
    return os.geteuid() == 0

def check_dependencies() -> List[str]:
    """Verifica as dependências necessárias."""
    required = ['iwconfig', 'iwlist', 'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'airmon-ng']
    missing = []
    
    for dep in required:
        if not command_exists(dep):
            missing.append(dep)
    

def command_exists(cmd: str) -> bool:
    """Verifica se um comando existe no sistema."""
    return shutil.which(cmd) is not None

# A função get_wireless_interfaces já está definida acima, então não precisamos duplicá-la

def run_command(cmd: Union[str, List[str]], capture_output: bool = False, 
               check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """
    Executa um comando no shell com tratamento de erros.
    
    Args:
        cmd: Comando a ser executado (string ou lista)
        capture_output: Se deve capturar a saída padrão e de erro
        check: Se deve lançar uma exceção em caso de código de saída diferente de zero
        **kwargs: Argumentos adicionais para subprocess.run()
        
    Returns:
        subprocess.ClosedProcess: Resultado da execução do comando
    """
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    kwargs.setdefault('stdout', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('stderr', subprocess.PIPE if capture_output else None)
    kwargs.setdefault('text', True)
    
    try:
        return subprocess.run(cmd, check=check, **kwargs)
    except Exception as e:
        logger.error(f"Erro ao executar comando: {e}")
        raise

def set_monitor_mode(interface: str, channel: int = None) -> bool:
    """Ativa o modo monitor em uma interface."""
    if not is_root():
        logger.error("Privilégios de root são necessários para ativar o modo monitor")
        return False
    
    try:
        # Para processos que podem interferir
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
        
        # Ativa o modo monitor
        cmd = ['airmon-ng', 'start', interface]
        if channel:
            cmd.extend(['-c', str(channel)])
            
        result = subprocess.run(cmd, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE,
                              text=True)
        
        if result.returncode != 0:
            logger.error(f"Falha ao ativar o modo monitor: {result.stderr}")
            return False
            
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar airmon-ng: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return False

def restore_network_interface(interface: str) -> bool:
    """Restaura a interface para o modo gerenciado."""
    if not is_root():
        logger.error("Privilégios de root são necessários para restaurar a interface")
        return False
    
    try:
        # Para o modo monitor
        subprocess.run(['airmon-ng', 'stop', interface], check=True)
        
        # Reinicia o gerenciador de rede
        if command_exists('systemctl'):
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], check=False)
        elif command_exists('service'):
            subprocess.run(['service', 'network-manager', 'restart'], check=False)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao parar o modo monitor: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return False

def start_monitor_mode(interface: str, channel: int = None) -> Optional[str]:
    """Inicia o modo monitor em uma interface usando airmon-ng."""
    if not is_root():
        logger.error("Privilégios de root são necessários para iniciar o modo monitor")
        return None
    
    try:
        # Para processos que podem interferir
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
        
        # Inicia o modo monitor
        cmd = ['airmon-ng', 'start', interface]
        if channel:
            cmd.extend(['-c', str(channel)])
            
        result = subprocess.run(cmd, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE,
                              text=True)
        
        if result.returncode != 0:
            logger.error(f"Falha ao iniciar o modo monitor: {result.stderr}")
            return None
            
        # Obtém o nome da interface em modo monitor (pode mudar, ex: wlan0 -> wlan0mon)
        for line in result.stdout.split('\n'):
            if 'monitor mode' in line and 'enabled' in line:
                parts = line.split()
                if len(parts) > 0:
                    return parts[0].strip('()')
                    
        return f"{interface}mon"  # Padrão comum
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar airmon-ng: {e}")
        return None
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return None

def stop_monitor_mode(interface: str) -> bool:
    """Para o modo monitor em uma interface usando airmon-ng."""
    if not is_root():
        logger.error("Privilégios de root são necessários para parar o modo monitor")
        return False
    
    try:
        # Para o modo monitor
        subprocess.run(['airmon-ng', 'stop', interface], check=True)
        
        # Reinicia o gerenciador de rede
        if command_exists('systemctl'):
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], check=False)
        elif command_exists('service'):
            subprocess.run(['service', 'network-manager', 'restart'], check=False)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao parar modo monitor: {e}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado: {e}")
        return False

def get_interface_mac(interface: str) -> Optional[str]:
    """Obtém o endereço MAC de uma interface de rede."""
    try:
        with open(f"/sys/class/net/{interface}/address") as f:
            return f.read().strip()
    except (IOError, FileNotFoundError):
        return None

def get_interface_ip(interface: str) -> Optional[str]:
    """Obtém o endereço IP de uma interface de rede."""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except (KeyError, IndexError):
        return None

def get_interface_netmask(interface: str) -> Optional[str]:
    """Obtém a máscara de rede de uma interface de rede."""
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
    except (KeyError, IndexError):
        return None

def get_interface_gateway(interface: str) -> Optional[str]:
    """Obtém o gateway padrão de uma interface de rede."""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except (KeyError, IndexError):
        return None

def is_wireless_interface(interface: str) -> bool:
    """Verifica se uma interface é sem fio."""
    try:
        with open(f"/sys/class/net/{interface}/wireless/uevent", 'r') as f:
            return True
    except (IOError, FileNotFoundError):
        return False

def get_interface_signal(interface: str) -> Optional[int]:
    """Obtém a intensidade do sinal de uma interface sem fio em dBm."""
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            return None
            
        match = re.search(r'Signal level=(-?\d+) dBm', result.stdout)
        if match:
            return int(match.group(1))
        return None
    except (subprocess.SubprocessError, ValueError):
        return None

def get_interface_ssid(interface: str) -> Optional[str]:
    """Obtém o SSID ao qual a interface está conectada."""
    try:
        result = subprocess.run(
            ['iwgetid', '-r', interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

def get_interface_channel(interface: str) -> Optional[int]:
    """Obtém o canal em que a interface está operando."""
    try:
        result = subprocess.run(
            ['iwlist', interface, 'channel'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            return None
            
        match = re.search(r'Channel (\d+)', result.stdout)
        if match:
            return int(match.group(1))
        return None
    except (subprocess.SubprocessError, ValueError):
        return None

def get_interface_bitrate(interface: str) -> Optional[float]:
    """Obtém a taxa de transmissão da interface em Mbps."""
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0:
            return None
            
        match = re.search(r'Bit Rate[:=]([\d.]+) (\w+)', result.stdout)
        if match:
            rate, unit = match.groups()
            rate = float(rate)
            if unit == 'Mb/s':
                return rate
            elif unit == 'Kb/s':
                return rate / 1000
        return None
    except (subprocess.SubprocessError, ValueError):
        return None

# Funções para manipulação de pacotes
def create_deauth_packet(bssid: str, client: str, reason: int = 7, count: int = 1) -> bytes:
    """Cria um pacote de desautenticação."""
    # Cabeçalho do pacote 802.11
    frame = [
        0x00, 0x00, 0x0c, 0x00,  # Radiotap header (versão, pad, len, presente)
        0x04, 0x80, 0x00, 0x00,   # Presente flags
        0x00, 0x00, 0x00, 0x00,   # Timestamp
        0x00, 0x00, 0x00, 0x00,   # Flags e taxa de dados
        0x00, 0x00,               # Canal, sinal, ruído, etc.
        0x00, 0x00, 0x00, 0x00,   # MCS conhecido, flags, mcs
        0x00, 0x00, 0x00, 0x00,   # A-MPDU
        
        # Cabeçalho 802.11 (tipo Management, subtipo Deauthentication)
        0x00, 0x00, 0x0c, 0x00,  # Controle de versão, tipo, subtipo, etc.
        0x00, 0x00,               # Duração
    ]
    
    # Endereço de destino (broadcast ou cliente específico)
    dest = [int(x, 16) for x in client.split(':')]
    frame.extend(dest)
    
    # Endereço de origem (BSSID)
    src = [int(x, 16) for x in bssid.split(':')]
    frame.extend(src)
    
    # BSSID (mesmo que origem para redes de infraestrutura)
    frame.extend(src)
    
    # Número de sequência
    frame.extend([0x00, 0x00])
    
    # Código de motivo (2 bytes, little-endian)
    frame.extend([reason, 0x00])
    
    return bytes(frame) * count

# Funções para execução de comandos
async def run_command_async(cmd: Union[str, List[str]], **kwargs) -> subprocess.CompletedProcess:
    """
    Executa um comando de forma assíncrona.
    
    Args:
        cmd: Comando a ser executado (string ou lista)
        **kwargs: Argumentos adicionais para asyncio.create_subprocess_exec()
        
    Returns:
        subprocess.CompletedProcess: Resultado da execução do comando
    """
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs
    )
    
    stdout, stderr = await process.communicate()
    
    return subprocess.CompletedProcess(
        args=cmd,
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr
    )

# Funções para processamento de saída
def parse_airodump_csv(csv_file: str) -> List[WiFiNetwork]:
    """Analisa o arquivo CSV gerado pelo airodump-ng."""
    networks = []
    
    try:
        with open(csv_file, 'r') as f:
            lines = f.readlines()
        
        # Encontra o início dos dados das redes
        start_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('BSSID, First time seen,'):
                start_idx = i + 1
                break
        
        # Processa as redes
        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('Station'):
                break
                
            # Extrai os campos da linha
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 14:  # Número mínimo de campos esperados
                continue
                
            bssid = parts[0].strip()
            first_seen = parts[1].strip()
            last_seen = parts[2].strip()
            channel = int(parts[3].strip())
            speed = parts[4].strip()
            privacy = parts[5].strip()
            cipher = parts[6].strip()
            auth = parts[7].strip()
            power = int(parts[8].strip())
            beacons = int(parts[9].strip())
            iv = int(parts[10].strip())
            ip = parts[11].strip()
            id_len = int(parts[12].strip())
            essid = parts[13].strip()
            
            # Cria o objeto da rede
            network = WiFiNetwork(
                bssid=bssid,
                ssid=essid,
                channel=channel,
                signal=power,
                encryption=privacy,
                cipher=cipher,
                authentication=auth,
                first_seen=first_seen,
                last_seen=last_seen,
                speed=speed,
                beacons=beacons,
                iv=iv,
                ip=ip if ip != '0.0.0.0' else None
            )
            
            networks.append(network)
            
    except Exception as e:
        logger.error(f"Erro ao analisar arquivo CSV: {e}")
    
    return networks

def parse_airodump_stations(csv_file: str) -> List[WiFiClient]:
    """Analisa a seção de estações do arquivo CSV do airodump-ng."""
    clients = []
    
    try:
        with open(csv_file, 'r') as f:
            lines = f.readlines()
        
        # Encontra o início da seção de estações
        start_idx = 0
        for i, line in enumerate(lines):
            if line.startswith('Station MAC,'):
                start_idx = i + 1
                break
        
        # Processa as estações
        for line in lines[start_idx:]:
            line = line.strip()
            if not line:
                continue
                
            # Extrai os campos da linha
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 6:  # Número mínimo de campos esperados
                continue
                
            mac = parts[0].strip()
            first_seen = parts[1].strip()
            last_seen = parts[2].strip()
            power = int(parts[3].strip())
            packets = int(parts[4].strip())
            bssid = parts[5].strip()
            
            # Cria o objeto do cliente
            client = WiFiClient(
                mac=mac,
                bssid=bssid,
                signal=power,
                packets=packets,
                first_seen=first_seen,
                last_seen=last_seen
            )
            
            clients.append(client)
            
    except Exception as e:
        logger.error(f"Erro ao analisar estações do arquivo CSV: {e}")
    
    return clients

def randomize_mac(interface: str) -> bool:
    """
    Aleatoriza o endereço MAC de uma interface de rede.
    
    Args:
        interface: Nome da interface de rede
        
    Returns:
        bool: True se bem-sucedido, False caso contrário
    """
    if not is_root():
        logger.error("Privilégios de root são necessários para alterar o endereço MAC")
        return False
    
    try:
        # Gera um endereço MAC aleatório
        import random
        new_mac = ':'.join(['%02x' % random.randint(0x00, 0xff) for _ in range(6)])
        
        # Desativa a interface
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
        
        # Define o novo endereço MAC
        subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', new_mac], check=True)
        
        # Reativa a interface
        subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
        
        logger.info(f"Endereço MAC da interface {interface} alterado para {new_mac}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Falha ao aleatorizar o endereço MAC: {e}")
        return False
