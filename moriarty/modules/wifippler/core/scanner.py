"""
Módulo de escaneamento WiFi para o WifiPPLER.

Este módulo fornece funcionalidades avançadas para descoberta e análise de redes WiFi,
incluindo detecção de clientes, análise de sinal e suporte a diferentes modos de varredura.
"""
import asyncio
import json
import time
import signal
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import subprocess
import re
import logging
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.table import Table, Column
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, 
    TimeElapsedColumn, TaskID
)

from moriarty.modules.wifippler.core.utils import (
    run_command_async, is_root, get_interface_mac,
    set_monitor_mode, restore_network_interface, command_exists,
    randomize_mac, get_wireless_interfaces
)

from moriarty.modules.wifippler.core.models.network import (
    WiFiSecurityType, SECURITY_MAP
)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ScanMode(Enum):
    """Modos de varredura disponíveis."""
    ACTIVE = auto()    # Varredura ativa (envia pacotes)
    PASSIVE = auto()   # Varredura passiva (apenas escuta)
    FAST = auto()      # Varredura rápida (canais mais comuns)
    DEEP = auto()      # Varredura profunda (todos os canais)

# WiFiSecurityType agora é importado de moriarty.modules.wifippler.core.models.network

@dataclass
class WiFiClient:
    """Representa um dispositivo cliente conectado a uma rede WiFi."""
    mac: str
    bssid: str
    signal: int
    packets: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    vendor: Optional[str] = None
    is_associated: bool = True

    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        return {
            'mac': self.mac,
            'bssid': self.bssid,
            'signal': self.signal,
            'packets': self.packets,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'vendor': self.vendor,
            'is_associated': self.is_associated
        }

    def update_seen(self):
        """Atualiza o timestamp da última vez que foi visto."""
        self.last_seen = datetime.utcnow()

@dataclass
class WiFiNetwork:
    """Represents a discovered WiFi network."""
    bssid: str
    ssid: str
    channel: int
    signal: int
    encryption: str
    cipher: str
    authentication: str
    wps: bool = False
    wps_locked: bool = False
    clients: List[Dict[str, str]] = field(default_factory=list)
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

class WiFiScanner:
    """Classe principal para escaneamento de redes WiFi.
    
    Esta classe fornece funcionalidades avançadas para descoberta e análise
    de redes WiFi, incluindo detecção de clientes, análise de sinal e suporte
    a diferentes modos de varredura.
    """
    
    def __init__(
        self, 
        interface: str = None, 
        scan_time: int = 10,
        scan_mode: ScanMode = ScanMode.ACTIVE,
        output_dir: str = None,
        random_mac: bool = False,
        verbose: bool = False
    ):
        """Inicializa o scanner WiFi.
        
        Args:
            interface: Interface de rede a ser usada para escaneamento
            scan_time: Tempo de escaneamento em segundos
            scan_mode: Modo de varredura (ACTIVE, PASSIVE, FAST, DEEP)
            output_dir: Diretório para salvar os resultados
            random_mac: Se deve usar um endereço MAC aleatório
            verbose: Habilita saída detalhada
        """
        if not is_root():
            raise PermissionError("Este aplicativo requer privilégios de root para executar.")
        
        # Configuração básica
        self.scan_time = max(5, min(scan_time, 300))  # Limita entre 5 e 300 segundos
        self.scan_mode = scan_mode
        self.verbose = verbose
        self.running = False
        self.original_mac = None
        self.original_mode = None
        self.temp_dir = None
        
        # Configuração de saída
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'wifippler_scan'
        self.output_file = self.output_dir / 'scan_results.json'
        
        # Configuração da interface
        self.interface = self._setup_interface(interface, random_mac)
        
        # Dados
        self.networks: Dict[str, WiFiNetwork] = {}
        self.clients: Dict[str, WiFiClient] = {}
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Interface de usuário
        self.console = Console()
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            console=self.console,
            transient=True,
        )
        
        # Thread pool para operações em segundo plano
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Configuração de sinal para encerramento gracioso
        self.should_stop = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Manipula sinais de encerramento."""
        self.console.print("\n[bold yellow]Recebido sinal de encerramento. Finalizando...[/]")
        self.should_stop = True
    
    def _setup_interface(self, interface: str = None, random_mac: bool = False) -> str:
        """Configura a interface de rede para escaneamento.
        
        Args:
            interface: Nome da interface
            random_mac: Se deve usar um endereço MAC aleatório
            
        Returns:
            str: Nome da interface configurada
        """
        # Obtém interfaces disponíveis
        interfaces = get_wireless_interfaces()
        if not interfaces:
            raise RuntimeError("Nenhuma interface WiFi encontrada.")
        
        # Seleciona a interface
        if interface:
            if interface not in [iface['name'] for iface in interfaces]:
                raise ValueError(f"Interface {interface} não encontrada ou não é sem fio.")
            selected_iface = interface
        else:
            # Usa a primeira interface sem fio disponível
            selected_iface = interfaces[0]['name']
        
        # Salva o estado original
        self.original_mac = get_interface_mac(selected_iface)
        self.original_mode = 'managed'  # Assumindo modo gerenciado por padrão
        
        # Configura o endereço MAC aleatório, se solicitado
        if random_mac:
            if not randomize_mac(selected_iface):
                logger.warning("Falha ao definir endereço MAC aleatório. Continuando com o endereço original.")
        
        # Configura o modo monitor
        if not set_monitor_mode(selected_iface):
            raise RuntimeError(f"Falha ao configurar o modo monitor na interface {selected_iface}.")
        
        return selected_iface
    
    def _restore_interface(self) -> bool:
        """Restaura a interface para o estado original.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário
        """
        try:
            # Restaura o modo original
            if self.original_mode == 'managed':
                if not restore_network_interface(self.interface):
                    logger.error(f"Falha ao restaurar o modo gerenciado na interface {self.interface}.")
                    return False
            
            # Restaura o endereço MAC original, se necessário
            if self.original_mac and get_interface_mac(self.interface) != self.original_mac:
                # Implementar lógica para restaurar o MAC original
                pass
                
            return True
            
        except Exception as e:
            logger.error(f"Erro ao restaurar a interface: {e}")
            return False
    
    def _create_output_dir(self) -> bool:
        """Cria o diretório de saída, se necessário.
        
        Returns:
            bool: True se bem-sucedido, False caso contrário
        """
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Falha ao criar diretório de saída {self.output_dir}: {e}")
            return False
    
    def _parse_airodump_line(self, line: str) -> Optional[WiFiNetwork]:
        """Analisa uma linha de saída do airodump-ng.
        
        Args:
            line: Linha de saída do airodump-ng
            
        Returns:
            Optional[WiFiNetwork]: Objeto WiFiNetwork ou None se a linha for inválida
        """
        if not line.strip() or line.startswith('BSSID') or line.startswith('Station'):
            return None
            
        parts = [p.strip() for p in line.split(',') if p.strip()]
        if len(parts) < 10:  # Não há dados suficientes para uma rede
            return None
            
        try:
            # Extrai informações básicas
            bssid = parts[0].upper()
            first_seen = datetime.utcnow()
            channel = int(parts[3]) if parts[3] else 1
            signal = int(parts[8].split()[0])  # Remove 'dBm' se presente
            
            # Determina o tipo de segurança
            encryption = parts[5].strip() or 'NONE'
            security = self._determine_security_type(encryption)
            
            # Cria o objeto de rede
            network = WiFiNetwork(
                bssid=bssid,
                ssid=parts[13] if len(parts) > 13 else "<hidden>",
                channel=channel,
                frequency=self._channel_to_frequency(channel),
                signal=signal,
                security=security,
                encryption=encryption,
                cipher=parts[6].strip() if len(parts) > 6 else '',
                authentication=parts[7].strip() if len(parts) > 7 else '',
                first_seen=first_seen,
                last_seen=first_seen,
                essid_hidden=len(parts) <= 13 or not parts[13].strip()
            )
            
            # Verifica recursos avançados
            self._detect_network_features(network, parts)
            
            return network
            
        except (IndexError, ValueError) as e:
            logger.debug(f"Não foi possível analisar a linha da rede: {line}. Erro: {e}")
            return None
    
    def _determine_security_type(self, encryption: str) -> WiFiSecurityType:
        """Determina o tipo de segurança com base na string de criptografia.
        
        Args:
            encryption: String de criptografia do airodump-ng
            
        Returns:
            WiFiSecurityType: Tipo de segurança detectado
        """
        if not encryption or encryption.upper() == 'NONE':
            return WiFiSecurityType.NONE
            
        encryption = encryption.upper()
        
        # Verifica se a criptografia está no mapeamento
        for key, security_type in SECURITY_MAP.items():
            if key in encryption:
                return security_type
                
        # Tenta inferir o tipo de segurança com base em padrões comuns
        if 'WPA3' in encryption and 'WPA2' in encryption:
            return WiFiSecurityType.WPA2
        elif 'WPA2' in encryption and 'WPA' in encryption:
            return WiFiSecurityType.WPA2
        elif 'WPA3' in encryption:
            return WiFiSecurityType.WPA3
        elif 'WPA2' in encryption:
            return WiFiSecurityType.WPA2
        elif 'WPA' in encryption:
            return WiFiSecurityType.WPA
        elif 'WEP' in encryption:
            return WiFiSecurityType.WEP
            
        # Se não conseguir determinar, retorna o tipo padrão
        return WiFiSecurityType.WPA2
    
    def _channel_to_frequency(self, channel: int) -> int:
        """Converte um número de canal para frequência em MHz.
        
        Args:
            channel: Número do canal (1-14 para 2.4GHz, 36-165 para 5GHz)
            
        Returns:
            int: Frequência em MHz
        """
        if 1 <= channel <= 13:  # 2.4 GHz
            return 2412 + (channel - 1) * 5
        elif channel == 14:  # 2.4 GHz (apenas Japão)
            return 2484
        elif 36 <= channel <= 165:  # 5 GHz
            return 5180 + (channel - 36) * 5
        else:
            return 0  # Canal desconhecido
    
    def _detect_network_features(self, network: WiFiNetwork, parts: list) -> None:
        """Detecta recursos avançados da rede.
        
        Args:
            network: Objeto WiFiNetwork a ser atualizado
            parts: Partes da linha do airodump-ng
        """
        # Verifica WPS
        if len(parts) > 9 and 'WPS' in parts[9]:
            network.wps = True
            # Detalhes adicionais do WPS podem ser extraídos aqui
        
        # Verifica recursos avançados (HT/VHT/HE)
        if len(parts) > 10:
            flags = parts[10].upper()
            network.ht = 'HT' in flags
            network.vht = 'VHT' in flags
            network.he = 'HE' in flags
            
            # Verifica se é uma rede de alto rendimento
            network.high_throughput = network.ht or network.vht or network.he
            network.very_high_throughput = network.vht or network.he
    
    async def scan_networks(self) -> List[WiFiNetwork]:
        """Realiza a varredura de redes WiFi próximas.
        
        Returns:
            List[WiFiNetwork]: Lista de redes WiFi descobertas
        """
        if not self._create_output_dir():
            raise RuntimeError("Falha ao criar diretório de saída")
        
        self.scan_start_time = datetime.utcnow()
        self.running = True
        self.should_stop = False
        
        # Configura o prefixo do arquivo temporário
        temp_prefix = f"wifippler_scan_{int(time.time())}"
        csv_file = self.output_dir / f"{temp_prefix}-01.csv"
        
        # Configura os parâmetros do airodump-ng
        cmd = [
            "airodump-ng",
            "--write-interval", "1",
            "--output-format", "csv",
            "--write", str(self.output_dir / temp_prefix),
        ]
        
        # Adiciona parâmetros específicos do modo de varredura
        if self.scan_mode == ScanMode.FAST:
            cmd.extend(["--band", "bg"])  # Apenas 2.4GHz
        elif self.scan_mode == ScanMode.DEEP:
            cmd.extend(["--band", "abg"])  # 2.4GHz e 5GHz
        
        # Adiciona a interface no final
        cmd.append(self.interface)
        
        self.console.print(f"[bold blue]\n🔍 Iniciando varredura WiFi no modo {self.scan_mode.name}...\n")
        
        try:
            # Inicia o airodump-ng em segundo plano
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Inicia a barra de progresso
            with self.progress:
                task = self.progress.add_task(
                    "[cyan]Escaneando redes...", 
                    total=self.scan_time
                )
                
                # Aguarda o arquivo de saída ser criado
                start_time = time.time()
                while not csv_file.exists() and (time.time() - start_time) < 5:
                    await asyncio.sleep(0.5)
                
                # Monitora o progresso
                while not self.should_stop and (time.time() - start_time) < self.scan_time:
                    await asyncio.sleep(0.5)
                    self.progress.update(
                        task, 
                        advance=0.5,
                        description=f"[cyan]Escaneando redes (restam {max(0, int(self.scan_time - (time.time() - start_time)))}s)..."
                    )
                    
                    # Atualiza a lista de redes periodicamente
                    if int(time.time() - start_time) % 2 == 0:
                        await self._update_networks_from_file(csv_file)
                
                # Finaliza o processo
                process.terminate()
                await process.wait()
                
                # Atualiza a lista de redes uma última vez
                if csv_file.exists():
                    await self._update_networks_from_file(csv_file)
            
            return list(self.networks.values())
            
        except Exception as e:
            logger.error(f"Erro durante a varredura: {e}", exc_info=self.verbose)
            self.console.print(f"[red]Erro durante a varredura: {e}[/]")
            return []
            
        finally:
            self.running = False
            self.scan_end_time = datetime.utcnow()
            await self._cleanup()
    
    async def _update_networks_from_file(self, csv_file: Path) -> None:
        """Atualiza a lista de redes a partir do arquivo CSV do airodump-ng.
        
        Args:
            csv_file: Caminho para o arquivo CSV
        """
        try:
            if not csv_file.exists():
                return
                
            with open(csv_file, 'r', errors='ignore') as f:
                content = f.read()
                
            # Divide o conteúdo em seções de redes e clientes
            sections = re.split(r'\n\n', content.strip())
            
            if not sections:
                return
                
            # Processa a seção de redes
            network_lines = sections[0].split('\n')[1:]  # Ignora o cabeçalho
            for line in network_lines:
                if not line.strip() or line.startswith('Station'):
                    continue
                    
                network = self._parse_airodump_line(line)
                if network:
                    self._update_network(network)
            
            # Processa a seção de clientes, se existir
            if len(sections) > 1:
                client_lines = sections[1].split('\n')[1:]  # Ignora o cabeçalho
                for line in client_lines:
                    if not line.strip():
                        continue
                        
                    self._process_client_line(line)
                    
        except Exception as e:
            logger.error(f"Erro ao processar arquivo de saída: {e}", exc_info=self.verbose)
    
    def _update_network(self, network: WiFiNetwork) -> None:
        """Atualiza ou adiciona uma rede à lista de redes conhecidas.
        
        Args:
            network: Rede a ser atualizada/adicionada
        """
        if network.bssid in self.networks:
            # Atualiza a rede existente
            existing = self.networks[network.bssid]
            existing.signal = network.signal
            existing.last_seen = datetime.utcnow()
            
            # Atualiza outros campos, se necessário
            if network.ssid and network.ssid != "<hidden>":
                existing.ssid = network.ssid
                
            if network.channel:
                existing.channel = network.channel
                existing.frequency = self._channel_to_frequency(network.channel)
                
            # Atualiza a segurança, se disponível
            if network.security != WiFiSecurityType.NONE:
                existing.security = network.security
                existing.encryption = network.encryption
                existing.cipher = network.cipher
                existing.authentication = network.authentication
                
        else:
            # Adiciona uma nova rede
            self.networks[network.bssid] = network
    
    def _process_client_line(self, line: str) -> None:
        """Processa uma linha de cliente do airodump-ng.
        
        Args:
            line: Linha de saída do airodump-ng contendo informações do cliente
        """
        parts = [p.strip() for p in line.split(',') if p.strip()]
        if len(parts) < 6:  # Não há dados suficientes para um cliente
            return
            
        try:
            client_mac = parts[0].upper()
            bssid = parts[5].upper()
            
            # Verifica se a rede do cliente está na nossa lista
            if bssid not in self.networks:
                return
                
            # Cria ou atualiza o cliente
            client = WiFiClient(
                mac=client_mac,
                bssid=bssid,
                signal=int(parts[3]) if parts[3] else 0,
                packets=int(parts[2]) if parts[2] else 0,
                is_associated=parts[4].strip() == '0',  # 0 = associado, 1 = não associado
            )
            
            # Atualiza a lista de clientes da rede
            self.networks[bssid].add_client(client)
            
        except (IndexError, ValueError) as e:
            logger.debug(f"Não foi possível analisar a linha do cliente: {line}. Erro: {e}")
    
    async def _cleanup(self):
        """Limpa arquivos temporários e restaura o estado original."""
        try:
            # Encerra processos em segundo plano
            await run_command_async(["pkill", "-f", "airodump-ng"])
            
            # Limpa arquivos temporários
            temp_files = list(self.output_dir.glob("wifippler_scan_*"))
            for file in temp_files:
                try:
                    if file.is_file():
                        file.unlink()
                    elif file.is_dir():
                        shutil.rmtree(file)
                except Exception as e:
                    logger.debug(f"Falha ao remover arquivo temporário {file}: {e}")
            
            # Restaura a interface de rede
            self._restore_interface()
            
        except Exception as e:
            logger.error(f"Erro durante a limpeza: {e}", exc_info=self.verbose)
    
    def display_networks(self, networks: List[WiFiNetwork] = None, sort_by: str = 'signal') -> None:
        """Exibe as redes descobertas em uma tabela formatada.
        
        Args:
            networks: Lista de redes a serem exibidas. Se None, usa as redes escaneadas.
            sort_by: Campo para ordenação (signal, channel, ssid, bssid)
        """
        if networks is None:
            networks = list(self.networks.values())
            
        if not networks:
            self.console.print("[yellow]Nenhuma rede encontrada.[/yellow]")
            return
        
        # Ordena as redes
        reverse_sort = sort_by == 'signal'  # Ordem decrescente para sinal
        networks_sorted = sorted(
            networks,
            key=lambda x: (
                getattr(x, sort_by, 0) if hasattr(x, sort_by) else 0,
                x.ssid or ""
            ),
            reverse=reverse_sort
        )
        
        # Cria a tabela
        table = Table(
            title=f"📶 Redes WiFi Encontradas ({len(networks_sorted)})",
            show_header=True,
            header_style="bold magenta",
            expand=True
        )
        
        # Adiciona colunas
        table.add_column("#", style="dim", width=4)
        table.add_column("SSID", min_width=20)
        table.add_column("BSSID", width=18)
        table.add_column("Canal", width=8, justify="center")
        table.add_column("Sinal", width=12, justify="right")
        table.add_column("Segurança", width=15)
        table.add_column("Clientes", width=10, justify="center")
        table.add_column("WPS", width=6, justify="center")
        
        # Adiciona linhas
        for i, network in enumerate(networks_sorted, 1):
            # Formata o SSID (mostra "<hidden>" se estiver oculto)
            ssid = network.ssid if network.ssid and network.ssid != "<hidden>" else "[dim]&lt;oculto&gt;[/]"
            
            # Formata o sinal com cores
            if network.signal >= -50:
                signal_str = f"[green]{network.signal} dBm[/]"
            elif network.signal >= -70:
                signal_str = f"[yellow]{network.signal} dBm[/]"
            else:
                signal_str = f"[red]{network.signal} dBm[/]"
            
            # Formata a segurança
            security = network.security.value if network.security else network.encryption
            
            # Ícone WPS
            wps_icon = "✅" if network.wps else "❌"
            if network.wps_locked:
                wps_icon = "🔒"
            
            # Adiciona a linha à tabela
            table.add_row(
                str(i),
                ssid,
                network.bssid,
                str(network.channel),
                signal_str,
                security,
                str(len(network.clients)),
                wps_icon
            )
        
        # Exibe a tabela
        self.console.print()
        self.console.print(table)
        
        # Adiciona um resumo
        self.console.print(f"[bold]Total de redes:[/] {len(networks_sorted)}")
        
        # Contagem por tipo de segurança
        security_counts = {}
        for net in networks_sorted:
            sec = net.security.value if net.security else "Desconhecido"
            security_counts[sec] = security_counts.get(sec, 0) + 1
        
        if security_counts:
            self.console.print("\n[bold]Distribuição de segurança:[/]")
            for sec, count in sorted(security_counts.items()):
                self.console.print(f"  • {sec}: {count}")
        
        # Tempo de escaneamento
        if self.scan_start_time and self.scan_end_time:
            duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            self.console.print(f"\n[dim]Escaneamento concluído em {duration:.1f} segundos.[/]")
    
    def get_network_by_bssid(self, bssid: str) -> Optional[WiFiNetwork]:
        """Obtém uma rede pelo seu BSSID.
        
        Args:
            bssid: Endereço BSSID da rede
            
        Returns:
            Optional[WiFiNetwork]: A rede encontrada ou None
        """
        return self.networks.get(bssid.upper())
    
    def get_networks_by_ssid(self, ssid: str) -> List[WiFiNetwork]:
        """Obtém todas as redes com um determinado SSID.
        
        Args:
            ssid: Nome da rede (SSID) a ser procurado
            
        Returns:
            List[WiFiNetwork]: Lista de redes com o SSID especificado
        """
        return [net for net in self.networks.values() 
                if net.ssid and net.ssid.lower() == ssid.lower()]
    
    def get_networks_by_security(self, security_type: WiFiSecurityType) -> List[WiFiNetwork]:
        """Obtém todas as redes com um determinado tipo de segurança.
        
        Args:
            security_type: Tipo de segurança a ser filtrado
            
        Returns:
            List[WiFiNetwork]: Lista de redes com o tipo de segurança especificado
        """
        return [net for net in self.networks.values() 
                if net.security == security_type]
    
    def get_networks_with_clients(self) -> List[WiFiNetwork]:
        """Obtém todas as redes que possuem clientes conectados.
        
        Returns:
            List[WiFiNetwork]: Lista de redes com clientes
        """
        return [net for net in self.networks.values() if net.clients]
    
    def get_wps_networks(self) -> List[WiFiNetwork]:
        """Obtém todas as redes com WPS ativado.
        
        Returns:
            List[WiFiNetwork]: Lista de redes com WPS ativado
        """
        return [net for net in self.networks.values() if net.wps]
    
    def to_json(self, file_path: str = None) -> Optional[str]:
        """Converte as redes descobertas para JSON.
        
        Args:
            file_path: Caminho para salvar o arquivo JSON. Se None, retorna a string JSON.
            
        Returns:
            Optional[str]: String JSON se file_path for None, caso contrário None
        """
        data = {
            'scan_start': self.scan_start_time.isoformat() if self.scan_start_time else None,
            'scan_end': self.scan_end_time.isoformat() if self.scan_end_time else None,
            'interface': self.interface,
            'networks': [net.to_dict() for net in self.networks.values()]
        }
        
        json_str = json.dumps(data, indent=2, default=str)
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(json_str)
                return None
            except Exception as e:
                logger.error(f"Falha ao salvar arquivo JSON: {e}")
                return None
        
        return json_str

async def run() -> None:
    """Função principal para executar o scanner a partir da linha de comando."""
    import argparse
    
    # Configura o parser de argumentos
    parser = argparse.ArgumentParser(description='WiFiPPLER - Ferramenta avançada de análise de redes WiFi')
    parser.add_argument('-i', '--interface', help='Interface de rede para escaneamento')
    parser.add_argument('-t', '--time', type=int, default=10, 
                        help='Tempo de escaneamento em segundos (padrão: 10)')
    parser.add_argument('-m', '--mode', choices=['active', 'passive', 'fast', 'deep'], 
                        default='active', help='Modo de varredura (padrão: active)')
    parser.add_argument('-o', '--output', help='Arquivo de saída para salvar os resultados em JSON')
    parser.add_argument('--random-mac', action='store_true', 
                        help='Usar endereço MAC aleatório')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Modo verboso (mais detalhes de depuração)')
    
    # Parse dos argumentos
    args = parser.parse_args()
    
    # Mapeia o modo de varredura
    scan_mode_map = {
        'active': ScanMode.ACTIVE,
        'passive': ScanMode.PASSIVE,
        'fast': ScanMode.FAST,
        'deep': ScanMode.DEEP
    }
    
    try:
        # Cria e configura o scanner
        scanner = WiFiScanner(
            interface=args.interface,
            scan_time=args.time,
            scan_mode=scan_mode_map[args.mode],
            random_mac=args.random_mac,
            verbose=args.verbose
        )
        
        # Executa a varredura
        console = Console()
        console.print("[bold green]🚀 Iniciando WiFiPPLER - Ferramenta de Análise WiFi[/]\n")
        
        # Mostra informações iniciais
        console.print(f"[bold]Interface:[/] {scanner.interface}")
        console.print(f"[bold]Modo de varredura:[/] {args.mode.capitalize()}")
        console.print(f"[bold]Tempo de escaneamento:[/] {args.time} segundos")
        console.print(f"[bold]Endereço MAC aleatório:[/] {'Sim' if args.random_mac else 'Não'}\n")
        
        # Realiza a varredura
        networks = await scanner.scan_networks()
        
        # Exibe os resultados
        scanner.display_networks(networks)
        
        # Salva os resultados em um arquivo, se solicitado
        if args.output:
            result = scanner.to_json(args.output)
            if result is None:
                console.print(f"[green]✅ Resultados salvos em {args.output}[/]")
            else:
                console.print(f"[yellow]⚠️  Resultados não foram salvos em {args.output}[/]")
        
        console.print("\n[bold green]✅ Análise concluída com sucesso![/]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Escaneamento interrompido pelo usuário.[/]")
    except Exception as e:
        console.print(f"[red]❌ Erro durante a execução: {e}[/]")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        # Garante que a interface seja restaurada
        if 'scanner' in locals():
            await scanner._cleanup()

async def main():
    """Função de entrada para testes rápidos."""
    try:
        console = Console()
        console.print("[bold blue]🔍 Iniciando teste do WiFiPPLER...[/]\n")
        
        # Cria o scanner com configurações padrão
        scanner = WiFiScanner(scan_time=15, verbose=True)
        
        # Executa a varredura
        console.print("[cyan]Escaneando redes próximas... (pressione Ctrl+C para interromper)[/]")
        networks = await scanner.scan_networks()
        
        # Exibe os resultados
        scanner.display_networks(networks)
        
        # Mostra um resumo
        console.print("\n[bold]Resumo:[/]")
        console.print(f"Total de redes encontradas: {len(networks)}")
        wps_count = sum(1 for net in networks if net.wps)
        console.print(f"Redes com WPS ativado: {wps_count}")
        
        # Se houver redes com WPS, destaca-as
        wps_nets = [net for net in networks if net.wps]
        if wps_nets:
            console.print("\n[bold yellow]⚠️  Redes com WPS ativado:[/]")
            for net in wps_nets:
                locked = "(travado) " if net.wps_locked else ""
                console.print(f"- {net.ssid or '<oculto>'} {locked}({net.bssid}) - Canal {net.channel}")
        
        console.print("\n[green]✅ Teste concluído com sucesso![/]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Teste interrompido pelo usuário.[/]")
    except Exception as e:
        console.print(f"[red]❌ Erro durante o teste: {e}[/]")
    finally:
        if 'scanner' in locals():
            await scanner._cleanup()

if __name__ == "__main__":
    asyncio.run(run())
