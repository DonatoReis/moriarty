"""Port scanning avançado com detecção de serviços usando Nmap."""
from __future__ import annotations

import asyncio
import json
import re
import nmap3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from pathlib import Path
import structlog
from rich.console import Console
from rich.table import Table, box
from rich.live import Live
from rich.spinner import Spinner

logger = structlog.get_logger(__name__)
console = Console()

# Perfis de varredura
PROFILES = {
    "quick": "21-23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9000,10000,27017",
    "web": "80,443,8080,8443,8000,8888,10443,4443",
    "db": "1433,1521,27017-27019,28017,3306,5000,5432,5984,6379,8081",
    "full": "1-1024",
    "all": "1-65535",
}

@dataclass
class ServiceInfo:
    """Informações detalhadas sobre um serviço."""
    name: str = "unknown"
    version: Optional[str] = None
    ssl: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    banner: Optional[str] = None
    vulns: List[str] = field(default_factory=list)
    cpe: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    last_checked: Optional[datetime] = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Converte o objeto para dicionário."""
        return {
            "name": self.name,
            "version": self.version,
            "ssl": self.ssl,
            "ssl_info": self.ssl_info,
            "banner": self.banner,
            "vulns": self.vulns,
            "cpe": self.cpe,
            "extra": self.extra,
            "confidence": self.confidence,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }

@dataclass
class PortScanResult:
    """Resultado da varredura de uma porta."""
    port: int
    protocol: str = "tcp"
    status: str = "closed"
    target: Optional[str] = None
    service: Optional[ServiceInfo] = None
    banner: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "target": self.target,
            "service": self.service.to_dict() if self.service else None,
            "banner": self.banner,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Retorna uma representação JSON do resultado."""
        return json.dumps(self.to_dict(), indent=2)

class PortScanner:
    """Execução de port scanning com detecção avançada de serviços usando Nmap."""

    def __init__(
        self,
        target: str,
        ports: Union[str, List[int], None] = None,
        scan_type: str = "tcp",  # CORREÇÃO: Padrão mudado para TCP (não requer root)
        stealth_level: int = 0,
        resolve_services: bool = True,
        check_vulns: bool = True,
        debug: bool = False,  # NOVO: Opção de debug
    ):
        self.target = target
        # CORREÇÃO: Armazena o range real, não o apelido
        self.ports = self._parse_ports(ports) if ports else PROFILES["all"]
        # CORREÇÃO: Default para TCP se não especificado
        self.scan_type = scan_type if scan_type in ["syn", "tcp", "udp", "sS", "sT", "sU"] else "sT"
        self.stealth_level = max(0, min(stealth_level, 5))
        self.resolve_services = resolve_services
        self.check_vulns = check_vulns
        self.debug = debug  # NOVO
        self.stealth_level = max(0, min(stealth_level, 5))
        self.resolve_services = resolve_services
        self.check_vulns = check_vulns

        self.nm = nmap3.Nmap()
        self.scan_tech = nmap3.NmapScanTechniques()
        
        # CORREÇÃO: Remove -sS dos args base (será adicionado pela técnica)
        self.scan_arguments = self._get_scan_arguments()

    def _parse_ports(self, ports: Union[str, List[int]]) -> str:
        """Converte diferentes formatos de portas para o formato do Nmap."""
        if isinstance(ports, list):
            return ",".join(str(p) for p in ports)
        if isinstance(ports, str):
            # CORREÇÃO: Sempre retorna o range real, não o apelido
            if ports in PROFILES:
                return PROFILES[ports]
            return ports
        return PROFILES["all"]

    def _get_scan_arguments(self) -> str:
        """Gera os argumentos do Nmap baseados nas configurações."""
        # CORREÇÃO: Remove -sV e -sC daqui pois já são adicionados pela técnica de scan
        args = "-Pn -T4 --open"
        
        if self.stealth_level > 0:
            args += f" --max-rtt-timeout {1000 - (self.stealth_level * 100)}ms"
            args += f" --scan-delay {self.stealth_level * 2}s"
            
        return args.strip()
    
    @staticmethod
    def render_pipe_summary(results: List[PortScanResult]) -> str:
        """Renderiza tabela em formato pipe (ASCII) com larguras automáticas."""
        if not results:
            return "Nenhuma porta aberta encontrada."
        
        # Prepara dados
        headers = ["  PORTA", "STATUS", "SERVICO", "PROTOCOLO", "VERSAO", "SSL"]
        rows = []
        
        for r in sorted(results, key=lambda x: (x.protocol, x.port)):
            service_name = r.service.name if r.service else "unknown"
            version = (r.service.version or "").strip() if r.service else ""
            ssl = "✅" if (r.service and r.service.ssl) else ""
            
            rows.append([
                str(r.port),
                r.status,
                service_name or "unknown",
                r.protocol.upper(),
                version or "-",
                ssl
            ])
        
        # Calcula larguras automáticas
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Formata linhas
        def fmt_line(cells):
            return " | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(cells))
        
        separator = "-+-".join("-" * w for w in col_widths)
        
        output = [
            fmt_line(headers),
            separator
        ]
        output.extend(fmt_line(row) for row in rows)
        
        return "\n".join(output)

    async def scan(self) -> List[PortScanResult]:
        """Executa a varredura de portas usando Nmap (python3-nmap)."""
        # CORREÇÃO: Exibe o range real
        logger.info(f"Iniciando varredura Nmap", target=self.target, ports=self.ports, arguments=self.scan_arguments)
        console.print(f"[bold]  🔍 Iniciando varredura Nmap em {self.target}[/bold]")
        console.print(f"  📊 Portas: [bold]{self.ports}[/bold]")
        console.print(f"  ⚙️  Argumentos: [bold]{self.scan_arguments}[/bold]")

        if self.stealth_level > 0:
            console.print(f"  🔒 Modo furtivo: nível {self.stealth_level}")

        # Cria spinner animado
        spinner = Spinner("dots", text="[cyan]Executando scan Nmap...[/cyan]", style="cyan")
        
        try:
            # CORREÇÃO: self.ports já é o range correto
            ports_str = self.ports
            args = f"{self.scan_arguments} -p {ports_str}"
            logger.debug("Argumentos completos do Nmap", nmap_args=args)

            st = self.scan_type
            logger.info(f"Técnica de varredura selecionada: {st}")
            
            # Inicia o spinner em Live context
            with Live(spinner, console=console, refresh_per_second=10):
                try:
                    # Detecta se precisa de root e ajusta automaticamente
                    needs_root = st in ("syn", "sS")
                    if needs_root:
                        spinner.update(text="[yellow]⚠️  Alternando para TCP Connect (-sT)...[/yellow]")
                        await asyncio.sleep(0.5)  # Pequena pausa para o usuário ver a mensagem
                        st = "sT"
                        self.scan_type = "sT"
                    
                    if self.debug:
                        console.print(f"[dim]🐛 Executando: nmap -{st} {args} {self.target}[/dim]")
                    
                    spinner.update(text=f"[cyan]Scaneando portas {self.ports}...[/cyan]")
                    
                    # Executa o scan baseado na técnica
                    if st in ("syn", "sS"):
                        logger.debug("Executando varredura SYN (sS)")
                        scan_results = await asyncio.to_thread(
                            self.scan_tech.nmap_syn_scan, self.target, args=args
                        )
                    elif st in ("tcp", "sT"):
                        logger.debug("Executando varredura TCP (sT)")
                        scan_results = await asyncio.to_thread(
                            self.scan_tech.nmap_tcp_scan, self.target, args=args
                        )
                    elif st in ("udp", "sU"):
                        if hasattr(self.scan_tech, "nmap_udp_scan"):
                            logger.debug("Executando varredura UDP (sU)")
                            scan_results = await asyncio.to_thread(
                                self.scan_tech.nmap_udp_scan, self.target, args=args
                            )
                        else:
                            logger.debug("Executando varredura UDP via fallback")
                            scan_results = await asyncio.to_thread(
                                self.nm.nmap_version_detection, self.target, args=f"-sU {args}"
                            )
                    else:
                        logger.debug(f"Técnica não reconhecida '{st}', usando fallback")
                        scan_results = await asyncio.to_thread(
                            self.nm.nmap_version_detection, self.target, args=args
                        )
                    
                    spinner.update(text="[cyan]Processando resultados...[/cyan]")
                    
                    if self.debug:
                        console.print(f"[dim]🐛 Tipo de resultado: {type(scan_results)}[/dim]")
                    
                    # Detecta erro de permissão e tenta novamente com TCP
                    if isinstance(scan_results, dict) and scan_results.get("error") and "root" in str(scan_results.get("msg", "")).lower():
                        spinner.update(text="[yellow]⚠️  Erro de permissão. Tentando TCP...[/yellow]")
                        await asyncio.sleep(0.5)
                        st = "sT"
                        self.scan_type = "sT"
                        scan_results = await asyncio.to_thread(
                            self.scan_tech.nmap_tcp_scan, self.target, args=args
                        )
                        if self.debug:
                            console.print(f"[dim]🐛 Tipo de resultado (2ª tentativa): {type(scan_results)}[/dim]")
                    
                    # Se ports está vazio, tenta scan com subprocess direto
                    if isinstance(scan_results, dict):
                        has_ports = False
                        for key, val in scan_results.items():
                            if isinstance(val, dict) and isinstance(val.get("ports"), list) and val.get("ports"):
                                has_ports = True
                                break
                        
                        if not has_ports and self.debug:
                            spinner.update(text="[yellow]⚠️  Tentando método alternativo...[/yellow]")
                            await asyncio.sleep(0.3)
                            try:
                                clean_args = args.replace("-sV", "").replace("-sC", "").strip()
                                scan_results = await asyncio.to_thread(
                                    self.scan_tech.nmap_tcp_scan,
                                    self.target, 
                                    args=f"{clean_args} -p {ports_str}"
                                )
                                console.print(f"[dim]🐛 Tipo de resultado (scan limpo): {type(scan_results)}[/dim]")
                            except Exception as e:
                                console.print(f"[red]❌ Erro no scan alternativo: {e}[/red]")
                    
                    if self.debug:
                        console.print(f"[dim]🐛 Resultado RAW:[/dim]")
                        try:
                            import pprint
                            console.print(f"[dim]{pprint.pformat(scan_results, width=120)}[/dim]")
                        except:
                            console.print(f"[dim]{str(scan_results)[:2000]}[/dim]")
                    
                    logger.debug("Varredura Nmap concluída", scan_results=scan_results)
                
                except Exception as e:
                    logger.error("Erro durante a execução do Nmap", error=str(e), exc_info=True)
                    raise

            # CORREÇÃO: Parser melhorado para lidar com diferentes formatos
            logger.debug("Iniciando processamento dos resultados do Nmap")
            
            results = []
            
            if self.debug:
                if isinstance(scan_results, dict):
                    console.print(f"[dim]🐛 Chaves do resultado: {list(scan_results.keys())}[/dim]")
            
            # CORREÇÃO: Trata múltiplos formatos de retorno
            if isinstance(scan_results, dict):
                for host_key, host_data in scan_results.items():
                    # Ignora chaves de metadados
                    if host_key in ("stats", "runtime", "task_results"):
                        if self.debug:
                            console.print(f"[dim]🐛 Ignorando chave de metadados: {host_key}[/dim]")
                        continue
                    
                    if self.debug:
                        console.print(f"[dim]🐛 Processando host: {host_key}[/dim]")
                        console.print(f"[dim]🐛 Tipo de host_data: {type(host_data)}[/dim]")
                    
                    # Formato: { "host": { "ports": [...] } }
                    if isinstance(host_data, dict):
                        if self.debug:
                            console.print(f"[dim]🐛 Chaves de host_data: {list(host_data.keys())}[/dim]")
                        
                        ports_list = host_data.get("ports", [])
                        
                        if self.debug:
                            console.print(f"[dim]🐛 Portas no formato 'ports': {len(ports_list)}[/dim]")
                        
                        # CORREÇÃO: Também processa ports no formato alternativo
                        if not ports_list and "tcp" in host_data:
                            if self.debug:
                                console.print(f"[dim]🐛 Tentando formato alternativo 'tcp'...[/dim]")
                            tcp_ports = host_data.get("tcp", {})
                            if self.debug:
                                console.print(f"[dim]🐛 Portas TCP encontradas: {list(tcp_ports.keys())}[/dim]")
                            
                            for port_num, port_data in tcp_ports.items():
                                ports_list.append({
                                    "portid": str(port_num),
                                    "protocol": "tcp",
                                    "state": port_data,
                                    "service": port_data.get("service", {}) if isinstance(port_data, dict) else {}
                                })
                        
                        # CORREÇÃO: Também processa formato direto de portas
                        if not ports_list and self.debug:
                            console.print(f"[dim]🐛 Tentando outros formatos de porta...[/dim]")
                            for key, value in host_data.items():
                                if key.isdigit() or (isinstance(value, dict) and "portid" in value):
                                    if self.debug:
                                        console.print(f"[dim]🐛 Encontrada porta: {key}[/dim]")
                                    ports_list.append(value if isinstance(value, dict) else {"portid": key, "state": value})
                        
                        if self.debug and ports_list:
                            console.print(f"[dim]🐛 Total de portas a processar: {len(ports_list)}[/dim]")
                        
                        for i, port_info in enumerate(ports_list):
                            if self.debug:
                                console.print(f"[dim]🐛 Processando porta {i+1}/{len(ports_list)}: {port_info}[/dim]")
                            result = self._process_port_info(port_info, host_key)
                            if result:
                                if self.debug:
                                    console.print(f"[dim]✅ Porta {result.port} processada com sucesso![/dim]")
                                results.append(result)
                            elif self.debug:
                                console.print(f"[dim]❌ Porta não passou na validação[/dim]")
                                
            elif isinstance(scan_results, list):
                if self.debug:
                    console.print(f"[dim]🐛 Resultado é uma lista com {len(scan_results)} itens[/dim]")
                for port_info in scan_results:
                    result = self._process_port_info(port_info, self.target)
                    if result:
                        results.append(result)
            else:
                if self.debug:
                    console.print(f"[red]⚠️  Formato de resultado desconhecido: {type(scan_results)}[/red]")

            results.sort(key=lambda x: x.port)
            
            console.print("\n[bold green]  ✅ Varredura concluída![/]")
            
            if not results:
                logger.warning(
                    "Nenhuma porta aberta encontrada", 
                    target=self.target, 
                    ports=self.ports,
                    arguments=args
                )
                console.print("[yellow]  ℹ️  Nenhuma porta aberta encontrada.[/]")
            else:
                logger.info(
                    "Portas abertas encontradas", 
                    count=len(results),
                    ports=[r.port for r in results]
                )
                
                # Exibe tabela formatada
                console.print("\n[bold cyan]  🚪 Portas Abertas:[/bold cyan]")
                table_output = self.render_pipe_summary(results)
                console.print(table_output)
                console.print(f"\n[bold]  Total: {len(results)} porta(s) aberta(s)[/bold]")
                
            return results

        except Exception as e:
            error_msg = f"Erro durante a varredura Nmap: {str(e)}"
            console.print(f"[bold red]❌ {error_msg}[/]")
            logger.error(
                error_msg, 
                target=self.target, 
                ports=self.ports,
                error_type=type(e).__name__,
                exc_info=True
            )
            raise

    def _process_port_info(self, port_info: Dict, host: str) -> Optional[PortScanResult]:
        """Processa informações de uma porta individual."""
        if not isinstance(port_info, dict):
            if self.debug:
                console.print(f"[dim]❌ port_info não é dict: {type(port_info)}[/dim]")
            return None
        
        try:
            if self.debug:
                console.print(f"[dim]🐛 Processando: {port_info}[/dim]")
            
            # CORREÇÃO: Aceita diferentes formatos de estado
            port_state = port_info.get("state", {})
            
            if self.debug:
                console.print(f"[dim]🐛 port_state: {port_state} (tipo: {type(port_state)})[/dim]")
            
            # Formato 1: { "state": { "state": "open" } }
            if isinstance(port_state, dict):
                state_value = port_state.get("state", "unknown")
            # Formato 2: { "state": "open" }
            elif isinstance(port_state, str):
                state_value = port_state
            else:
                state_value = "unknown"
            
            if self.debug:
                console.print(f"[dim]🐛 state_value: {state_value}[/dim]")
            
            # CORREÇÃO: Aceita portas abertas E filtered (importantes)
            if state_value not in ("open", "filtered"):
                if self.debug:
                    console.print(f"[dim]❌ Estado '{state_value}' não aceito[/dim]")
                return None
            
            port_num = int(port_info.get("portid", 0))
            if port_num == 0:
                if self.debug:
                    console.print(f"[dim]❌ Porta número 0 inválida[/dim]")
                return None
            
            if self.debug:
                console.print(f"[dim]  ✅ Porta {port_num} válida, estado: {state_value}[/dim]")
            
            # Extrai informações do serviço
            service_data = port_info.get("service", {})
            service_info = None
            
            if isinstance(service_data, dict) and service_data:
                service_info = ServiceInfo(
                    name=service_data.get("name", "unknown"),
                    version=service_data.get("version", ""),
                    banner=service_data.get("product", ""),
                )
            
            result = PortScanResult(
                port=port_num,
                protocol=port_info.get("protocol", "tcp"),
                status=state_value,
                target=host,
                service=service_info,
                banner=service_data.get("product", "") if isinstance(service_data, dict) else "",
            )
            
            logger.debug(
                "Porta processada",
                port=port_num,
                status=state_value,
                service=service_info.name if service_info else "unknown",
                protocol=port_info.get("protocol")
            )
            
            return result
            
        except (TypeError, ValueError, KeyError) as e:
            if self.debug:
                console.print(f"[red]❌ Erro ao processar porta: {e}[/red]")
            logger.warning("Erro ao processar porta", 
                         port_info=port_info, 
                         error=str(e),
                         error_type=type(e).__name__)
            return None

def format_scan_results(results: List[PortScanResult], output_format: str = "text", total_ports: Optional[int] = None) -> str:
    """Formata os resultados da varredura no formato solicitado."""
    if output_format == "json":
        return json.dumps([r.to_dict() for r in results], indent=2)

    if output_format == "pipe":
        base = PortScanner.render_pipe_summary(results)
        suffix = f"\n\n  🔍 Total de portas abertas: {len(results)}"
        if total_ports:
            suffix = f"\n\n  🔍 Resumo: {len(results)} portas abertas de {total_ports} verificadas"
        return base + suffix
    
    # Formato de texto
    if not results:
        return "Nenhuma porta aberta encontrada."
    
    # Cria tabela
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Porta", style="cyan", width=10)
    table.add_column("Protocolo", style="blue")
    table.add_column("Status", style="yellow")
    table.add_column("Serviço", style="green")
    table.add_column("Versão", style="yellow")
    table.add_column("SSL/TLS", style="magenta")
    
    for result in results:
        service = result.service.name if result.service and hasattr(result.service, 'name') else "desconhecido"
        version = result.service.version if result.service and hasattr(result.service, 'version') else ""
        ssl = "✅" if result.service and result.service.ssl else ""
        
        table.add_row(
            f"{result.port}",
            result.protocol.upper(),
            result.status,
            service,
            version or "-",
            ssl
        )
    
    output = [str(table)]
    
    # Adiciona resumo
    if total_ports:
        output.append(f"\n  🔍 [bold]Resumo:[/bold] {len(results)} portas abertas de {total_ports} verificadas")
    else:
        output.append(f"\n  🔍 [bold]Total de portas:[/bold] {len(results)}")
    
    return "\n".join(output)

__all__ = ["PortScanner", "PortScanResult", "format_scan_results"]