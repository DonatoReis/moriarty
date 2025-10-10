"""Port scanning avançado com detecção de serviços usando Nmap."""
from __future__ import annotations

import asyncio
import json
import re
import nmap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Union
from pathlib import Path
import structlog
from rich.console import Console
from rich.table import Table, box

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
        scan_type: str = "syn",
        stealth_level: int = 0,
        resolve_services: bool = True,
        check_vulns: bool = True,
    ):
        self.target = target
        self.ports = self._parse_ports(ports) if ports else PROFILES["all"]
        self.scan_type = scan_type if scan_type in ["syn", "tcp", "udp", "sS", "sT", "sU"] else "sS"
        self.stealth_level = max(0, min(stealth_level, 5))
        self.resolve_services = resolve_services
        self.check_vulns = check_vulns
        self.nm = nmap.PortScanner()
        
        # Configurações baseadas no nível de stealth
        self.scan_arguments = self._get_scan_arguments()

    def _parse_ports(self, ports: Union[str, List[int]]) -> str:
        """Converte diferentes formatos de portas para o formato do Nmap."""
        if isinstance(ports, list):
            return ",".join(str(p) for p in ports)
        elif ports in PROFILES:
            return PROFILES[ports]
        return ports

    def _get_scan_arguments(self) -> str:
        """Gera os argumentos do Nmap baseados nas configurações."""
        # Argumentos base - removendo -O (OS detection) e usando -T4 para velocidade
        args = "-T4 -sT"  # Usando TCP Connect por padrão sem necessidade de root
        
        # Adiciona detecção de versão se necessário
        if self.resolve_services:
            args += " -sV"
        
        # Adiciona scripts padrão se não for muito furtivo
        if self.stealth_level < 3:
            args += " -sC"
            
        # Adiciona argumentos de furtividade baseado no nível
        if self.stealth_level > 0:
            args += f" --max-rtt-timeout {1000 - (self.stealth_level * 100)}ms"
            args += f" --scan-delay {self.stealth_level * 2}s"
        
        return args.strip()
    
    @staticmethod
    def render_pipe_summary(results: List[PortScanResult]) -> str:
        if not results:
            return "Nenhuma porta aberta encontrada."
        headers = ["PORTA", "STATUS", "SERVICO", "PROTOCOLO", "VERSAO", "SSL"]
        rows = []
        for r in sorted(results, key=lambda x: (x.protocol, x.port)):
            service_name = r.service.name if r.service else "unknown"
            version = (r.service.version or "").strip() if r.service else ""
            ssl = "✅" if (r.service and r.service.ssl) else ""
            rows.append([
                str(r.port), r.status, service_name or "unknown",
                r.protocol.upper(), version, ssl
            ])

        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(cell))

        def fmt_line(cells):
            return " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(cells))

        out = [fmt_line(headers), " | ".join("-" * w for w in col_widths)]
        out.extend(fmt_line(row) for row in rows)
        return "\n".join(out)

    async def scan(self) -> List[PortScanResult]:
        """Executa a varredura de portas usando Nmap."""
        console.print(f"[bold]🔍 Iniciando varredura Nmap em {self.target}[/bold]")
        console.print(f"📊 Portas: [bold]{self.ports}[/bold]")
        console.print(f"⚙️  Argumentos: [bold]{self.scan_arguments}[/bold]")
        
        if self.stealth_level > 0:
            console.print(f"🔒 Modo furtivo: nível {self.stealth_level}")
        
        try:
            # Executa o scan Nmap
            self.nm.scan(
                hosts=self.target,
                ports=self.ports,
                arguments=self.scan_arguments,
                sudo=False  # Necessário para SYN scan
            )
            
            # Processa os resultados
            results = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        
                        # Cria o objeto ServiceInfo
                        service_info = ServiceInfo(
                            name=port_info.get('name', 'unknown'),
                            version=port_info.get('version', ''),
                            banner=port_info.get('product', ''),
                            ssl=port_info.get('tunnel') == 'ssl' or 'ssl' in port_info.get('name', '').lower()
                        )
                        
                        # Adiciona CPE se disponível
                        if 'cpe' in port_info:
                            service_info.cpe = port_info['cpe']
                        
                        state = port_info.get('state', 'closed')
                        if state != 'open':
                            continue

                        # Cria o resultado da porta
                        result = PortScanResult(
                            port=port,
                            protocol=proto,
                            status=state,
                            target=host,
                            service=service_info,
                            banner=port_info.get('product', '') + ' ' + port_info.get('version', '')
                        )
                        
                        results.append(result)
            
            # Ordena os resultados por número de porta
            results.sort(key=lambda x: x.port)
            
            # Exibe resumo
            open_ports = len(results)
            console.print(f"\n✅ [bold green]Varredura concluída![/bold green] {open_ports} portas abertas encontradas.")

            # Mostra a visão tipo "PORTA | STATUS | SERVICO | ..."
            console.print("\n[bold]Resumo das portas abertas[/bold]")
            console.print(self.render_pipe_summary(results))   

            return results
            
        except Exception as e:
            console.print(f"[bold red]❌ Erro ao executar Nmap: {str(e)}[/bold red]")
            raise

def format_scan_results(results: List[PortScanResult], output_format: str = "text", total_ports: Optional[int] = None) -> str:
    """Formata os resultados da varredura no formato solicitado.
    
    Args:
        results: Lista de resultados da varredura
        output_format: Formato de saída ('text' ou 'json')
        total_ports: Número total de portas verificadas (opcional)
    """
    if output_format == "json":
        return json.dumps([r.to_dict() for r in results], indent=2)

    if output_format == "pipe":
        base = PortScanner.render_pipe_summary(results)
        suffix = f"\n\n🔍 Total de portas abertas: {len(results)}"
        if total_ports:
            suffix = f"\n\n🔍 Resumo: {len(results)} portas abertas de {total_ports} verificadas"
        return base + suffix

    
    # Formato de texto
    output = []
    
    if not results:
        return "Nenhuma porta aberta encontrada."
    
    # Cria tabela
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Porta", style="cyan", width=10)
    table.add_column("Protocolo", style="blue")
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
            service,
            version,
            ssl
        )
    
    output.append(str(table))
    
    # Adiciona resumo
    if total_ports:
        output.append(f"\n🔍 [bold]Resumo:[/bold] {len(results)} portas abertas de {total_ports} verificadas")
    else:
        output.append(f"\n🔍 [bold]Total de portas abertas:[/bold] {len(results)}")
    
    return "\n".join(output)

__all__ = ["PortScanner", "PortScanResult", "format_scan_results"]
