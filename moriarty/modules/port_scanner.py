"""Port scanning avançado com detecção de serviços e vulnerabilidades."""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# Importa a classe ServiceInfo para uso no código

import aiohttp
import dns.resolver
import dns.asyncresolver
import OpenSSL.crypto
import structlog
from rich.console import Console
from rich.json import JSON
from rich.table import Table

logger = structlog.get_logger(__name__)
console = Console()

# Perfis de varredura
PROFILES = {
    "quick": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 
              465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 
              8080, 8443, 9000, 10000, 27017],
    "web": [80, 443, 8080, 8443, 8000, 8888, 10443, 4443],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "db": [1433, 1521, 27017, 27018, 27019, 28017, 3306, 5000, 5432, 5984, 6379, 8081],
    "full": list(range(1, 1025)),
    "all": list(range(1, 65536)),
}

# Mapeamento de portas para serviços comuns
SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    515: "LPD",
    554: "RTSP",
    587: "SMTP (Submission)",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Node.js",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "AMQP",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8088: "HTTP-Alt",
    8089: "Splunk",
    8090: "HTTP-Alt",
    8091: "Couchbase",
    8096: "Plex",
    8125: "StatsD",
    8140: "Puppet",
    8200: "Vault",
    8300: "Consul",
    8333: "Bitcoin",
    8443: "HTTPS-Alt",
    8500: "Consul",
    8545: "Ethereum",
    8765: "Grafana",
    8888: "Jupyter",
    9000: "SonarQube",
    9001: "Tor",
    9042: "Cassandra",
    9090: "Prometheus",
    9092: "Kafka",
    9100: "Node-Exporter",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9418: "Git",
    9999: "JIRA",
    10000: "Webmin",
    10250: "Kubelet",
    11211: "Memcached",
    15672: "RabbitMQ",
    16379: "Redis",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    28017: "MongoDB",
    32608: "Kubernetes",
}

# Vulnerabilidades comuns por serviço
VULNERABILITIES = {
    "SSH": ["CVE-2016-0777", "CVE-2016-0778", "CVE-2018-15473"],
    "SMB": ["EternalBlue", "SMBGhost", "EternalRomance", "SambaCry"],
    "RDP": ["BlueKeep", "CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
    "Redis": ["Unauthenticated Access", "CVE-2015-4335", "CVE-2016-8339"],
    "MongoDB": ["Unauthenticated Access", "CVE-2016-6494"],
    "Elasticsearch": ["CVE-2015-1427", "CVE-2015-3337", "CVE-2015-5531"],
    "Memcached": ["DRDoS Amplification", "CVE-2016-8704", "CVE-2016-8705"],
    "Docker": ["CVE-2019-5736", "CVE-2019-13139", "CVE-2019-14271"],
    "Kubernetes": ["CVE-2018-1002105", "CVE-2019-11253", "CVE-2019-11255"],
    "VNC": ["CVE-2006-2369", "CVE-2015-5239", "CVE-2018-20019"],
    "Jenkins": ["CVE-2017-1000353", "CVE-2018-1000861", "CVE-2019-1003000"],
    "MySQL": ["CVE-2016-6662", "CVE-2016-6663", "CVE-2016-6664"],
    "PostgreSQL": ["CVE-2019-9193", "CVE-2018-1058", "CVE-2016-5423"],
    "Oracle": ["CVE-2012-1675", "CVE-2012-3137", "CVE-2018-3110"],
    "MSSQL": ["CVE-2019-1068", "CVE-2018-8273", "CVE-2018-8271"],
}

@dataclass
class ServiceInfo:
    """Informações detalhadas sobre um serviço."""
    name: str
    version: Optional[str] = None
    ssl: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    banner: Optional[str] = None
    vulns: List[str] = field(default_factory=list)
    cpe: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PortScanResult:
    port: int
    protocol: str = "tcp"
    status: str = "open"
    target: Optional[str] = None
    service: Optional[ServiceInfo] = None
    banner: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o resultado para dicionário."""
        result = {
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "banner": self.banner,
            "timestamp": self.timestamp,
        }
        
        if self.service:
            service_info = {
                "name": self.service.name,
                "version": self.service.version,
                "ssl": self.service.ssl,
                "vulnerabilities": self.service.vulns,
                "cpe": self.service.cpe,
                "extra": self.service.extra,
            }
            if self.service.ssl_info:
                service_info["ssl_info"] = self.service.ssl_info
            
            result["service"] = service_info
            
        return result

    def to_json(self) -> str:
        """Retorna uma representação JSON do resultado."""
        return json.dumps(self.to_dict(), indent=2)

class PortScanner:
    """Execução assíncrona de port scanning com detecção avançada de serviços."""

    def __init__(
        self,
        target: str,
        profile: str = "quick",
        concurrency: int = 200,
        timeout: float = 2.0,
        stealth_level: int = 0,
        resolve_services: bool = True,
        check_vulns: bool = True,
    ):
        self.target = target
        self.profile = profile if profile in PROFILES else "quick"
        self.stealth_level = max(0, min(stealth_level, 5))
        self.resolve_services = resolve_services
        self.check_vulns = check_vulns
        
        # Ajusta concorrência baseado no nível de stealth
        stealth_factors = [1.0, 0.8, 0.6, 0.4, 0.2, 0.1]
        adjusted_concurrency = int(concurrency * stealth_factors[self.stealth_level])
        self.concurrency = max(10, min(adjusted_concurrency, 500))
        
        # Ajusta timeout baseado no nível de stealth
        self.timeout = timeout * (1 + (self.stealth_level * 0.5))
        
        # Cache para serviços já identificados
        self.service_cache: Dict[int, ServiceInfo] = {}
        
        # Resolvedor DNS assíncrono
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0

    async def scan(self) -> List[PortScanResult]:
        """Executa a varredura de portas."""
        console.print(f"[bold]Iniciando varredura em {self.target}[/bold]")
        console.print(f"Perfil: {self.profile}, Portas: {len(PROFILES[self.profile])}")
        
        ports = PROFILES[self.profile]
        if self.stealth_level > 0:
            # Aleatoriza a ordem das portas para maior discrição
            random.shuffle(ports)
            
        sem = asyncio.Semaphore(self.concurrency)
        results: List[PortScanResult] = []
        
        async def worker(port: int):
            async with sem:
                result = await self._probe_port(port)
                if result:
                    results.append(result)
                    self._print_result(result)
        
        # Executa os workers em paralelo
        tasks = [worker(port) for port in ports]
        await asyncio.gather(*tasks)
        
        # Ordena os resultados por número de porta
        results.sort(key=lambda r: r.port)
        
        return results
    
    def _print_result(self, result: PortScanResult):
        """Exibe o resultado formatado no console."""
        port_info = f"[bold blue]{result.port:>5}/tcp[/bold blue]"
        status = "[green]open[/green]" if result.status == "open" else "[yellow]filtered[/yellow]"
        
        service_name = result.service.name if result.service else "unknown"
        service_info = f"[cyan]{service_name}[/cyan]"
        
        if result.service and result.service.version:
            service_info += f" [yellow]{result.service.version}[/yellow]"
            
        if result.service and result.service.ssl:
            service_info += " [green]🔒[/green]"
            
        if result.service and result.service.vulns:
            vuln_count = len(result.service.vulns)
            service_info += f" [red]({vuln_count} vulns)[/red]"
        
        console.print(f"{port_info} {status} {service_info}")
        
        if result.banner:
            console.print(f"      [dim]Banner: {result.banner[:100]}{'...' if len(result.banner) > 100 else ''}[/dim]")
    
    async def _probe_port(self, port: int) -> Optional[PortScanResult]:
        """Verifica se uma porta está aberta e coleta informações do serviço."""
        # Atraso aleatório para evitar detecção
        if self.stealth_level > 0:
            await asyncio.sleep(random.uniform(0.01, 0.5) * self.stealth_level)
        
        # Tenta conexão TCP
        try:
            # Usa um timeout menor para a conexão inicial
            conn_timeout = min(1.0, self.timeout)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=conn_timeout
            )
            
            # Se chegou aqui, a porta está aberta
            result = PortScanResult(port=port, status="open", target=self.target)
            
            # Tenta obter o banner do serviço
            try:
                # Configura timeout para leitura
                read_timeout = max(0.5, self.timeout - 0.5)
                
                # Lê o banner (se houver)
                writer.write(b"\r\n\r\n")
                await writer.drain()
                
                # Lê até 1024 bytes
                banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=read_timeout)
                if banner_bytes:
                    # Tenta decodificar como texto
                    try:
                        banner = banner_bytes.decode('utf-8', errors='replace').strip()
                        result.banner = banner
                        
                        # Tenta identificar o serviço pelo banner
                        service_info = await self._identify_service(port, banner)
                        if service_info:
                            result.service = service_info
                    except UnicodeDecodeError:
                        # Se não for texto, mostra como hexdump
                        result.banner = banner_bytes.hex(' ', 1)
            except (asyncio.TimeoutError, ConnectionResetError, OSError):
                # Ignora erros de leitura do banner
                pass
            
            # Verifica se é um serviço SSL/TLS
            if port in [443, 465, 636, 993, 995, 8443] or (result.service and result.service.ssl):
                ssl_info = await self._check_ssl(port)
                if ssl_info:
                    if not result.service:
                        result.service = ServiceInfo(name="ssl")
                    result.service.ssl = True
                    result.service.ssl_info = ssl_info
                    
                    # Tenta identificar o serviço SSL
                    if not result.service.name or result.service.name == "ssl":
                        service_name = self._identify_ssl_service(port, ssl_info)
                        result.service.name = service_name
            
            # Se não identificou o serviço, tenta pelo número da porta
            if not result.service and port in SERVICE_MAP:
                result.service = ServiceInfo(name=SERVICE_MAP[port])
                
                # Verifica vulnerabilidades conhecidas
                if self.check_vulns:
                    result.service.vulns = self._check_known_vulns(port, result.service.name)
            
            return result
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Porta fechada ou inacessível
            return None
            
        except Exception as e:
            logger.error(f"Erro ao verificar porta {port}: {str(e)}")
            return None
        
        finally:
            # Fecha a conexão se ainda estiver aberta
            if 'writer' in locals():
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
    
    async def _identify_service(self, port: int, banner: str) -> Optional[ServiceInfo]:
        """Tenta identificar o serviço rodando na porta com base no banner."""
        if not banner:
            return None
            
        banner_lower = banner.lower()
        service = ServiceInfo(name="unknown")
        
        # Verifica por padrões comuns de banners
        if "apache" in banner_lower or "httpd" in banner_lower:
            service.name = "Apache HTTP Server"
            if match := re.search(r'Apache[/\s]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:apache:http_server:{service.version}"
                
        elif "nginx" in banner_lower:
            service.name = "Nginx"
            if match := re.search(r'nginx[/\s]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:nginx:nginx:{service.version}"
                
        elif "microsoft-iis" in banner_lower or "microsoft httpapi" in banner_lower:
            service.name = "Microsoft IIS"
            if match := re.search(r'Microsoft-IIS/([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:microsoft:iis:{service.version}"
                
        elif "openbsd openssh" in banner_lower or "openssh" in banner_lower:
            service.name = "OpenSSH"
            if match := re.search(r'openssh[_-]?([0-9.]+[a-z]*)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:openbsd:openssh:{service.version}"
                
        elif "postfix" in banner_lower:
            service.name = "Postfix"
            if match := re.search(r'postfix[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:postfix:postfix:{service.version}"
                
        elif "exim" in banner_lower:
            service.name = "Exim"
            if match := re.search(r'exim[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:exim:exim:{service.version}"
                
        elif "dovecot" in banner_lower:
            service.name = "Dovecot"
            if match := re.search(r'dovecot[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:dovecot:dovecot:{service.version}"
                
        elif "proftpd" in banner_lower:
            service.name = "ProFTPD"
            if match := re.search(r'proftpd[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:proftpd:proftpd:{service.version}"
                
        elif "vsftpd" in banner_lower:
            service.name = "vsFTPd"
            if match := re.search(r'vsftpd[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:vsftpd:vsftpd:{service.version}"
                
        elif "mysql" in banner_lower:
            service.name = "MySQL"
            if match := re.search(r'([0-9.]+)[- ]*mysql', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:mysql:mysql:{service.version}"
                
        elif "postgresql" in banner_lower or 'postgres' in banner_lower:
            service.name = "PostgreSQL"
            if match := re.search(r'postgresql[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:postgresql:postgresql:{service.version}"
                
        elif "redis" in banner_lower:
            service.name = "Redis"
            if match := re.search(r'redis[\s:]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:redis:redis:{service.version}"
                
        elif "mongodb" in banner_lower:
            service.name = "MongoDB"
            if match := re.search(r'mongod?b[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:mongodb:mongodb:{service.version}"
                
        elif "microsoft sql server" in banner_lower or "sql server" in banner_lower:
            service.name = "Microsoft SQL Server"
            if match := re.search(r'sql server[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:microsoft:sql_server:{service.version}"
                
        elif "oracle" in banner_lower and "database" in banner_lower:
            service.name = "Oracle Database"
            if match := re.search(r'oracle[\s(]([0-9.]+)', banner, re.IGNORECASE):
                service.version = match.group(1)
                service.cpe = f"cpe:/a:oracle:database:{service.version}"
                
        # Se não identificou pelo banner, tenta pela porta
        if service.name == "unknown" and port in SERVICE_MAP:
            service.name = SERVICE_MAP[port]
        
        # Verifica vulnerabilidades conhecidas
        if self.check_vulns:
            service.vulns = self._check_known_vulns(port, service.name)
        
        return service if service.name != "unknown" else None
    
    def _identify_ssl_service(self, port: int, ssl_info: Dict[str, Any]) -> str:
        """Tenta identificar o serviço baseado na porta e informações SSL."""
        # Mapeia portas comuns para serviços SSL
        ssl_services = {
            443: "HTTPS",
            465: "SMTPS",
            563: "NNTPS",
            636: "LDAPS",
            853: "DNS-over-TLS",
            989: "FTPS (data)",
            990: "FTPS (control)",
            992: "Telnet over TLS/SSL",
            993: "IMAPS",
            994: "IRC over SSL",
            995: "POP3S",
            1443: "HTTPS (alt)",
            2376: "Docker TLS",
            2377: "Docker Swarm",
            3001: "HTTPS (Node.js)",
            3306: "MySQL over SSL",
            3389: "RDP over TLS",
            4000: "HTTPS (alt)",
            4001: "HTTPS (alt)",
            4002: "HTTPS (alt)",
            4003: "HTTPS (alt)",
            4004: "HTTPS (alt)",
            4005: "HTTPS (alt)",
            4006: "HTTPS (alt)",
            4007: "HTTPS (alt)",
            4008: "HTTPS (alt)",
            4009: "HTTPS (alt)",
            4433: "HTTPS (alt)",
            4443: "HTTPS (alt)",
            5000: "HTTPS (alt)",
            5001: "HTTPS (alt)",
            5002: "HTTPS (alt)",
            5003: "HTTPS (alt)",
            5004: "HTTPS (alt)",
            5005: "HTTPS (alt)",
            5006: "HTTPS (alt)",
            5007: "HTTPS (alt)",
            5008: "HTTPS (alt)",
            5009: "HTTPS (alt)",
            5432: "PostgreSQL over SSL",
            5671: "AMQPS",
            5800: "VNC over TLS",
            5901: "VNC over TLS (alt)",
            6001: "HTTPS (alt)",
            6002: "HTTPS (alt)",
            6003: "HTTPS (alt)",
            6004: "HTTPS (alt)",
            6005: "HTTPS (alt)",
            6006: "HTTPS (alt)",
            6007: "HTTPS (alt)",
            6008: "HTTPS (alt)",
            6009: "HTTPS (alt)",
            7000: "HTTPS (alt)",
            7001: "HTTPS (alt)",
            7002: "HTTPS (alt)",
            7003: "HTTPS (alt)",
            7004: "HTTPS (alt)",
            7005: "HTTPS (alt)",
            7006: "HTTPS (alt)",
            7007: "HTTPS (alt)",
            7008: "HTTPS (alt)",
            7009: "HTTPS (alt)",
            8000: "HTTPS (alt)",
            8001: "HTTPS (alt)",
            8002: "HTTPS (alt)",
            8003: "HTTPS (alt)",
            8004: "HTTPS (alt)",
            8005: "HTTPS (alt)",
            8006: "HTTPS (alt)",
            8007: "HTTPS (alt)",
            8008: "HTTPS (alt)",
            8009: "HTTPS (alt)",
            8080: "HTTPS (alt)",
            8081: "HTTPS (alt)",
            8082: "HTTPS (alt)",
            8083: "HTTPS (alt)",
            8084: "HTTPS (alt)",
            8085: "HTTPS (alt)",
            8086: "HTTPS (alt)",
            8087: "HTTPS (alt)",
            8088: "HTTPS (alt)",
            8089: "HTTPS (alt)",
            8090: "HTTPS (alt)",
            8091: "HTTPS (alt)",
            8443: "HTTPS (alt)",
            8444: "HTTPS (alt)",
            8445: "HTTPS (alt)",
            8446: "HTTPS (alt)",
            8447: "HTTPS (alt)",
            8448: "HTTPS (alt)",
            8449: "HTTPS (alt)",
            9000: "HTTPS (alt)",
            9001: "HTTPS (alt)",
            9002: "HTTPS (alt)",
            9003: "HTTPS (alt)",
            9004: "HTTPS (alt)",
            9005: "HTTPS (alt)",
            9006: "HTTPS (alt)",
            9007: "HTTPS (alt)",
            9008: "HTTPS (alt)",
            9009: "HTTPS (alt)",
            9010: "HTTPS (alt)",
            9443: "HTTPS (alt)",
            10000: "HTTPS (alt)",
            10443: "HTTPS (alt)",
            18080: "HTTPS (alt)",
            18081: "HTTPS (alt)",
            18082: "HTTPS (alt)",
            18083: "HTTPS (alt)",
            18084: "HTTPS (alt)",
            18085: "HTTPS (alt)",
            18086: "HTTPS (alt)",
            18087: "HTTPS (alt)",
            18088: "HTTPS (alt)",
            18089: "HTTPS (alt)",
            20000: "HTTPS (alt)",
            27017: "MongoDB over SSL",
            27018: "MongoDB over SSL (alt)",
            27019: "MongoDB over SSL (alt)",
            28017: "MongoDB over SSL (alt)",
            30000: "HTTPS (alt)",
            30001: "HTTPS (alt)",
            30002: "HTTPS (alt)",
            30003: "HTTPS (alt)",
            30004: "HTTPS (alt)",
            30005: "HTTPS (alt)",
            30006: "HTTPS (alt)",
            30007: "HTTPS (alt)",
            30008: "HTTPS (alt)",
            30009: "HTTPS (alt)",
            30010: "HTTPS (alt)",
            40000: "HTTPS (alt)",
            40001: "HTTPS (alt)",
            40002: "HTTPS (alt)",
            40003: "HTTPS (alt)",
            40004: "HTTPS (alt)",
            40005: "HTTPS (alt)",
            40006: "HTTPS (alt)",
            40007: "HTTPS (alt)",
            40008: "HTTPS (alt)",
            40009: "HTTPS (alt)",
            40010: "HTTPS (alt)",
            50000: "HTTPS (alt)",
            50001: "HTTPS (alt)",
            50002: "HTTPS (alt)",
            50003: "HTTPS (alt)",
            50004: "HTTPS (alt)",
            50005: "HTTPS (alt)",
            50006: "HTTPS (alt)",
            50007: "HTTPS (alt)",
            50008: "HTTPS (alt)",
            50009: "HTTPS (alt)",
            50010: "HTTPS (alt)",
            60000: "HTTPS (alt)",
            60001: "HTTPS (alt)",
            60002: "HTTPS (alt)",
            60003: "HTTPS (alt)",
            60004: "HTTPS (alt)",
            60005: "HTTPS (alt)",
            60006: "HTTPS (alt)",
            60007: "HTTPS (alt)",
            60008: "HTTPS (alt)",
            60009: "HTTPS (alt)",
            60010: "HTTPS (alt)",
        }
        
        return ssl_services.get(port, "SSL Service")
    
    async def _check_ssl(self, port: int) -> Optional[Dict[str, Any]]:
        """Verifica informações SSL/TLS da porta."""
        ssl_info = {}
        
        try:
            # Cria um contexto SSL
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Tenta conectar com SSL/TLS
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.target, 
                    port, 
                    ssl=ssl_context,
                    server_hostname=self.target
                ),
                timeout=self.timeout
            )
            
            # Obtém o certificado
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object and hasattr(ssl_object, 'getpeercert'):
                cert = ssl_object.getpeercert()
                
                # Extrai informações do certificado
                if cert:
                    ssl_info = {
                        'version': ssl_object.version(),
                        'cipher': ssl_object.cipher(),
                        'compression': ssl_object.compression(),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'serial_number': cert.get('serialNumber'),
                        'subject_alt_name': [
                            name[1] for name in cert.get('subjectAltName', [])
                            if name[0] == 'DNS'
                        ],
                        'ocsp': cert.get('OCSP', []),
                        'ca_issuers': cert.get('caIssuers', []),
                        'crl_distribution_points': cert.get('crlDistributionPoints', []),
                    }
                    
                    # Verifica se o certificado está expirado
                    from datetime import datetime
                    now = datetime.utcnow()
                    not_after = datetime.strptime(ssl_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    ssl_info['expired'] = now > not_after
                    
                    # Verifica se o certificado é auto-assinado
                    ssl_info['self_signed'] = (
                        ssl_info['issuer'] == ssl_info['subject']
                        and ssl_info['issuer'].get('organizationName', '').lower() != 'let\'s encrypt'
                    )
                    
                    # Verifica se o certificado é válido para o domínio
                    import idna
                    from socket import gethostbyname
                    
                    try:
                        hostname = idna.encode(self.target).decode('ascii')
                        ip = gethostbyname(hostname)
                        
                        # Verifica se o IP está nos subjectAltNames
                        alt_names = []
                        for name in ssl_info.get('subject_alt_name', []):
                            if name.startswith('*'):
                                # Lida com wildcards básicos
                                domain = name[2:]  # Remove o *.
                                if hostname.endswith(domain):
                                    alt_names.append(hostname)
                            else:
                                alt_names.append(name)
                        
                        ssl_info['valid_hostname'] = (
                            hostname in alt_names or
                            f'*.{hostname.split(".", 1)[1]}' in alt_names
                        )
                        
                        # Verifica se o IP está nos subjectAltNames
                        ssl_info['valid_ip'] = ip in alt_names
                        
                    except (UnicodeError, IndexError, OSError):
                        ssl_info['valid_hostname'] = False
                        ssl_info['valid_ip'] = False
            
            return ssl_info
            
        except (ssl.SSLError, asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Erro ao verificar SSL na porta {port}: {str(e)}")
            return None
            
        except Exception as e:
            logger.error(f"Erro inesperado ao verificar SSL na porta {port}: {str(e)}", exc_info=True)
            return None
            
        finally:
            if 'writer' in locals():
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
    
    def _check_known_vulns(self, port: int, service_name: str) -> List[str]:
        """Verifica vulnerabilidades conhecidas para o serviço na porta."""
        vulns = []
        
        # Verifica vulnerabilidades específicas do serviço
        for service, cves in VULNERABILITIES.items():
            if service.lower() in service_name.lower():
                vulns.extend(cves)
        
        # Verifica vulnerabilidades específicas da porta
        if port == 22:  # SSH
            vulns.extend(["CVE-2016-0777", "CVE-2016-0778", "CVE-2018-15473"])
        elif port == 445:  # SMB
            vulns.extend(["EternalBlue", "SMBGhost", "EternalRomance", "SambaCry"])
        elif port == 3389:  # RDP
            vulns.extend(["BlueKeep", "CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"])
        elif port == 27017:  # MongoDB
            vulns.extend(["Unauthenticated Access", "CVE-2016-6494"])
        elif port == 9200:  # Elasticsearch
            vulns.extend(["CVE-2015-1427", "CVE-2015-3337", "CVE-2015-5531"])
        elif port == 11211:  # Memcached
            vulns.extend(["DRDoS Amplification", "CVE-2016-8704", "CVE-2016-8705"])
        elif port == 2375:  # Docker
            vulns.extend(["CVE-2019-5736", "CVE-2019-13139", "CVE-2019-14271"])
        elif port == 10250:  # Kubelet
            vulns.extend(["CVE-2018-1002105", "CVE-2019-11253", "CVE-2019-11255"])
        
        return list(set(vulns))  # Remove duplicatas


def format_scan_results(results: List[PortScanResult], output_format: str = "text") -> str:
    """Formata os resultados da varredura no formato solicitado."""
    if output_format.lower() == "json":
        return json.dumps([r.to_dict() for r in results], indent=2)
    
    # Formato de texto para saída no console
    output = []
    output.append("")
    output.append(f"[bold]Resultado da varredura de portas[/bold]")
    output.append(f"Alvo: {results[0].target if results else 'N/A'}")
    output.append(f"Portas verificadas: {len(results)}")
    output.append("-" * 80)
    
    # Cabeçalho da tabela
    output.append(
        f"{'PORTA':<8} {'PROTOCOLO':<10} {'STATUS':<10} {'SERVIÇO':<25} {'VULNERABILIDADES'}"
    )
    output.append("-" * 80)
    
    # Linhas da tabela
    for result in results:
        if result.status == "open":
            port = f"[green]{result.port}[/green]"
            status = "[green]ABERTA[/green]"
        else:
            port = f"[yellow]{result.port}[/yellow]"
            status = "[yellow]FILTRADA[/yellow]"
            
        service = result.service.name if result.service else "desconhecido"
        version = f" {result.service.version}" if result.service and result.service.version else ""
        service_info = f"{service}{version}"
        
        if result.service and result.service.ssl:
            service_info += " 🔒"
            
        vulns = ", ".join(result.service.vulns) if result.service and result.service.vulns else "-"
        
        output.append(
            f"{port:<8} {'tcp':<10} {status:<10} {service_info:<25} {vulns}"
        )
    
    # Resumo
    open_ports = [r for r in results if r.status == "open"]
    output.append("-" * 80)
    output.append(f"Total de portas abertas: {len(open_ports)}")
    
    # Conta serviços por tipo
    services = {}
    for result in open_ports:
        if result.service:
            service_name = result.service.name
            services[service_name] = services.get(service_name, 0) + 1
    
    if services:
        output.append("\nServiços identificados:")
        for service, count in sorted(services.items()):
            output.append(f"  - {service}: {count} porta{'s' if count > 1 else ''}")
    
    # Verifica vulnerabilidades críticas
    critical_vulns = []
    for result in open_ports:
        if result.service and result.service.vulns:
            for vuln in result.service.vulns:
                if any(cve in vuln.upper() for cve in ["CVE", "MS"]):
                    critical_vulns.append((result.port, vuln))
    
    if critical_vulns:
        output.append("\n[bold red]VULNERABILIDADES CRÍTICAS ENCONTRADAS:[/bold red]")
        for port, vuln in critical_vulns:
            output.append(f"  - Porta {port}: {vuln}")
    
    return "\n".join(output)


__all__ = ["PortScanner", "PortScanResult", "format_scan_results"]
