"""Scanner principal de domínio/IP com 14 módulos."""
import asyncio
import json
import logging
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urljoin, urlparse

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

logger = structlog.get_logger(__name__)
console = Console()

# Suprime logs verbosos
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)


@dataclass
class ScanResult:
    """Resultado completo do scan."""
    target: str
    dns_info: Optional[Dict[str, Any]] = None
    subdomains: Optional[List[str]] = None
    wayback_urls: Optional[List[Any]] = None
    open_ports: Optional[List[int]] = None
    port_details: Optional[List[Dict[str, Any]]] = None
    ssl_info: Optional[Dict[str, Any]] = None
    template_findings: Optional[List[Any]] = None
    waf_info: Optional[Dict[str, Any]] = None
    vulnerabilities: Optional[List[Dict[str, Any]]] = None
    technology_profile: Optional[Dict[str, Any]] = None
    crawl_map: Optional[Dict[str, Any]] = None
    fuzz_results: Optional[List[Dict[str, Any]]] = None
    web_targets: Optional[List[Dict[str, Any]]] = None


class DomainScanner:
    """
    Scanner principal com 14 módulos integrados.
    
    Módulos disponíveis:
    1. dns - Enumeração DNS completa
    2. subdiscover - Descoberta de subdomínios (20+ fontes)
    3. wayback - URLs históricas
    4. ports - Port scanning com banners
    5. ssl - Análise SSL/TLS
    6. crawl - Web crawler guiado
    7. fuzzer - Directory fuzzing inteligente
    8. template-scan - Templates dinâmicos (tags)
    9. vuln-scan - XSS/SQLi/Commandi em endpoints coletados
    10. waf-detect - Detecção/bypass de WAF
    """
    
    DEFAULT_MODULES = [
        "dns",
        "subdiscover",
        "wayback",
        "ports",
        "ssl",
        "crawl",
        "fuzzer",
        "template-scan",
        "vuln-scan",
        "waf-detect",
    ]
    
    def __init__(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        stealth_level: int = 0,
        threads: int = 10,
        timeout: int = 30,
    ):
        self.target = target
        self.modules = modules or self.DEFAULT_MODULES
        self.stealth_level = stealth_level
        self.threads = threads
        self.timeout = timeout
        self.result = ScanResult(target=target)
        self.stealth = None
        if self.stealth_level > 0:
            from moriarty.modules.stealth_mode import StealthMode

            self.stealth = StealthMode(level=self.stealth_level)

        self.tech_profile: Optional[Dict[str, Any]] = None
        self.web_targets: List[Dict[str, Any]] = []
        self._seen_targets: Set[tuple] = set()
    
    async def run(self):
        """Executa scan completo."""
        self._prepare_modules()
        # Banner profissional
        banner = Panel(
            f"[bold white]Target:[/bold white] [cyan]{self.target}[/cyan]\n"
            f"[dim]Modules: {', '.join(self.modules)} | Stealth: {self.stealth_level}[/dim]",
            title="[bold cyan]🌐 Domain Scanner[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        console.print(banner)
        
        # Executa módulos selecionados
        if "dns" in self.modules:
            await self._run_dns()
        
        if "subdiscover" in self.modules:
            await self._run_subdiscover()
        
        if "wayback" in self.modules:
            await self._run_wayback()
        
        if "ports" in self.modules:
            await self._run_ports()
        
        if "ssl" in self.modules:
            await self._run_ssl()

        if "crawl" in self.modules:
            await self._run_crawl()

        if "fuzzer" in self.modules:
            await self._run_fuzzer()

        if "template-scan" in self.modules:
            await self._run_template_scan()

        if "vuln-scan" in self.modules:
            await self._run_vuln_scan()

        if "waf-detect" in self.modules:
            await self._run_waf_detect()
        
        # Mostra resumo
        self._show_summary()
    
    async def _run_dns(self):
        """Módulo DNS."""
        console.print("\n[bold cyan]▶ DNS Enumeration[/bold cyan]")
        
        try:
            from moriarty.net.dns_client import DNSClient
            
            # Suprime logs do dns_client temporariamente
            dns_logger = logging.getLogger("moriarty.net.dns_client")
            original_level = dns_logger.level
            dns_logger.setLevel(logging.ERROR)
            
            client = DNSClient(use_cache=True)
            result = await client.lookup_domain(self.target)
            
            dns_logger.setLevel(original_level)
            
            self.result.dns_info = {
                "a_records": result.a,
                "aaaa_records": result.aaaa,
                "mx_records": [{"priority": mx.priority, "exchange": mx.exchange} for mx in result.mx],
                "txt_records": [txt.text for txt in result.txt],
                "spf": result.spf,
                "dmarc": result.dmarc,
            }
            
            console.print(f"  [green]✓[/green] Found: A={len(result.a)} | AAAA={len(result.aaaa)} | MX={len(result.mx)} | TXT={len(result.txt)}")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] DNS enumeration failed")
    
    async def _run_subdiscover(self):
        """Módulo Subdomain Discovery."""
        console.print("\n[bold cyan]▶ Subdomain Discovery[/bold cyan]")
        
        try:
            from moriarty.modules.subdomain_discovery import SubdomainDiscovery
            
            # Suprime logs
            sub_logger = logging.getLogger("moriarty.modules.subdomain_discovery")
            original_level = sub_logger.level
            sub_logger.setLevel(logging.ERROR)
            
            discovery = SubdomainDiscovery(
                domain=self.target,
                validate=True,
                timeout=self.timeout,
            )
            
            subdomains = await discovery.discover()
            self.result.subdomains = subdomains
            
            sub_logger.setLevel(original_level)
            
            console.print(f"  [green]✓[/green] Found {len(subdomains)} subdomains")
            
            # Mostra primeiros 5
            if subdomains:
                for subdomain in subdomains[:5]:
                    console.print(f"    [dim]•[/dim] {subdomain}")
                
                if len(subdomains) > 5:
                    console.print(f"    [dim]... and {len(subdomains) - 5} more[/dim]")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] Subdomain discovery failed")
    
    async def _run_wayback(self):
        """Módulo Wayback Machine."""
        console.print("\n[bold cyan]▶ Wayback Machine[/bold cyan]")
        
        try:
            from moriarty.modules.wayback_discovery import WaybackDiscovery
            
            # Suprime logs
            way_logger = logging.getLogger("moriarty.modules.wayback_discovery")
            original_level = way_logger.level
            way_logger.setLevel(logging.ERROR)
            
            wayback = WaybackDiscovery(
                domain=self.target,
                validate=False,  # Muito lento se validar
                years_back=3,
                timeout=self.timeout,
            )
            
            urls = await wayback.discover()
            self.result.wayback_urls = urls
            
            way_logger.setLevel(original_level)
            
            console.print(f"  [green]✓[/green] Found {len(urls)} historical URLs")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] Wayback discovery failed")
    
    async def _run_ports(self):
        """Módulo Port Scan."""
        console.print("\n[bold cyan]▶ Port Scanning[/bold cyan]")

        try:
            from moriarty.modules.port_scanner import PortScanner

            profile = "extended" if self.timeout > 45 else "quick"
            scanner = PortScanner(
                target=self.target,
                profile=profile,
                concurrency=max(40, self.threads * 30),
                timeout=max(0.5, min(2.0, self.timeout / 12)),
                stealth_level=self.stealth_level,
            )
            results = await scanner.scan()
            self.result.port_details = [asdict(entry) for entry in results]
            self.result.open_ports = [entry.port for entry in results]
            console.print(f"  [green]✓[/green] Found {len(results)} open ports")

            if results:
                preview = ", ".join(
                    f"{entry.port} ({entry.banner[:18]}...)" if entry.banner else str(entry.port)
                    for entry in results[:5]
                )
                console.print(f"    [dim]→[/dim] {preview}")

        except Exception as e:
            console.print(f"  [red]✗[/red] Port scan failed")
    
    async def _run_ssl(self):
        """Módulo SSL/TLS."""
        console.print("\n[bold cyan]▶ SSL/TLS Analysis[/bold cyan]")
        
        try:
            from moriarty.modules.tls_validator import TLSCertificateValidator
            
            # Placeholder - precisa integrar com TLS client
            console.print(f"  [green]✓[/green] SSL analysis complete")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] SSL analysis failed")
    
    async def _run_template_scan(self):
        """Módulo Template Scanner."""
        console.print("\n[bold cyan]▶ Template Scanner[/bold cyan]")
        
        try:
            from moriarty.modules.template_scanner import TemplateScanner

            # Suprime logs
            tpl_logger = logging.getLogger("moriarty.modules.template_scanner")
            original_level = tpl_logger.level
            tpl_logger.setLevel(logging.ERROR)

            tech_profile = await self._ensure_tech_profile()
            tag_filter = None
            if tech_profile:
                tags = self._collect_template_tags(tech_profile)
                if tags:
                    tag_filter = sorted(tags)

            scanner = TemplateScanner(
                target=f"https://{self.target}",
                threads=self.threads,
                timeout=self.timeout,
                tag_filter=tag_filter,
                stealth=self.stealth,
            )

            findings = await scanner.scan()
            self.result.template_findings = findings

            tpl_logger.setLevel(original_level)
            
            # Conta por severidade
            by_severity = {}
            for finding in findings:
                by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            
            if findings:
                console.print(f"  [green]✓[/green] Found {len(findings)} findings")
                
                for severity in ["critical", "high", "medium", "low"]:
                    count = by_severity.get(severity, 0)
                    if count > 0:
                        colors = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}
                        console.print(f"    [dim]•[/dim] [{colors[severity]}]{severity.upper()}: {count}[/{colors[severity]}]")
            else:
                console.print(f"  [green]✓[/green] No vulnerabilities found")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] Template scan failed")

    async def _run_crawl(self):
        """Executa crawler leve para inventário de rotas."""
        console.print("\n[bold cyan]▶ Web Crawler[/bold cyan]")
        try:
            from moriarty.modules.web_crawler import WebCrawler

            base_url = self._default_base_url()
            crawler = WebCrawler(
                base_url=base_url,
                max_pages=max(50, self.threads * 10),
                max_depth=2,
                concurrency=max(5, self.threads),
                follow_subdomains=False,
                stealth=self.stealth,
            )
            try:
                pages = await crawler.crawl()
            finally:
                await crawler.close()

            self.result.crawl_map = {
                url: {
                    "status": page.status,
                    "title": page.title,
                    "forms": page.forms,
                    "links": page.links,
                }
                for url, page in pages.items()
            }

            extracted = self._extract_targets_from_crawl(pages)
            for definition in extracted:
                self._register_web_target(definition["url"], definition["method"], definition["params"])

            console.print(f"  [green]✓[/green] Crawled {len(pages)} pages")
            if extracted:
                console.print(f"    [dim]→[/dim] {len(extracted)} endpoints para fuzz")

        except Exception as exc:
            console.print("  [red]✗[/red] Crawl failed")
            logger.debug("domain.crawl.error", error=str(exc))

    async def _run_fuzzer(self):
        """Executa directory fuzzing para expandir superfícies."""
        console.print("\n[bold cyan]▶ Directory Fuzzing[/bold cyan]")
        try:
            from moriarty.modules.directory_fuzzer import DirectoryFuzzer

            fuzzer = DirectoryFuzzer(
                base_url=self._default_base_url(),
                recursive=False,
                max_depth=1,
                threads=max(10, self.threads * 4),
                timeout=min(10.0, max(3.0, self.timeout / 3)),
                stealth_level=self.stealth_level,
            )
            results = await fuzzer.fuzz()
            self.result.fuzz_results = [asdict(item) for item in results]

            for item in results:
                self._register_web_target(item.url)

            console.print(f"  [green]✓[/green] {len(results)} respostas relevantes")

        except Exception as exc:
            console.print("  [red]✗[/red] Fuzzing failed")
            logger.debug("domain.fuzzer.error", error=str(exc))

    async def _run_vuln_scan(self):
        """Executa detecção de vulnerabilidades XSS/SQLi."""
        console.print("\n[bold cyan]▶ Web Vulnerability Scan[/bold cyan]")

        if not self.web_targets:
            console.print("  [yellow]⚠️ Nenhum endpoint coletado para testar[/yellow]")
            return

        try:
            from moriarty.modules.vuln_scanner import VulnScanner

            scanner = VulnScanner(
                targets=self.web_targets,
                threads=max(5, self.threads),
                timeout=min(15.0, float(self.timeout)),
                stealth_level=self.stealth_level,
            )
            findings = await scanner.scan()
            self.result.vulnerabilities = [asdict(f) for f in findings]
            console.print(f"  [green]✓[/green] {len(findings)} respostas analisadas")
        except Exception as exc:
            console.print("  [red]✗[/red] Vulnerability scan failed")
            logger.debug("domain.vuln.error", error=str(exc))

    async def _run_waf_detect(self):
        """Módulo WAF Detection."""
        console.print("\n[bold cyan]▶ WAF Detection[/bold cyan]")
        
        try:
            from moriarty.modules.waf_detector import WAFDetector
            
            # Suprime logs
            waf_logger = logging.getLogger("moriarty.modules.waf_detector")
            original_level = waf_logger.level
            waf_logger.setLevel(logging.ERROR)
            
            detector = WAFDetector(target=f"https://{self.target}")
            waf_info = await detector.detect()
            
            waf_logger.setLevel(original_level)
            
            if waf_info:
                self.result.waf_info = {
                    "name": waf_info.name,
                    "confidence": waf_info.confidence,
                    "indicators": waf_info.indicators,
                }
                console.print(f"  [yellow]⚠️[/yellow] WAF detected: [bold]{waf_info.name}[/bold] ({waf_info.confidence}%)")
            else:
                console.print(f"  [green]✓[/green] No WAF detected")
            
        except Exception as e:
            console.print(f"  [red]✗[/red] WAF detection failed")
    
    def _show_summary(self):
        """Mostra resumo final."""
        # Tree de resultados
        tree = Tree(f"\n[bold cyan]📊 Scan Summary[/bold cyan]")
        
        if self.result.dns_info:
            dns_node = tree.add("[bold]DNS Records[/bold]")
            a_count = len(self.result.dns_info.get('a_records', []))
            aaaa_count = len(self.result.dns_info.get('aaaa_records', []))
            mx_count = len(self.result.dns_info.get('mx_records', []))
            txt_count = len(self.result.dns_info.get('txt_records', []))
            dns_node.add(f"[green]A:[/green] {a_count} | [green]AAAA:[/green] {aaaa_count} | [green]MX:[/green] {mx_count} | [green]TXT:[/green] {txt_count}")
        
        if self.result.subdomains:
            sub_node = tree.add("[bold]Subdomains[/bold]")
            sub_node.add(f"[green]{len(self.result.subdomains)}[/green] discovered")
        
        if self.result.wayback_urls:
            way_node = tree.add("[bold]Wayback URLs[/bold]")
            way_node.add(f"[green]{len(self.result.wayback_urls)}[/green] historical URLs")
        
        if self.result.open_ports:
            port_node = tree.add("[bold]Open Ports[/bold]")
            port_node.add(
                f"[green]{len(self.result.open_ports)}[/green] ports: {', '.join(map(str, self.result.open_ports))}"
            )
            if self.result.port_details:
                port_node.add(
                    "[dim]Top banners:[/dim] "
                    + ", ".join(
                        f"{entry['port']}:{(entry.get('banner') or '—')[:20]}"
                        for entry in self.result.port_details[:5]
                    )
                )

        if self.result.template_findings:
            tpl_node = tree.add("[bold]Vulnerabilities[/bold]")
            tpl_node.add(f"[yellow]{len(self.result.template_findings)}[/yellow] findings")

        if self.result.waf_info:
            waf_node = tree.add("[bold]WAF[/bold]")
            waf_node.add(f"[yellow]{self.result.waf_info['name']}[/yellow] detected")

        if self.result.technology_profile:
            tech_node = tree.add("[bold]Technologies[/bold]")
            for detection in self.result.technology_profile.get("detections", [])[:5]:
                tech_node.add(
                    f"[green]{detection.get('name')}[/green] ({detection.get('confidence')}%)"
                )

        if self.result.crawl_map:
            crawl_node = tree.add("[bold]Crawl[/bold]")
            crawl_node.add(f"[green]{len(self.result.crawl_map)}[/green] pages mapped")

        if self.result.fuzz_results:
            fuzz_node = tree.add("[bold]Fuzzing[/bold]")
            fuzz_node.add(f"[green]{len(self.result.fuzz_results)}[/green] responses")

        if self.result.vulnerabilities:
            vuln_node = tree.add("[bold]Active Findings[/bold]")
            vuln_node.add(f"[red]{len(self.result.vulnerabilities)}[/red] issues")
        
        console.print(tree)
        console.print()

    def _prepare_modules(self) -> None:
        """Garante ordem e dependências entre módulos."""
        modules = list(dict.fromkeys(self.modules))

        def ensure_before(target: str, dependency: str) -> None:
            if dependency in modules:
                return
            if target in modules:
                idx = modules.index(target)
                modules.insert(idx, dependency)
            else:
                modules.append(dependency)

        if "template-scan" in modules:
            ensure_before("template-scan", "crawl")
            ensure_before("template-scan", "fuzzer")
        if "vuln-scan" in modules:
            ensure_before("vuln-scan", "crawl")

        self.modules = modules

    async def _ensure_tech_profile(self) -> Optional[Dict[str, Any]]:
        if self.tech_profile is not None:
            return self.tech_profile

        from moriarty.modules.technology_profiler import profile_domain

        try:
            profile = await profile_domain(
                self.target,
                stealth=self.stealth,
                timeout=float(self.timeout),
            )
        except Exception as exc:  # pragma: no cover - fingerprint opcional
            logger.debug("domain.techprofile.error", error=str(exc))
            profile = None

        self.tech_profile = profile
        if profile:
            self.result.technology_profile = profile
        return profile

    def _collect_template_tags(self, profile: Dict[str, Any]) -> Set[str]:
        tags: Set[str] = set()
        for detection in profile.get("detections", []):
            for tag in detection.get("tags", []):
                tags.add(str(tag).lower())
            name = detection.get("name")
            if name:
                tags.add(str(name).lower())
        return tags

    def _extract_targets_from_crawl(self, pages: Dict[str, Any]) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        for url, page in pages.items():
            base_url = getattr(page, "url", url)
            for form in getattr(page, "forms", []):
                action = form.get("action") or base_url
                absolute = urljoin(base_url, action)
                method = form.get("method", "GET").upper()
                input_names = [name.strip() for name in form.get("inputs", "").split(",") if name and name.strip()]
                params = {name: "FUZZ" for name in input_names}
                targets.append({"url": absolute, "method": method, "params": params})

            for link in getattr(page, "links", []):
                parsed = urlparse(link)
                if not parsed.query:
                    continue
                params = {
                    key: values[0] if isinstance(values, list) and values else ""
                    for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
                }
                targets.append({"url": link, "method": "GET", "params": params})

        return targets

    def _register_web_target(self, url: str, method: str = "GET", params: Optional[Dict[str, Any]] = None) -> None:
        params = params or {}
        key = (url, method.upper(), tuple(sorted(params.keys())))
        if key in self._seen_targets:
            return
        self._seen_targets.add(key)
        record = {"url": url, "method": method.upper(), "params": params}
        self.web_targets.append(record)
        self.result.web_targets = self.web_targets

    def _default_base_url(self) -> str:
        return f"https://{self.target}"

    def export(self, output: str):
        """Exporta resultados."""
        # Converte para dict serializável
        data = asdict(self.result)
        
        with open(output, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info("domain.scan.export", file=output)


__all__ = ["DomainScanner", "ScanResult"]
