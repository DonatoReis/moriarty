"""Comandos de scanning de domínios/IPs."""
import json
from typing import Optional

import typer

from moriarty.modules.port_scanner import PortScanner, PROFILES
from moriarty.modules.passive_recon import PassiveRecon
from rich.console import Console

app = typer.Typer(name="domain", help="🌐 Domain/IP reconnaissance and scanning.")
console = Console()


@app.command("scan")
def scan_full(
    target: str = typer.Argument(..., help="Domain ou IP alvo"),
    modules: str = typer.Option(
        "all",
        "--modules",
        "-m",
        help="Módulos: all,dns,subdiscover,wayback,ports,ssl,crawl,fuzzer,template-scan,vuln-scan,waf-detect",
    ),
    stealth: int = typer.Option(0, "--stealth", "-s", help="Stealth level (0-4)"),
    threads: int = typer.Option(10, "--threads", "-t", help="Threads concorrentes"),
    timeout: int = typer.Option(30, "--timeout", help="Timeout em segundos"),
    output: str = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
):
    """
    🔍 Scan completo de domínio/IP com 14 módulos.
    
    Exemplos:
        moriarty domain scan example.com
        moriarty domain scan 8.8.8.8 --stealth 3
        moriarty domain scan target.com --modules dns,ports,ssl
    """
    from moriarty.modules.domain_scanner import DomainScanner
    import asyncio
    import logging
    
    # Suprime logs verbosos globalmente
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("moriarty").setLevel(logging.ERROR)
    
    scanner = DomainScanner(
        target=target,
        modules=modules.split(",") if modules != "all" else None,
        stealth_level=stealth,
        threads=threads,
        timeout=timeout,
    )
    
    asyncio.run(scanner.run())
    
    if output:
        scanner.export(output)
        console.print(f"[green]✅[/green] Results saved to: [cyan]{output}[/cyan]\n")


@app.command("subdiscover")
def subdomain_discovery(
    domain: str = typer.Argument(..., help="Domínio alvo"),
    sources: str = typer.Option("all", "--sources", "-s", help="Fontes: all,crtsh,virustotal,..."),
    validate: bool = typer.Option(True, "--validate/--no-validate", help="Validar subdomínios encontrados"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Busca recursiva"),
    wordlist: str = typer.Option(None, "--wordlist", "-w", help="Wordlist personalizada"),
    output: str = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
):
    """
    🔍 Descoberta de subdomínios usando 20+ fontes.
    
    Fontes suportadas:
    - crt.sh (Certificate Transparency)
    - VirusTotal
    - SecurityTrails
    - Shodan
    - DNSDumpster
    - AlienVault OTX
    - ThreatCrowd
    - Wayback Machine
    - CommonCrawl
    - Google Dorking
    - Bing
    - Yahoo
    - Ask
    - DNS Bruteforce
    - Zone Transfer
    - Reverse DNS
    - DNSSEC
    - NSEC Walking
    - Subdomain Permutations
    - GitHub Code Search
    """
    from moriarty.modules.subdomain_discovery import SubdomainDiscovery
    import asyncio
    
    console.print(f"[bold cyan]🔍 Descobrindo subdomínios de:[/bold cyan] {domain}\n")
    
    discovery = SubdomainDiscovery(
        domain=domain,
        sources=sources.split(",") if sources != "all" else None,
        validate=validate,
        recursive=recursive,
        wordlist=wordlist,
    )
    
    results = asyncio.run(discovery.discover())
    
    console.print(f"\n[green]✅ {len(results)} subdomínios encontrados[/green]")
    
    for subdomain in sorted(results):
        console.print(f"  • {subdomain}")
    
    if output:
        discovery.export(results, output)


@app.command("wayback")
def wayback_urls(
    domain: str = typer.Argument(..., help="Domínio alvo"),
    validate: bool = typer.Option(True, "--validate/--no-validate", help="Validar URLs ativas"),
    filter_ext: str = typer.Option(None, "--filter", "-f", help="Filtrar extensões (ex: php,asp,jsp)"),
    status_filter: str = typer.Option(None, "--status", help="Filtrar status codes (ex: 200,404,301)"),
    years: int = typer.Option(5, "--years", "-y", help="Anos para buscar"),
    output: str = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
):
    """
    🕰️ Descobre URLs históricas via Wayback Machine.
    
    Exemplos:
        moriarty domain wayback example.com
        moriarty domain wayback target.com --filter php,asp --years 10
    """
    from moriarty.modules.wayback_discovery import WaybackDiscovery
    import asyncio
    
    console.print(f"[bold cyan]🕰️ Buscando URLs históricas de:[/bold cyan] {domain}\n")
    
    wayback = WaybackDiscovery(
        domain=domain,
        validate=validate,
        filter_extensions=filter_ext.split(",") if filter_ext else None,
        filter_status_codes=[int(code.strip()) for code in status_filter.split(",") if code.strip()]
        if status_filter
        else None,
        years_back=years,
    )
    
    urls = asyncio.run(wayback.discover())
    
    console.print(f"\n[green]✅ {len(urls)} URLs encontradas[/green]")
    
    if output:
        wayback.export(urls, output)


@app.command("template-scan")
def template_scan(
    target: str = typer.Argument(..., help="Alvo (domain ou IP)"),
    templates: str = typer.Option(None, "--templates", "-t", help="Path para templates ou tag"),
    severity: str = typer.Option("all", "--severity", "-s", help="Severidade: all,critical,high,medium,low"),
    threads: int = typer.Option(20, "--threads", help="Threads concorrentes"),
    output: str = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
):
    """
    📝 Scan baseado em templates (estilo Nuclei).
    
    Exemplos:
        moriarty domain template-scan example.com
        moriarty domain template-scan target.com --templates cves/
        moriarty domain template-scan target.com --severity critical,high
    """
    import asyncio

    from moriarty.modules.template_scanner import TemplateScanner

    console.print(f"[bold cyan]📝 Template scan em:[/bold cyan] {target}\n")

    scanner = TemplateScanner(
        target=target,
        templates_path=templates,
        severity_filter=severity.split(",") if severity != "all" else None,
        threads=threads,
    )

    results = asyncio.run(scanner.scan())

    console.print(f"\n[bold]Resultados:[/bold]")
    for severity_level in ["critical", "high", "medium", "low", "info"]:
        findings = [r for r in results if r.severity == severity_level]
        if findings:
            color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green", "info": "dim"}[severity_level]
            console.print(f"[{color}]• {severity_level.upper()}: {len(findings)} findings[/{color}]")

    if output:
        scanner.export(results, output)


@app.command("pipeline")
def run_pipeline(
    pipeline_file: str = typer.Argument(..., help="Arquivo YAML do pipeline"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo (sobrescreve YAML)"),
    vars_file: str = typer.Option(None, "--vars", "-v", help="Arquivo de variáveis"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simular sem executar"),
):
    """
    🔄 Executa pipeline de scan via YAML declarativo.
    
    Exemplo de pipeline.yaml:
        name: "Full Recon"
        target: "example.com"
        stages:
          - name: "DNS Discovery"
            module: "dns"
          - name: "Subdomain Enum"
            module: "subdiscover"
          - name: "Port Scan"
            module: "ports"
    """
    from moriarty.modules.pipeline_orchestrator import PipelineOrchestrator
    import asyncio
    
    console.print(f"[bold cyan]🔄 Executando pipeline:[/bold cyan] {pipeline_file}\n")
    
    orchestrator = PipelineOrchestrator(
        pipeline_file=pipeline_file,
        target_override=target,
        vars_file=vars_file,
        dry_run=dry_run,
    )
    
    asyncio.run(orchestrator.run())


@app.command("stealth")
def stealth_command(
    action: str = typer.Argument(..., help="Ação: scan, config, proxy, test"),
    target: str = typer.Option(None, "--target", "-t", help="Alvo para scan/test"),
    level: int = typer.Option(2, "--level", "-l", help="Nível stealth (0-4)"),
):
    """
    🥷 Stealth Mode - Sistema completo de evasão.
    
    Níveis:
        0 - Disabled: Sem stealth
        1 - Low: Randomização básica
        2 - Medium: Proxies + timing
        3 - High: Fragmentação + adaptativo
        4 - Paranoid: Todas técnicas + decoys
    
    Exemplos:
        moriarty domain stealth scan example.com --level 3
        moriarty domain stealth config
        moriarty domain stealth test --target example.com
    """
    from moriarty.modules.stealth_mode import StealthMode
    import asyncio
    
    stealth = StealthMode(level=level)
    
    if action == "config":
        stealth.show_config()
    elif action == "scan":
        if not target:
            console.print("[red]❌ --target é obrigatório para scan[/red]")
            raise typer.Exit(1)
        asyncio.run(stealth.scan(target))
    elif action == "proxy":
        stealth.manage_proxies()
    elif action == "test":
        if not target:
            console.print("[red]❌ --target é obrigatório para test[/red]")
            raise typer.Exit(1)
        asyncio.run(stealth.test_capabilities(target))
    else:
        console.print(f"[red]❌ Ação inválida: {action}[/red]")


@app.command("ports")
def port_scan(
    target: str = typer.Argument(..., help="IP ou domínio"),
    ports: str = typer.Option("common", "--ports", "-p", help="Portas: common, all, 1-1000, 80,443"),
    scan_type: str = typer.Option("syn", "--type", "-t", help="Tipo: syn, tcp, udp"),
    stealth: int = typer.Option(0, "--stealth", "-s", help="Stealth level (0-4)"),
    output: str = typer.Option(None, "--output", "-o", help="Arquivo de saída"),
):
    """
    🔌 Scan avançado de portas.
    
    Exemplos:
        moriarty domain ports 8.8.8.8
        moriarty domain ports target.com --ports 1-10000
        moriarty domain ports target.com --type syn --stealth 3
    """
    from moriarty.modules.port_scanner import PortScanner
    import asyncio
    
    console.print(f"[bold cyan]🔌 Port scan em:[/bold cyan] {target}\n")
    
    scanner = PortScanner(
        target=target,
        ports=ports,
        scan_type=scan_type,
        stealth_level=stealth,
    )
    
    results = asyncio.run(scanner.scan())
    
    console.print(f"\n[green]✅ {len(results)} portas abertas encontradas[/green]")
    
    if output:
        scanner.export(results, output)


@app.command("waf-detect")
def waf_detection(
    target: str = typer.Argument(..., help="URL alvo"),
    bypass: bool = typer.Option(False, "--bypass", "-b", help="Tentar bypass automático"),
):
    """
    🛡️ Detecta WAF/IPS e tenta bypass automático.
    
    Detecta:
    - Cloudflare
    - AWS WAF
    - Akamai
    - Imperva
    - F5 BIG-IP
    - ModSecurity
    - Sucuri
    - Barracuda
    - Fortinet
    """
    from moriarty.modules.waf_detector import WAFDetector
    import asyncio
    
    console.print(f"[bold cyan]🛡️ Detectando WAF em:[/bold cyan] {target}\n")
    
    detector = WAFDetector(target=target)
    waf_info = asyncio.run(detector.detect())
    
    if waf_info:
        console.print(f"[yellow]⚠️ WAF detectado:[/yellow] {waf_info['name']}")
        console.print(f"[dim]Confidence: {waf_info['confidence']}%[/dim]")
        
        if bypass:
            console.print("\n[cyan]🔓 Tentando bypass...[/cyan]")
            bypass_methods = asyncio.run(detector.attempt_bypass())
            
            for method in bypass_methods:
                if method['success']:
                    console.print(f"[green]✅ Bypass bem-sucedido:[/green] {method['technique']}")
    else:
        console.print("[green]✅ Nenhum WAF detectado[/green]")


__all__ = ["app"]
@app.command("recon")
def passive_recon(
    domain: str = typer.Argument(..., help="Domínio alvo"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Arquivo JSON de saída"),
    status_only: bool = typer.Option(False, "--status-only", help="Mostrar apenas resumo"),
):
    """
    🌐 Coleta passiva de inteligência sobre domínios.
    
    Exemplos:
        moriarty domain recon example.com
        moriarty domain recon target.com --output resultado.json
    """
    import asyncio
    import json
    import logging
    from datetime import datetime
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    
    # Configuração de logs
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("moriarty").setLevel(logging.ERROR)
    
    console = Console()
    
    # Cabeçalho
    console.print(f"\n[bold cyan]🌐 Moriarty Passive Recon[/bold cyan]")
    console.print(f"[dim]Alvo:[/dim] {domain}")
    console.print(f"[dim]Data:[/dim] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    async def _run():
        with console.status(f"[bold green]Coletando informações sobre [cyan]{domain}[/cyan]..."):
            recon = PassiveRecon(domain)
            try:
                return await recon.collect()
            finally:
                await recon.close()

    try:
        result = asyncio.run(_run())
        payload = result.to_dict()
        
        if status_only:
            sub_count = sum(len(v) for v in payload["subdomains"].values())
            console.print(f"[bold]🔍 Resumo do Reconhecimento[/bold]")
            console.print(f"  • [cyan]Subdomínios:[/cyan] {sub_count} encontrados")
            console.print(f"  • [cyan]Fontes:[/cyan] {', '.join(payload['subdomains'].keys()) or 'nenhuma'}")
            console.print(f"  • [cyan]Credenciais vazadas:[/cyan] {len(payload['leaks'])}")
            return
            
        # Seção de Subdomínios
        if payload.get("subdomains"):
            table = Table(title="[bold]🌐 Subdomínios Encontrados[/bold]", box=box.ROUNDED)
            table.add_column("Subdomínio", style="cyan")
            table.add_column("Fonte", style="green")
            
            for source, subdomains in payload["subdomains"].items():
                for sub in subdomains:
                    table.add_row(sub, source)
            
            console.print(Panel.fit(table, border_style="blue"))
        
        # Seção de Tecnologias
        if payload.get("technologies", {}).get("detections"):
            tech_table = Table(title="[bold]🛠️ Tecnologias Detectadas[/bold]", box=box.ROUNDED)
            tech_table.add_column("Tecnologia", style="cyan")
            tech_table.add_column("Confiança", style="green")
            tech_table.add_column("Categoria", style="magenta")
            
            for tech in payload["technologies"]["detections"]:
                tech_table.add_row(
                    tech["name"],
                    f"{tech['confidence']}%",
                    ", ".join(tech.get("categories", []))
                )
            
            console.print(Panel.fit(tech_table, border_style="blue"))
        
        # Seção de Segurança
        security_table = Table(title="[bold]🔒 Análise de Segurança[/bold]", box=box.ROUNDED)
        security_table.add_column("Item", style="cyan")
        security_table.add_column("Status", style="green")
        
        # Verifica HSTS
        headers = payload.get("technologies", {}).get("headers", {})
        hsts = "Sim" if "strict-transport-security" in str(headers).lower() else "Não"
        security_table.add_row("HSTS Habilitado", hsts)
        
        # Verifica XSS Protection
        xss_protection = "Sim" if "x-xss-protection" in str(headers).lower() else "Não"
        security_table.add_row("Proteção XSS", xss_protection)
        
        # Verifica Content Security Policy
        csp = "Sim" if "content-security-policy" in str(headers).lower() else "Não"
        security_table.add_row("Content Security Policy", csp)
        
        console.print(Panel.fit(security_table, border_style="blue"))
        
        # Seção de Reputação
        if payload.get("reputation"):
            rep_table = Table(title="[bold]📊 Reputação do Domínio[/bold]", box=box.ROUNDED)
            rep_table.add_column("Fonte", style="cyan")
            rep_table.add_column("Status", style="green")
            
            for source, data in payload["reputation"].items():
                if isinstance(data, dict) and data.get("pulses") is not None:
                    rep_table.add_row(source, f"{len(data['pulses'])} ameaças conhecidas")
                elif source == "alienvault" and data.get("pulses") is not None:
                    rep_table.add_row("AlienVault OTX", f"{len(data['pulses'])} ameaças conhecidas")
            
            console.print(Panel.fit(rep_table, border_style="blue"))
        
        # Seção de Informações WHOIS
        if payload.get("whois"):
            whois_info = "\n".join(line for line in payload["whois"].split("\n") 
                                 if not line.startswith("%") and line.strip())
            console.print(Panel.fit(
                f"[bold]📝 Informações de Registro (WHOIS)[/bold]\n\n[dim]{whois_info}",
                border_style="blue"
            ))
        
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
            console.print(f"\n[green]✓[/green] Resultados salvos em: [cyan]{output}[/cyan]")
    
    except Exception as e:
        console.print(f"[red]✗ Erro durante o reconhecimento:[/red] {str(e)}")
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                json.dump({"error": str(e)}, handle, indent=2)
            console.print(f"[yellow]⚠  Log de erro salvo em: {output}[/yellow]")


@app.command("ports")
def port_scan(
    domain: str = typer.Argument(..., help="Alvo para o port scan"),
    profile: str = typer.Option("quick", "--profile", "-p", help=f"Perfil ({', '.join(PROFILES.keys())})"),
    concurrency: int = typer.Option(200, "--concurrency", help="Conexões simultâneas"),
    timeout: float = typer.Option(1.5, "--timeout", help="Timeout por porta"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Arquivo de saída JSON"),
):
    """Executa port scan assíncrono com banners."""
    import asyncio
    import json

    async def _run():
        scanner = PortScanner(
            target=domain,
            profile=profile,
            concurrency=concurrency,
            timeout=timeout,
        )
        return await scanner.scan()

    results = asyncio.run(_run())
    if not results:
        console.print("[yellow]Nenhuma porta aberta detectada[/yellow]")
    else:
        table_data = [
            {"port": r.port, "status": r.status, "banner": r.banner or "-"}
            for r in results
        ]
        console.print_json(data=table_data)

    if output:
        json_payload = [r.__dict__ for r in results]
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(json_payload, handle, indent=2, ensure_ascii=False)
        console.print(f"[green]✓ Resultado salvo em[/green] {output}")


@app.command("crawl")
def crawl(
    domain: str = typer.Argument(..., help="Alvo base (ex: https://example.com)"),
    max_pages: int = typer.Option(100, "--max-pages", help="Máximo de páginas"),
    max_depth: int = typer.Option(2, "--max-depth", help="Profundidade máxima"),
    concurrency: int = typer.Option(10, "--concurrency", help="Workers paralelos"),
    follow_subdomains: bool = typer.Option(False, "--follow-subdomains", help="Seguir subdomínios"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Arquivo JSON de saída"),
):
    """Crawler leve para mapear formulários e rotas."""
    import asyncio
    import json

    async def _run():
        crawler = WebCrawler(
            base_url=domain,
            max_pages=max_pages,
            max_depth=max_depth,
            concurrency=concurrency,
            follow_subdomains=follow_subdomains,
        )
        try:
            return await crawler.crawl()
        finally:
            await crawler.close()

    pages = asyncio.run(_run())
    summary = {
        "total_pages": len(pages),
        "forms": sum(len(page.forms) for page in pages.values()),
    }
    console.print_json(data=summary)

    if output:
        payload = {url: page.__dict__ for url, page in pages.items()}
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        console.print(f"[green]✓ Resultado salvo em[/green] {output}")
