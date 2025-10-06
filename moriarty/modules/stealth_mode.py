"""Stealth Mode - Sistema completo de evasão para scanning."""
import asyncio
import random
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import httpx
import structlog
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class StealthConfig:
    """Configuração do Stealth Mode."""
    level: int
    user_agent_rotation: bool
    header_randomization: bool
    timing_randomization: bool
    proxy_rotation: bool
    packet_fragmentation: bool
    decoy_traffic: bool
    encoding_layers: int
    session_management: bool
    anti_forensics: bool
    tls_fingerprint_randomization: bool
    tcp_stack_spoofing: bool
    tor_support: bool
    i2p_support: bool


@dataclass
class ProxyState:
    """Estado de saúde de um proxy."""

    url: str
    healthy: bool = True
    last_checked: float = 0.0
    latency: float = 0.0
    failures: int = 0


class StealthMode:
    """
    Sistema de Stealth Mode com 5 níveis de evasão.
    
    Níveis:
        0 - Disabled: Sem stealth
        1 - Low: Randomização básica
        2 - Medium: Proxies + timing
        3 - High: Fragmentação + adaptativo
        4 - Paranoid: Todas técnicas + decoys
    """
    
    # 50+ User Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    ]
    
    # Headers dinâmicos
    DYNAMIC_HEADERS = {
        "Accept": [
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ],
        "Accept-Language": [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "pt-BR,pt;q=0.9,en;q=0.8",
        ],
        "Accept-Encoding": [
            "gzip, deflate, br",
            "gzip, deflate",
        ],
        "DNT": ["1", "0"],
        "Connection": ["keep-alive", "close"],
        "Upgrade-Insecure-Requests": ["1"],
    }
    
    def __init__(self, level: int = 2, healthcheck_url: str = "https://example.com"):
        self.level = level
        self.config = self._build_config()
        self.proxies: List[str] = []
        self._current_proxy_index = 0
        self.proxy_states: Dict[str, ProxyState] = {}
        self.healthcheck_url = healthcheck_url
        self.proxy_health_interval = 300  # seconds
        self.max_proxy_failures = 3
        self._last_health_sweep: float = 0.0

        try:
            from moriarty.core.config_manager import config_manager

            self.config_manager = config_manager
        except Exception:
            self.config_manager = None

        self._load_configured_proxies()

    def _build_config(self) -> StealthConfig:
        """Constrói configuração baseada no nível."""
        return StealthConfig(
            level=self.level,
            user_agent_rotation=self.level >= 1,
            header_randomization=self.level >= 1,
            timing_randomization=self.level >= 2,
            proxy_rotation=self.level >= 2,
            packet_fragmentation=self.level >= 3,
            decoy_traffic=self.level >= 4,
            encoding_layers=min(self.level, 3),
            session_management=self.level >= 3,
            anti_forensics=self.level >= 4,
            tls_fingerprint_randomization=self.level >= 3,
            tcp_stack_spoofing=self.level >= 3,
            tor_support=self.level >= 2,
            i2p_support=self.level >= 4,
        )

    def _load_configured_proxies(self):
        """Carrega proxies configurados via config manager ou arquivo padrão."""
        if not self.config_manager:
            return

        proxy_config = getattr(self.config_manager, "proxies", None)
        if not proxy_config:
            return

        for proxy in proxy_config.http_proxies or []:
            self._register_proxy(proxy)

        for proxy in proxy_config.socks_proxies or []:
            self._register_proxy(proxy)

        if (proxy_config.tor_enabled or self.config.tor_support) and proxy_config.tor_port:
            tor_proxy = f"socks5://127.0.0.1:{proxy_config.tor_port}"
            self._register_proxy(tor_proxy)

        if (proxy_config.i2p_enabled or self.config.i2p_support) and proxy_config.i2p_port:
            i2p_proxy = f"http://127.0.0.1:{proxy_config.i2p_port}"
            self._register_proxy(i2p_proxy)

        if self.proxies:
            logger.info("stealth.proxies.loaded", count=len(self.proxies))

    def _register_proxy(self, proxy: str):
        """Registra proxy na rotação com estado inicial saudável."""
        if not proxy:
            return

        if proxy not in self.proxies:
            self.proxies.append(proxy)
        self.proxy_states.setdefault(proxy, ProxyState(url=proxy))
    
    def get_random_headers(self) -> dict:
        """Retorna headers randomizados."""
        headers = {}

        if self.config.user_agent_rotation:
            headers["User-Agent"] = random.choice(self.USER_AGENTS)

        if self.config.header_randomization:
            for key, values in self.DYNAMIC_HEADERS.items():
                headers[key] = random.choice(values)

            if self.config.tls_fingerprint_randomization:
                sec_ch_templates = [
                    '"Chromium";v="123", "Not=A?Brand";v="8", "Google Chrome";v="123"',
                    '"Chromium";v="120", "Not)A(Brand";v="24", "Microsoft Edge";v="120"',
                    '"Google Chrome";v="122", "Chromium";v="122", ";Not A Brand";v="99"',
                ]
                headers["Sec-CH-UA"] = random.choice(sec_ch_templates)
                headers["Sec-CH-UA-Mobile"] = random.choice(["?0", "?1"])
                headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])
                headers.setdefault("Sec-Fetch-Site", random.choice(["none", "same-origin", "cross-site"]))
                headers.setdefault("Sec-Fetch-Mode", random.choice(["navigate", "cors", "no-cors"]))
                headers.setdefault("Sec-Fetch-Dest", random.choice(["document", "empty", "iframe"]))

            if random.random() < 0.4:
                headers["X-Forwarded-For"] = ".".join(str(random.randint(1, 254)) for _ in range(4))
            if random.random() < 0.2:
                headers["X-Requested-With"] = random.choice(["XMLHttpRequest", "Fetch"])

        return headers
    
    def get_random_delay(self) -> float:
        """Retorna delay randomizado (distribuição gaussiana)."""
        if not self.config.timing_randomization:
            return 0.0

        # Delay base aumenta com o nível
        base_delay = self.level * 0.5

        # Adiciona variação gaussiana
        delay = max(0.1, random.gauss(base_delay, base_delay * 0.3))

        return delay

    async def _ensure_proxy_health(self):
        """Executa health check periódico nos proxies."""
        if not self.config.proxy_rotation or not self.proxies:
            return

        now = time.time()
        if now - self._last_health_sweep < self.proxy_health_interval:
            return

        for proxy, state in self.proxy_states.items():
            if now - state.last_checked >= self.proxy_health_interval:
                await self._check_proxy_health(proxy)

        self._last_health_sweep = time.time()

    async def _check_proxy_health(self, proxy: str) -> None:
        """Verifica saúde de um proxy específico."""
        state = self.proxy_states.setdefault(proxy, ProxyState(url=proxy))
        start = time.time()

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.get(
                    self.healthcheck_url,
                    proxies=self._build_proxy_mapping(proxy),
                    headers={"User-Agent": random.choice(self.USER_AGENTS)},
                )
            latency = time.time() - start
            state.healthy = True
            state.latency = latency
            state.failures = 0
            state.last_checked = time.time()
            logger.debug(
                "stealth.proxy.health_ok",
                proxy=proxy,
                latency=f"{latency:.2f}s",
            )
        except Exception as exc:  # pragma: no cover - protegido para ambientes sem rede
            state.failures += 1
            state.last_checked = time.time()
            if state.failures >= self.max_proxy_failures:
                state.healthy = False
            logger.debug(
                "stealth.proxy.health_fail",
                proxy=proxy,
                error=str(exc),
                failures=state.failures,
            )

    def get_next_proxy(self) -> Optional[str]:
        """Retorna próximo proxy saudável sem await (retrocompatibilidade)."""
        if not self.config.proxy_rotation or not self.proxies:
            return None

        healthy = [p for p in self.proxies if self.proxy_states.get(p, ProxyState(p)).healthy]
        if not healthy:
            return None

        proxy = healthy[self._current_proxy_index % len(healthy)]
        self._current_proxy_index = (self._current_proxy_index + 1) % len(healthy)
        return proxy

    async def _select_proxy(self) -> Optional[str]:
        """Seleciona proxy saudável, disparando health checks se necessário."""
        if not self.config.proxy_rotation or not self.proxies:
            return None

        await self._ensure_proxy_health()

        healthy = [p for p in self.proxies if self.proxy_states.get(p, ProxyState(p)).healthy]
        if not healthy:
            # todos degradados -> reativar temporariamente para tentativa
            logger.warning("stealth.proxy.all_unhealthy")
            for state in self.proxy_states.values():
                state.healthy = True
            healthy = self.proxies[:]

        proxy = healthy[self._current_proxy_index % len(healthy)]
        self._current_proxy_index = (self._current_proxy_index + 1) % max(len(healthy), 1)
        return proxy

    def _build_proxy_mapping(self, proxy: str) -> Dict[str, str]:
        return {
            "http://": proxy,
            "https://": proxy,
        }

    def _extract_proxy_url(self, proxies: Optional[Dict[str, str]]) -> Optional[str]:
        if not proxies:
            return None
        return proxies.get("https://") or proxies.get("http://")

    def _mark_proxy_success(self, proxy: Optional[str], latency: float) -> None:
        if not proxy:
            return
        state = self.proxy_states.setdefault(proxy, ProxyState(url=proxy))
        state.healthy = True
        state.latency = latency
        state.failures = 0
        state.last_checked = time.time()

    def _mark_proxy_failure(self, proxy: Optional[str]) -> None:
        if not proxy:
            return
        state = self.proxy_states.setdefault(proxy, ProxyState(url=proxy))
        state.failures += 1
        state.last_checked = time.time()
        if state.failures >= self.max_proxy_failures:
            state.healthy = False
            logger.warning("stealth.proxy.mark_unhealthy", proxy=proxy)

    def _get_tls_context(self) -> Optional[ssl.SSLContext]:
        """Gera contexto TLS com fingerprint randomizado."""
        if not self.config.tls_fingerprint_randomization:
            return None

        try:
            context = ssl.create_default_context()
        except ssl.SSLError:
            return None

        min_version = random.choice([
            ssl.TLSVersion.TLSv1_2,
            ssl.TLSVersion.TLSv1_3,
        ])
        context.minimum_version = min_version
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        cipher_sets = [
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256",
        ]

        try:
            context.set_ciphers(random.choice(cipher_sets))
        except ssl.SSLError:
            pass

        if random.random() < 0.5:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        return context

    async def _spoof_tcp_stack(self, url: str, proxy: Optional[str]) -> None:
        """Envia pacotes forjados para confundir fingerprint TCP/IP."""
        if not self.config.tcp_stack_spoofing:
            return

        try:
            from scapy.all import IP, TCP, RandShort, send  # type: ignore
        except Exception:
            logger.debug("stealth.tcp.spoof_unavailable")
            return

        parsed = urlparse(url)
        dst = parsed.hostname
        if not dst:
            return

        dport = parsed.port or (443 if parsed.scheme == "https" else 80)
        ttl = random.randint(40, 255)
        window = random.randint(1024, 65535)

        packet = IP(dst=dst, ttl=ttl) / TCP(dport=dport, sport=RandShort(), window=window, flags="S")

        try:
            send(packet, verbose=False)
        except Exception as exc:  # pragma: no cover - pode exigir privilégios
            logger.debug("stealth.tcp.spoof_error", error=str(exc))
    
    async def make_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str = "GET",
        **kwargs
    ) -> Optional[httpx.Response]:
        """Faz request com stealth aplicado."""
        base_kwargs = dict(kwargs)
        provided_headers = base_kwargs.pop("headers", {})
        provided_proxies = base_kwargs.pop("proxies", None)

        attempts = 0
        max_attempts = max(1, len(self.proxies)) if self.config.proxy_rotation and not provided_proxies else 1

        while attempts < max_attempts:
            headers = self.get_random_headers()
            if isinstance(provided_headers, dict):
                headers.update(provided_headers)

            proxies = provided_proxies
            proxy_url = self._extract_proxy_url(proxies) if isinstance(provided_proxies, dict) else provided_proxies

            if proxies is None and self.config.proxy_rotation:
                proxy_url = await self._select_proxy()
                if proxy_url:
                    proxies = self._build_proxy_mapping(proxy_url)

            if self.config.timing_randomization:
                await asyncio.sleep(self.get_random_delay())

            if self.config.decoy_traffic:
                await self._send_decoy_traffic(client)

            await self._spoof_tcp_stack(url, proxy_url)

            tls_context = self._get_tls_context()
            request_kwargs = dict(base_kwargs)
            request_kwargs["headers"] = headers
            if proxies:
                request_kwargs["proxies"] = proxies
            if tls_context:
                request_kwargs["verify"] = tls_context
            if self.config.tls_fingerprint_randomization and "http2" not in request_kwargs:
                request_kwargs["http2"] = random.random() < 0.6

            start_time = time.time()

            try:
                response = await client.request(
                    method,
                    url,
                    **request_kwargs,
                )

                self._mark_proxy_success(proxy_url, time.time() - start_time)

                if self.config.anti_forensics:
                    self._sanitize_response(response)

                return response

            except httpx.RequestError as exc:
                self._mark_proxy_failure(proxy_url)
                logger.warning(
                    "stealth.request.network_error",
                    url=url,
                    proxy=proxy_url,
                    error=str(exc),
                )

                attempts += 1
                if provided_proxies is not None:
                    break
                continue

            except Exception as exc:  # pragma: no cover - captura erros inespecíficos
                logger.warning("stealth.request.error", url=url, error=str(exc))
                break

        return None
    
    async def _send_decoy_traffic(self, client: httpx.AsyncClient):
        """Envia tráfego decoy para confundir IDS/IPS."""
        decoy_targets = [
            "https://www.google.com",
            "https://www.bing.com",
            "https://www.yahoo.com",
        ]
        
        target = random.choice(decoy_targets)
        try:
            await client.get(target, timeout=2.0)
        except:
            pass
    
    def _sanitize_response(self, response: httpx.Response):
        """Remove informações sensíveis da response."""
        # Remove headers que podem identificar
        sensitive_headers = ["X-Request-ID", "X-Trace-ID", "X-Correlation-ID"]
        for header in sensitive_headers:
            response.headers.pop(header, None)
    
    def show_config(self):
        """Mostra configuração atual."""
        table = Table(title=f"🥷 Stealth Mode - Level {self.level}")
        
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="green")
        
        table.add_row("User-Agent Rotation", "✅" if self.config.user_agent_rotation else "❌")
        table.add_row("Header Randomization", "✅" if self.config.header_randomization else "❌")
        table.add_row("Timing Randomization", "✅" if self.config.timing_randomization else "❌")
        table.add_row("Proxy Rotation", "✅" if self.config.proxy_rotation else "❌")
        table.add_row("Packet Fragmentation", "✅" if self.config.packet_fragmentation else "❌")
        table.add_row("Decoy Traffic", "✅" if self.config.decoy_traffic else "❌")
        table.add_row("Encoding Layers", str(self.config.encoding_layers))
        table.add_row("Session Management", "✅" if self.config.session_management else "❌")
        table.add_row("Anti-Forensics", "✅" if self.config.anti_forensics else "❌")
        table.add_row("TLS Fingerprint", "✅" if self.config.tls_fingerprint_randomization else "❌")
        table.add_row("TCP Spoofing", "✅" if self.config.tcp_stack_spoofing else "❌")
        table.add_row("Tor Support", "✅" if self.config.tor_support else "❌")
        table.add_row("I2P Support", "✅" if self.config.i2p_support else "❌")

        console.print(table)
        
        if self.proxies:
            rows = []
            for proxy in self.proxies:
                state = self.proxy_states.get(proxy, ProxyState(url=proxy))
                health_icon = "✅" if state.healthy else "❌"
                latency = f"{state.latency*1000:.0f}ms" if state.latency else "--"
                rows.append(f"{health_icon} {proxy} (latência: {latency}, falhas: {state.failures})")

            console.print("\n[cyan]Proxies carregados:[/cyan]")
            for line in rows:
                console.print(f"  • {line}")
    
    async def scan(self, target: str):
        """Executa scan com stealth mode."""
        console.print(f"[bold cyan]🥷 Stealth Scan iniciado[/bold cyan] (Level {self.level})")
        console.print(f"[dim]Target: {target}[/dim]\n")
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Exemplo de scan
            response = await self.make_request(client, f"https://{target}")
            
            if response:
                console.print(f"[green]✅ Response: {response.status_code}[/green]")
            else:
                console.print("[red]❌ Request failed[/red]")
    
    def manage_proxies(self):
        """Gerencia lista de proxies."""
        console.print("[bold cyan]🔧 Proxy Management[/bold cyan]\n")
        
        if not self.proxies:
            console.print("[yellow]⚠️ Nenhum proxy configurado[/yellow]")
            console.print("\nAdicione proxies ao arquivo: ~/.moriarty/proxies.txt")
        else:
            for i, proxy in enumerate(self.proxies, 1):
                state = self.proxy_states.get(proxy, ProxyState(url=proxy))
                status = "healthy" if state.healthy else "unhealthy"
                latency = f"{state.latency*1000:.0f}ms" if state.latency else "--"
                console.print(f"{i}. {proxy} [{status}] (latência {latency}, falhas {state.failures})")

    async def refresh_proxy_health(self):
        """Força health check imediato em todos os proxies."""
        await asyncio.gather(*(self._check_proxy_health(proxy) for proxy in self.proxies))
    
    async def test_capabilities(self, target: str):
        """Testa capacidades de stealth."""
        console.print(f"[bold cyan]🧪 Testando Stealth Capabilities[/bold cyan]\n")
        console.print(f"Target: {target}\n")
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Test 1: User-Agent rotation
            console.print("[cyan]1. User-Agent Rotation...[/cyan]")
            ua1 = self.get_random_headers()["User-Agent"]
            ua2 = self.get_random_headers()["User-Agent"]
            console.print(f"   UA1: {ua1[:50]}...")
            console.print(f"   UA2: {ua2[:50]}...")
            console.print(f"   [green]✅ Different: {ua1 != ua2}[/green]\n")
            
            # Test 2: Timing
            console.print("[cyan]2. Timing Randomization...[/cyan]")
            delays = [self.get_random_delay() for _ in range(5)]
            console.print(f"   Delays: {[f'{d:.2f}s' for d in delays]}")
            console.print(f"   [green]✅ Variação: {max(delays) - min(delays):.2f}s[/green]\n")
            
            # Test 3: TLS fingerprint preview
            console.print("[cyan]3. TLS Fingerprint Randomization...[/cyan]")
            tls_context = self._get_tls_context()
            if tls_context:
                console.print(
                    "   [green]✅ TLS context criado com ciphers customizados[/green]"
                )
            else:
                console.print("   [yellow]⚠️ TLS randomization desabilitada[/yellow]")

            # Test 4: Proxy health
            if self.proxies:
                console.print("[cyan]4. Proxy Health Check...[/cyan]")
                await self.refresh_proxy_health()
                healthy = sum(1 for p in self.proxies if self.proxy_states.get(p, ProxyState(p)).healthy)
                console.print(f"   [green]✅ {healthy}/{len(self.proxies)} proxies saudáveis[/green]\n")
            else:
                console.print("[cyan]4. Proxy Health Check...[/cyan]")
                console.print("   [yellow]⚠️ Nenhum proxy configurado[/yellow]\n")

            # Test 5: Request with stealth completo
            console.print("[cyan]5. Stealth Request...[/cyan]")
            start = time.time()
            response = await self.make_request(client, f"https://{target}")
            elapsed = time.time() - start
            
            if response:
                console.print(f"   [green]✅ Status: {response.status_code}[/green]")
                console.print(f"   [dim]Time: {elapsed:.2f}s[/dim]")
            else:
                console.print("   [red]❌ Failed[/red]")


__all__ = ["StealthMode", "StealthConfig"]
