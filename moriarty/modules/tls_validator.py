"""Validação avançada de certificados TLS."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class WildcardInfo:
    """Informações sobre wildcard no certificado."""
    has_wildcard: bool
    wildcard_domains: List[str]
    scope: str  # "single-level" ou "multi-level"


@dataclass
class MisissuanceIndicator:
    """Indicadores de possível mis-issuance."""
    suspicious: bool
    indicators: List[str]
    severity: str  # "low", "medium", "high", "critical"
    details: dict


class TLSCertificateValidator:
    """Validador avançado de certificados TLS."""
    
    # Padrões suspeitos
    SUSPICIOUS_PATTERNS = [
        r'localhost',
        r'test\.', r'staging\.', r'dev\.',
        r'\.local$',
        r'example\.com', r'example\.org',
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IPs
    ]
    
    # CAs problemáticas conhecidas
    REVOKED_CAS = [
        'WoSign', 'StartCom', 'Symantec',  # Histórico de problemas
    ]
    
    def analyze_wildcards(self, subject: str, sans: List[str]) -> WildcardInfo:
        """
        Analisa wildcards no certificado.
        
        Wildcards válidos:
        - *.example.com -> Válido para sub.example.com
        - *.*.example.com -> NÃO é válido (RFC proíbe)
        """
        wildcard_domains = []
        
        # Checa subject
        if subject.startswith('*.'):
            wildcard_domains.append(subject)
        
        # Checa SANs
        for san in sans:
            if san.startswith('*.'):
                wildcard_domains.append(san)
        
        has_wildcard = len(wildcard_domains) > 0
        
        # Determina escopo
        scope = "none"
        if has_wildcard:
            # Verifica se há múltiplos asteriscos (inválido)
            if any('*.*' in domain for domain in wildcard_domains):
                scope = "multi-level-invalid"
            else:
                scope = "single-level"
        
        logger.info(
            "tls.wildcard.analyzed",
            has_wildcard=has_wildcard,
            count=len(wildcard_domains),
            scope=scope,
        )
        
        return WildcardInfo(
            has_wildcard=has_wildcard,
            wildcard_domains=wildcard_domains,
            scope=scope,
        )
    
    def detect_misissuance(
        self,
        subject: str,
        issuer: str,
        sans: List[str],
        valid_from: datetime,
        valid_until: datetime,
    ) -> MisissuanceIndicator:
        """
        Detecta possível mis-issuance (emissão incorreta) de certificado.
        
        Verifica:
        1. Domínios suspeitos (localhost, test, IPs, etc.)
        2. Validade excessivamente longa (> 398 dias é inválido por CA/Browser Forum)
        3. CA problemática
        4. SANs vazios ou malformados
        5. Wildcards inválidos
        """
        indicators = []
        severity = "low"
        details = {}
        
        # 1. Verifica domínios suspeitos
        all_domains = [subject] + sans
        for domain in all_domains:
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    indicators.append(f"Suspicious domain pattern: {domain}")
                    severity = "high"
                    details['suspicious_domain'] = domain
        
        # 2. Verifica validade
        validity_days = (valid_until - valid_from).days
        if validity_days > 398:
            indicators.append(f"Excessive validity period: {validity_days} days (max 398)")
            severity = "critical" if validity_days > 825 else "high"  # 825 = antigo limite
            details['validity_days'] = validity_days
        
        # 3. Verifica CA
        for bad_ca in self.REVOKED_CAS:
            if bad_ca.lower() in issuer.lower():
                indicators.append(f"Certificate from revoked/untrusted CA: {bad_ca}")
                severity = "critical"
                details['bad_ca'] = bad_ca
        
        # 4. Verifica SANs vazios
        if not sans and subject:
            indicators.append("No Subject Alternative Names (SANs) - deprecated")
            severity = max(severity, "medium", key=lambda x: ["low", "medium", "high", "critical"].index(x))
        
        # 5. Verifica wildcards inválidos
        wildcard_info = self.analyze_wildcards(subject, sans)
        if wildcard_info.scope == "multi-level-invalid":
            indicators.append("Invalid multi-level wildcard detected")
            severity = "high"
            details['invalid_wildcard'] = True
        
        # 6. Verifica se é auto-assinado (subject == issuer)
        if subject.lower() == issuer.lower():
            indicators.append("Self-signed certificate detected")
            # Não é necessariamente suspeito em alguns contextos
            details['self_signed'] = True
        
        # 7. Verifica se já expirou
        if datetime.utcnow() > valid_until:
            indicators.append("Certificate has expired")
            severity = "critical"
            details['expired'] = True
        
        # 8. Verifica se ainda não é válido
        if datetime.utcnow() < valid_from:
            indicators.append("Certificate not yet valid")
            severity = "high"
            details['not_yet_valid'] = True
        
        suspicious = len(indicators) > 0
        
        if suspicious:
            logger.warning(
                "tls.misissuance.detected",
                subject=subject,
                indicators=len(indicators),
                severity=severity,
            )
        else:
            logger.info("tls.misissuance.clean", subject=subject)
        
        return MisissuanceIndicator(
            suspicious=suspicious,
            indicators=indicators,
            severity=severity,
            details=details,
        )


__all__ = [
    "TLSCertificateValidator",
    "WildcardInfo",
    "MisissuanceIndicator",
]
