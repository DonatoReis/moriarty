"""Módulo de tipos e validação de IOCs (Indicadores de Comprometimento)."""

import re
import ipaddress
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional, Union, Pattern, TypeVar, Type, ClassVar

# Expressões regulares para validação de IOCs
DOMAIN_PATTERN = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
URL_PATTERN = r'^https?://[^\s/$.?#].[^\s]*$'
EMAIL_PATTERN = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
CVE_PATTERN = r'^CVE-\d{4}-\d{4,7}$'
MD5_PATTERN = r'^[a-fA-F0-9]{32}$'
SHA1_PATTERN = r'^[a-fA-F0-9]{40}$'
SHA256_PATTERN = r'^[a-fA-F0-9]{64}$'
SSDEEP_PATTERN = r'^\d+:[a-zA-Z0-9/+]{20,}:[a-zA-Z0-9/+]{20,}$'
YARA_PATTERN = r'^rule\s+[a-zA-Z0-9_]+\s*{.*?}'
BITCOIN_PATTERN = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'

class IOCType(str, Enum):
    """Tipos de IOCs suportados."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    CVE = "cve"
    BTC = "btc"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SSDEEP = "ssdeep"
    YARA = "yara"
    SNORT = "snort"
    SURICATA = "suricata"
    CUSTOM = "custom"

class ThreatType(str, Enum):
    """Tipos de ameaças."""
    MALWARE = "malware"
    PHISHING = "phishing"
    EXPLOIT = "exploit"
    C2 = "c2"
    SCANNER = "scanner"
    SPAM = "spam"
    ABUSE = "abuse"
    UNKNOWN = "unknown"

@dataclass
class IOC:
    """Classe base para Indicadores de Comprometimento (IOCs)."""
    
    value: str
    ioc_type: IOCType
    threat_type: ThreatType = ThreatType.UNKNOWN
    source: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    confidence: int = 50  # 0-100
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Cache para expressões regulares compiladas
    _regex_cache: ClassVar[Dict[str, Pattern]] = {}
    
    def __post_init__(self):
        # Garante que o tipo seja uma instância de IOCType
        if isinstance(self.ioc_type, str):
            self.ioc_type = IOCType(self.ioc_type.lower())
            
        if isinstance(self.threat_type, str):
            self.threat_type = ThreatType(self.threat_type.lower())
        
        # Valida o valor do IOC com base no tipo
        self._validate()
    
    def _validate(self):
        """Valida o valor do IOC com base no tipo."""
        if not self.value:
            raise ValueError("O valor do IOC não pode estar vazio")
            
        validators = {
            IOCType.IP: self._validate_ip,
            IOCType.DOMAIN: self._validate_domain,
            IOCType.URL: self._validate_url,
            IOCType.EMAIL: self._validate_email,
            IOCType.CVE: self._validate_cve,
            IOCType.BTC: self._validate_btc,
            IOCType.MD5: self._validate_md5,
            IOCType.SHA1: self._validate_sha1,
            IOCType.SHA256: self._validate_sha256,
            IOCType.SSDEEP: self._validate_ssdeep,
            IOCType.YARA: self._validate_yara,
        }
        
        validator = validators.get(self.ioc_type)
        if validator and not validator():
            raise ValueError(f"Valor inválido para IOC do tipo {self.ioc_type}: {self.value}")
    
    def _get_cached_regex(self, pattern: str) -> Pattern:
        """Obtém uma expressão regular compilada do cache ou compila uma nova."""
        if pattern not in self._regex_cache:
            self._regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
        return self._regex_cache[pattern]
    
    def _validate_ip(self) -> bool:
        """Valida um endereço IP."""
        try:
            ipaddress.ip_address(self.value)
            return True
        except ValueError:
            return False
    
    def _validate_domain(self) -> bool:
        """Valida um domínio."""
        if not self.value or len(self.value) > 253:
            return False
            
        # Verifica se o domínio corresponde ao padrão
        if not self._get_cached_regex(DOMAIN_PATTERN).match(self.value):
            return False
            
        # Verifica se cada parte do domínio tem no máximo 63 caracteres
        return all(len(part) <= 63 for part in self.value.split('.'))
    
    def _validate_url(self) -> bool:
        """Valida uma URL."""
        return bool(self._get_cached_regex(URL_PATTERN).match(self.value))
    
    def _validate_email(self) -> bool:
        """Valida um endereço de e-mail."""
        return bool(self._get_cached_regex(EMAIL_PATTERN).match(self.value))
    
    def _validate_cve(self) -> bool:
        """Valida um identificador CVE."""
        return bool(self._get_cached_regex(CVE_PATTERN).match(self.value.upper()))
    
    def _validate_btc(self) -> bool:
        """Valida um endereço Bitcoin."""
        return bool(self._get_cached_regex(BITCOIN_PATTERN).match(self.value))
    
    def _validate_md5(self) -> bool:
        """Valida um hash MD5."""
        return bool(self._get_cached_regex(MD5_PATTERN).match(self.value))
    
    def _validate_sha1(self) -> bool:
        """Valida um hash SHA-1."""
        return bool(self._get_cached_regex(SHA1_PATTERN).match(self.value))
    
    def _validate_sha256(self) -> bool:
        """Valida um hash SHA-256."""
        return bool(self._get_cached_regex(SHA256_PATTERN).match(self.value))
    
    def _validate_ssdeep(self) -> bool:
        """Valida um hash SSDEEP."""
        return bool(self._get_cached_regex(SSDEEP_PATTERN).match(self.value))
    
    def _validate_yara(self) -> bool:
        """Valida uma regra YARA."""
        # Verificação básica de sintaxe de regra YARA
        return bool(self._get_cached_regex(YARA_PATTERN).search(self.value))
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o IOC para um dicionário."""
        return {
            'value': self.value,
            'ioc_type': self.ioc_type.value,
            'threat_type': self.threat_type.value,
            'source': self.source,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'confidence': self.confidence,
            'tags': self.tags,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IOC':
        """Cria um IOC a partir de um dicionário."""
        return cls(
            value=data['value'],
            ioc_type=data.get('ioc_type', 'custom'),
            threat_type=data.get('threat_type', 'unknown'),
            source=data.get('source', 'unknown'),
            first_seen=datetime.fromisoformat(data.get('first_seen', datetime.utcnow().isoformat())),
            last_seen=datetime.fromisoformat(data.get('last_seen', datetime.utcnow().isoformat())),
            confidence=data.get('confidence', 50),
            tags=data.get('tags', []),
            metadata=data.get('metadata', {})
        )

# Tipos específicos de IOCs para facilitar a criação
@dataclass
class IPAddress(IOC):
    """Representa um endereço IP como IOC."""
    
    def __post_init__(self):
        self.ioc_type = IOCType.IP
        super().__post_init__()
    
    @property
    def is_private(self) -> bool:
        """Verifica se o endereço IP é privado."""
        try:
            return ipaddress.ip_address(self.value).is_private
        except ValueError:
            return False
    
    @property
    def version(self) -> int:
        """Retorna a versão do IP (4 ou 6)."""
        try:
            return ipaddress.ip_address(self.value).version
        except ValueError:
            return 0

@dataclass
class Domain(IOC):
    """Representa um domínio como IOC."""
    
    def __post_init__(self):
        self.ioc_type = IOCType.DOMAIN
        super().__post_init__()
    
    @property
    def tld(self) -> str:
        """Retorna o TLD (Top-Level Domain) do domínio."""
        return self.value.split('.')[-1] if '.' in self.value else ''
    
    @property
    def domain_parts(self) -> List[str]:
        """Retorna as partes do domínio como uma lista."""
        return self.value.split('.') if self.value else []

# Funções auxiliares
def detect_ioc_type(value: str) -> Optional[IOCType]:
    """Tenta detectar o tipo de IOC com base no valor."""
    if not value or not isinstance(value, str):
        return None
        
    value = value.strip()
    
    # Ordem de verificação: mais específico para o mais genérico
    checks = [
        (IOCType.IP, lambda x: bool(IPAddress(x, 'ip')._validate_ip())),
        (IOCType.DOMAIN, lambda x: bool(Domain(x, 'domain')._validate_domain())),
        (IOCType.URL, lambda x: bool(IOC(x, 'url')._validate_url())),
        (IOCType.EMAIL, lambda x: bool(IOC(x, 'email')._validate_email())),
        (IOCType.CVE, lambda x: bool(IOC(x, 'cve')._validate_cve())),
        (IOCType.BTC, lambda x: bool(IOC(x, 'btc')._validate_btc())),
        (IOCType.MD5, lambda x: bool(IOC(x, 'md5')._validate_md5())),
        (IOCType.SHA1, lambda x: bool(IOC(x, 'sha1')._validate_sha1())),
        (IOCType.SHA256, lambda x: bool(IOC(x, 'sha256')._validate_sha256())),
        (IOCType.SSDEEP, lambda x: bool(IOC(x, 'ssdeep')._validate_ssdeep())),
        (IOCType.YARA, lambda x: bool(IOC(x, 'yara')._validate_yara())),
    ]
    
    for ioc_type, check in checks:
        try:
            if check(value):
                return ioc_type
        except Exception:
            continue
    
    return None
