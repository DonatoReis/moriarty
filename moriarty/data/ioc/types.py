"""Tipos de IOCs (Indicadores de Comprometimento) suportados."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Union, Pattern
import re
import ipaddress
from urllib.parse import urlparse

class IOCType(Enum):
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

class ThreatType(Enum):
    """Tipos de ameaças."""
    MALWARE = "malware"
    PHISHING = "phishing"
    EXPLOIT = "exploit"
    C2 = "c2"
    BOTNET = "botnet"
    SCANNING = "scanning"
    SPAM = "spam"
    PHISHING_KIT = "phishing_kit"
    MALICIOUS_DOC = "malicious_document"
    EXPLOIT_KIT = "exploit_kit"
    BRUTE_FORCE = "brute_force"
    DATA_LEAK = "data_leak"
    CREDENTIAL_STUFFING = "credential_stuffing"
    DARKNET = "darknet"
    TOR = "tor"
    VPN = "vpn"
    PROXY = "proxy"
    ABUSE = "abuse"
    SCAM = "scam"
    FRAUD = "fraud"
    CRYPTOJACKING = "cryptojacking"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    BACKDOOR = "backdoor"
    WORM = "worm"
    VIRUS = "virus"
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
    
    def __post_init__(self):
        # Garante que o tipo seja uma instância de IOCType
        if isinstance(self.ioc_type, str):
            self.ioc_type = IOCType(self.ioc_type.lower())
        if isinstance(self.threat_type, str):
            self.threat_type = ThreatType(self.threat_type.lower())
        
        # Valida o valor com base no tipo
        self._validate()
    
    def _validate(self):
        """Valida o valor com base no tipo de IOC."""
        if not self.value:
            raise ValueError("O valor do IOC não pode estar vazio")
        
        validators = {
            IOCType.IP: self._validate_ip,
            IOCType.DOMAIN: self._validate_domain,
            IOCType.URL: self._validate_url,
            IOCType.HASH: self._validate_hash,
            IOCType.EMAIL: self._validate_email,
            IOCType.CVE: self._validate_cve,
            IOCType.BTC: self._validate_btc,
            IOCType.MD5: self._validate_md5,
            IOCType.SHA1: self._validate_sha1,
            IOCType.SHA256: self._validate_sha256,
            IOCType.SSDEEP: self._validate_ssdeep,
            IOCType.YARA: self._validate_yara,
            IOCType.SNORT: self._validate_snort,
            IOCType.SURICATA: self._validate_suricata,
        }
        
        validator = validators.get(self.ioc_type)
        if validator and not validator():
            raise ValueError(f"Valor inválido para IOC do tipo {self.ioc_type.value}: {self.value}")
    
    # Métodos de validação
    
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
            
        # Verifica se é um domínio válido
        domain_regex = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_regex, self.value))
    
    def _validate_url(self) -> bool:
        """Valida uma URL."""
        try:
            result = urlparse(self.value)
            return all([result.scheme in ('http', 'https', 'ftp', 'ftps'), 
                       result.netloc])
        except:
            return False
    
    def _validate_hash(self) -> bool:
        """Valida um hash genérico."""
        # Aceita MD5, SHA-1, SHA-256, etc.
        hash_regex = r'^[a-fA-F0-9]{32,128}$'
        return bool(re.match(hash_regex, self.value))
    
    def _validate_email(self) -> bool:
        """Valida um endereço de e-mail."""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_regex, self.value))
    
    def _validate_cve(self) -> bool:
        """Valida um CVE (Common Vulnerabilities and Exposures)."""
        cve_regex = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_regex, self.value, re.IGNORECASE))
    
    def _validate_btc(self) -> bool:
        """Valida um endereço Bitcoin."""
        btc_regex = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$'
        return bool(re.match(btc_regex, self.value))
    
    def _validate_md5(self) -> bool:
        """Valida um hash MD5."""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', self.value))
    
    def _validate_sha1(self) -> bool:
        """Valida um hash SHA-1."""
        return bool(re.match(r'^[a-fA-F0-9]{40}$', self.value))
    
    def _validate_sha256(self) -> bool:
        """Valida um hash SHA-256."""
        return bool(re.match(r'^[a-fA-F0-9]{64}$', self.value))
    
    def _validate_ssdeep(self) -> bool:
        """Valida um hash ssdeep."""
        return ':' in self.value and all(part for part in self.value.split(':'))
    
    def _validate_yara(self) -> bool:
        """Valida uma regra YARA."""
        return 'rule ' in self.value and '{' in self.value and '}' in self.value
    
    def _validate_snort(self) -> bool:
        """Valida uma regra Snort."""
        return self.value.strip().startswith('alert ') and ('->' in self.value or '<>' in self.value)
    
    def _validate_suricata(self) -> bool:
        """Valida uma regra Suricata."""
        return self.value.strip().startswith(('alert ', 'drop ', 'reject ')) and ';' in self.value
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o IOC para um dicionário."""
        return {
            'value': self.value,
            'type': self.ioc_type.value,
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
            ioc_type=data['type'],
            threat_type=data.get('threat_type', 'unknown'),
            source=data.get('source', 'unknown'),
            first_seen=datetime.fromisoformat(data.get('first_seen', datetime.utcnow().isoformat())),
            last_seen=datetime.fromisoformat(data.get('last_seen', datetime.utcnow().isoformat())),
            confidence=data.get('confidence', 50),
            tags=data.get('tags', []),
            metadata=data.get('metadata', {})
        )

# Classes específicas para cada tipo de IOC

@dataclass
class IPAddress(IOC):
    """Representa um endereço IP como IOC."""
    def __post_init__(self):
        self.ioc_type = IOCType.IP
        super().__post_init__()
    
    @property
    def is_private(self) -> bool:
        """Verifica se o IP é privado."""
        return ipaddress.ip_address(self.value).is_private
    
    @property
    def is_global(self) -> bool:
        """Verifica se o IP é global (público)."""
        return ipaddress.ip_address(self.value).is_global

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
    def sld(self) -> str:
        """Retorna o SLD (Second-Level Domain) do domínio."""
        parts = self.value.split('.')
        return parts[-2] if len(parts) > 1 else ''

# Adicione mais classes específicas conforme necessário

def create_ioc(value: str, ioc_type: Union[str, IOCType], **kwargs) -> IOC:
    """Cria um IOC do tipo especificado."""
    if isinstance(ioc_type, str):
        ioc_type = IOCType(ioc_type.lower())
    
    ioc_classes = {
        IOCType.IP: IPAddress,
        IOCType.DOMAIN: Domain,
        # Adicione mais mapeamentos conforme necessário
    }
    
    ioc_class = ioc_classes.get(ioc_type, IOC)
    return ioc_class(value=value, ioc_type=ioc_type, **kwargs)
