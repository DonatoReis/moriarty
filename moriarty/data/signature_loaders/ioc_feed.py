"""Carregador de feeds de IOCs (Indicadores de Comprometimento)."""
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Union, Optional, Pattern, Set

import yaml
import requests
from urllib.parse import urlparse

from .base import BaseSignatureLoader

class IOCFeedLoader(BaseSignatureLoader):
    """Carrega IOCs de várias fontes (JSON, CSV, MISP, etc.)."""
    
    def __init__(self, source: Union[str, Path, Dict[str, Any]]):
        super().__init__(source)
        self.ioc_types = {
            'ip': self._is_ip,
            'domain': self._is_domain,
            'url': self._is_url,
            'hash': self._is_hash,
            'email': self._is_email,
            'cve': self._is_cve,
            'btc': self._is_btc,
            'md5': self._is_md5,
            'sha1': self._is_sha1,
            'sha256': self._is_sha256,
            'ssdeep': self._is_ssdeep,
            'yara': self._is_yara,
            'snort': self._is_snort,
            'suricata': self._is_suricata,
        }
    
    def load(self) -> List[Dict[str, Any]]:
        """Carrega IOCs da fonte especificada."""
        if isinstance(self.source, (str, Path)) and str(self.source).startswith(('http://', 'https://')):
            return self._load_from_url(self.source)
        elif isinstance(self.source, (str, Path)):
            return self._load_from_file(self.source)
        elif isinstance(self.source, dict):
            return self._load_from_dict(self.source)
        else:
            raise ValueError(f"Fonte de IOCs não suportada: {type(self.source)}")
    
    def _load_from_url(self, url: str) -> List[Dict[str, Any]]:
        """Carrega IOCs de uma URL remota."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            if 'json' in content_type:
                return self._parse_json(response.json())
            elif 'yaml' in content_type or 'x-yaml' in content_type:
                return self._parse_yaml(response.text)
            else:
                # Tenta detectar o formato pelo conteúdo
                try:
                    return self._parse_json(response.json())
                except:
                    try:
                        return self._parse_yaml(response.text)
                    except:
                        return self._parse_text(response.text)
        except Exception as e:
            print(f"Erro ao carregar IOCs de {url}: {e}")
            return []
    
    def _load_from_file(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Carrega IOCs de um arquivo local."""
        file_path = Path(file_path)
        if not file_path.exists():
            print(f"Arquivo não encontrado: {file_path}")
            return []
        
        try:
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    return self._parse_json(json.load(f))
            elif file_path.suffix.lower() in ('.yaml', '.yml'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return self._parse_yaml(f.read())
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return self._parse_text(f.read())
        except Exception as e:
            print(f"Erro ao processar arquivo {file_path}: {e}")
            return []
    
    def _load_from_dict(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Carrega IOCs de um dicionário Python."""
        if 'iocs' in data:
            return self._parse_iocs(data['iocs'])
        elif 'indicators' in data:
            return self._parse_indicators(data['indicators'])
        elif 'data' in data and isinstance(data['data'], list):
            return self._parse_generic(data['data'])
        else:
            return self._parse_generic([data])
    
    def _parse_json(self, data: Any) -> List[Dict[str, Any]]:
        """Analisa dados JSON."""
        if isinstance(data, dict):
            return self._load_from_dict(data)
        elif isinstance(data, list):
            return self._parse_generic(data)
        else:
            return []
    
    def _parse_yaml(self, yaml_str: str) -> List[Dict[str, Any]]:
        """Analisa dados YAML."""
        data = yaml.safe_load(yaml_str)
        return self._parse_json(data)
    
    def _parse_text(self, text: str) -> List[Dict[str, Any]]:
        """Analisa texto simples, um IOC por linha."""
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            ioc_type = self.detect_ioc_type(line)
            if ioc_type:
                iocs.append({
                    'type': ioc_type,
                    'value': line,
                    'source': 'text_import',
                    'first_seen': datetime.utcnow().isoformat(),
                    'last_seen': datetime.utcnow().isoformat(),
                })
        return iocs
    
    def _parse_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analisa uma lista de IOCs no formato padrão."""
        result = []
        for ioc in iocs:
            if not isinstance(ioc, dict):
                continue
                
            ioc_type = ioc.get('type')
            value = ioc.get('value')
            
            if not ioc_type or not value:
                continue
                
            result.append({
                'type': ioc_type.lower(),
                'value': value,
                'threat_type': ioc.get('threat_type', 'unknown'),
                'source': ioc.get('source', 'unknown'),
                'first_seen': ioc.get('first_seen') or datetime.utcnow().isoformat(),
                'last_seen': ioc.get('last_seen') or datetime.utcnow().isoformat(),
                'confidence': int(ioc.get('confidence', 50)),
                'metadata': ioc.get('metadata', {})
            })
        return result
    
    def _parse_indicators(self, indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analisa indicadores no formato MISP/STIX."""
        result = []
        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue
                
            ioc_type = indicator.get('type')
            value = indicator.get('value')
            
            if not ioc_type or not value:
                continue
                
            result.append({
                'type': ioc_type.lower(),
                'value': value,
                'threat_type': indicator.get('threat_type', 'unknown'),
                'source': 'misp' if 'misp' in str(indicator).lower() else 'stix',
                'first_seen': indicator.get('first_seen') or datetime.utcnow().isoformat(),
                'last_seen': indicator.get('last_seen') or datetime.utcnow().isoformat(),
                'confidence': int(indicator.get('confidence', 50)),
                'metadata': indicator.get('metadata', {})
            })
        return result
    
    def _parse_generic(self, items: List[Any]) -> List[Dict[str, Any]]:
        """Tenta analisar uma lista genérica de itens."""
        result = []
        for item in items:
            if not item:
                continue
                
            if isinstance(item, str):
                ioc_type = self.detect_ioc_type(item)
                if ioc_type:
                    result.append({
                        'type': ioc_type,
                        'value': item,
                        'source': 'generic_import',
                        'first_seen': datetime.utcnow().isoformat(),
                        'last_seen': datetime.utcnow().isoformat(),
                    })
            elif isinstance(item, dict):
                # Tenta extrair tipo e valor automaticamente
                ioc_type = None
                value = None
                
                for key, val in item.items():
                    if not isinstance(val, str):
                        continue
                        
                    detected_type = self.detect_ioc_type(val)
                    if detected_type:
                        ioc_type = detected_type
                        value = val
                        break
                
                if ioc_type and value:
                    result.append({
                        'type': ioc_type,
                        'value': value,
                        'threat_type': item.get('threat_type', 'unknown'),
                        'source': item.get('source', 'generic_dict'),
                        'first_seen': item.get('first_seen') or datetime.utcnow().isoformat(),
                        'last_seen': item.get('last_seen') or datetime.utcnow().isoformat(),
                        'confidence': int(item.get('confidence', 50)),
                        'metadata': {k: v for k, v in item.items() 
                                   if k not in {'type', 'value', 'threat_type', 
                                               'source', 'first_seen', 'last_seen', 'confidence'}}
                    })
        return result
    
    def detect_ioc_type(self, value: str) -> Optional[str]:
        """Detecta o tipo de IOC com base no valor."""
        if not value or not isinstance(value, str):
            return None
            
        value = value.strip()
        
        # Verifica cada tipo de IOC conhecido
        for ioc_type, check_func in self.ioc_types.items():
            if check_func(value):
                return ioc_type
        
        return None
    
    # Funções de verificação de tipos de IOC
    
    @staticmethod
    def _is_ip(value: str) -> bool:
        """Verifica se o valor é um endereço IP."""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _is_domain(value: str) -> bool:
        """Verifica se o valor é um domínio válido."""
        if not value or len(value) > 253:
            return False
            
        # Verifica se é um domínio válido
        domain_regex = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_regex, value))
    
    @staticmethod
    def _is_url(value: str) -> bool:
        """Verifica se o valor é uma URL válida."""
        try:
            result = urlparse(value)
            return all([result.scheme in ('http', 'https', 'ftp', 'ftps'), 
                       result.netloc])
        except:
            return False
    
    @staticmethod
    def _is_hash(value: str) -> bool:
        """Verifica se o valor é um hash conhecido."""
        if not value:
            return False
            
        # MD5 (32 caracteres hexadecimais)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return True
            
        # SHA-1 (40 caracteres hexadecimais)
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return True
            
        # SHA-256 (64 caracteres hexadecimais)
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return True
            
        # SHA-512 (128 caracteres hexadecimais)
        if re.match(r'^[a-fA-F0-9]{128}$', value):
            return True
            
        return False
    
    @staticmethod
    def _is_email(value: str) -> bool:
        """Verifica se o valor é um endereço de e-mail válido."""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_regex, value))
    
    @staticmethod
    def _is_cve(value: str) -> bool:
        """Verifica se o valor é um CVE (Common Vulnerabilities and Exposures)."""
        cve_regex = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_regex, value, re.IGNORECASE))
    
    @staticmethod
    def _is_btc(value: str) -> bool:
        """Verifica se o valor é um endereço Bitcoin."""
        # Endereços Bitcoin podem começar com 1, 3 ou bc1
        btc_regex = r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$'
        return bool(re.match(btc_regex, value))
    
    @staticmethod
    def _is_md5(value: str) -> bool:
        """Verifica se o valor é um hash MD5."""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', value))
    
    @staticmethod
    def _is_sha1(value: str) -> bool:
        """Verifica se o valor é um hash SHA-1."""
        return bool(re.match(r'^[a-fA-F0-9]{40}$', value))
    
    @staticmethod
    def _is_sha256(value: str) -> bool:
        """Verifica se o valor é um hash SHA-256."""
        return bool(re.match(r'^[a-fA-F0-9]{64}$', value))
    
    @staticmethod
    def _is_ssdeep(value: str) -> bool:
        """Verifica se o valor é um hash ssdeep."""
        # Formato: blocksize:hash:hash
        return ':' in value and all(part for part in value.split(':'))
    
    @staticmethod
    def _is_yara(value: str) -> bool:
        """Verifica se o valor é uma regra YARA."""
        return 'rule ' in value and '{' in value and '}' in value
    
    @staticmethod
    def _is_snort(value: str) -> bool:
        """Verifica se o valor é uma regra Snort."""
        return value.strip().startswith('alert ') and ('->' in value or '<>' in value)
    
    @staticmethod
    def _is_suricata(value: str) -> bool:
        """Verifica se o valor é uma regra Suricata."""
        return value.strip().startswith(('alert ', 'drop ', 'reject ')) and ';' in value
