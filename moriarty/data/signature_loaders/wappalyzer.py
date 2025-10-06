"""Carregador de assinaturas no formato Wappalyzer."""
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Union, Optional, Pattern

import yaml

from .base import BaseSignatureLoader

class WappalyzerLoader(BaseSignatureLoader):
    """Carrega assinaturas no formato Wappalyzer (JSON)."""
    
    def __init__(self, source: Union[str, Path, Dict[str, Any]]):
        super().__init__(source)
        self.pattern_cache: Dict[str, Pattern] = {}
    
    def load(self) -> List[Dict[str, Any]]:
        """Carrega assinaturas do Wappalyzer."""
        if isinstance(self.source, (str, Path)):
            with open(self.source, 'r', encoding='utf-8') as f:
                if str(self.source).endswith('.json'):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
        else:
            data = self.source
        
        signatures = []
        for tech_name, tech_data in data.get('technologies', {}).items():
            signatures.extend(self._parse_technology(tech_name, tech_data))
        
        return signatures
    
    def _parse_technology(self, name: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analisa uma tecnologia individual do Wappalyzer."""
        signatures = []
        
        # Categorias
        categories = data.get('cats', [])
        
        # URL
        for url_pattern in data.get('url', []):
            signatures.append({
                'name': name,
                'categories': categories,
                'pattern_type': 'url',
                'pattern': url_pattern,
                'confidence': 80,
                'source': 'wappalyzer'
            })
        
        # HTML
        for html_pattern in data.get('html', []):
            signatures.append({
                'name': name,
                'categories': categories,
                'pattern_type': 'html',
                'pattern': html_pattern,
                'confidence': 80,
                'source': 'wappalyzer'
            })
        
        # Headers
        for header, patterns in data.get('headers', {}).items():
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns:
                signatures.append({
                    'name': name,
                    'categories': categories,
                    'pattern_type': 'header',
                    'pattern': f"{header}: {pattern}",
                    'confidence': 80,
                    'source': 'wappalyzer'
                })
        
        # Cookies
        for cookie in data.get('cookies', {}).keys():
            signatures.append({
                'name': name,
                'categories': categories,
                'pattern_type': 'cookie',
                'pattern': cookie,
                'confidence': 70,
                'source': 'wappalyzer'
            })
        
        # Scripts
        for script in data.get('scripts', []):
            signatures.append({
                'name': name,
                'categories': categories,
                'pattern_type': 'script',
                'pattern': script,
                'confidence': 90,
                'source': 'wappalyzer'
            })
        
        # Meta tags
        for meta in data.get('meta', {}).items():
            meta_name, meta_content = meta
            signatures.append({
                'name': name,
                'categories': categories,
                'pattern_type': 'meta',
                'pattern': f'<meta[^>]*name=["\']{re.escape(meta_name)}["\'][^>]*content=["\']{re.escape(meta_content)}["\']',
                'confidence': 85,
                'source': 'wappalyzer'
            })
        
        return signatures
