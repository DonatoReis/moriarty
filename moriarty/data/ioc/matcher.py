"""Módulo para correspondência avançada de IOCs."""
from __future__ import annotations

import re
import ipaddress
from typing import Dict, List, Optional, Set, Union, Any, Pattern, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from .types import IOC, IOCType, ThreatType

class IOCMatcher:
    """Classe para realizar correspondência avançada de IOCs."""
    
    def __init__(self):
        self.iocs: Dict[IOCType, Dict[str, List[IOC]]] = defaultdict(dict)
        self.compiled_patterns: Dict[IOCType, Dict[str, Pattern]] = defaultdict(dict)
        self.tags_index: Dict[str, Set[IOC]] = defaultdict(set)
        self.threat_type_index: Dict[ThreatType, Set[IOC]] = defaultdict(set)
        self.source_index: Dict[str, Set[IOC]] = defaultdict(set)
    
    def add_ioc(self, ioc: IOC) -> None:
        """Adiciona um IOC ao matcher."""
        # Adiciona ao índice principal
        if ioc.value not in self.iocs[ioc.ioc_type]:
            self.iocs[ioc.ioc_type][ioc.value] = []
        
        self.iocs[ioc.ioc_type][ioc.value].append(ioc)
        
        # Adiciona aos índices secundários
        for tag in ioc.tags:
            self.tags_index[tag.lower()].add(ioc)
        
        self.threat_type_index[ioc.threat_type].add(ioc)
        self.source_index[ioc.source.lower()].add(ioc)
        
        # Compila padrões regex se necessário
        if ioc.ioc_type in {IOCType.URL, IOCType.EMAIL, IOCType.DOMAIN}:
            self._compile_pattern(ioc)
    
    def _compile_pattern(self, ioc: IOC) -> None:
        """Compila padrões regex para IOCs que suportam correspondência de padrão."""
        if ioc.ioc_type == IOCType.URL:
            # Converte wildcards para regex
            pattern = re.escape(ioc.value)
            pattern = pattern.replace('\\*', '.*')
            self.compiled_patterns[ioc.ioc_type][ioc.value] = re.compile(f'^{pattern}$', re.IGNORECASE)
            
        elif ioc.ioc_type == IOCType.EMAIL:
            # Suporta wildcards no domínio (ex: user@*.example.com)
            user, domain = ioc.value.split('@', 1)
            pattern = f"^{re.escape(user)}@{re.escape(domain).replace('\\*', '.*')}$"
            self.compiled_patterns[ioc.ioc_type][ioc.value] = re.compile(pattern, re.IGNORECASE)
            
        elif ioc.ioc_type == IOCType.DOMAIN:
            # Suporta wildcards (ex: *.example.com)
            pattern = f"^{re.escape(ioc.value).replace('\\*', '.*')}$"
            self.compiled_patterns[ioc.ioc_type][ioc.value] = re.compile(pattern, re.IGNORECASE)
    
    def match(self, value: str, ioc_type: Optional[IOCType] = None) -> List[IOC]:
        """
        Encontra todos os IOCs que correspondem ao valor fornecido.
        
        Args:
            value: O valor a ser verificado
            ioc_type: Tipo de IOC para restringir a busca (opcional)
            
        Returns:
            Lista de IOCs correspondentes
        """
        if not value:
            return []
            
        # Se o tipo for especificado, pesquisa apenas nesse tipo
        if ioc_type is not None:
            return self._match_single_type(value, ioc_type)
        
        # Caso contrário, pesquisa em todos os tipos
        results = []
        for it in IOCType:
            results.extend(self._match_single_type(value, it))
            
        return results
    
    def _match_single_type(self, value: str, ioc_type: IOCType) -> List[IOC]:
        """Verifica correspondência para um único tipo de IOC."""
        if ioc_type not in self.iocs:
            return []
            
        # Para URLs, e-mails e domínios, usa correspondência de padrão
        if ioc_type in {IOCType.URL, IOCType.EMAIL, IOCType.DOMAIN}:
            return self._match_pattern(value, ioc_type)
            
        # Para hashes, normaliza para minúsculas
        if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SSDEEP}:
            value = value.lower()
            
        # Para IPs, normaliza o formato
        if ioc_type == IOCType.IP:
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                return []
        
        # Correspondência exata para outros tipos
        return self.iocs[ioc_type].get(value, [])
    
    def _match_pattern(self, value: str, ioc_type: IOCType) -> List[IOC]:
        """Verifica correspondência de padrão para URLs, e-mails e domínios."""
        results = []
        
        for ioc_value, ioc_list in self.iocs[ioc_type].items():
            # Tenta correspondência exata primeiro
            if ioc_value.lower() == value.lower():
                results.extend(ioc_list)
                continue
                
            # Tenta correspondência de padrão se houver um padrão compilado
            pattern = self.compiled_patterns[ioc_type].get(ioc_value)
            if pattern and pattern.match(value):
                results.extend(ioc_list)
        
        return results
    
    def search(self, query: str, limit: int = 100) -> List[IOC]:
        """
        Realiza uma busca textual nos IOCs.
        
        Args:
            query: Termo de busca
            limit: Número máximo de resultados a retornar
            
        Returns:
            Lista de IOCs correspondentes à consulta
        """
        query = query.lower()
        results = set()
        
        # Busca em valores de IOC
        for ioc_type, values in self.iocs.items():
            for value, ioc_list in values.items():
                if query in value.lower():
                    results.update(ioc_list)
                    if len(results) >= limit:
                        return list(results)[:limit]
        
        # Busca em metadados
        for ioc_list in self.iocs.values():
            for ioc in ioc_list:
                # Verifica tags
                if any(query in tag.lower() for tag in ioc.tags):
                    results.add(ioc)
                    if len(results) >= limit:
                        return list(results)[:limit]
                        
                # Verifica metadados
                if any(query in str(v).lower() 
                      for v in ioc.metadata.values() 
                      if v and isinstance(v, str)):
                    results.add(ioc)
                    if len(results) >= limit:
                        return list(results)[:limit]
        
        return list(results)[:limit]
    
    def get_by_tag(self, tag: str) -> List[IOC]:
        """Retorna todos os IOCs com a tag especificada."""
        return list(self.tags_index.get(tag.lower(), set()))
    
    def get_by_threat_type(self, threat_type: Union[str, ThreatType]) -> List[IOC]:
        """Retorna todos os IOCs do tipo de ameaça especificado."""
        if isinstance(threat_type, str):
            threat_type = ThreatType(threat_type.lower())
        return list(self.threat_type_index.get(threat_type, set()))
    
    def get_by_source(self, source: str) -> List[IOC]:
        """Retorna todos os IOCs da fonte especificada."""
        return list(self.source_index.get(source.lower(), set()))
    
    def get_recent(self, days: int = 7) -> List[IOC]:
        """Retorna IOCs adicionados nos últimos N dias."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        results = []
        
        for ioc_list in self.iocs.values():
            for ioc in ioc_list:
                if ioc.first_seen >= cutoff:
                    results.append(ioc)
        
        return sorted(results, key=lambda x: x.first_seen, reverse=True)
    
    def get_related(self, ioc: IOC, max_relations: int = 10) -> Dict[str, List[IOC]]:
        """
        Encontra IOCs relacionados ao IOC fornecido.
        
        Args:
            ioc: O IOC de referência
            max_relations: Número máximo de IOCs relacionados a retornar por tipo
            
        Returns:
            Dicionário mapeando tipos de relacionamento para listas de IOCs relacionados
        """
        related = defaultdict(list)
        
        # IOCs com as mesmas tags
        for tag in ioc.tags:
            for related_ioc in self.get_by_tag(tag):
                if related_ioc != ioc and related_ioc not in related['tags']:
                    related['tags'].append(related_ioc)
        
        # IOCs do mesmo tipo de ameaça
        for threat_ioc in self.get_by_threat_type(ioc.threat_type):
            if threat_ioc != ioc and threat_ioc not in related['threat_type']:
                related['threat_type'].append(threat_ioc)
        
        # IOCs da mesma fonte
        for source_ioc in self.get_by_source(ioc.source):
            if source_ioc != ioc and source_ioc not in related['source']:
                related['source'].append(source_ioc)
        
        # Limita o número de resultados por tipo
        for key in related:
            related[key] = related[key][:max_relations]
        
        return dict(related)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte o matcher para um dicionário."""
        return {
            'iocs': {
                ioc_type.value: {
                    value: [ioc.to_dict() for ioc in ioc_list]
                    for value, ioc_list in values.items()
                }
                for ioc_type, values in self.iocs.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IOCMatcher':
        """Cria um IOCMatcher a partir de um dicionário."""
        matcher = cls()
        
        for ioc_type_str, values in data.get('iocs', {}).items():
            try:
                ioc_type = IOCType(ioc_type_str)
                for value, ioc_dicts in values.items():
                    for ioc_dict in ioc_dicts:
                        ioc = IOC.from_dict(ioc_dict)
                        matcher.add_ioc(ioc)
            except (KeyError, ValueError) as e:
                print(f"Erro ao carregar IOCs do tipo {ioc_type_str}: {e}")
        
        return matcher
