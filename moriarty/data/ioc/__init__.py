"""Módulo para manipulação de Indicadores de Comprometimento (IOCs)."""
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set

from .types import (
    IOC, IOCType, ThreatType, 
    create_ioc, IPAddress, Domain
)
from .matcher import IOCMatcher

# Exporta as classes e funções principais
__all__ = [
    'IOC',
    'IOCType',
    'ThreatType',
    'create_ioc',
    'IPAddress',
    'Domain',
    'IOCMatcher',
    'load_iocs_from_file',
    'save_iocs_to_file',
    'merge_iocs'
]

def load_iocs_from_file(file_path: Union[str, Path], 
                      format_name: str = 'auto') -> List[IOC]:
    """
    Carrega IOCs de um arquivo.
    
    Args:
        file_path: Caminho para o arquivo
        format_name: Formato do arquivo ('json', 'yaml', 'csv', 'auto' para detectar)
        
    Returns:
        Lista de IOCs carregados
    """
    from ..signature_loaders import create_loader
    
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
    
    # Tenta detectar o formato se não for especificado
    if format_name == 'auto':
        if file_path.suffix.lower() == '.json':
            format_name = 'ioc'
        elif file_path.suffix.lower() in ('.yaml', '.yml'):
            format_name = 'ioc'
        elif file_path.suffix.lower() == '.csv':
            format_name = 'ioc'
        else:
            format_name = 'ioc'  # Padrão
    
    # Cria o carregador apropriado
    loader = create_loader(file_path, format_name)
    
    # Carrega os IOCs
    ioc_dicts = loader.load()
    
    # Converte para objetos IOC
    iocs = []
    for ioc_dict in ioc_dicts:
        try:
            ioc = IOC.from_dict(ioc_dict) if isinstance(ioc_dict, dict) else ioc_dict
            if isinstance(ioc, IOC):
                iocs.append(ioc)
        except Exception as e:
            print(f"Erro ao carregar IOC: {e}")
    
    return iocs

def save_iocs_to_file(iocs: List[IOC], 
                     file_path: Union[str, Path], 
                     format_name: str = 'json') -> None:
    """
    Salva uma lista de IOCs em um arquivo.
    
    Args:
        iocs: Lista de IOCs para salvar
        file_path: Caminho para o arquivo de saída
        format_name: Formato de saída ('json', 'yaml', 'csv')
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Converte os IOCs para dicionários
    ioc_dicts = [ioc.to_dict() for ioc in iocs]
    
    # Salva no formato apropriado
    if format_name.lower() == 'json':
        import json
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({'iocs': ioc_dicts}, f, indent=2, ensure_ascii=False)
    
    elif format_name.lower() in ('yaml', 'yml'):
        import yaml
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump({'iocs': ioc_dicts}, f, allow_unicode=True)
    
    elif format_name.lower() == 'csv':
        import csv
        if not ioc_dicts:
            return
            
        # Extrai todos os campos possíveis
        all_fields = set()
        for ioc in ioc_dicts:
            all_fields.update(ioc.keys())
        
        fieldnames = sorted(all_fields)
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(ioc_dicts)
    
    else:
        raise ValueError(f"Formato não suportado: {format_name}")

def merge_iocs(*ioc_lists: List[IOC]) -> List[IOC]:
    """
    Combina várias listas de IOCs, removendo duplicatas.
    
    Args:
        *ioc_lists: Listas de IOCs para combinar
        
    Returns:
        Lista única de IOCs únicos
    """
    seen = set()
    result = []
    
    for ioc_list in ioc_lists:
        for ioc in ioc_list:
            # Cria uma chave única para cada IOC
            key = (ioc.ioc_type.value, ioc.value.lower())
            
            if key not in seen:
                seen.add(key)
                result.append(ioc)
    
    return result
