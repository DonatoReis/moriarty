"""Módulo de armazenamento e processamento de inteligência local.

Este módulo fornece funcionalidades para armazenar e processar dados de inteligência
localmente, incluindo assinaturas de ameaças, IOCs (Indicadores de Comprometimento)
e outras informações relevantes para análise de segurança.
"""
from pathlib import Path
from typing import Optional, Dict, Any, List, Union

from .local_intelligence import (
    LocalIntelligence,
    LocalIntelligenceConfig,
    get_local_intelligence
)
from .ioc import (
    IOC,
    IOCType,
    ThreatType,
    create_ioc,
    IPAddress,
    Domain,
    IOCMatcher,
    load_iocs_from_file,
    save_iocs_to_file,
    merge_iocs
)

# Caminho padrão para armazenamento de dados
DEFAULT_DATA_DIR = Path("~/.moriarty/data").expanduser()

def init_local_intelligence(data_dir: Optional[Union[str, Path]] = None, 
                          config: Optional[Dict[str, Any]] = None) -> LocalIntelligence:
    """
    Inicializa e retorna uma instância de LocalIntelligence.
    
    Args:
        data_dir: Diretório para armazenamento de dados (opcional)
        config: Configuração adicional (opcional)
        
    Returns:
        Instância de LocalIntelligence configurada
    """
    # Configuração padrão
    cfg = LocalIntelligenceConfig()
    
    # Atualiza com o diretório de dados personalizado, se fornecido
    if data_dir is not None:
        cfg.data_dir = Path(data_dir).expanduser().resolve()
    
    # Aplica configurações adicionais
    if config:
        for key, value in config.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
    
    return LocalIntelligence(cfg)

__all__ = [
    # Classes principais
    'LocalIntelligence',
    'LocalIntelligenceConfig',
    'IOC',
    'IOCType',
    'ThreatType',
    'IOCMatcher',
    'IPAddress',
    'Domain',
    
    # Funções de fábrica
    'get_local_intelligence',
    'init_local_intelligence',
    'create_ioc',
    
    # Funções de utilidade
    'load_iocs_from_file',
    'save_iocs_to_file',
    'merge_iocs',
    
    # Constantes
    'DEFAULT_DATA_DIR'
]
