"""Módulo para carregamento de assinaturas de diferentes fontes."""
from pathlib import Path
from typing import Dict, Type, Any, Optional

from .base import BaseSignatureLoader, SignatureManager
from .wappalyzer import WappalyzerLoader
from .ioc_feed import IOCFeedLoader

# Mapeamento de formatos para classes de carregador
LOADER_CLASSES: Dict[str, Type[BaseSignatureLoader]] = {
    'wappalyzer': WappalyzerLoader,
    'ioc': IOCFeedLoader,
    # Adicione mais formatos aqui
}

def get_loader_class(format_name: str) -> Type[BaseSignatureLoader]:
    """
    Obtém a classe de carregador para o formato especificado.
    
    Args:
        format_name: Nome do formato (ex: 'wappalyzer', 'ioc')
        
    Returns:
        Classe de carregador correspondente
        
    Raises:
        ValueError: Se o formato não for suportado
    """
    format_name = format_name.lower()
    if format_name not in LOADER_CLASSES:
        raise ValueError(f"Formato de assinatura não suportado: {format_name}")
    return LOADER_CLASSES[format_name]

def create_loader(source: Any, format_name: Optional[str] = None) -> BaseSignatureLoader:
    """
    Cria um carregador de assinaturas apropriado para a fonte fornecida.
    
    Args:
        source: Fonte das assinaturas (caminho do arquivo, URL, dicionário, etc.)
        format_name: Nome do formato (opcional, tenta detectar automaticamente)
        
    Returns:
        Instância de BaseSignatureLoader apropriada
        
    Raises:
        ValueError: Se não for possível determinar o formato
    """
    # Se o formato for especificado, usa-o diretamente
    if format_name:
        loader_class = get_loader_class(format_name)
        return loader_class(source)
    
    # Tenta detectar o formato com base na fonte
    if isinstance(source, (str, Path)):
        source_str = str(source).lower()
        
        # Verifica se é uma URL
        if source_str.startswith(('http://', 'https://')):
            # Tenta determinar o formato pela URL ou cabeçalhos
            return IOCFeedLoader(source)  # Padrão para URLs
        
        # Verifica a extensão do arquivo
        if source_str.endswith('.json'):
            # Tenta determinar o formato pelo conteúdo
            with open(source, 'r', encoding='utf-8') as f:
                content = f.read(1024)
                
            # Verifica se parece ser um arquivo Wappalyzer
            if '"technologies"' in content:
                return WappalyzerLoader(source)
            # Verifica se parece ser um feed de IOCs
            elif '"iocs"' in content or '"indicators"' in content:
                return IOCFeedLoader(source)
            
        elif source_str.endswith(('.yaml', '.yml')):
            # Para YAML, tenta determinar o formato pelo conteúdo
            import yaml
            with open(source, 'r', encoding='utf-8') as f:
                try:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        if 'technologies' in data:
                            return WappalyzerLoader(source)
                        elif 'iocs' in data or 'indicators' in data:
                            return IOCFeedLoader(source)
                except:
                    pass
    
    # Se chegou aqui, não foi possível detectar o formato
    raise ValueError(
        "Não foi possível determinar o formato da fonte. "
        "Especifique o parâmetro 'format_name'."
    )

# Exporta as classes principais
__all__ = [
    'BaseSignatureLoader',
    'SignatureManager',
    'WappalyzerLoader',
    'IOCFeedLoader',
    'get_loader_class',
    'create_loader',
]
