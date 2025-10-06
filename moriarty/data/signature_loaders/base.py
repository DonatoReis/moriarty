"""Módulo base para carregadores de assinaturas."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

class BaseSignatureLoader(ABC):
    """Classe base para carregadores de assinaturas."""
    
    def __init__(self, source: Union[str, Path, Dict[str, Any]]):
        self.source = source
        self.signatures: List[Dict[str, Any]] = []
    
    @abstractmethod
    def load(self) -> List[Dict[str, Any]]:
        """Carrega as assinaturas da fonte."""
        pass
    
    def normalize(self, signature: Dict[str, Any]) -> Dict[str, Any]:
        """Normaliza uma assinatura para o formato interno."""
        return {
            "name": signature.get("name"),
            "category": signature.get("categories", ["unknown"])[0],
            "pattern_type": signature.get("pattern_type", "unknown"),
            "pattern": signature.get("pattern"),
            "version_detection": signature.get("version"),
            "confidence": int(signature.get("confidence", 80)),
            "metadata": {
                k: v for k, v in signature.items()
                if k not in {"name", "categories", "pattern_type", 
                            "pattern", "version", "confidence"
                }
            }
        }


class SignatureManager:
    """Gerencia múltiplos carregadores de assinaturas."""
    
    def __init__(self):
        self.loaders: Dict[str, BaseSignatureLoader] = {}
    
    def register_loader(self, name: str, loader: BaseSignatureLoader):
        """Registra um novo carregador de assinaturas."""
        self.loaders[name] = loader
    
    def load_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Carrega assinaturas de todos os carregadores registrados."""
        results = {}
        for name, loader in self.loaders.items():
            try:
                results[name] = loader.load()
            except Exception as e:
                print(f"Erro ao carregar assinaturas de {name}: {e}")
        return results
