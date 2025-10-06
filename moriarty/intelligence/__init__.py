"""Módulo de Inteligência Local do Moriarty.

Este módulo fornece funcionalidades para coleta, armazenamento e análise de dados
de inteligência sobre ameaças, incluindo IOCs (Indicadores de Comprometimento)
e assinaturas de ameaças.
"""

__version__ = "0.1.0"

# Importações principais para facilitar o acesso
try:
    from .ioc import IOC, IOCType, ThreatType
    from .storage import LocalStorage
    from .signatures import SignatureManager
    from .collectors import (
        CTLogCollector,
        PassiveDNSCollector,
        WebTechProfiler,
        ThreatFeedCollector
    )
    from .api import app as api_app
    from .cli import app as cli_app
    from .config import settings

except ImportError as e:
    import warnings
    warnings.warn(f"Não foi possível importar todos os módulos de inteligência: {e}")
