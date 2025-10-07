"""
Módulo de Ataques do WiFiPPLER.

Implementa um sistema de registro de ataques para permitir descoberta dinâmica
e execução de diferentes tipos de ataques de segurança WiFi.

Este módulo utiliza o padrão de registro para permitir que novos ataques sejam
facilmente adicionados ao sistema sem modificar o código existente.

Exemplo de uso:
    >>> # Registrar um novo tipo de ataque
    >>> @register_attack
    >>> class MeuAtaque:
    ...     name = "meu_ataque"
    ...     description = "Descrição do meu ataque personalizado"
    ...     
    ...     def run(self, *, iface: str, target: Optional[str] = None, **kwargs):
    ...         # Implementação do ataque
    ...         pass
    
    >>> # Obter um ataque pelo nome
    >>> ataque_cls = get_attack("meu_ataque")
    >>> if ataque_cls:
    ...     ataque = ataque_cls()
    ...     ataque.run(iface="wlan0", target="00:11:22:33:44:55")
"""
from typing import Dict, Type, Protocol, Optional, Any, TypeVar

# Tipo genérico para a classe Attack
T = TypeVar('T', bound='Attack')

class Attack(Protocol):
    """Protocolo que define a interface para todos os ataques.
    
    Para criar um novo ataque, crie uma classe que implemente este protocolo
    e use o decorador @register_attack para registrá-lo.
    """
    # Nome único do ataque (deve ser um identificador em minúsculas com underscores)
    name: str
    
    # Descrição do ataque (aparecerá na lista de ataques disponíveis)
    description: str = ""
    
    def run(self, *, iface: str, target: Optional[str] = None, **kwargs: Any) -> None:
        """Executa o ataque.
        
        Args:
            iface: Interface de rede a ser usada (ex: 'wlan0')
            target: Alvo do ataque (opcional, pode ser um endereço MAC, BSSID, etc.)
            **kwargs: Argumentos adicionais específicos do ataque
            
        Raises:
            Exception: Se ocorrer um erro durante a execução do ataque
        """
        ...

# Registro global de ataques
REGISTRY: Dict[str, Type[Attack]] = {}

def register_attack(attack_cls: Type[T]) -> Type[T]:
    """Decorador para registrar uma classe de ataque.
    
    Exemplo:
        >>> @register_attack
        >>> class MeuAtaque:
        ...     name = "meu_ataque"
        ...     description = "Descrição do meu ataque"
        ...     def run(self, *, iface: str, **kwargs):
        ...         pass
    
    Args:
        attack_cls: Classe de ataque a ser registrada. Deve implementar o protocolo Attack.
        
    Returns:
        A própria classe de ataque, permitindo uso como decorador
        
    Raises:
        ValueError: Se o nome do ataque já estiver registrado
    """
    if not hasattr(attack_cls, 'name') or not attack_cls.name:
        raise ValueError(f"A classe {attack_cls.__name__} deve definir um atributo 'name'")
        
    if attack_cls.name in REGISTRY:
        raise ValueError(f"Já existe um ataque registrado com o nome '{attack_cls.name}'")
        
    REGISTRY[attack_cls.name] = attack_cls
    return attack_cls

def get_attack(name: str) -> Optional[Type[Attack]]:
    """Obtém uma classe de ataque pelo nome.
    
    Args:
        name: Nome do ataque a ser recuperado (case-sensitive)
        
    Returns:
        A classe de ataque correspondente ou None se não encontrado
        
    Example:
        >>> ataque_cls = get_attack("deauth")
        >>> if ataque_cls:
        ...     ataque = ataque_cls()
        ...     ataque.run(iface="wlan0", target="00:11:22:33:44:55")
    """
    return REGISTRY.get(name)

def list_attacks() -> Dict[str, str]:
    """Lista todos os ataques registrados.
    
    Returns:
        Dicionário onde as chaves são os nomes dos ataques e os valores são suas descrições
        
    Example:
        >>> for nome, descricao in list_attacks().items():
        ...     print(f"{nome}: {descricao}")
    """
    return {name: cls.description for name, cls in REGISTRY.items()}

# Importa os módulos de ataque para registrar as classes automaticamente
# A ordem de importação é importante para evitar importações circulares
from .deauth import DeauthAttack
from .handshake import HandshakeCapture
from .pmkid import PMKIDAttack
from .wep import WEPAttack
from .wpa import WPAHandshakeAttack
from .wps import WPSAttack

# Exporta a API pública
__all__ = [
    # Interface e registro
    'Attack',
    'register_attack',  # Alias para register para melhor clareza
    'get_attack',
    'list_attacks',
    'register',         # Mantido para compatibilidade
    
    # Ataques específicos
    'DeauthAttack',
    'HandshakeCapture',
    'PMKIDAttack',
    'WEPAttack',
    'WPAHandshakeAttack',
    'WPSAttack',
    
    # Registro interno (exposto apenas para testes)
    'REGISTRY',
]
