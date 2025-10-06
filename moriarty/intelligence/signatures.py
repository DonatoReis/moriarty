"""Módulo de gerenciamento de assinaturas de ameaças."""

import re
import json
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Pattern, Type, TypeVar, Set
from datetime import datetime
from abc import ABC, abstractmethod

from .ioc import IOC, IOCType, ThreatType
from .storage import get_storage, StorageError

# Configuração de logging
logger = logging.getLogger(__name__)

# Tipo genérico para documentação
T = TypeVar('T', bound='BaseSignature')

class SignatureError(Exception):
    """Exceção base para erros de assinatura."""
    pass

class BaseSignature(ABC):
    """Classe base para assinaturas de ameaças."""
    
    def __init__(self, name: str, signature_type: str, pattern: str, 
                 description: str = None, threat_type: Union[str, ThreatType] = None, 
                 source: str = None, confidence: int = 50, 
                 metadata: Dict[str, Any] = None):
        """Inicializa uma assinatura.
        
        Args:
            name: Nome da assinatura.
            signature_type: Tipo da assinatura (ex: 'yara', 'snort', 'regex').
            pattern: Padrão da assinatura.
            description: Descrição da assinatura.
            threat_type: Tipo de ameaça associada.
            source: Fonte da assinatura.
            confidence: Nível de confiança (0-100).
            metadata: Metadados adicionais.
        """
        self.name = name
        self.signature_type = signature_type.lower()
        self.pattern = pattern
        self.description = description or ""
        self.threat_type = ThreatType(threat_type) if isinstance(threat_type, str) else (threat_type or ThreatType.UNKNOWN)
        self.source = source or "unknown"
        self.confidence = max(0, min(100, confidence))  # Garante que está entre 0 e 100
        self.metadata = metadata or {}
        self._compiled_pattern = None
    
    def compile(self):
        """Compila o padrão da assinatura para uso posterior.
        
        Returns:
            O padrão compilado.
            
        Raises:
            SignatureError: Se houver um erro ao compilar o padrão.
        """
        if self._compiled_pattern is None:
            try:
                self._compiled_pattern = self._compile_pattern()
            except Exception as e:
                raise SignatureError(f"Erro ao compilar assinatura '{self.name}': {e}")
        return self._compiled_pattern
    
    @abstractmethod
    def _compile_pattern(self):
        """Método abstrato para compilar o padrão da assinatura."""
        pass
    
    @abstractmethod
    def match(self, data: Any) -> bool:
        """Verifica se os dados correspondem à assinatura.
        
        Args:
            data: Dados a serem verificados.
            
        Returns:
            bool: True se houver correspondência, False caso contrário.
        """
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte a assinatura para um dicionário."""
        return {
            'name': self.name,
            'signature_type': self.signature_type,
            'pattern': self.pattern,
            'description': self.description,
            'threat_type': self.threat_type.value,
            'source': self.source,
            'confidence': self.confidence,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls: Type[T], data: Dict[str, Any]) -> T:
        """Cria uma assinatura a partir de um dicionário."""
        return cls(
            name=data['name'],
            signature_type=data['signature_type'],
            pattern=data['pattern'],
            description=data.get('description'),
            threat_type=data.get('threat_type'),
            source=data.get('source'),
            confidence=data.get('confidence', 50),
            metadata=data.get('metadata', {})
        )
    
    def __str__(self) -> str:
        return f"{self.name} ({self.signature_type}): {self.pattern}"

class RegexSignature(BaseSignature):
    """Assinatura baseada em expressões regulares."""
    
    def _compile_pattern(self) -> Pattern:
        """Compila a expressão regular."""
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
    
    def match(self, data: str) -> bool:
        """Verifica se a string corresponde ao padrão da assinatura."""
        if not isinstance(data, str):
            return False
        
        try:
            pattern = self.compile()
            return bool(pattern.search(data))
        except Exception as e:
            logger.error(f"Erro ao verificar correspondência da assinatura {self.name}: {e}")
            return False

class YaraSignature(BaseSignature):
    """Assinatura no formato YARA."""
    
    def _compile_pattern(self) -> Any:
        """Compila a regra YARA."""
        # Em uma implementação real, isso usaria o módulo yara
        # Por enquanto, apenas retornamos o padrão como está
        return self.pattern
    
    def match(self, data: Any) -> bool:
        """Verifica se os dados correspondem à regra YARA."""
        # Em uma implementação real, isso usaria o módulo yara para compilar e verificar
        # Por enquanto, apenas verificamos se o padrão está contido nos dados
        if not isinstance(data, (str, bytes)):
            return False
        
        try:
            # Verificação básica de correspondência de string
            return self.pattern in str(data)
        except Exception as e:
            logger.error(f"Erro ao verificar correspondência da assinatura YARA {self.name}: {e}")
            return False

class SnortSignature(BaseSignature):
    """Assinatura no formato Snort."""
    
    def _compile_pattern(self) -> Any:
        """Processa a regra Snort."""
        # Em uma implementação real, isso processaria a regra Snort
        # Por enquanto, apenas retornamos o padrão como está
        return self.pattern
    
    def match(self, data: Any) -> bool:
        """Verifica se os dados correspondem à regra Snort."""
        # Em uma implementação real, isso usaria um analisador de regras Snort
        # Por enquanto, apenas verificamos se o padrão está contido nos dados
        if not isinstance(data, (str, bytes)):
            return False
        
        try:
            # Extrai o conteúdo entre parênteses da regra Snort
            content_match = re.search(r'content:"([^"]+)"', self.pattern)
            if content_match:
                content = content_match.group(1)
                return content in str(data)
            return False
        except Exception as e:
            logger.error(f"Erro ao verificar correspondência da assinatura Snort {self.name}: {e}")
            return False

class SignatureManager:
    """Gerenciador de assinaturas de ameaças."""
    
    def __init__(self, storage=None):
        """Inicializa o gerenciador de assinaturas.
        
        Args:
            storage: Instância de armazenamento para persistência (opcional).
        """
        self.storage = storage or get_storage()
        self.signatures: Dict[str, Dict[str, BaseSignature]] = {}
        self.signature_classes = {
            'regex': RegexSignature,
            'yara': YaraSignature,
            'snort': SnortSignature,
        }
    
    def register_signature_type(self, signature_type: str, signature_class: Type[BaseSignature]):
        """Registra um novo tipo de assinatura.
        
        Args:
            signature_type: Nome do tipo de assinatura.
            signature_class: Classe que implementa a assinatura.
        """
        if not issubclass(signature_class, BaseSignature):
            raise TypeError(f"A classe de assinatura deve herdar de BaseSignature")
        self.signature_classes[signature_type.lower()] = signature_class
    
    def add_signature(self, signature: Union[BaseSignature, Dict[str, Any]], 
                     signature_type: str = None) -> bool:
        """Adiciona uma assinatura ao gerenciador.
        
        Args:
            signature: Instância de BaseSignature ou dicionário com os dados da assinatura.
            signature_type: Tipo da assinatura (opcional, se não for fornecida, será obtido da assinatura).
            
        Returns:
            bool: True se a assinatura foi adicionada, False se já existir.
            
        Raises:
            SignatureError: Se houver um erro ao adicionar a assinatura.
        """
        if isinstance(signature, dict):
            if signature_type is None:
                signature_type = signature.get('signature_type')
                if not signature_type:
                    raise SignatureError("Tipo de assinatura não especificado")
            
            signature_cls = self.signature_classes.get(signature_type.lower())
            if not signature_cls:
                raise SignatureError(f"Tipo de assinatura não suportado: {signature_type}")
            
            try:
                signature = signature_cls.from_dict(signature)
            except Exception as e:
                raise SignatureError(f"Falha ao criar assinatura: {e}")
        
        if not isinstance(signature, BaseSignature):
            raise TypeError("A assinatura deve ser uma instância de BaseSignature ou um dicionário válido")
        
        # Obtém o tipo da assinatura
        sig_type = signature.signature_type.lower()
        
        # Inicializa o dicionário para o tipo de assinatura, se necessário
        if sig_type not in self.signatures:
            self.signatures[sig_type] = {}
        
        # Verifica se a assinatura já existe
        if signature.name in self.signatures[sig_type]:
            logger.warning(f"Assinatura '{signature.name}' do tipo '{sig_type}' já existe")
            return False
        
        # Compila a assinatura para verificar se é válida
        try:
            signature.compile()
        except Exception as e:
            raise SignatureError(f"Falha ao compilar assinatura '{signature.name}': {e}")
        
        # Adiciona a assinatura ao gerenciador
        self.signatures[sig_type][signature.name] = signature
        logger.debug(f"Assinatura adicionada: {signature.name} ({sig_type})")
        
        # Tenta salvar no armazenamento, se disponível
        if self.storage:
            try:
                return self.storage.add_signature(
                    name=signature.name,
                    signature_type=sig_type,
                    pattern=signature.pattern,
                    description=signature.description,
                    threat_type=signature.threat_type.value,
                    source=signature.source,
                    confidence=signature.confidence,
                    metadata=signature.metadata
                )
            except Exception as e:
                logger.error(f"Erro ao salvar assinatura no armazenamento: {e}")
        
        return True
    
    def load_from_file(self, file_path: Union[str, Path], signature_type: str = None) -> int:
        """Carrega assinaturas de um arquivo.
        
        Args:
            file_path: Caminho para o arquivo de assinaturas.
            signature_type: Tipo das assinaturas (opcional, tenta detectar automaticamente).
            
        Returns:
            int: Número de assinaturas carregadas.
            
        Raises:
            SignatureError: Se houver um erro ao carregar as assinaturas.
        """
        file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            raise SignatureError(f"Arquivo não encontrado: {file_path}")
        
        # Tenta detectar o tipo de assinatura com base na extensão do arquivo
        if signature_type is None:
            ext = file_path.suffix.lower()
            if ext in ('.yar', '.yara'):
                signature_type = 'yara'
            elif ext in ('.rules', '.snort'):
                signature_type = 'snort'
            elif ext in ('.json', '.yaml', '.yml'):
                # Para JSON/YAML, o tipo deve ser especificado
                signature_type = 'regex'  # Padrão
            else:
                signature_type = 'regex'  # Padrão para arquivos de texto
        
        # Carrega as assinaturas do arquivo
        try:
            if file_path.suffix.lower() in ('.json', '.yaml', '.yml'):
                return self._load_from_structured_file(file_path, signature_type)
            else:
                return self._load_from_text_file(file_path, signature_type)
        except Exception as e:
            raise SignatureError(f"Erro ao carregar assinaturas de {file_path}: {e}")
    
    def _load_from_structured_file(self, file_path: Path, signature_type: str) -> int:
        """Carrega assinaturas de um arquivo estruturado (JSON/YAML)."""
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.suffix.lower() == '.json':
                data = json.load(f)
            else:  # YAML
                data = yaml.safe_load(f)
        
        # Verifica se é uma lista de assinaturas ou um dicionário com uma lista 'signatures'
        if isinstance(data, list):
            signatures = data
        elif isinstance(data, dict) and 'signatures' in data:
            signatures = data['signatures']
        else:
            signatures = [data]  # Assume que é um único objeto de assinatura
               
        # Adiciona cada assinatura
        count = 0
        for sig_data in signatures:
            if not isinstance(sig_data, dict):
                logger.warning(f"Formato de assinatura inválido: {sig_data}")
                continue
                
            # Define o tipo de assinatura, se não estiver definido
            if 'signature_type' not in sig_data and signature_type:
                sig_data['signature_type'] = signature_type
                
            try:
                if self.add_signature(sig_data):
                    count += 1
            except Exception as e:
                logger.error(f"Falha ao adicionar assinatura: {e}")
        
        logger.info(f"Carregadas {count} assinaturas de {file_path}")
        return count
    
    def _load_from_text_file(self, file_path: Path, signature_type: str) -> int:
        """Carrega assinaturas de um arquivo de texto."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
        
        count = 0
        current_sig = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Tenta detectar o tipo de assinatura com base no conteúdo
            if signature_type == 'auto':
                if line.startswith('rule '):
                    sig_type = 'yara'
                elif 'content:' in line and 'sid:' in line:
                    sig_type = 'snort'
                else:
                    sig_type = 'regex'
            else:
                sig_type = signature_type
            
            # Cria uma assinatura para cada linha
            try:
                sig_name = f"{file_path.stem}_{count}"
                sig = {
                    'name': sig_name,
                    'signature_type': sig_type,
                    'pattern': line,
                    'source': str(file_path)
                }
                
                if self.add_signature(sig):
                    count += 1
            except Exception as e:
                logger.error(f"Falha ao adicionar assinatura da linha: {line[:50]}...: {e}")
        
        logger.info(f"Carregadas {count} assinaturas de {file_path}")
        return count
    
    def load_from_directory(self, directory: Union[str, Path], 
                          recursive: bool = True, 
                          signature_type: str = None) -> int:
        """Carrega assinaturas de um diretório.
        
        Args:
            directory: Caminho para o diretório com arquivos de assinaturas.
            recursive: Se deve carregar de subdiretórios também.
            signature_type: Tipo das assinaturas (opcional, tenta detectar automaticamente).
            
        Returns:
            int: Número total de assinaturas carregadas.
        """
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            raise SignatureError(f"Diretório não encontrado: {directory}")
        
        count = 0
        
        # Extensões de arquivo suportadas
        extensions = ['.json', '.yaml', '.yml', '.yar', '.yara', '.rules', '.snort', '.txt']
        
        # Função para processar um arquivo
        def process_file(file_path: Path):
            nonlocal count
            try:
                count += self.load_from_file(file_path, signature_type)
            except Exception as e:
                logger.error(f"Erro ao carregar assinaturas de {file_path}: {e}")
        
        # Processa os arquivos no diretório
        for ext in extensions:
            pattern = f"*{ext}"
            for file_path in directory.glob(pattern):
                if file_path.is_file():
                    process_file(file_path)
        
        # Processa recursivamente os subdiretórios, se solicitado
        if recursive:
            for subdir in directory.iterdir():
                if subdir.is_dir():
                    count += self.load_from_directory(subdir, recursive, signature_type)
        
        logger.info(f"Total de {count} assinaturas carregadas de {directory}")
        return count
    
    def match(self, data: Any, signature_type: str = None) -> List[Dict[str, Any]]:
        """Verifica se os dados correspondem a alguma assinatura.
        
        Args:
            data: Dados a serem verificados.
            signature_type: Tipo de assinatura para verificar (opcional, verifica todos os tipos).
            
        Returns:
            Lista de dicionários com informações sobre as assinaturas que corresponderam.
        """
        matches = []
        
        # Determina quais tipos de assinatura verificar
        if signature_type:
            signature_types = [signature_type.lower()]
        else:
            signature_types = list(self.signatures.keys())
        
        # Verifica cada tipo de assinatura
        for sig_type in signature_types:
            if sig_type not in self.signatures:
                continue
                
            # Verifica cada assinatura do tipo
            for name, signature in self.signatures[sig_type].items():
                try:
                    if signature.match(data):
                        matches.append({
                            'name': name,
                            'signature_type': sig_type,
                            'threat_type': signature.threat_type.value,
                            'confidence': signature.confidence,
                            'source': signature.source,
                            'description': signature.description,
                            'metadata': signature.metadata
                        })
                except Exception as e:
                    logger.error(f"Erro ao verificar assinatura {name}: {e}")
        
        # Ordena por confiança (maior primeiro) e depois por nome
        matches.sort(key=lambda x: (-x['confidence'], x['name']))
        return matches
    
    def get_signatures(self, signature_type: str = None) -> List[Dict[str, Any]]:
        """Obtém todas as assinaturas ou de um tipo específico.
        
        Args:
            signature_type: Tipo de assinatura (opcional, retorna todos os tipos se None).
            
        Returns:
            Lista de dicionários com informações sobre as assinaturas.
        """
        result = []
        
        if signature_type:
            signature_types = [signature_type.lower()]
        else:
            signature_types = list(self.signatures.keys())
        
        for sig_type in signature_types:
            if sig_type in self.signatures:
                for name, signature in self.signatures[sig_type].items():
                    result.append({
                        'name': name,
                        'signature_type': sig_type,
                        'threat_type': signature.threat_type.value,
                        'confidence': signature.confidence,
                        'source': signature.source,
                        'description': signature.description,
                        'pattern': signature.pattern,
                        'metadata': signature.metadata
                    })
        
        return result
    
    def clear(self, signature_type: str = None):
        """Remove todas as assinaturas ou de um tipo específico.
        
        Args:
            signature_type: Tipo de assinatura a ser removido (opcional, remove todas se None).
        """
        if signature_type:
            if signature_type in self.signatures:
                count = len(self.signatures[signature_type])
                del self.signatures[signature_type]
                logger.info(f"Removidas {count} assinaturas do tipo '{signature_type}'")
        else:
            count = sum(len(sigs) for sigs in self.signatures.values())
            self.signatures.clear()
            logger.info(f"Removidas todas as {count} assinaturas")

# Instância global para uso em todo o módulo
signature_manager = SignatureManager()

def get_signature_manager() -> SignatureManager:
    """Obtém a instância global do gerenciador de assinaturas."""
    return signature_manager

def set_signature_manager(manager: SignatureManager):
    """Define a instância global do gerenciador de assinaturas."""
    global signature_manager
    signature_manager = manager
