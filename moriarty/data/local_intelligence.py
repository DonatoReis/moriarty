"""Módulo de inteligência local para coleta e análise de ameaças."""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict, dataclass, field

from .signature_loaders import (
    SignatureManager, WappalyzerLoader, IOCFeedLoader,
    create_loader, get_loader_class
)
from .ioc import (
    IOC, IOCType, ThreatType, IOCMatcher,
    load_iocs_from_file, save_iocs_to_file, merge_iocs
)

# Configuração de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LocalIntelligenceConfig:
    """Configuração para o módulo de inteligência local."""
    # Diretório base para armazenamento de dados
    data_dir: Path = Path("~/.moriarty/data").expanduser()
    
    # Configuração do banco de dados
    db_path: Path = field(init=False)
    
    # Configuração de atualização
    update_interval: int = 86400  # segundos (padrão: 24h)
    
    # Fontes de assinaturas
    signature_sources: List[Dict[str, Any]] = field(default_factory=lambda: [
        {
            'name': 'wappalyzer',
            'url': 'https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies.json',
            'format': 'wappalyzer',
            'enabled': True
        },
        {
            'name': 'otx-alienvault',
            'url': 'https://otx.alienvault.com/otxapi',
            'format': 'otx',
            'enabled': True,
            'api_key': ''  # Deve ser configurado pelo usuário
        },
        # Adicione mais fontes conforme necessário
    ])
    
    def __post_init__(self):
        """Inicializa os caminhos dos arquivos."""
        self.data_dir = Path(self.data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Caminhos dos bancos de dados
        self.db_path = self.data_dir / 'intelligence.db'
        
        # Cria os diretórios necessários
        (self.data_dir / 'cache').mkdir(exist_ok=True)
        (self.data_dir / 'signatures').mkdir(exist_ok=True)
        (self.data_dir / 'iocs').mkdir(exist_ok=True)

class LocalIntelligence:
    """Classe principal para gerenciar inteligência local de ameaças."""
    
    def __init__(self, config: Optional[LocalIntelligenceConfig] = None):
        """Inicializa o gerenciador de inteligência local."""
        self.config = config or LocalIntelligenceConfig()
        self.signature_manager = SignatureManager()
        self.ioc_matcher = IOCMatcher()
        
        # Inicializa o banco de dados
        self._init_database()
        
        # Carrega assinaturas e IOCs existentes
        self._load_signatures()
        self._load_iocs()
    
    def _init_database(self) -> None:
        """Inicializa o banco de dados SQLite."""
        with sqlite3.connect(str(self.config.db_path)) as conn:
            # Tabela de assinaturas
            conn.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                version_detection TEXT,
                confidence INTEGER DEFAULT 80,
                source TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, pattern_type, pattern)
            )
            """)
            
            # Tabela de IOCs
            conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                confidence INTEGER DEFAULT 50,
                tags TEXT,  # JSON array
                metadata TEXT,  # JSON object
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(type, value, source)
            )
            """)
            
            # Tabela de atualizações
            conn.execute("""
            CREATE TABLE IF NOT EXISTS updates (
                source TEXT PRIMARY KEY,
                last_updated TIMESTAMP,
                next_update TIMESTAMP,
                status TEXT,
                error TEXT
            )
            """)
            
            # Índices para consultas rápidas
            conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_name ON signatures(name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_signatures_category ON signatures(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_threat_type ON iocs(threat_type)")
            
            conn.commit()
    
    def _load_signatures(self) -> None:
        """Carrega assinaturas do banco de dados."""
        with sqlite3.connect(str(self.config.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Carrega assinaturas de tecnologia
            cursor.execute("SELECT * FROM signatures")
            for row in cursor.fetchall():
                signature = dict(row)
                self.signature_manager.add_signature(signature)
            
            logger.info(f"Carregadas {len(self.signature_manager.signatures)} assinaturas")
    
    def _load_iocs(self) -> None:
        """Carrega IOCs do banco de dados."""
        with sqlite3.connect(str(self.config.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Carrega IOCs
            cursor.execute("SELECT * FROM iocs")
            for row in cursor.fetchall():
                ioc_dict = dict(row)
                
                # Converte campos JSON
                for field in ('tags', 'metadata'):
                    if ioc_dict[field]:
                        ioc_dict[field] = json.loads(ioc_dict[field])
                
                try:
                    ioc = IOC.from_dict(ioc_dict)
                    self.ioc_matcher.add_ioc(ioc)
                except Exception as e:
                    logger.error(f"Erro ao carregar IOC {ioc_dict.get('value')}: {e}")
            
            logger.info(f"Carregados {sum(len(iocs) for iocs in self.ioc_matcher.iocs.values())} IOCs")
    
    def update_signatures(self, force: bool = False) -> bool:
        """
        Atualiza as assinaturas a partir das fontes configuradas.
        
        Args:
            force: Se True, força a atualização mesmo que não seja necessário
            
        Returns:
            True se a atualização foi bem-sucedida, False caso contrário
        """
        updated = False
        
        for source in self.config.signature_sources:
            if not source.get('enabled', True):
                continue
                
            source_name = source['name']
            logger.info(f"Atualizando assinaturas de {source_name}...")
            
            try:
                # Verifica se é necessário atualizar
                if not force and not self._needs_update(source_name):
                    logger.info(f"As assinaturas de {source_name} estão atualizadas")
                    continue
                
                # Cria o carregador apropriado
                loader = create_loader(
                    source.get('url', ''),
                    source.get('format', 'auto')
                )
                
                # Carrega as assinaturas
                signatures = loader.load()
                
                # Processa as assinaturas
                self._process_signatures(signatures, source_name)
                
                # Atualiza o status
                self._update_source_status(source_name, success=True)
                updated = True
                
                logger.info(f"Assinaturas de {source_name} atualizadas com sucesso")
                
            except Exception as e:
                logger.error(f"Erro ao atualizar assinaturas de {source_name}: {e}")
                self._update_source_status(source_name, success=False, error=str(e))
        
        return updated
    
    def _needs_update(self, source_name: str) -> bool:
        """Verifica se uma fonte precisa ser atualizada."""
        with sqlite3.connect(str(self.config.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT next_update FROM updates WHERE source = ?",
                (source_name,)
            )
            row = cursor.fetchone()
            
            if not row:
                return True
                
            next_update = datetime.fromisoformat(row[0])
            return datetime.utcnow() >= next_update
    
    def _update_source_status(self, source_name: str, success: bool, error: str = '') -> None:
        """Atualiza o status de uma fonte no banco de dados."""
        now = datetime.utcnow()
        next_update = now + timedelta(seconds=self.config.update_interval)
        
        with sqlite3.connect(str(self.config.db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO updates 
                (source, last_updated, next_update, status, error)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_name,
                    now.isoformat(),
                    next_update.isoformat(),
                    'success' if success else 'error',
                    error or ''
                )
            )
            conn.commit()
    
    def _process_signatures(self, signatures: List[Dict[str, Any]], source: str) -> None:
        """Processa e armazena as assinaturas carregadas."""
        with sqlite3.connect(str(self.config.db_path)) as conn:
            cursor = conn.cursor()
            
            for sig in signatures:
                try:
                    # Normaliza a assinatura
                    if 'name' not in sig or 'pattern' not in sig:
                        continue
                        
                    # Insere ou atualiza a assinatura
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO signatures 
                        (name, category, pattern_type, pattern, 
                         version_detection, confidence, source, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                        (
                            sig['name'],
                            sig.get('category', 'unknown'),
                            sig.get('pattern_type', 'unknown'),
                            sig['pattern'],
                            sig.get('version_detection'),
                            int(sig.get('confidence', 80)),
                            source
                        )
                    )
                    
                except Exception as e:
                    logger.error(f"Erro ao processar assinatura {sig.get('name')}: {e}")
            
            conn.commit()
    
    def add_ioc(self, ioc: Union[IOC, Dict[str, Any]]) -> bool:
        """
        Adiciona um IOC ao banco de dados e ao matcher.
        
        Args:
            ioc: O IOC a ser adicionado (pode ser um dicionário ou objeto IOC)
            
        Returns:
            True se o IOC foi adicionado com sucesso, False caso contrário
        """
        if isinstance(ioc, dict):
            try:
                ioc = IOC.from_dict(ioc)
            except Exception as e:
                logger.error(f"Erro ao criar IOC a partir de dicionário: {e}")
                return False
        
        if not isinstance(ioc, IOC):
            logger.error("O parâmetro 'ioc' deve ser um dicionário ou instância de IOC")
            return False
        
        try:
            with sqlite3.connect(str(self.config.db_path)) as conn:
                # Converte listas/dicionários para JSON
                tags_json = json.dumps(ioc.tags) if ioc.tags else '[]'
                metadata_json = json.dumps(ioc.metadata) if ioc.metadata else '{}'
                
                # Insere ou atualiza o IOC
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO iocs 
                    (type, value, threat_type, source, first_seen, last_seen, 
                     confidence, tags, metadata, updated_at)
                    VALUES (?, ?, ?, ?, COALESCE(?, ?), ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        ioc.ioc_type.value,
                        ioc.value,
                        ioc.threat_type.value,
                        ioc.source,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        ioc.confidence,
                        tags_json,
                        metadata_json,
                        ioc.first_seen.isoformat(),
                        datetime.utcnow().isoformat()
                    )
                )
                
                # Atualiza o matcher
                self.ioc_matcher.add_ioc(ioc)
                
                return True
                
        except Exception as e:
            logger.error(f"Erro ao adicionar IOC {ioc.value}: {e}")
            return False
    
    def search_iocs(self, query: str, limit: int = 100) -> List[IOC]:
        """
        Busca IOCs que correspondem à consulta.
        
        Args:
            query: Termo de busca
            limit: Número máximo de resultados a retornar
            
        Returns:
            Lista de IOCs correspondentes
        """
        return self.ioc_matcher.search(query, limit)
    
    def get_ioc(self, ioc_type: Union[str, IOCType], value: str) -> Optional[IOC]:
        """
        Obtém um IOC específico.
        
        Args:
            ioc_type: Tipo do IOC
            value: Valor do IOC
            
        Returns:
            O IOC correspondente ou None se não encontrado
        """
        if isinstance(ioc_type, str):
            ioc_type = IOCType(ioc_type.lower())
            
        matches = self.ioc_matcher.match(value, ioc_type)
        return matches[0] if matches else None
    
    def get_related_iocs(self, ioc: Union[IOC, str, Tuple[str, str]], 
                        max_relations: int = 10) -> Dict[str, List[IOC]]:
        """
        Obtém IOCs relacionados ao IOC especificado.
        
        Args:
            ioc: O IOC de referência (pode ser um objeto IOC, um valor, ou uma tupla (tipo, valor))
            max_relations: Número máximo de IOCs relacionados a retornar por tipo
            
        Returns:
            Dicionário mapeando tipos de relacionamento para listas de IOCs relacionados
        """
        if not isinstance(ioc, IOC):
            if isinstance(ioc, str):
                # Tenta encontrar o IOC pelo valor
                matches = self.ioc_matcher.match(ioc)
                if not matches:
                    return {}
                ioc = matches[0]
            elif isinstance(ioc, tuple) and len(ioc) == 2:
                # Tupla (tipo, valor)
                ioc_type, value = ioc
                matches = self.ioc_matcher.match(value, ioc_type)
                if not matches:
                    return {}
                ioc = matches[0]
            else:
                raise ValueError("O parâmetro 'ioc' deve ser um objeto IOC, um valor, ou uma tupla (tipo, valor)")
        
        return self.ioc_matcher.get_related(ioc, max_relations)
    
    def export_iocs(self, file_path: Union[str, Path], 
                   format_name: str = 'json') -> bool:
        """
        Exporta todos os IOCs para um arquivo.
        
        Args:
            file_path: Caminho para o arquivo de saída
            format_name: Formato de saída ('json', 'yaml', 'csv')
            
        Returns:
            True se a exportação foi bem-sucedida, False caso contrário
        """
        try:
            # Obtém todos os IOCs do banco de dados
            with sqlite3.connect(str(self.config.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM iocs")
                
                iocs = []
                for row in cursor.fetchall():
                    ioc_dict = dict(row)
                    # Converte campos JSON
                    for field in ('tags', 'metadata'):
                        if ioc_dict[field]:
                            ioc_dict[field] = json.loads(ioc_dict[field])
                    iocs.append(ioc_dict)
            
            # Salva no formato especificado
            save_iocs_to_file(iocs, file_path, format_name)
            return True
            
        except Exception as e:
            logger.error(f"Erro ao exportar IOCs: {e}")
            return False
    
    def import_iocs(self, file_path: Union[str, Path], 
                   format_name: str = 'auto') -> int:
        """
        Importa IOCs de um arquivo.
        
        Args:
            file_path: Caminho para o arquivo de entrada
            format_name: Formato do arquivo ('json', 'yaml', 'csv', 'auto' para detectar)
            
        Returns:
            Número de IOCs importados com sucesso
        """
        try:
            iocs = load_iocs_from_file(file_path, format_name)
            count = 0
            
            for ioc in iocs:
                if self.add_ioc(ioc):
                    count += 1
            
            logger.info(f"Importados {count} IOCs de {file_path}")
            return count
            
        except Exception as e:
            logger.error(f"Erro ao importar IOCs de {file_path}: {e}")
            return 0

# Função de conveniência para criar uma instância
def get_local_intelligence(config: Optional[LocalIntelligenceConfig] = None) -> LocalIntelligence:
    """
    Retorna uma instância de LocalIntelligence configurada.
    
    Args:
        config: Configuração opcional
        
    Returns:
        Instância de LocalIntelligence
    """
    return LocalIntelligence(config)

__all__ = [
    'LocalIntelligence',
    'LocalIntelligenceConfig',
    'get_local_intelligence',
    'IOC',
    'IOCType',
    'ThreatType'
]
