"""Módulo de armazenamento local para IOCs e assinaturas."""

import os
import json
import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, TypeVar, Type, Tuple, Set
from datetime import datetime

from .ioc import IOC, IOCType, detect_ioc_type

# Configuração de logging
logger = logging.getLogger(__name__)

# Tipo genérico para documentação
T = TypeVar('T')

class StorageError(Exception):
    """Exceção base para erros de armazenamento."""
    pass

class IOCStorage:
    """Armazenamento de IOCs em banco de dados SQLite."""
    
    def __init__(self, db_path: Union[str, Path] = None):
        """Inicializa o armazenamento de IOCs.
        
        Args:
            db_path: Caminho para o arquivo do banco de dados SQLite.
                     Se não for especificado, será usado um banco em memória.
        """
        self.db_path = str(db_path) if db_path else ":memory:"
        self._conn = None
        self._initialize_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Obtém uma conexão com o banco de dados."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                check_same_thread=False  # Permitir acesso de múltiplas threads
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn
    
    def _initialize_database(self):
        """Inicializa as tabelas do banco de dados."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Tabela de IOCs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TIMESTAMP NOT NULL,
            last_seen TIMESTAMP NOT NULL,
            confidence INTEGER NOT NULL,
            tags TEXT,  -- JSON array
            metadata TEXT,  -- JSON object
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(value, ioc_type)
        )
        ''')
        
        # Índices para buscas rápidas
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_threat_type ON iocs(threat_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_source ON iocs(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_tags ON iocs(tags)')
        
        # Tabela de assinaturas
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            signature_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            description TEXT,
            threat_type TEXT,
            source TEXT,
            confidence INTEGER,
            metadata TEXT,  -- JSON object
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(name, signature_type, pattern)
        )
        ''')
        
        # Índices para assinaturas
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sig_name ON signatures(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sig_type ON signatures(signature_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sig_threat_type ON signatures(threat_type)')
        
        conn.commit()
    
    def add_ioc(self, ioc: IOC) -> bool:
        """Adiciona um novo IOC ao armazenamento.
        
        Args:
            ioc: Instância de IOC a ser adicionada.
            
        Returns:
            bool: True se o IOC foi adicionado, False se já existir.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT OR IGNORE INTO iocs 
            (value, ioc_type, threat_type, source, first_seen, last_seen, confidence, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc.value,
                ioc.ioc_type.value,
                ioc.threat_type.value,
                ioc.source,
                ioc.first_seen,
                ioc.last_seen,
                ioc.confidence,
                json.dumps(ioc.tags),
                json.dumps(ioc.metadata)
            ))
            
            if cursor.rowcount > 0:
                conn.commit()
                logger.debug(f"IOC adicionado: {ioc.value} ({ioc.ioc_type.value})")
                return True
            else:
                # Atualiza o IOC existente
                cursor.execute('''
                UPDATE iocs 
                SET last_seen = ?, 
                    confidence = MAX(confidence, ?),
                    tags = ?,
                    metadata = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE value = ? AND ioc_type = ?
                ''', (
                    ioc.last_seen,
                    ioc.confidence,
                    json.dumps(ioc.tags),
                    json.dumps(ioc.metadata),
                    ioc.value,
                    ioc.ioc_type.value
                ))
                conn.commit()
                logger.debug(f"IOC atualizado: {ioc.value} ({ioc.ioc_type.value})")
                return False
                
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erro ao adicionar IOC {ioc.value}: {e}")
            raise StorageError(f"Erro ao adicionar IOC: {e}")
    
    def get_ioc(self, value: str, ioc_type: Union[str, IOCType] = None) -> Optional[IOC]:
        """Obtém um IOC pelo valor e tipo.
        
        Args:
            value: Valor do IOC.
            ioc_type: Tipo do IOC (opcional, tenta detectar automaticamente).
            
        Returns:
            IOC ou None se não encontrado.
        """
        if ioc_type is None:
            detected = detect_ioc_type(value)
            if detected is None:
                return None
            ioc_type = detected.value
        elif isinstance(ioc_type, IOCType):
            ioc_type = ioc_type.value
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM iocs 
        WHERE value = ? AND ioc_type = ?
        ''', (value, ioc_type))
        
        row = cursor.fetchone()
        if not row:
            return None
            
        return self._row_to_ioc(row)
    
    def search_iocs(self, query: str = None, ioc_type: Union[str, IOCType] = None, 
                   threat_type: Union[str, ThreatType] = None, source: str = None,
                   min_confidence: int = 0, limit: int = 100, offset: int = 0) -> List[IOC]:
        """Busca IOCs com base em critérios de pesquisa.
        
        Args:
            query: Termo de busca (pesquisa no valor do IOC).
            ioc_type: Tipo de IOC para filtrar.
            threat_type: Tipo de ameaça para filtrar.
            source: Fonte do IOC para filtrar.
            min_confidence: Confiança mínima (0-100).
            limit: Número máximo de resultados.
            offset: Deslocamento para paginação.
            
        Returns:
            Lista de IOCs que correspondem aos critérios.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Constrói a consulta SQL dinamicamente
        sql = 'SELECT * FROM iocs WHERE 1=1'
        params = []
        
        if query:
            sql += ' AND value LIKE ?'
            params.append(f'%{query}%')
            
        if ioc_type is not None:
            if isinstance(ioc_type, IOCType):
                ioc_type = ioc_type.value
            sql += ' AND ioc_type = ?'
            params.append(ioc_type)
            
        if threat_type is not None:
            if isinstance(threat_type, ThreatType):
                threat_type = threat_type.value
            sql += ' AND threat_type = ?'
            params.append(threat_type)
            
        if source is not None:
            sql += ' AND source = ?'
            params.append(source)
            
        if min_confidence > 0:
            sql += ' AND confidence >= ?'
            params.append(min_confidence)
        
        # Ordenação e paginação
        sql += ' ORDER BY last_seen DESC, confidence DESC'
        sql += ' LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(sql, params)
        return [self._row_to_ioc(row) for row in cursor.fetchall()]
    
    def delete_ioc(self, value: str, ioc_type: Union[str, IOCType] = None) -> bool:
        """Remove um IOC do armazenamento.
        
        Args:
            value: Valor do IOC.
            ioc_type: Tipo do IOC (opcional, tenta detectar automaticamente).
            
        Returns:
            bool: True se o IOC foi removido, False se não existir.
        """
        if ioc_type is None:
            detected = detect_ioc_type(value)
            if detected is None:
                return False
            ioc_type = detected.value
        elif isinstance(ioc_type, IOCType):
            ioc_type = ioc_type.value
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            DELETE FROM iocs 
            WHERE value = ? AND ioc_type = ?
            ''', (value, ioc_type))
            
            deleted = cursor.rowcount > 0
            if deleted:
                conn.commit()
                logger.info(f"IOC removido: {value} ({ioc_type})")
            
            return deleted
            
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erro ao remover IOC {value}: {e}")
            raise StorageError(f"Erro ao remover IOC: {e}")
    
    def add_signature(self, name: str, signature_type: str, pattern: str, 
                     description: str = None, threat_type: str = None, 
                     source: str = None, confidence: int = 50, 
                     metadata: Dict[str, Any] = None) -> bool:
        """Adiciona uma nova assinatura ao armazenamento.
        
        Args:
            name: Nome da assinatura.
            signature_type: Tipo da assinatura (ex: 'yara', 'snort').
            pattern: Padrão da assinatura.
            description: Descrição da assinatura.
            threat_type: Tipo de ameaça associada.
            source: Fonte da assinatura.
            confidence: Nível de confiança (0-100).
            metadata: Metadados adicionais.
            
        Returns:
            bool: True se a assinatura foi adicionada, False se já existir.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT OR IGNORE INTO signatures 
            (name, signature_type, pattern, description, threat_type, source, confidence, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                name,
                signature_type,
                pattern,
                description,
                threat_type,
                source,
                min(max(confidence, 0), 100),  # Garante que está entre 0 e 100
                json.dumps(metadata or {})
            ))
            
            if cursor.rowcount > 0:
                conn.commit()
                logger.debug(f"Assinatura adicionada: {name} ({signature_type})")
                return True
            else:
                # Atualiza a assinatura existente
                cursor.execute('''
                UPDATE signatures 
                SET description = COALESCE(?, description),
                    threat_type = COALESCE(?, threat_type),
                    source = COALESCE(?, source),
                    confidence = ?,
                    metadata = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE name = ? AND signature_type = ? AND pattern = ?
                ''', (
                    description,
                    threat_type,
                    source,
                    min(max(confidence, 0), 100),
                    json.dumps(metadata or {}),
                    name,
                    signature_type,
                    pattern
                ))
                conn.commit()
                logger.debug(f"Assinatura atualizada: {name} ({signature_type})")
                return False
                
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erro ao adicionar assinatura {name}: {e}")
            raise StorageError(f"Erro ao adicionar assinatura: {e}")
    
    def search_signatures(self, query: str = None, signature_type: str = None, 
                         threat_type: str = None, source: str = None,
                         min_confidence: int = 0, limit: int = 100, 
                         offset: int = 0) -> List[Dict[str, Any]]:
        """Busca assinaturas com base em critérios de pesquisa.
        
        Args:
            query: Termo de busca (pesquisa no nome e descrição).
            signature_type: Tipo de assinatura para filtrar.
            threat_type: Tipo de ameaça para filtrar.
            source: Fonte da assinatura para filtrar.
            min_confidence: Confiança mínima (0-100).
            limit: Número máximo de resultados.
            offset: Deslocamento para paginação.
            
        Returns:
            Lista de dicionários com as assinaturas encontradas.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Constrói a consulta SQL dinamicamente
        sql = 'SELECT * FROM signatures WHERE 1=1'
        params = []
        
        if query:
            sql += ' AND (name LIKE ? OR description LIKE ?)'
            params.extend([f'%{query}%', f'%{query}%'])
            
        if signature_type is not None:
            sql += ' AND signature_type = ?'
            params.append(signature_type)
            
        if threat_type is not None:
            sql += ' AND threat_type = ?'
            params.append(threat_type)
            
        if source is not None:
            sql += ' AND source = ?'
            params.append(source)
            
        if min_confidence > 0:
            sql += ' AND confidence >= ?'
            params.append(min_confidence)
        
        # Ordenação e paginação
        sql += ' ORDER BY name, confidence DESC'
        sql += ' LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(sql, params)
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def delete_signature(self, signature_id: int) -> bool:
        """Remove uma assinatura do armazenamento.
        
        Args:
            signature_id: ID da assinatura a ser removida.
            
        Returns:
            bool: True se a assinatura foi removida, False se não existir.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            DELETE FROM signatures 
            WHERE id = ?
            ''', (signature_id,))
            
            deleted = cursor.rowcount > 0
            if deleted:
                conn.commit()
                logger.info(f"Assinatura removida: ID {signature_id}")
            
            return deleted
            
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Erro ao remover assinatura ID {signature_id}: {e}")
            raise StorageError(f"Erro ao remover assinatura: {e}")
    
    def _row_to_ioc(self, row) -> IOC:
        """Converte uma linha do banco de dados em um objeto IOC."""
        return IOC(
            value=row['value'],
            ioc_type=row['ioc_type'],
            threat_type=row['threat_type'],
            source=row['source'],
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            confidence=row['confidence'],
            tags=json.loads(row['tags']) if row['tags'] else [],
            metadata=json.loads(row['metadata']) if row['metadata'] else {}
        )
    
    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Converte uma linha do banco de dados em um dicionário."""
        return {
            'id': row['id'],
            'name': row['name'],
            'signature_type': row['signature_type'],
            'pattern': row['pattern'],
            'description': row['description'],
            'threat_type': row['threat_type'],
            'source': row['source'],
            'confidence': row['confidence'],
            'metadata': json.loads(row['metadata']) if row['metadata'] else {},
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        }
    
    def close(self):
        """Fecha a conexão com o banco de dados."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
    
    def __del__(self):
        """Garante que a conexão seja fechada quando o objeto for destruído."""
        self.close()

# Instância global para uso em todo o módulo
local_storage = IOCStorage()

def get_storage() -> IOCStorage:
    """Obtém a instância global do armazenamento local."""
    return local_storage

def set_storage_path(path: Union[str, Path]):
    """Define o caminho do banco de dados do armazenamento local.
    
    Args:
        path: Caminho para o arquivo do banco de dados SQLite.
    """
    global local_storage
    local_storage.close()
    local_storage = IOCStorage(path)
