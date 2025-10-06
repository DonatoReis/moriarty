"""Configurações do módulo de inteligência."""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Caminho padrão para o diretório de configuração
DEFAULT_CONFIG_DIR = Path.home() / '.moriarty'
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / 'intelligence_config.json'

class ConfigError(Exception):
    """Exceção para erros de configuração."""
    pass

class Config:
    """Gerenciador de configurações do módulo de inteligência."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._config = {}
        self._config_file = None
        self._initialized = True
        
        # Carrega as configurações padrão
        self._load_defaults()
        
        # Tenta carregar as configurações do arquivo
        self._config_file = self._find_config_file()
        if self._config_file:
            self.load(self._config_file)
    
    def _load_defaults(self):
        """Carrega as configurações padrão."""
        self._config = {
            # Configurações de armazenamento
            'storage': {
                'type': 'sqlite',
                'path': str(DEFAULT_CONFIG_DIR / 'intelligence.db'),
                'in_memory': False
            },
            
            # Configurações de coleta
            'collection': {
                'enabled': True,
                'interval': 3600,  # segundos
                'max_items': 1000,
                'sources': ['all'],  # ou lista de fontes específicas
                'exclude': []  # fontes a serem excluídas
            },
            
            # Configurações de assinaturas
            'signatures': {
                'enabled': True,
                'auto_update': True,
                'update_interval': 86400,  # segundos (1 dia)
                'sources': [
                    {
                        'name': 'default',
                        'type': 'local',
                        'path': str(DEFAULT_CONFIG_DIR / 'signatures'),
                        'enabled': True
                    }
                ]
            },
            
            # Configurações de feeds de ameaças
            'threat_feeds': {
                'enabled': True,
                'auto_update': True,
                'update_interval': 3600,  # segundos (1 hora)
                'feeds': []  # Será preenchido com feeds padrão
            },
            
            # Configurações de API
            'api_keys': {
                # Chaves de API para serviços externos
                'virustotal': '',
                'abuseipdb': '',
                'shodan': '',
                'censys_id': '',
                'censys_secret': '',
                'greynoise': '',
                'otx': ''
            },
            
            # Configurações de proxy
            'proxy': {
                'enabled': False,
                'http': '',
                'https': '',
                'no_proxy': 'localhost,127.0.0.1'
            },
            
            # Configurações de logging
            'logging': {
                'level': 'INFO',
                'file': str(DEFAULT_CONFIG_DIR / 'intelligence.log'),
                'max_size': 10485760,  # 10 MB
                'backup_count': 5
            },
            
            # Configurações de cache
            'cache': {
                'enabled': True,
                'ttl': 3600,  # segundos (1 hora)
                'max_size': 1000
            },
            
            # Configurações de privacidade
            'privacy': {
                'anonymize_ips': False,
                'anonymize_domains': False,
                'log_sensitive_data': False
            },
            
            # Configurações avançadas
            'advanced': {
                'max_workers': 10,
                'timeout': 30,
                'retry_attempts': 3,
                'retry_delay': 5
            }
        }
        
        # Adiciona feeds de ameaças padrão
        self._add_default_feeds()
    
    def _add_default_feeds(self):
        """Adiciona os feeds de ameaças padrão à configuração."""
        from .collectors import ThreatFeedCollector
        
        self._config['threat_feeds']['feeds'] = [
            {
                'name': feed['name'],
                'url': feed['url'],
                'format': feed['format'],
                'ioc_type': feed['ioc_type'],
                'threat_type': feed['threat_type'],
                'confidence': feed['confidence'],
                'enabled': feed.get('enabled', True),
                'api_key_required': feed.get('api_key_required', False)
            }
            for feed in ThreatFeedCollector.THREAT_FEEDS
        ]
    
    def _find_config_file(self) -> Optional[Path]:
        """Encontra o arquivo de configuração em locais padrão."""
        # 1. Verifica o caminho especificado na variável de ambiente
        env_config = os.environ.get('MORIARTY_CONFIG')
        if env_config:
            config_path = Path(env_config).expanduser().resolve()
            if config_path.exists() and config_path.is_file():
                return config_path
        
        # 2. Verifica no diretório de configuração do usuário
        user_config = DEFAULT_CONFIG_FILE
        if user_config.exists() and user_config.is_file():
            return user_config
        
        # 3. Verifica no diretório de instalação do pacote
        try:
            import moriarty
            package_dir = Path(moriarty.__file__).parent
            package_config = package_dir / 'config' / 'intelligence_config.json'
            if package_config.exists() and package_config.is_file():
                return package_config
        except (ImportError, AttributeError):
            pass
        
        # 4. Verifica no diretório de trabalho atual
        cwd_config = Path.cwd() / 'intelligence_config.json'
        if cwd_config.exists() and cwd_config.is_file():
            return cwd_config
        
        return None
    
    def load(self, config_file: Union[str, Path] = None):
        """Carrega as configurações de um arquivo JSON.
        
        Args:
            config_file: Caminho para o arquivo de configuração.
                        Se None, usa o arquivo padrão.
        """
        if config_file is None:
            config_file = self._config_file or DEFAULT_CONFIG_FILE
        else:
            config_file = Path(config_file).expanduser().resolve()
        
        if not config_file.exists() or not config_file.is_file():
            raise ConfigError(f"Arquivo de configuração não encontrado: {config_file}")
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
                
            # Atualiza recursivamente o dicionário de configuração
            self._update_dict(self._config, user_config)
            self._config_file = config_file
            
            # Cria o diretório de configuração se não existir
            if not config_file.parent.exists():
                config_file.parent.mkdir(parents=True, exist_ok=True)
                
        except json.JSONDecodeError as e:
            raise ConfigError(f"Erro ao decodificar o arquivo de configuração {config_file}: {e}")
        except Exception as e:
            raise ConfigError(f"Erro ao carregar o arquivo de configuração {config_file}: {e}")
    
    def save(self, config_file: Union[str, Path] = None):
        """Salva as configurações em um arquivo JSON.
        
        Args:
            config_file: Caminho para o arquivo de configuração.
                        Se None, usa o arquivo atual ou o padrão.
        """
        if config_file is None:
            if self._config_file is None:
                config_file = DEFAULT_CONFIG_FILE
            else:
                config_file = self._config_file
        else:
            config_file = Path(config_file).expanduser().resolve()
        
        try:
            # Garante que o diretório existe
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
                
            self._config_file = config_file
            
        except Exception as e:
            raise ConfigError(f"Erro ao salvar o arquivo de configuração {config_file}: {e}")
    
    def get(self, key: str, default=None) -> Any:
        """Obtém um valor de configuração.
        
        Args:
            key: Chave de configuração no formato 'section.subsection.key'.
            default: Valor padrão se a chave não existir.
            
        Returns:
            O valor da configuração ou o valor padrão.
        """
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Define um valor de configuração.
        
        Args:
            key: Chave de configuração no formato 'section.subsection.key'.
            value: Valor a ser definido.
        """
        keys = key.split('.')
        current = self._config
        
        for i, k in enumerate(keys[:-1], 1):
            if k not in current:
                current[k] = {}
            current = current[k]
            
        current[keys[-1]] = value
    
    def _update_dict(self, d: Dict, u: Dict) -> Dict:
        """Atualiza recursivamente um dicionário."""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                d[k] = self._update_dict(d[k], v)
            else:
                d[k] = v
        return d
    
    def to_dict(self) -> Dict:
        """Retorna as configurações como um dicionário."""
        return self._config.copy()
    
    def __getitem__(self, key: str) -> Any:
        """Permite o acesso a itens usando colchetes."""
        return self.get(key)
    
    def __setitem__(self, key: str, value: Any):
        """Permite a definição de itens usando colchetes."""
        self.set(key, value)
    
    def __contains__(self, key: str) -> bool:
        """Verifica se uma chave de configuração existe."""
        try:
            self.get(key)
            return True
        except KeyError:
            return False

# Instância global para uso em todo o módulo
settings = Config()

def get_config() -> Config:
    """Obtém a instância global de configuração."""
    return settings

def init_config(config_file: Union[str, Path] = None):
    """Inicializa a configuração global.
    
    Args:
        config_file: Caminho para o arquivo de configuração (opcional).
    """
    global settings
    settings = Config()
    
    if config_file:
        settings.load(config_file)
    elif settings._config_file:
        settings.load()
    else:
        # Cria o diretório de configuração se não existir
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        settings.save()
    
    # Configura o logging
    _setup_logging()

def _setup_logging():
    """Configura o sistema de logging com base nas configurações."""
    import logging.config
    import logging.handlers
    
    log_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            },
            'detailed': {
                'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': settings['logging.level'],
                'formatter': 'standard',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': settings['logging.level'],
                'formatter': 'detailed',
                'filename': settings['logging.file'],
                'maxBytes': settings['logging.max_size'],
                'backupCount': settings['logging.backup_count'],
                'encoding': 'utf8'
            }
        },
        'loggers': {
            'moriarty.intelligence': {
                'handlers': ['console', 'file'],
                'level': settings['logging.level'],
                'propagate': False
            },
            '': {
                'handlers': ['console'],
                'level': 'WARNING',
                'propagate': False
            }
        },
        'root': {
            'level': 'WARNING',
            'handlers': ['console']
        }
    }
    
    # Aplica a configuração de logging
    logging.config.dictConfig(log_config)
