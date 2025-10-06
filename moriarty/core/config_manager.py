"""Gerenciador de configurações e API keys."""
import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class APIKeys:
    """API Keys configuration."""
    virustotal: Optional[str] = None
    securitytrails: Optional[str] = None
    shodan: Optional[str] = None
    censys: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    hunter: Optional[str] = None
    fofa: Optional[str] = None
    zoomeye: Optional[str] = None
    binaryedge: Optional[str] = None
    github: Optional[str] = None
    telegram: Optional[str] = None
    discord_webhook: Optional[str] = None
    slack_webhook: Optional[str] = None
    passivetotal_username: Optional[str] = None
    passivetotal_key: Optional[str] = None
    spyse_key: Optional[str] = None
    leakix_key: Optional[str] = None
    leakpeek_key: Optional[str] = None
    hibp_key: Optional[str] = None
    captcha_solver: Optional[str] = None
    captcha_solver_url: Optional[str] = None


@dataclass
class ProxyConfig:
    """Proxy configuration."""
    http_proxies: list[str] = None
    socks_proxies: list[str] = None
    tor_enabled: bool = False
    tor_port: int = 9050
    i2p_enabled: bool = False
    i2p_port: int = 4444
    rotate_interval: int = 60  # seconds
    health_check_interval: int = 300  # seconds


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    backend: str = "memory"  # memory, sqlite, redis
    sqlite_path: Optional[str] = None
    redis_url: Optional[str] = None
    ttl_default: int = 3600  # seconds
    max_size: int = 10000
    eviction_policy: str = "lru"  # lru, lfu, fifo
    persistence: bool = True
    warmup_enabled: bool = False


@dataclass
class NotificationConfig:
    """Notification configuration."""
    enabled: bool = False
    discord_enabled: bool = False
    discord_webhook: Optional[str] = None
    slack_enabled: bool = False
    slack_webhook: Optional[str] = None
    email_enabled: bool = False
    email_smtp: Optional[str] = None
    email_from: Optional[str] = None
    email_to: Optional[list[str]] = None
    telegram_enabled: bool = False
    telegram_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None


class ConfigManager:
    """Centralized configuration manager."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.config_dir = Path.home() / ".moriarty"
            self.config_file = self.config_dir / "config.yaml"
            self.api_keys = APIKeys()
            self.proxies = ProxyConfig()
            self.cache = CacheConfig()
            self.notifications = NotificationConfig()
            self.wordlists = {}
            self.templates_dir = None
            self._load_config()
            self._initialized = True
    
    def _load_config(self):
        """Load configuration from file."""
        if not self.config_dir.exists():
            self.config_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_config()
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = yaml.safe_load(f) or {}
                
                # Load API keys
                api_keys = config.get('api_keys', {})
                for key, value in api_keys.items():
                    if hasattr(self.api_keys, key):
                        setattr(self.api_keys, key, value or os.getenv(f"MORIARTY_{key.upper()}"))
                
                # Load proxy config
                proxy_config = config.get('proxies', {})
                self.proxies.http_proxies = proxy_config.get('http', [])
                self.proxies.socks_proxies = proxy_config.get('socks', [])
                self.proxies.tor_enabled = proxy_config.get('tor_enabled', False)
                self.proxies.tor_port = proxy_config.get('tor_port', 9050)
                self.proxies.i2p_enabled = proxy_config.get('i2p_enabled', False)
                self.proxies.rotate_interval = proxy_config.get('rotate_interval', 60)
                
                # Load cache config
                cache_config = config.get('cache', {})
                self.cache.enabled = cache_config.get('enabled', True)
                self.cache.backend = cache_config.get('backend', 'memory')
                self.cache.sqlite_path = cache_config.get('sqlite_path', str(self.config_dir / 'cache.db'))
                self.cache.redis_url = cache_config.get('redis_url')
                self.cache.ttl_default = cache_config.get('ttl_default', 3600)
                self.cache.max_size = cache_config.get('max_size', 10000)
                self.cache.eviction_policy = cache_config.get('eviction_policy', 'lru')
                
                # Load notifications
                notif_config = config.get('notifications', {})
                self.notifications.enabled = notif_config.get('enabled', False)
                self.notifications.discord_webhook = notif_config.get('discord_webhook')
                self.notifications.slack_webhook = notif_config.get('slack_webhook')
                self.notifications.telegram_token = notif_config.get('telegram_token')
                self.notifications.telegram_chat_id = notif_config.get('telegram_chat_id')
                
                # Load wordlists
                self.wordlists = config.get('wordlists', {
                    'subdomains': str(self.config_dir / 'wordlists' / 'subdomains.txt'),
                    'directories': str(self.config_dir / 'wordlists' / 'directories.txt'),
                    'passwords': str(self.config_dir / 'wordlists' / 'passwords.txt'),
                })
                
                # Load templates directory
                self.templates_dir = Path(config.get('templates_dir', self.config_dir / 'templates'))
                
                logger.info("config.loaded", config_file=str(self.config_file))
                
            except Exception as e:
                logger.error("config.load.error", error=str(e))
                self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file."""
        default_config = {
            'api_keys': {
                'virustotal': None,
                'securitytrails': None,
                'shodan': None,
                'censys': None,
                'censys_id': None,
                'censys_secret': None,
                'hunter': None,
                'fofa': None,
                'zoomeye': None,
                'binaryedge': None,
                'github': None,
                'discord_webhook': None,
                'slack_webhook': None,
                'passivetotal_username': None,
                'passivetotal_key': None,
                'spyse_key': None,
                'leakix_key': None,
                'leakpeek_key': None,
                'hibp_key': None,
                'captcha_solver': None,
                'captcha_solver_url': None,
            },
            'proxies': {
                'http': [],
                'socks': [],
                'tor_enabled': False,
                'tor_port': 9050,
                'i2p_enabled': False,
                'i2p_port': 4444,
                'rotate_interval': 60,
                'health_check_interval': 300,
            },
            'cache': {
                'enabled': True,
                'backend': 'memory',  # memory, sqlite, redis
                'sqlite_path': str(self.config_dir / 'cache.db'),
                'redis_url': None,
                'ttl_default': 3600,
                'max_size': 10000,
                'eviction_policy': 'lru',
                'persistence': True,
                'warmup_enabled': False,
            },
            'notifications': {
                'enabled': False,
                'discord_webhook': None,
                'slack_webhook': None,
                'telegram_token': None,
                'telegram_chat_id': None,
                'email_smtp': None,
                'email_from': None,
                'email_to': [],
            },
            'wordlists': {
                'subdomains': str(self.config_dir / 'wordlists' / 'subdomains.txt'),
                'directories': str(self.config_dir / 'wordlists' / 'directories.txt'),
                'passwords': str(self.config_dir / 'wordlists' / 'passwords.txt'),
            },
            'templates_dir': str(self.config_dir / 'templates'),
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        logger.info("config.created", config_file=str(self.config_file))
        
        # Create wordlists directory
        wordlists_dir = self.config_dir / 'wordlists'
        wordlists_dir.mkdir(parents=True, exist_ok=True)
        
        # Create templates directory
        templates_dir = self.config_dir / 'templates'
        templates_dir.mkdir(parents=True, exist_ok=True)
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for service."""
        return getattr(self.api_keys, service, None)
    
    def get_proxies(self) -> list[str]:
        """Get all configured proxies."""
        proxies = []
        if self.proxies.http_proxies:
            proxies.extend(self.proxies.http_proxies)
        if self.proxies.socks_proxies:
            proxies.extend(self.proxies.socks_proxies)
        if self.proxies.tor_enabled:
            proxies.append(f"socks5://127.0.0.1:{self.proxies.tor_port}")
        return proxies
    
    def save_config(self):
        """Save current configuration to file."""
        config = {
            'api_keys': {
                k: v for k, v in self.api_keys.__dict__.items() if v
            },
            'proxies': {
                'http': self.proxies.http_proxies or [],
                'socks': self.proxies.socks_proxies or [],
                'tor_enabled': self.proxies.tor_enabled,
                'tor_port': self.proxies.tor_port,
                'rotate_interval': self.proxies.rotate_interval,
            },
            'cache': {
                'enabled': self.cache.enabled,
                'backend': self.cache.backend,
                'sqlite_path': self.cache.sqlite_path,
                'redis_url': self.cache.redis_url,
                'ttl_default': self.cache.ttl_default,
                'max_size': self.cache.max_size,
                'eviction_policy': self.cache.eviction_policy,
            },
            'notifications': {
                'enabled': self.notifications.enabled,
                'discord_webhook': self.notifications.discord_webhook,
                'slack_webhook': self.notifications.slack_webhook,
                'telegram_token': self.notifications.telegram_token,
                'telegram_chat_id': self.notifications.telegram_chat_id,
            },
            'wordlists': self.wordlists,
            'templates_dir': str(self.templates_dir),
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info("config.saved", config_file=str(self.config_file))


# Global instance
config_manager = ConfigManager()

__all__ = ["ConfigManager", "config_manager", "APIKeys", "ProxyConfig", "CacheConfig", "NotificationConfig"]
