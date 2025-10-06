"""Cache DNS com suporte a TTL, persistência e métricas."""
import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

from moriarty.core.cache_backend import (
    BaseCacheBackend,
    CacheRecord,
    MemoryCacheBackend,
    SQLiteCacheBackend,
)

logger = structlog.get_logger(__name__)


class DNSCache:
    """Cache DNS thread-safe com TTL."""
    
    def __init__(self):
        self._lock = asyncio.Lock()
        self.config_manager = self._load_config_manager()
        self.cache_config = getattr(self.config_manager, "cache", None) if self.config_manager else None
        self.backend: BaseCacheBackend = self._initialize_backend()
        self.metrics: Dict[str, Any] = {
            "hits": 0,
            "misses": 0,
            "backend": self.backend.name,
            "warmed": 0,
        }

        if self.cache_config and getattr(self.cache_config, "warmup_enabled", False):
            self._warm_cache()
    
    async def get(self, domain: str, record_type: str) -> Optional[List[Any]]:
        """Busca no cache."""
        key = (domain.lower(), record_type.upper())
        
        async with self._lock:
            record = self.backend.get(key)
            if record is None:
                logger.debug("dns.cache.miss", domain=domain, type=record_type)
                self.metrics["misses"] += 1
                return None

            ttl_remaining = int(record.expires_at - time.time())
            if ttl_remaining <= 0:
                logger.debug("dns.cache.expired", domain=domain, type=record_type)
                self.backend.delete(key)
                self.metrics["misses"] += 1
                return None

            logger.debug(
                "dns.cache.hit",
                domain=domain,
                type=record_type,
                ttl_remaining=ttl_remaining,
            )
            self.metrics["hits"] += 1
            return record.value
    
    async def set(self, domain: str, record_type: str, value: List[Any], ttl: int = 300):
        """Armazena no cache."""
        key = (domain.lower(), record_type.upper())
        
        async with self._lock:
            self.backend.set(key, value, ttl)
            logger.debug("dns.cache.set", domain=domain, type=record_type, ttl=ttl)
    
    async def clear(self):
        """Limpa o cache."""
        async with self._lock:
            self.backend.clear()
            logger.info("dns.cache.cleared")
    
    async def purge_expired(self):
        """Remove entradas expiradas."""
        async with self._lock:
            self.backend.purge_expired()
            logger.info("dns.cache.purged")
    
    def stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do cache."""
        base_stats = dict(self.metrics)
        base_stats.update(self.backend.stats())
        return base_stats

    def _load_config_manager(self):
        try:
            from moriarty.core.config_manager import config_manager

            return config_manager
        except Exception:
            return None

    def _initialize_backend(self) -> BaseCacheBackend:
        backend_name = "memory"
        max_size = 10000
        eviction_policy = "lru"
        sqlite_path = None

        if self.cache_config:
            backend_name = getattr(self.cache_config, "backend", "memory").lower()
            max_size = getattr(self.cache_config, "max_size", 10000) or 10000
            eviction_policy = getattr(self.cache_config, "eviction_policy", "lru")
            sqlite_path = getattr(self.cache_config, "sqlite_path", None)

        if backend_name == "sqlite":
            db_path = Path(sqlite_path) if sqlite_path else self._default_sqlite_path()
            db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug("dns.cache.backend", backend="sqlite", path=str(db_path))
            return SQLiteCacheBackend(db_path, max_size)

        logger.debug("dns.cache.backend", backend="memory", policy=eviction_policy)
        return MemoryCacheBackend(max_size=max_size, eviction_policy=eviction_policy)

    def _default_sqlite_path(self) -> Path:
        if self.config_manager:
            return self.config_manager.config_dir / "cache" / "dns_cache.db"
        return Path.home() / ".moriarty" / "cache" / "dns_cache.db"

    def _warm_cache(self) -> None:
        if not self.config_manager:
            return

        warmup_dir = self.config_manager.config_dir / "warmup"
        warmup_file = warmup_dir / "dns.json"

        if not warmup_file.exists():
            return

        try:
            with open(warmup_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)

            records = []
            for item in payload.get("records", []):
                domain = item.get("domain")
                record_type = item.get("type", "A")
                values = item.get("values", [])
                ttl = int(item.get("ttl", 300))
                if not domain or not values:
                    continue
                expires_at = time.time() + ttl
                record = CacheRecord(
                    key=(domain.lower(), record_type.upper()),
                    value=values,
                    ttl=ttl,
                    expires_at=expires_at,
                    last_access=time.time(),
                )
                records.append(record)

            if records:
                self.backend.warm(records)
                self.metrics["warmed"] = len(records)
                logger.info("dns.cache.warmed", records=len(records))

        except Exception as exc:  # pragma: no cover - leitura auxiliar
            logger.warning("dns.cache.warm_failed", error=str(exc))


# Singleton global
_global_cache: Optional[DNSCache] = None


def get_global_cache() -> DNSCache:
    """Retorna cache global."""
    global _global_cache
    if _global_cache is None:
        _global_cache = DNSCache()
    return _global_cache
