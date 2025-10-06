"""Cache backends with LRU eviction and persistence support."""
from __future__ import annotations

import pickle
import sqlite3
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CacheRecord:
    """Representa um registro em cache."""

    key: Tuple[str, str]
    value: Any
    expires_at: float
    ttl: int
    last_access: float


class BaseCacheBackend:
    """Interface base para backends de cache."""

    name: str = "base"

    def __init__(self):
        self.metrics = {
            "evictions": 0,
            "writes": 0,
            "reads": 0,
        }

    def get(self, key: Tuple[str, str]) -> Optional[CacheRecord]:  # pragma: no cover - interface
        raise NotImplementedError

    def set(self, key: Tuple[str, str], value: Any, ttl: int) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def delete(self, key: Tuple[str, str]) -> None:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError

    def purge_expired(self) -> None:
        raise NotImplementedError

    def warm(self, records: Iterable[CacheRecord]) -> None:
        for record in records:
            now = time.time()
            remaining_ttl = int(record.expires_at - now)
            if remaining_ttl > 0:
                self.set(record.key, record.value, remaining_ttl)

    def stats(self) -> Dict[str, Any]:
        return {"backend": self.name, **self.metrics}


class MemoryCacheBackend(BaseCacheBackend):
    """Cache em memória com política LRU."""

    name = "memory"

    def __init__(self, max_size: int, eviction_policy: str = "lru"):
        super().__init__()
        self.max_size = max_size
        self.eviction_policy = eviction_policy.lower()
        self._store: OrderedDict[Tuple[str, str], CacheRecord] = OrderedDict()

    def get(self, key: Tuple[str, str]) -> Optional[CacheRecord]:
        record = self._store.get(key)
        if not record:
            return None

        if record.expires_at <= time.time():
            self._store.pop(key, None)
            return None

        if self.eviction_policy == "lru":
            self._store.move_to_end(key)

        record.last_access = time.time()
        self.metrics["reads"] += 1
        return record

    def set(self, key: Tuple[str, str], value: Any, ttl: int) -> None:
        expires_at = time.time() + ttl
        record = CacheRecord(key=key, value=value, expires_at=expires_at, ttl=ttl, last_access=time.time())
        self._store[key] = record
        if self.eviction_policy == "lru":
            self._store.move_to_end(key)
        self.metrics["writes"] += 1
        self._evict_if_needed()

    def delete(self, key: Tuple[str, str]) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def purge_expired(self) -> None:
        now = time.time()
        expired_keys = [key for key, record in self._store.items() if record.expires_at <= now]
        for key in expired_keys:
            self._store.pop(key, None)

    def _evict_if_needed(self) -> None:
        while len(self._store) > self.max_size > 0:
            key, _ = self._store.popitem(last=False)
            self.metrics["evictions"] += 1


class SQLiteCacheBackend(BaseCacheBackend):
    """Cache persistente em SQLite com política LRU."""

    name = "sqlite"

    def __init__(self, db_path: Path, max_size: int):
        super().__init__()
        self.db_path = db_path
        self.max_size = max_size
        self._connection = sqlite3.connect(str(db_path), check_same_thread=False)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                cache_key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                expires_at REAL NOT NULL,
                last_access REAL NOT NULL,
                ttl INTEGER NOT NULL
            )
            """
        )
        self._connection.commit()

    def get(self, key: Tuple[str, str]) -> Optional[CacheRecord]:
        cursor = self._connection.execute(
            "SELECT value, expires_at, last_access, ttl FROM cache WHERE cache_key = ?",
            (self._serialize_key(key),),
        )
        row = cursor.fetchone()
        if not row:
            return None

        value_blob, expires_at, _, ttl = row
        if expires_at <= time.time():
            self.delete(key)
            return None

        value = pickle.loads(value_blob)
        record = CacheRecord(
            key=key,
            value=value,
            expires_at=expires_at,
            ttl=ttl,
            last_access=time.time(),
        )
        self._connection.execute(
            "UPDATE cache SET last_access = ? WHERE cache_key = ?",
            (record.last_access, self._serialize_key(key)),
        )
        self._connection.commit()
        self.metrics["reads"] += 1
        return record

    def set(self, key: Tuple[str, str], value: Any, ttl: int) -> None:
        expires_at = time.time() + ttl
        blob = pickle.dumps(value)
        last_access = time.time()
        self._connection.execute(
            "REPLACE INTO cache (cache_key, value, expires_at, last_access, ttl) VALUES (?, ?, ?, ?, ?)",
            (self._serialize_key(key), blob, expires_at, last_access, ttl),
        )
        self._connection.commit()
        self.metrics["writes"] += 1
        self._evict_if_needed()

    def delete(self, key: Tuple[str, str]) -> None:
        self._connection.execute(
            "DELETE FROM cache WHERE cache_key = ?",
            (self._serialize_key(key),),
        )
        self._connection.commit()

    def clear(self) -> None:
        self._connection.execute("DELETE FROM cache")
        self._connection.commit()

    def purge_expired(self) -> None:
        now = time.time()
        self._connection.execute("DELETE FROM cache WHERE expires_at <= ?", (now,))
        self._connection.commit()

    def warm(self, records: Iterable[CacheRecord]) -> None:
        for record in records:
            remaining_ttl = int(record.expires_at - time.time())
            if remaining_ttl > 0:
                self.set(record.key, record.value, remaining_ttl)

    def _serialize_key(self, key: Tuple[str, str]) -> str:
        return "|".join(key)

    def _evict_if_needed(self) -> None:
        if self.max_size <= 0:
            return
        cursor = self._connection.execute("SELECT COUNT(*) FROM cache")
        count = cursor.fetchone()[0]
        if count <= self.max_size:
            return
        overflow = count - self.max_size
        self._connection.execute(
            "DELETE FROM cache WHERE cache_key IN (SELECT cache_key FROM cache ORDER BY last_access ASC LIMIT ?)",
            (overflow,),
        )
        self._connection.commit()
        self.metrics["evictions"] += overflow
