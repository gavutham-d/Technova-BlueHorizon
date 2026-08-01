import time
from typing import Dict, Any, Optional

class CacheManager:
    """
    Thread-safe-ish simple in-memory TTL caching manager.
    """
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            return None
        
        entry = self._cache[key]
        if time.time() > entry["expires_at"]:
            del self._cache[key]
            return None
            
        return entry["value"]

    def set(self, key: str, value: Any, ttl_seconds: int = 10) -> None:
        self._cache[key] = {
            "value": value,
            "expires_at": time.time() + ttl_seconds
        }

    def invalidate(self, key: str) -> None:
        if key in self._cache:
            del self._cache[key]

    def invalidate_all(self) -> None:
        self._cache.clear()

cache_store = CacheManager()
