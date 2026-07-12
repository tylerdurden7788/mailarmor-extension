import time
import threading
import collections
from typing import Any, Optional, Tuple
import config.ai_operations_config as config

class AICache:
    def __init__(self):
        self._cache = collections.OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieves cached entry. Updates LRU order and checks TTL.
        """
        with self._lock:
            if key not in self._cache:
                self.misses += 1
                return None
            
            value, timestamp = self._cache[key]
            
            # Check TTL
            if time.time() - timestamp > config.CACHE_TTL_SEC:
                # Expired
                del self._cache[key]
                self.misses += 1
                return None
                
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        """
        Inserts or updates entry. Evicts LRU if capacity is exceeded.
        """
        with self._lock:
            # Overwrite if exists, and move to end
            if key in self._cache:
                del self._cache[key]
                
            self._cache[key] = (value, time.time())
            
            # Evict if max size is exceeded
            if len(self._cache) > config.CACHE_MAX_SIZE:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self.hits = 0
            self.misses = 0

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

# Global thread-safe cache instance
ai_cache = AICache()
