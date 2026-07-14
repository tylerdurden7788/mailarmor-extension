import hashlib
import asyncio
from typing import Dict, Any, Optional, Tuple

class RequestDeduplicator:
    def __init__(self):
        self._in_flight: Dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()

    def generate_cache_key(self, capability: str, version: str, context: str) -> str:
        """
        Generates unique SHA-256 identifier for prompt context.
        """
        hasher = hashlib.sha256()
        hasher.update(capability.encode('utf-8'))
        hasher.update(version.encode('utf-8'))
        hasher.update(context.encode('utf-8'))
        return hasher.hexdigest()

    async def get_or_create_future(self, key: str) -> Tuple[bool, Optional[asyncio.Future]]:
        """
        Checks if an identical request is already in-flight.
        Returns: (is_creator, future)
        """
        async with self._lock:
            if key in self._in_flight:
                return False, self._in_flight[key]
            
            # Create a new future for this in-flight key
            loop = asyncio.get_event_loop()
            fut = loop.create_future()
            self._in_flight[key] = fut
            return True, fut

    async def complete_future(self, key: str, result: Any) -> None:
        """
        Resolves in-flight duplicate requests with result.
        """
        async with self._lock:
            if key in self._in_flight:
                fut = self._in_flight.pop(key)
                if not fut.done():
                    fut.set_result(result)

# Global request deduplicator instance
request_deduplicator = RequestDeduplicator()
