import asyncio
import aiohttp
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("ThrottledHttpClient")

class ThrottledHttpClient:
    """
    A reusable, resilient asynchronous HTTP Client featuring:
    - Token Bucket Rate Limiting per provider
    - Exponential Backoff Retries
    - Graceful Exception and Timeout Handling
    """
    def __init__(self):
        # Maps provider_name to a Lock to serialize queries if rate limited
        self._provider_locks: Dict[str, asyncio.Lock] = {}
        # Maps provider_name to last request timestamp
        self._last_request_time: Dict[str, float] = {}

    def _get_lock(self, provider_name: str) -> asyncio.Lock:
        if provider_name not in self._provider_locks:
            self._provider_locks[provider_name] = asyncio.Lock()
        return self._provider_locks[provider_name]

    async def request(
        self,
        method: str,
        url: str,
        provider_name: str,
        rate_limit_delay: float = 0.0,  # Min delay between queries in seconds
        timeout_sec: float = 2.0,
        retries: int = 1,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Executes HTTP requests with rate limiting, timeouts, and exponential backoff retries.
        Returns a dict: { "status": str, "data": Any, "error_message": Optional[str] }
        """
        lock = self._get_lock(provider_name)
        
        # Enforce rate limit (one request at a time per provider if configured)
        async with lock:
            if rate_limit_delay > 0.0:
                last_time = self._last_request_time.get(provider_name, 0.0)
                elapsed = time.time() - last_time
                if elapsed < rate_limit_delay:
                    await asyncio.sleep(rate_limit_delay - elapsed)
            self._last_request_time[provider_name] = time.time()

        # Retry loop with exponential backoff
        delay = 0.5
        for attempt in range(retries + 1):
            try:
                # Disable ssl verification if needed, but defaults to True. Let's make it robust
                timeout = aiohttp.ClientTimeout(total=timeout_sec)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        params=params,
                        json=json_data,
                        data=data
                    ) as response:
                        if response.status == 200:
                            try:
                                json_resp = await response.json()
                                return {"status": "SUCCESS", "data": json_resp, "error_message": None}
                            except Exception:
                                text_resp = await response.text()
                                return {"status": "SUCCESS", "data": {"raw_text": text_resp}, "error_message": None}
                        elif response.status == 404:
                            return {"status": "NO_DATA", "data": None, "error_message": "Resource not found (404)"}
                        elif response.status == 429:
                            logger.warning(f"Rate limited by {provider_name} (429)")
                            if attempt < retries:
                                await asyncio.sleep(delay)
                                delay *= 2
                                continue
                            return {"status": "RATE_LIMITED", "data": None, "error_message": "Rate limit exceeded (429)"}
                        elif response.status in [500, 502, 503, 504]:
                            if attempt < retries:
                                await asyncio.sleep(delay)
                                delay *= 2
                                continue
                            return {"status": "UNAVAILABLE", "data": None, "error_message": f"Provider server error ({response.status})"}
                        else:
                            return {"status": "ERROR", "data": None, "error_message": f"HTTP status error: {response.status}"}
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout for {provider_name} on attempt {attempt + 1}")
                if attempt < retries:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return {"status": "UNAVAILABLE", "data": None, "error_message": "Request timed out"}
            except aiohttp.ClientConnectorError as e:
                logger.warning(f"Connection failure for {provider_name} on attempt {attempt + 1}: {e}")
                if attempt < retries:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return {"status": "UNAVAILABLE", "data": None, "error_message": f"Connection error: {e}"}
            except Exception as e:
                logger.warning(f"Unexpected request error for {provider_name}: {e}")
                return {"status": "ERROR", "data": None, "error_message": str(e)}
                
        return {"status": "ERROR", "data": None, "error_message": "Max retry attempts reached"}

# Global singleton client instance
http_client = ThrottledHttpClient()
