import asyncio
import aiohttp
import time
from typing import Dict, Any, Optional
from utils.structured_logger import structured_logger
from utils.metrics import metrics_collector

class ThrottledHttpClient:
    """
    A reusable, resilient asynchronous HTTP Client featuring:
    - Connection Pooling & Shared ClientSession
    - Token Bucket Rate Limiting per provider
    - Retry-After suspended backoff handling
    - Exponential Backoff Retries on Transient Failures
    - Graceful Exception and Timeout Handling
    """
    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._provider_locks: Dict[str, asyncio.Lock] = {}
        self._buckets: Dict[str, Dict[str, Any]] = {}
        self._retry_after_until: Dict[str, float] = {}

    def _get_lock(self, provider_name: str) -> asyncio.Lock:
        if provider_name not in self._provider_locks:
            self._provider_locks[provider_name] = asyncio.Lock()
        return self._provider_locks[provider_name]

    async def start(self) -> None:
        """Initializes connection pooling session."""
        if self._session is None or self._session.closed:
            self._connector = aiohttp.TCPConnector(
                ttl_dns_cache=300,
                limit=100,
                enable_cleanup_closed=True
            )
            # Default timeout for overall operations inside session
            self._session = aiohttp.ClientSession(connector=self._connector)
            structured_logger.info("Shared ThrottledHttpClient session started")

    async def close(self) -> None:
        """Gracefully closes persistent session and connector pools."""
        if self._session and not self._session.closed:
            await self._session.close()
        if self._connector:
            await self._connector.close()
        self._session = None
        self._connector = None
        structured_logger.info("Shared ThrottledHttpClient session closed")

    def _init_bucket(self, provider_name: str, rate_limit_delay: float) -> None:
        if provider_name not in self._buckets:
            # Capacity allows a small burst of 5 requests or 1 if delay is extremely long
            capacity = 5.0 if rate_limit_delay < 5.0 else 1.0
            self._buckets[provider_name] = {
                "tokens": capacity,
                "capacity": capacity,
                "refill_rate": (1.0 / rate_limit_delay) if rate_limit_delay > 0.0 else 1000.0,
                "last_refill": time.time()
            }

    async def _consume_token(self, provider_name: str, rate_limit_delay: float) -> None:
        if rate_limit_delay <= 0.0:
            return
            
        self._init_bucket(provider_name, rate_limit_delay)
        b = self._buckets[provider_name]
        
        # Enforce serialized lock per provider token consumption
        lock = self._get_lock(provider_name)
        async with lock:
            now = time.time()
            elapsed = now - b["last_refill"]
            b["last_refill"] = now
            # Refill tokens
            b["tokens"] = min(b["capacity"], b["tokens"] + elapsed * b["refill_rate"])
            
            if b["tokens"] < 1.0:
                # Calculate sleep duration to refill to 1 token
                wait_time = (1.0 - b["tokens"]) / b["refill_rate"]
                structured_logger.info("Rate limit token bucket delay triggered", provider_name, {"wait_time_sec": wait_time})
                await asyncio.sleep(wait_time)
                # Recalculate last refill
                b["last_refill"] = time.time()
                b["tokens"] = 0.0
            else:
                b["tokens"] -= 1.0

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
        # Ensure ClientSession is started
        if self._session is None or self._session.closed:
            await self.start()

        # Check if provider is temporarily suspended under Retry-After directive
        suspended_until = self._retry_after_until.get(provider_name, 0.0)
        if time.time() < suspended_until:
            wait_rem = suspended_until - time.time()
            structured_logger.warning("Query skipped - provider under Retry-After backoff", provider_name, {"wait_remaining_sec": wait_rem})
            return {"status": "RATE_LIMITED", "data": None, "error_message": f"Suspended due to Retry-After for {wait_rem:.1f}s"}

        # Consume token bucket token
        await self._consume_token(provider_name, rate_limit_delay)

        # Retry loop with exponential backoff
        delay = 0.5
        for attempt in range(retries + 1):
            structured_logger.info("HTTP query dispatched", provider_name, {"url": url, "attempt": attempt + 1})
            
            try:
                # Enforce total timeout for this connection/read attempt
                timeout = aiohttp.ClientTimeout(total=timeout_sec)
                async with self._session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    data=data,
                    timeout=timeout
                ) as response:
                    # Parse Retry-After if rate limited
                    if response.status == 429:
                        retry_after_hdr = response.headers.get("Retry-After")
                        if retry_after_hdr:
                            try:
                                # Retry-After can be seconds
                                backoff_sec = float(retry_after_hdr)
                                self._retry_after_until[provider_name] = time.time() + backoff_sec
                                structured_logger.warning("Enforced Retry-After backoff", provider_name, {"duration_sec": backoff_sec})
                            except ValueError:
                                # Retry-After can be an HTTP Date string
                                pass
                                
                        structured_logger.warning("Rate limited (429)", provider_name, {"attempt": attempt + 1})
                        if attempt < retries:
                            await asyncio.sleep(delay)
                            delay *= 2
                            continue
                        return {"status": "RATE_LIMITED", "data": None, "error_message": "Rate limit exceeded (429)"}
                        
                    elif response.status == 200:
                        try:
                            json_resp = await response.json()
                            return {"status": "SUCCESS", "data": json_resp, "error_message": None}
                        except Exception:
                            text_resp = await response.text()
                            return {"status": "SUCCESS", "data": {"raw_text": text_resp}, "error_message": None}
                            
                    elif response.status == 404:
                        return {"status": "NO_DATA", "data": None, "error_message": "Resource not found (404)"}
                        
                    elif response.status in [400, 401, 403]:
                        # Non-transient failure: do not retry
                        return {"status": "ERROR", "data": None, "error_message": f"Non-transient HTTP error: {response.status}"}
                        
                    elif response.status in [500, 502, 503, 504]:
                        structured_logger.warning(f"Server error ({response.status})", provider_name, {"attempt": attempt + 1})
                        if attempt < retries:
                            await asyncio.sleep(delay)
                            delay *= 2
                            continue
                        return {"status": "UNAVAILABLE", "data": None, "error_message": f"Provider server error ({response.status})"}
                        
                    else:
                        return {"status": "ERROR", "data": None, "error_message": f"HTTP status error: {response.status}"}
                        
            except asyncio.TimeoutError:
                structured_logger.warning("Request timed out", provider_name, {"attempt": attempt + 1})
                if attempt < retries:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return {"status": "UNAVAILABLE", "data": None, "error_message": "Request timed out"}
                
            except aiohttp.ClientConnectorError as e:
                structured_logger.warning(f"Connection failure: {e}", provider_name, {"attempt": attempt + 1})
                if attempt < retries:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return {"status": "UNAVAILABLE", "data": None, "error_message": f"Connection error: {e}"}
                
            except Exception as e:
                structured_logger.error(f"Unexpected query error: {e}", provider_name)
                return {"status": "ERROR", "data": None, "error_message": str(e)}
                
        return {"status": "ERROR", "data": None, "error_message": "Max retry attempts reached"}

# Global singleton client instance
http_client = ThrottledHttpClient()
