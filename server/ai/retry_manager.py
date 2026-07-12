import asyncio
import logging

logger = logging.getLogger("RetryManager")

class RetryManager:
    def is_retry_eligible(self, error: Exception) -> bool:
        """
        Determines if an error is a transient failure and is eligible for a retry.
        Transients: Timeouts, connection failures, rate limits, server errors.
        Non-Transients: Schema mismatches, auth errors, client invalid request.
        """
        err_msg = str(error).lower()
        err_name = type(error).__name__

        # 1. Standard library transient errors
        if isinstance(error, (asyncio.TimeoutError, TimeoutError, ConnectionError, OSError)):
            return True

        # 2. Dynamic check for anthropic client library error types
        if "anthropic" in err_name.lower() or "anthropic" in type(error).__module__:
            # Check for RateLimitError, APITimeoutError, APIConnectionError, InternalServerError
            if "rate" in err_name.lower() or "timeout" in err_name.lower() or "connection" in err_name.lower() or "server" in err_name.lower():
                return True
            # Auth errors (401/403) or BadRequestError (400) are non-transient
            if "authentication" in err_name.lower() or "badrequest" in err_name.lower() or "invalid" in err_name.lower():
                return False

        # 3. HTTP status matching from error message strings
        if "429" in err_msg or "500" in err_msg or "502" in err_msg or "503" in err_msg or "504" in err_msg:
            return True
            
        if "timeout" in err_msg or "timed out" in err_msg or "connection" in err_msg:
            return True
            
        if "400" in err_msg or "401" in err_msg or "403" in err_msg:
            return False

        # If we are unsure, default to not retrying (fail-safe)
        return False

    async def wait_before_retry(self, attempt: int, base_delay_sec: float) -> None:
        """Applies exponential backoff sleep delay."""
        delay = base_delay_sec * (2.0 ** attempt)
        logger.info(f"Retrying AI API request. Backoff delay: {delay}s (Attempt: {attempt + 1})")
        await asyncio.sleep(delay)

# Global retry manager instance
retry_manager = RetryManager()
