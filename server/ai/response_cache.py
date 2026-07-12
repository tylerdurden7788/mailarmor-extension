import logging
from typing import Optional
from models.ai_model import AIResponse
from ai.ai_cache import ai_cache
from ai.cache_policy import cache_policy

logger = logging.getLogger("ResponseCache")

class ResponseCache:
    def get_response(self, key: str) -> Optional[AIResponse]:
        """
        Retrieves cached response from global cache store.
        """
        cached = ai_cache.get(key)
        if cached and isinstance(cached, AIResponse):
            return cached
        return None

    def store_response(self, key: str, response: AIResponse, capability: str) -> None:
        """
        Stores response in cache only if it is fully validated, successful, and not a local fallback.
        """
        # Ensure cache eligibility
        if not cache_policy.is_cacheable(capability):
            return

        # Cache ONLY successful, non-fallback, validated responses
        if not response or not response.success:
            logger.debug(f"Skipping cache store: request failed or unsuccessful.")
            return
            
        if response.model == "fallback-local-rules":
            logger.debug(f"Skipping cache store: fallback local rules model response.")
            return
            
        if response.validation_status != "VALIDATED":
            logger.debug(f"Skipping cache store: invalid validation status '{response.validation_status}'.")
            return

        # Store in LRU cache
        ai_cache.set(key, response)
        logger.debug(f"Successfully cached validated AI response for key '{key}'.")

# Global response cache instance
response_cache = ResponseCache()
