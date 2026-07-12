from typing import Dict, Any
import config.ai_operations_config as config

class CachePolicy:
    def is_cacheable(self, capability: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Determines cache eligibility. Checks allowed list and any specific metadata flags.
        """
        # Exclude temporary or non-cacheable capabilities
        allowed_capabilities = ["email_threat_analysis", "email_threat_explainability"]
        if capability not in allowed_capabilities:
            return False
            
        if metadata and metadata.get("bypass_cache", False):
            return False
            
        return True

# Global cache policy instance
cache_policy = CachePolicy()
