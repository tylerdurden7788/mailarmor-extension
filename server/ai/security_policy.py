from typing import List, Dict, Any
import config.ai_security_config as config

class SecurityPolicy:
    def get_allowed_capabilities(self) -> List[str]:
        return config.ALLOWED_CAPABILITIES

    def get_blocked_prompt_patterns(self) -> List[str]:
        return config.BLOCKED_PROMPT_PATTERNS

    def get_blocked_response_patterns(self) -> List[str]:
        return config.BLOCKED_RESPONSE_PATTERNS

    def get_max_prompt_size(self) -> int:
        return config.MAX_PROMPT_SIZE

    def should_block_severity(self, severity: str) -> bool:
        """Only HIGH and CRITICAL violations should block AI execution."""
        return severity.upper() in ["HIGH", "CRITICAL"]

# Global security policy instance
security_policy = SecurityPolicy()
