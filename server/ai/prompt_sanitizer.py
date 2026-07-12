import logging
import re
from ai.security_policy import security_policy

logger = logging.getLogger("PromptSanitizer")

class PromptSanitizer:
    def sanitize(self, prompt: str) -> str:
        """
        Normalizes whitespace and trims/truncates prompt to respect maximum prompt size limits.
        """
        # 1. Normalize whitespace (tabs, newlines, duplicate spaces)
        cleaned = re.sub(r'[ \t]+', ' ', prompt)
        
        # 2. Enforce prompt size limits
        max_size = security_policy.get_max_prompt_size()
        if len(cleaned) > max_size:
            logger.warning(f"Prompt size {len(cleaned)} exceeds limit {max_size}. Truncating.")
            cleaned = cleaned[:max_size]
            
        return cleaned

# Global prompt sanitizer instance
prompt_sanitizer = PromptSanitizer()
