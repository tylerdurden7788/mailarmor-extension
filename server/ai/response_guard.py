import re
from typing import Tuple, List
from ai.security_policy import security_policy

class ResponseGuard:
    def validate_response(self, text: str) -> Tuple[bool, List[str], str]:
        """
        Inspects incoming completion outputs.
        Returns: (passed, violations, severity)
        """
        violations = []
        severity = "INFO"

        blocked_patterns = security_policy.get_blocked_response_patterns()
        for pattern in blocked_patterns:
            if re.search(pattern, text):
                violations.append(f"Adversarial data leakage check failed. Pattern: '{pattern}'")
                severity = "CRITICAL"

        passed = not security_policy.should_block_severity(severity)
        return passed, violations, severity

# Global response guard instance
response_guard = ResponseGuard()
