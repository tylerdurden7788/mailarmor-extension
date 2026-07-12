from typing import Tuple, List
from ai.security_policy import security_policy

class CapabilityGuard:
    def validate_capability(self, capability: str) -> Tuple[bool, List[str], str]:
        """
        Validates if the requested capability is allowed by the security policy.
        """
        violations = []
        severity = "INFO"
        
        allowed = security_policy.get_allowed_capabilities()
        if capability not in allowed:
            violations.append(f"Unauthorized AI capability invocation attempt: '{capability}'")
            severity = "CRITICAL"

        passed = not security_policy.should_block_severity(severity)
        return passed, violations, severity

# Global capability guard instance
capability_guard = CapabilityGuard()
