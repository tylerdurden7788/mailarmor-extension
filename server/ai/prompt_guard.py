import re
from typing import Tuple, List
from ai.security_policy import security_policy

class PromptGuard:
    def validate_prompt(self, prompt: str) -> Tuple[bool, List[str], str, float, str]:
        """
        Validates outgoing prompts.
        Returns: (passed, violations, severity, risk_score, risk_class)
        """
        violations = []
        severity = "INFO"
        risk_score = 0.0
        risk_class = "SAFE"

        # Check for blocked prompt override/injection patterns
        blocked_patterns = security_policy.get_blocked_prompt_patterns()
        
        high_risk_matches = 0
        warning_matches = 0
        
        for pattern in blocked_patterns:
            if re.search(pattern, prompt):
                # Classify severity of violation
                if "ignore" in pattern or "override" in pattern or "system" in pattern:
                    violations.append(f"Detected override injection pattern: '{pattern}'")
                    high_risk_matches += 1
                else:
                    violations.append(f"Detected suspicious pattern: '{pattern}'")
                    warning_matches += 1

        # Calculate bounded risk score and class
        if high_risk_matches > 0:
            severity = "HIGH"
            risk_score = min(0.5 + 0.25 * high_risk_matches, 1.0)
            risk_class = "BLOCKED" if risk_score >= 0.9 else "HIGH_RISK"
        elif warning_matches > 0:
            severity = "WARNING"
            risk_score = min(0.1 + 0.2 * warning_matches, 0.49)
            risk_class = "WARNING"
        else:
            severity = "INFO"
            risk_score = 0.0
            risk_class = "SAFE"

        # passed is False only for HIGH and CRITICAL severities
        passed = not security_policy.should_block_severity(severity)

        return passed, violations, severity, risk_score, risk_class

# Global prompt guard instance
prompt_guard = PromptGuard()
