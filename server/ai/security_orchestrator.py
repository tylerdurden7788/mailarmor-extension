from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from models.ai_security_model import AISecurityResult, AuditTrailStage, RedactionStats
from ai.prompt_sanitizer import prompt_sanitizer
from ai.pii_redactor import pii_redactor
from ai.secret_redactor import secret_redactor
from ai.prompt_guard import prompt_guard
from ai.jailbreak_detector import jailbreak_detector
from ai.capability_guard import capability_guard
from ai.integrity_checker import integrity_checker
from ai.response_guard import response_guard
from ai.ai_security_logger import ai_security_logger
import config.ai_security_config as config

class SecurityOrchestrator:
    def _create_stage(self, name: str, result: str, severity: str, violations: List[str] = None) -> AuditTrailStage:
        return AuditTrailStage(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            stage_name=name,
            result=result,
            severity=severity,
            violations=violations or []
        )

    def secure_request(
        self,
        request_id: str,
        capability: str,
        system_prompt: str,
        formatted_prompt: str
    ) -> Tuple[AISecurityResult, str, str]:
        """
        Coordinates outbound request defenses:
        INITIAL -> SANITIZED -> REDACTED -> GUARDED -> VALIDATED
        """
        audit_trail: List[AuditTrailStage] = []
        violations: List[str] = []
        warnings: List[str] = []
        redacted_lookup: Dict[str, str] = {}
        
        # 1. State: INITIAL
        state = "INITIAL"
        prompt_hash = integrity_checker.compute_hash(system_prompt + formatted_prompt)
        audit_trail.append(self._create_stage(state, "PASS", "INFO"))
        ai_security_logger.log_security_event("REQUEST_INITIALIZED", request_id, "INFO", {"prompt_hash": prompt_hash, "capability": capability})

        # 2. State: SANITIZED
        state = "SANITIZED"
        orig_size = len(system_prompt + formatted_prompt)
        sanitized_system = prompt_sanitizer.sanitize(system_prompt)
        sanitized_prompt = prompt_sanitizer.sanitize(formatted_prompt)
        san_size = len(sanitized_system + sanitized_prompt)
        
        audit_trail.append(self._create_stage(state, "PASS", "INFO"))

        # 3. State: REDACTED
        state = "REDACTED"
        # PII Redaction
        red_prompt, pii_lookup, pii_count = pii_redactor.redact(sanitized_prompt)
        redacted_lookup.update(pii_lookup)
        
        # Secret Redaction
        red_prompt, secret_count = secret_redactor.redact(red_prompt)
        red_system, secret_system_count = secret_redactor.redact(sanitized_system)
        
        tot_secrets = secret_count + secret_system_count
        
        # Calculate size metrics
        final_size = len(red_system + red_prompt)
        pct_reduction = ((orig_size - final_size) / orig_size * 100.0) if orig_size > 0 else 0.0
        stats = RedactionStats(
            pii_redacted_count=pii_count,
            secrets_removed_count=tot_secrets,
            original_size=orig_size,
            sanitized_size=final_size,
            reduction_percentage=pct_reduction
        )
        audit_trail.append(self._create_stage(state, "REDACTED", "INFO"))
        
        # 4. State: GUARDED
        state = "GUARDED"
        guard_passed, guard_viols, guard_sev, risk_score, risk_class = prompt_guard.validate_prompt(red_prompt)
        
        # Run jailbreak check
        jb_detected, jb_viols, jb_sev = jailbreak_detector.detect_jailbreak(red_prompt)
        
        # Aggregate violations & severity
        if guard_viols:
            violations.extend(guard_viols)
        if jb_viols:
            violations.extend(jb_viols)
            guard_sev = "HIGH"

        stage_res = "PASS" if guard_passed and not jb_detected else "FAIL"
        audit_trail.append(self._create_stage(state, stage_res, guard_sev, violations))

        # 5. State: VALIDATED
        state = "VALIDATED"
        cap_passed, cap_viols, cap_sev = capability_guard.validate_capability(capability)
        if cap_viols:
            violations.extend(cap_viols)
            guard_sev = "CRITICAL"
            
        stage_res = "PASS" if cap_passed else "FAIL"
        audit_trail.append(self._create_stage(state, stage_res, cap_sev, cap_viols))

        # Overall severity summary
        overall_passed = guard_passed and not jb_detected and cap_passed
        
        result = AISecurityResult(
            passed=overall_passed,
            violations=violations,
            warnings=warnings,
            sanitized_prompt=red_prompt,
            redacted_fields=redacted_lookup,
            response_validation="UNVALIDATED",
            security_version=config.SECURITY_POLICY_VERSION,
            severity=guard_sev,
            audit_trail=audit_trail,
            prompt_risk_score=risk_score,
            prompt_risk_class=risk_class,
            redaction_stats=stats
        )

        if not overall_passed:
            ai_security_logger.log_security_event("REQUEST_BLOCKED", request_id, guard_sev, {"violations": violations})
            
        return result, red_system, red_prompt

    def secure_response(
        self,
        request_id: str,
        security_result: AISecurityResult,
        completion: str
    ) -> AISecurityResult:
        """
        Coordinates inbound response defenses:
        EXECUTED -> RESPONSE_VERIFIED -> COMPLETE
        """
        audit_trail = list(security_result.audit_trail)
        violations = list(security_result.violations)
        
        # 6. State: EXECUTED
        state = "EXECUTED"
        resp_hash = integrity_checker.compute_hash(completion)
        audit_trail.append(self._create_stage(state, "PASS", "INFO"))

        # 7. State: RESPONSE_VERIFIED
        state = "RESPONSE_VERIFIED"
        resp_passed, resp_viols, resp_sev = response_guard.validate_response(completion)
        if resp_viols:
            violations.extend(resp_viols)
            
        stage_res = "PASS" if resp_passed else "FAIL"
        audit_trail.append(self._create_stage(state, stage_res, resp_sev, resp_viols))

        # 8. State: COMPLETE
        state = "COMPLETE"
        overall_passed = security_result.passed and resp_passed
        
        audit_trail.append(self._create_stage(state, "PASS" if overall_passed else "FAIL", resp_sev))
        
        final_result = AISecurityResult(
            passed=overall_passed,
            violations=violations,
            warnings=security_result.warnings,
            sanitized_prompt=security_result.sanitized_prompt,
            redacted_fields=security_result.redacted_fields,
            response_validation="VALIDATED" if overall_passed else "REJECTED",
            security_version=security_result.security_version,
            severity=resp_sev if resp_sev != "INFO" else security_result.severity,
            audit_trail=audit_trail,
            prompt_risk_score=security_result.prompt_risk_score,
            prompt_risk_class=security_result.prompt_risk_class,
            redaction_stats=security_result.redaction_stats
        )

        if not overall_passed:
            ai_security_logger.log_security_event("RESPONSE_REJECTED", request_id, final_result.severity, {"violations": violations})

        return final_result

# Global security orchestrator instance
security_orchestrator = SecurityOrchestrator()
