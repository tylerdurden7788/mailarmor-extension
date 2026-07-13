import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from models.evidence_model import Evidence
from config.rule_registry import RULE_REGISTRY
from config.risk_config import RISK_WEIGHTS

def create_evidence(analyzer_name: str, rule_id: str, technical_details: Dict[str, Any] = None, confidence: float = 1.0) -> Evidence:
    """
    Decoupled factory to create an Evidence instance using configuration definitions from RULE_REGISTRY.
    """
    rule = RULE_REGISTRY.get(rule_id, {
        "category": "GENERAL",
        "severity": "INFO",
        "explanation": "No description available.",
        "recommendation": "Review with baseline precaution."
    })
    
    severity = rule.get("severity", "INFO")
    risk_contribution = RISK_WEIGHTS.get(severity, 0.0) * confidence
    
    evidence_id = f"EV-{analyzer_name.upper()}-{uuid.uuid4().hex[:8]}"
    
    return Evidence(
        evidence_id=evidence_id,
        analyzer_name=analyzer_name,
        category=rule.get("category", "GENERAL"),
        severity=severity,
        confidence=confidence,
        risk_contribution=risk_contribution,
        triggered_rule=rule_id,
        technical_details=technical_details or {},
        explanation=rule.get("explanation", ""),
        recommendation=rule.get("recommendation", ""),
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
