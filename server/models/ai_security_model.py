from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional

class AuditTrailStage(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(description="ISO timestamp of audit stage entry")
    stage_name: str = Field(description="Name of the security stage (e.g., SANITIZED, GUARDED)")
    result: str = Field(description="Status result (e.g. PASS, FAIL, REDACTED)")
    severity: str = Field(description="Severity categorization: INFO, WARNING, HIGH, CRITICAL")
    violations: List[str] = Field(default_factory=list, description="Descriptive list of violations")

class RedactionStats(BaseModel):
    model_config = ConfigDict(frozen=True)

    pii_redacted_count: int = Field(default=0)
    secrets_removed_count: int = Field(default=0)
    original_size: int = Field(default=0)
    sanitized_size: int = Field(default=0)
    reduction_percentage: float = Field(default=0.0)

class AISecurityRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(description="Incident correlation ID")
    prompt_hash: str = Field(description="SHA-256 hash of the prompt template")
    capability: str = Field(description="Requested capability name")
    context_hash: str = Field(description="SHA-256 hash of the context payload")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary")

class AISecurityResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    passed: bool = Field(description="Boolean flag denoting if checks passed")
    violations: List[str] = Field(default_factory=list, description="Descriptive list of violations")
    warnings: List[str] = Field(default_factory=list, description="Descriptive list of warnings")
    sanitized_prompt: str = Field(description="Cleaned and sanitized prompt")
    redacted_fields: Dict[str, str] = Field(default_factory=dict, description="Placeholder mappings for restored references")
    response_validation: str = Field(default="UNVALIDATED", description="Status validation check on completion")
    security_version: str = Field(description="Version string of security module")
    
    # Refined attributes
    severity: str = Field(default="INFO", description="INFO, WARNING, HIGH, CRITICAL")
    audit_trail: List[AuditTrailStage] = Field(default_factory=list, description="Immutable security stages audit trail")
    prompt_risk_score: float = Field(default=0.0, description="Risk evaluation score from 0.0 to 1.0")
    prompt_risk_class: str = Field(default="SAFE", description="SAFE, WARNING, HIGH_RISK, BLOCKED")
    redaction_stats: RedactionStats = Field(default_factory=RedactionStats, description="Operational size metrics")
