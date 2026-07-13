from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from .evidence_model import EvidenceReport

class CheckResult(BaseModel):
    passed: bool = Field(description="Whether this security check category passed")
    detail: str = Field(description="Explanation details of this security check")

class EmailAnalysisResponse(BaseModel):
    # API metadata
    api_version: str = Field(default="2.0", description="API protocol version")
    pipeline_version: str = Field(default="10A", description="Production integration pipeline version")
    response_schema: str = Field(default="2.0", description="Response schema version")

    # Unified audit data
    report: EvidenceReport = Field(description="The complete structured audit Evidence Report")
    verdict: str = Field(description="Verdict (SAFE, SUSPICIOUS, DANGEROUS)")
    risk_level: str = Field(default="Low", description="Risk level (Low, Medium, High)")
    confidence: float = Field(default=0.5, description="Confidence score (0.0 to 1.0)")
    phishing_probability: float = Field(default=0.0, description="Estimated phishing probability (0.0 to 1.0)")
    triggered_rules: List[str] = Field(default_factory=list, description="List of rule IDs triggered during analysis")
    
    # Threat Intelligence context
    threat_intelligence_summary: str = Field(default="", description="Summary of external intelligence results")
    supporting_providers: List[str] = Field(default_factory=list, description="External intelligence providers consulted")
    
    # Explainability & AI content
    attack_chain: List[str] = Field(default_factory=list, description="Annotated steps detailing the attack path")
    reason: str = Field(description="User-facing summary / advice (legacy backward compatibility)")
    user_explanation: str = Field(default="", description="Simplified user-facing explanation")
    technical_explanation: str = Field(default="", description="Technical analyst details")
    recommendations: List[str] = Field(default_factory=list, description="Contextual safety advice")
    
    # Telemetry & Diagnostics
    score: int = Field(description="Confidence score in 0-100 format (legacy backward compatibility)")
    scan_duration_ms: float = Field(default=0.0, description="Total scan time in milliseconds")
    diagnostics: Optional[Dict[str, Any]] = Field(default=None, description="Detailed execution traces and profiling (debug only)")

    # Backward compatible checks dictionary
    checks: Dict[str, CheckResult] = Field(default_factory=dict, description="Status checklist for the extension UI")
