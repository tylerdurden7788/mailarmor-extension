from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from models.evidence_model import Evidence, EvidenceReport

class DecisionModel(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_report: EvidenceReport
    
    # Internal Pipeline Evidence Sets
    classified_evidence: List[Evidence] = Field(default_factory=list)
    correlated_evidence: List[Evidence] = Field(default_factory=list)
    ignored_evidence: List[Evidence] = Field(default_factory=list)
    conflicting_evidence: List[Evidence] = Field(default_factory=list)
    suppressed_evidence: List[Evidence] = Field(default_factory=list)

    # Dynamic Scoring & Classifications
    confidence: float = 0.0
    risk_level: str = "Minimal"
    attack_types: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # Final Verdict Output
    verdict: str = "UNKNOWN"
    technical_explanation: str = ""
    user_explanation: str = ""
    decision_trace: List[str] = Field(default_factory=list)
    
    # Threat Intelligence Integration summaries (backward compatible)
    threat_intelligence_summary: Dict[str, Any] = Field(default_factory=dict)
    provider_statistics: Dict[str, Any] = Field(default_factory=dict)
    ioc_consensus: Dict[str, Any] = Field(default_factory=dict)
    
    # Telemetry
    metadata: Dict[str, Any] = Field(default_factory=dict)
