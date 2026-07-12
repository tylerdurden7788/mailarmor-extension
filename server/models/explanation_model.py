from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional

class ExplanationRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(description="Correlation request/incident ID")
    audience: str = Field(description="Intended audience (e.g., SOC Analyst, User, Executive)")
    decision: str = Field(description="MailArmour fused verdict")
    evidence: List[Dict[str, Any]] = Field(description="Cleaned, token-efficient evidence summary triggers")
    confidence: float = Field(description="Confidence value score (0.0 to 1.0)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context parameters")

class ExplanationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    technical_summary: str = Field(description="Technical summary citing rules for SOC analysts")
    user_summary: str = Field(description="Simplified advice citing rules for end-users")
    executive_summary: str = Field(description="Management report detailing risk and business impact")
    attack_chain: List[str] = Field(description="Chronological steps annotated with confidence metrics")
    recommendations: List[str] = Field(description="Actionable mitigation steps")
    confidence_reasoning: str = Field(description="Attribution explaining the confidence score factors")
    generated_sections: List[str] = Field(default_factory=list, description="Sections successfully generated")
    schema_version: str = Field(description="Version string of explainability schema")
