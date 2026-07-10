from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class Evidence(BaseModel):
    evidence_id: str = Field(description="Unique identifier for this specific piece of evidence")
    analyzer_name: str = Field(description="Name of the analyzer that produced this evidence")
    category: str = Field(description="Category of check (e.g., AUTHENTICATION, URL, HTML, CONTENT, UNICODE)")
    severity: str = Field(description="Severity classification: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=1.0, description="Confidence in this analyzer finding, from 0.0 to 1.0")
    risk_contribution: float = Field(default=0.0, description="Numerical weight indicating threat level")
    triggered_rule: str = Field(description="The matching rule ID from the rule registry")
    technical_details: Dict[str, Any] = Field(default_factory=dict, description="Metadata, strings, parsed arrays for developers")
    explanation: str = Field(description="Human-readable user-facing explanation")
    recommendation: str = Field(description="Actionable security advice for the user")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

class EvidenceReport(BaseModel):
    schema_version: str = "1.0.0"
    rule_version: str = "1.0.0"
    analyzer_version: str = "1.0.0"
    scan_duration_ms: float = 0.0
    analyzer_statistics: Dict[str, Any] = Field(default_factory=dict, description="Execution success status and trace info")
    confidence_summary: Dict[str, Any] = Field(default_factory=dict, description="Derived overall confidence analysis")
    triggered_rules: List[str] = Field(default_factory=list, description="Flat list of all rule IDs matched in the scan")
    processing_metadata: Dict[str, Any] = Field(default_factory=dict, description="System metadata, cache hits, versions")
    evidence_list: List[Evidence] = Field(default_factory=list, description="Array of collected evidence objects")
