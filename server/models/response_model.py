from pydantic import BaseModel, Field
from .evidence_model import EvidenceReport

class EmailAnalysisResponse(BaseModel):
    # For now, return the structured Evidence Report
    report: EvidenceReport = Field(description="The complete structured audit Evidence Report")
    
    # We can also keep optional legacy fields so the existing extension doesn't crash during development
    verdict: str = Field(default="SUSPICIOUS", description="Legacy verdict (for compatibility)")
    reason: str = Field(default="Analysis complete. Rule engine gathered evidence.", description="Legacy reason")
    score: int = Field(default=50, description="Legacy score")
