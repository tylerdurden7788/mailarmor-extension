from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, List
from datetime import datetime

class ThreatObservable(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: str = Field(description="The canonical normalized string representation of the IOC")
    type: str = Field(description="Types: Domain, URL, IP Address, Email Address, File Hash, Certificate, ASN")

class ThreatEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str = Field(description="Name of the threat intelligence provider that analyzed the observable")
    observable: str = Field(description="The normalized value checked")
    observable_type: str = Field(description="The matched observable type")
    classification: str = Field(description="Status: malicious, clean, suspicious, unknown")
    severity: str = Field(description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    provider_confidence: float = Field(default=1.0, description="Reliability score from provider, 0.0 to 1.0")
    technical_details: Dict[str, Any] = Field(default_factory=dict, description="Metadata specific to the provider response")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Generic tags, scan date, categories")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
