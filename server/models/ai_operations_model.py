from pydantic import BaseModel, Field, ConfigDict
from typing import Dict, Any, Optional

class AIOperationRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str = Field(description="Correlation request identifier")
    cache_key: str = Field(description="SHA-256 caching lookup identifier key")
    capability: str = Field(description="Capability invoking the AI call")
    estimated_tokens: int = Field(default=0, description="Estimated input prompt size in tokens")
    optimization_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata dictionary")

class AIOperationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    cache_hit: bool = Field(default=False, description="Denotes if result was fetched from cache")
    optimization_applied: bool = Field(default=False, description="Flag representing optimization application")
    latency: float = Field(default=0.0, description="Pipeline step execution duration in seconds")
    token_savings: int = Field(default=0, description="Count of input tokens saved via compression")
    estimated_cost: float = Field(default=0.0, description="Financial token expenditure cost in USD")
    diagnostics: Dict[str, Any] = Field(default_factory=dict, description="Key-value profile timeline and statistics")
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Averaged execution indicators and distributions")
    optimization_version: str = Field(description="Current operations schema capability version")
