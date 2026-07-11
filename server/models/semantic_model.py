from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from models.html_model import DocumentGraph

class SemanticFeature(BaseModel):
    model_config = ConfigDict(frozen=True)
    category: str          # e.g., "urgency", "financial", "identity", "credential"
    value: str             # e.g., "immediate_action_required", "invoice_due"
    confidence: float      # score from 0.0 to 1.0
    context_snippet: str   # surrounding context in email body

class SemanticContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    canonicalized_text: str
    features: List[SemanticFeature] = Field(default_factory=list)
    intents: List[str] = Field(default_factory=list)
    victim_actions: List[str] = Field(default_factory=list)
    soc_eng_techniques: List[str] = Field(default_factory=list)
    document_graph: Optional[DocumentGraph] = None
    
    performance_limits: Dict[str, Any] = Field(default_factory=lambda: {
        "max_words": 5000,
        "timeout_sec": 2.0
    })
