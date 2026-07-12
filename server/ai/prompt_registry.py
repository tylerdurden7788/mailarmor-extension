from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class PromptMetadata(BaseModel):
    name: str
    version: str
    description: str
    expected_schema: Dict[str, Any]
    supported_model: str
    max_tokens: int
    template: str

class PromptRegistry:
    def __init__(self):
        self._prompts: Dict[str, PromptMetadata] = {}

    def register(self, metadata: PromptMetadata) -> None:
        key = f"{metadata.name}:{metadata.version}"
        self._prompts[key] = metadata

    def get_prompt(self, name: str, version: str) -> Optional[PromptMetadata]:
        key = f"{name}:{version}"
        return self._prompts.get(key)

# Global registry instance
prompt_registry = PromptRegistry()

# Register the standard 'email_threat_analysis' prompt version 1.0.0
EMAIL_THREAT_ANALYSIS_SCHEMA_V1 = {
    "type": "object",
    "properties": {
        "attack_type": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "user_explanation": {"type": "string"},
        "technical_explanation": {"type": "string"},
        "uncertainties": {"type": "array", "items": {"type": "string"}},
        "schema_version": {"type": "string"}
    },
    "required": ["attack_type", "confidence", "user_explanation", "technical_explanation", "uncertainties", "schema_version"]
}

EMAIL_THREAT_ANALYSIS_TEMPLATE_V1 = """You are an expert cybersecurity decision reasoning engine.
Analyze the following structured email intelligence context and classify the threat intent:

CONTEXT:
{context}

INSTRUCTIONS:
1. Reason only from the provided evidence. Do not invent any new indicators.
2. Determine if the email represents a threat, indicating the likely attack_type category.
3. Formulate a technical explanation detailing why the flags trigger a risk, and a non-technical explanation advising the user on safety.
4. Output your analysis strictly as a single JSON object. Do not include markdown formatting or extra text outside the JSON.
5. In your JSON response, always set "schema_version" to "{schema_version}".

JSON Schema:
{{
  "attack_type": "string",
  "confidence": float (0.0 to 1.0),
  "user_explanation": "string",
  "technical_explanation": "string",
  "uncertainties": ["string"],
  "schema_version": "string"
}}
"""

prompt_registry.register(PromptMetadata(
    name="email_threat_analysis",
    version="1.0.0",
    description="Analyze email threat signals and generate explanations",
    expected_schema=EMAIL_THREAT_ANALYSIS_SCHEMA_V1,
    supported_model="claude-3-5-sonnet-20241022",
    max_tokens=1000,
    template=EMAIL_THREAT_ANALYSIS_TEMPLATE_V1
))

# Register the standard 'email_threat_explainability' prompt version 1.0.0
EMAIL_THREAT_EXPLAINABILITY_SCHEMA_V1 = {
    "type": "object",
    "properties": {
        "technical_summary": {"type": "string"},
        "user_summary": {"type": "string"},
        "executive_summary": {"type": "string"},
        "attack_chain": {"type": "array", "items": {"type": "string"}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "confidence_reasoning": {"type": "string"},
        "schema_version": {"type": "string"}
    },
    "required": [
        "technical_summary",
        "user_summary",
        "executive_summary",
        "attack_chain",
        "recommendations",
        "confidence_reasoning",
        "schema_version"
    ]
}

EMAIL_THREAT_EXPLAINABILITY_TEMPLATE_V1 = """You are an expert security analyst and incident response reasoning system.
Analyze the following email security context and build a comprehensive explainability report.

CONTEXT:
{context}

INSTRUCTIONS:
1. Generate multiple audience-specific explanation summaries (technical analyst report, non-technical user advice, executive manager summary).
2. Construct a step-by-step chronological attack chain of events. Every node in the chain must represent a verified evidence trigger and include its confidence (e.g., "Spoofed Domain Detected (Confidence: 0.9)").
3. Cite the relevant evidence rules (e.g. [BR_001], [CT_001]) explicitly in your summaries, explaining exactly how they support your conclusions.
4. Explain why the confidence score has the assigned value by attributing it to key factors (agreement count, source reliability, etc.).
5. Generate actionable mitigation recommendations tailored to this threat.
6. Output your response strictly as a single JSON object. Do not include markdown formatting or extra text outside the JSON.
7. In your JSON response, always set "schema_version" to "{schema_version}".

JSON Schema:
{{
  "technical_summary": "string citing evidence rules",
  "user_summary": "string citing evidence rules",
  "executive_summary": "string citing evidence rules",
  "attack_chain": ["stage 1 (Confidence: float)", "stage 2 (Confidence: float)"],
  "recommendations": ["string"],
  "confidence_reasoning": "string explaining attribution",
  "schema_version": "string"
}}
"""

prompt_registry.register(PromptMetadata(
    name="email_threat_explainability",
    version="1.0.0",
    description="Explain email threat signals to multiple audiences with citations",
    expected_schema=EMAIL_THREAT_EXPLAINABILITY_SCHEMA_V1,
    supported_model="claude-3-5-sonnet-20241022",
    max_tokens=1500,
    template=EMAIL_THREAT_EXPLAINABILITY_TEMPLATE_V1
))
