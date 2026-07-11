from typing import Dict, Any

class ClaudePromptBuilder:
    @staticmethod
    def build(context: Dict[str, Any]) -> str:
        """
        Builds a deterministic reasoning prompt for Claude.
        """
        return f"""
You are an expert cybersecurity decision reasoning engine.
Analyze the following structured email intelligence context and classify the threat intent:

CONTEXT:
{context}

INSTRUCTIONS:
1. Reason only from the provided evidence. Do not invent any new indicators.
2. Determine if the email represents a threat, indicating the likely attack_type category.
3. Formulate a technical explanation detailing why the flags trigger a risk, and a non-technical explanation advising the user on safety.
4. Output your analysis strictly as a single JSON object. Do not include markdown formatting or extra text outside the JSON.

JSON Schema:
{{
  "attack_type": "string",
  "confidence": float (0.0 to 1.0),
  "user_explanation": "string",
  "technical_explanation": "string",
  "uncertainties": ["string"]
}}
"""
