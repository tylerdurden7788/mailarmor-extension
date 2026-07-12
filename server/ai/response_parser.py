import json
import re
from typing import Dict, Any

class ResponseParser:
    def parse_response(self, text: str) -> Dict[str, Any]:
        """
        Cleans and extracts JSON payload from Claude completion response.
        Handles Markdown JSON wrappers and syntax variances.
        """
        cleaned = text.strip()
        
        # 1. Clean Markdown code blocks (```json ... ``` or ``` ... ```)
        if "```" in cleaned:
            # Match the content inside triple backticks
            match = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, re.DOTALL)
            if match:
                cleaned = match.group(1).strip()

        # 2. Extract boundaries in case of surrounding conversational text
        # Look for the first '{' and the last '}'
        start_idx = cleaned.find('{')
        end_idx = cleaned.rfind('}')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            cleaned = cleaned[start_idx:end_idx + 1]

        # 3. Clean JSON formatting variances (e.g., trailing commas, common invalid chars)
        # Remove trailing commas before closing braces/brackets
        cleaned = re.sub(r',\s*([\]}])', r'\1', cleaned)

        # 4. JSON safe load
        try:
            return json.loads(cleaned)
        except Exception as e:
            raise ValueError(f"Failed to parse text as JSON. Error: {e}. Cleaned content: '{cleaned}'")

# Global response parser instance
response_parser = ResponseParser()
