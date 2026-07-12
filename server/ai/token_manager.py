import copy
import logging
from typing import Dict, Any, List

logger = logging.getLogger("TokenManager")

PRIORITY_WEIGHTS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFORMATIONAL": 1
}

class TokenManager:
    def estimate_tokens(self, text: str) -> int:
        """Approximates token count based on string length (heuristic: 4 characters per token)."""
        return int(len(text) / 4.0)

    def calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculates API cost in USD based on Claude 3.5 Sonnet pricing."""
        # Input: $3.00 / M tokens, Output: $15.00 / M tokens
        return (input_tokens * 3.0 / 1_000_000.0) + (output_tokens * 15.0 / 1_000_000.0)

    def enforce_budget_and_trim(self, context: Dict[str, Any], prompt_template: str, schema_version: str, budget: int) -> Dict[str, Any]:
        """
        Enforces a hard token budget limit on the generated prompt.
        If it exceeds the budget, it trims the lowest-priority evidence items.
        If reduction is insufficient (or list is empty and still fails), raises ValueError.
        """
        ctx_copy = copy.deepcopy(context)
        
        def check_size(current_ctx: Dict[str, Any]) -> int:
            # Render a dummy prompt to estimate final token length
            # Note: template format uses braces, double brace escape JSON schema
            try:
                rendered = prompt_template.format(
                    context=current_ctx,
                    schema_version=schema_version
                )
            except Exception:
                rendered = prompt_template.replace("{context}", str(current_ctx)).replace("{schema_version}", schema_version)
            return self.estimate_tokens(rendered)

        # 1. Check initial size
        initial_tokens = check_size(ctx_copy)
        if initial_tokens <= budget:
            return ctx_copy
            
        logger.warning(f"Prompt size {initial_tokens} tokens exceeds budget {budget}. Starting context trimming.")

        # 2. Get evidence list
        evidence_list: List[Dict[str, Any]] = ctx_copy.get("evidence", [])
        if not evidence_list:
            raise ValueError(f"Token budget {budget} exceeded even with zero evidence items (estimated: {initial_tokens}).")

        # Sort evidence ascending by priority weight (lowest priority first)
        evidence_list.sort(key=lambda ev: PRIORITY_WEIGHTS.get(str(ev.get("priority", "")).upper(), 0))

        # 3. Trim lowest-priority items until it fits
        while check_size(ctx_copy) > budget:
            if not evidence_list:
                break
            # Pop the first element (lowest priority)
            removed = evidence_list.pop(0)
            logger.info(f"Trimmed low-priority trigger flag '{removed.get('rule_id')}' to fit within token budget.")

        # Recalculate final size
        final_tokens = check_size(ctx_copy)
        if final_tokens > budget:
            raise ValueError(f"Context reduction insufficient to meet token budget {budget} (final size: {final_tokens}).")

        # Update evidence count
        ctx_copy["evidence_count"] = len(evidence_list)
        return ctx_copy

# Global token manager instance
token_manager = TokenManager()
