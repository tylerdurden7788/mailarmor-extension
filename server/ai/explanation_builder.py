import logging
from typing import Dict, Any, Tuple
from models.decision_model import DecisionModel
from models.ai_model import AIRequest, AIResponse, TokenUsage
from ai.orchestrator import AIOrchestrator
from ai.context_builder import ai_context_builder
from ai.prompt_manager import prompt_manager
from ai.prompt_registry import prompt_registry
from ai.token_manager import token_manager
from ai.response_parser import response_parser
from ai.response_validator import response_validator
import config.ai_config as ai_config

logger = logging.getLogger("ExplanationBuilder")

class ExplanationBuilder:
    async def build_explanation_response(
        self,
        orchestrator: AIOrchestrator,
        model: DecisionModel,
        request_id: str
    ) -> Tuple[AIResponse, Dict[str, Any]]:
        """
        Builds threat explainability report details by querying AIOrchestrator.
        Enforces token limits and schema validations.
        """
        prompt_name = "email_threat_explainability"
        prompt_ver = "1.0.0"
        prompt_meta = prompt_registry.get_prompt(prompt_name, prompt_ver)
        if not prompt_meta:
            raise ValueError(f"Capability '{prompt_name}' not registered in registry.")

        # Build raw context
        raw_context = ai_context_builder.build_context(model)
        
        # Enforce budget & trim low priority signals
        trimmed_context = token_manager.enforce_budget_and_trim(
            context=raw_context,
            prompt_template=prompt_meta.template,
            schema_version=ai_config.SCHEMA_VERSION,
            budget=ai_config.TOKEN_BUDGET
        )

        formatted_prompt = prompt_manager.format_prompt(
            name=prompt_name,
            version=prompt_ver,
            context=trimmed_context,
            schema_version=ai_config.SCHEMA_VERSION
        )

        ai_req = AIRequest(
            request_id=request_id,
            prompt_name=prompt_name,
            prompt_version=prompt_ver,
            context=trimmed_context,
            metadata={"max_tokens": prompt_meta.max_tokens, "temperature": ai_config.TEMPERATURE}
        )

        # Query Claude client
        system_prompt = "You are an expert security analyst and incident response reasoning system. Always return valid JSON only."
        response = await orchestrator.client.execute_request(
            request=ai_req,
            system_prompt=system_prompt,
            formatted_prompt=formatted_prompt,
            model_id=prompt_meta.supported_model,
            timeout_sec=ai_config.TIMEOUT_SEC
        )

        if not response.success:
            raise RuntimeError(response.error or "Claude execution failed")

        # Parse & Validate
        parsed = response_parser.parse_response(response.completion)
        response_validator.validate_response(parsed, prompt_meta.expected_schema)
        
        # Return success Response
        return response, parsed

# Global explanation builder instance
explanation_builder = ExplanationBuilder()
