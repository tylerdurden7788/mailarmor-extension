import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from models.decision_model import DecisionModel
from models.ai_model import AIRequest, AIResponse, TokenUsage
from ai.claude_client import ClaudeClient
from ai.context_builder import ai_context_builder
from ai.prompt_manager import prompt_manager
from ai.prompt_registry import prompt_registry
from ai.token_manager import token_manager
from ai.response_parser import response_parser
from ai.response_validator import response_validator
from ai.retry_manager import retry_manager
from ai.fallback_handler import fallback_handler
from ai.ai_metrics import ai_metrics
from utils.structured_logger import structured_logger
import config.ai_config as ai_config

logger = logging.getLogger("AIOrchestrator")

class AIOrchestrator:
    def __init__(self, anthropic_client: Optional[Any] = None):
        self.client = ClaudeClient(anthropic_client)

    async def analyze_decision_model(self, model: DecisionModel) -> Tuple[AIResponse, List[str]]:
        """
        Coordinates the immutable orchestration pipeline state transitions:
        INITIAL -> CONTEXT_READY -> PROMPT_READY -> REQUEST_SENT -> RESPONSE_RECEIVED -> PARSED -> VALIDATED -> COMPLETE
        With optional failover to FALLBACK state.
        
        Returns a tuple: (AIResponse, list of state transition traces)
        """
        traces = []
        
        # 1. State: INITIAL
        state = "INITIAL"
        request_id = model.metadata.get("request_id")
        if not request_id:
            request_id = model.evidence_report.processing_metadata.get("request_id")
        if not request_id:
            request_id = str(uuid.uuid4())
            
        traces.append(f"AI_ORCHESTRATOR_STATE: {state} | request_id={request_id}")
        structured_logger.info(f"AI orchestration pipeline started", None, {"request_id": request_id, "state": state})
        ai_metrics.record_request(request_id)
        
        # Load prompt metadata configuration
        prompt_name = "email_threat_analysis"
        prompt_ver = ai_config.PROMPT_VERSION
        prompt_meta = prompt_registry.get_prompt(prompt_name, prompt_ver)
        if not prompt_meta:
            # Fallback immediately if prompt is missing
            err_msg = f"Prompt '{prompt_name}' version '{prompt_ver}' is not registered."
            return self._enter_fallback_state(model, request_id, err_msg, traces)

        # 2. State: CONTEXT_READY
        try:
            state = "CONTEXT_READY"
            traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
            raw_context = ai_context_builder.build_context(model)
        except Exception as e:
            return self._enter_fallback_state(model, request_id, f"ContextBuilder error: {e}", traces)

        # 3. State: PROMPT_READY
        try:
            state = "PROMPT_READY"
            traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
            
            # Enforce hard token budget and trim low priority triggers
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
            system_prompt = "You are an expert security classification model. Always return valid JSON only."
        except Exception as e:
            return self._enter_fallback_state(model, request_id, f"Prompt formatting or budget trimming error: {e}", traces)

        ai_req = AIRequest(
            request_id=request_id,
            prompt_name=prompt_name,
            prompt_version=prompt_ver,
            context=trimmed_context,
            metadata={"max_tokens": prompt_meta.max_tokens, "temperature": ai_config.TEMPERATURE}
        )

        # 4. State: REQUEST_SENT (with retries and timeouts)
        state = "REQUEST_SENT"
        traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
        
        response: Optional[AIResponse] = None
        last_error = ""
        
        for attempt in range(ai_config.RETRY_COUNT + 1):
            try:
                response = await self.client.execute_request(
                    request=ai_req,
                    system_prompt=system_prompt,
                    formatted_prompt=formatted_prompt,
                    model_id=prompt_meta.supported_model,
                    timeout_sec=ai_config.TIMEOUT_SEC
                )
                
                if response.success:
                    break
                else:
                    last_error = response.error or "Unknown client execution error"
                    # Check if error is transient
                    if retry_manager.is_retry_eligible(RuntimeError(last_error)):
                        ai_metrics.record_retry(request_id)
                        await retry_manager.wait_before_retry(attempt, ai_config.RETRY_DELAY_SEC)
                    else:
                        break
            except Exception as e:
                last_error = str(e)
                if retry_manager.is_retry_eligible(e):
                    ai_metrics.record_retry(request_id)
                    await retry_manager.wait_before_retry(attempt, ai_config.RETRY_DELAY_SEC)
                else:
                    break

        if not response or not response.success:
            return self._enter_fallback_state(model, request_id, f"Execution failed: {last_error}", traces)

        # 5. State: RESPONSE_RECEIVED
        state = "RESPONSE_RECEIVED"
        traces.append(f"AI_ORCHESTRATOR_STATE: {state} | execution_time={response.execution_time:.3f}s")
        
        # 6. State: PARSED
        try:
            state = "PARSED"
            traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
            parsed_dict = response_parser.parse_response(response.completion)
        except Exception as e:
            return self._enter_fallback_state(model, request_id, f"JSON Parsing error: {e}", traces)

        # 7. State: VALIDATED
        try:
            state = "VALIDATED"
            traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
            val_status = response_validator.validate_response(parsed_dict, prompt_meta.expected_schema)
        except Exception as e:
            ai_metrics.record_validation_failure(request_id)
            return self._enter_fallback_state(model, request_id, f"Schema validation error: {e}", traces)

        # 8. State: COMPLETE
        state = "COMPLETE"
        traces.append(f"AI_ORCHESTRATOR_STATE: {state}")
        
        # Build success response
        final_res = AIResponse(
            request_id=request_id,
            schema_version=ai_config.SCHEMA_VERSION,
            model=response.model,
            completion=response.completion,
            parsed_json=parsed_dict,
            raw_response=response.raw_response,
            token_usage=response.token_usage,
            execution_time=response.execution_time,
            success=True,
            validation_status=val_status
        )
        
        ai_metrics.record_success(
            request_id=request_id,
            latency=response.execution_time,
            input_tok=response.token_usage.input_tokens,
            output_tok=response.token_usage.output_tokens,
            cost=response.token_usage.estimated_cost
        )
        structured_logger.info("AI orchestration completed successfully", None, {"request_id": request_id, "state": state})
        
        return final_res, traces

    def _enter_fallback_state(self, model: DecisionModel, request_id: str, error_msg: str, traces: List[str]) -> Tuple[AIResponse, List[str]]:
        state = "FALLBACK"
        traces.append(f"AI_ORCHESTRATOR_STATE: {state} | error={error_msg}")
        traces.append(f"WARNING: Claude analysis failed: {error_msg}. Reverting to local engine.")
        structured_logger.warning("AI orchestration failing over to local fallback", None, {"request_id": request_id, "error": error_msg, "state": state})
        
        fallback_json = fallback_handler.get_fallback_verdict(model, error_msg)
        
        # Estimate dummy token usage for fallback
        usage = TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0)
        
        fallback_res = AIResponse(
            request_id=request_id,
            schema_version=ai_config.SCHEMA_VERSION,
            model="fallback-local-rules",
            completion="",
            parsed_json=fallback_json,
            token_usage=usage,
            execution_time=0.0,
            success=False,
            validation_status="VALIDATED",
            error=error_msg
        )
        
        # Add COMPLETE state after fallback entry
        traces.append("AI_ORCHESTRATOR_STATE: COMPLETE")
        return fallback_res, traces
