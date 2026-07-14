import time
import asyncio
import logging
from typing import Any, Optional
from models.ai_model import AIRequest, AIResponse, TokenUsage
from ai.token_manager import token_manager
from config.ai_config import SCHEMA_VERSION

logger = logging.getLogger("ClaudeClient")

class ClaudeClient:
    def __init__(self, anthropic_client: Optional[Any] = None):
        self.client = anthropic_client

    async def execute_request(
        self,
        request: AIRequest,
        system_prompt: str,
        formatted_prompt: str,
        model_id: str,
        timeout_sec: float
    ) -> AIResponse:
        """
        Executes an asynchronous request to the Claude API.
        Wraps execution with timeouts and records latency, correlation IDs, and token usage.
        """
        if not self.client:
            return AIResponse(
                request_id=request.request_id,
                schema_version=SCHEMA_VERSION,
                model=model_id,
                completion="",
                token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0),
                execution_time=0.0,
                success=False,
                validation_status="UNVALIDATED",
                error="Claude client is not configured (Offline/Mock Mode)"
            )

        start_time = time.perf_counter()
        try:
            # Enforce overall timeout
            response = await asyncio.wait_for(
                self.client.messages.create(
                    model=model_id,
                    max_tokens=request.metadata.get("max_tokens", 1000),
                    temperature=request.metadata.get("temperature", 0.0),
                    system=system_prompt,
                    messages=[{"role": "user", "content": formatted_prompt}]
                ),
                timeout=timeout_sec
            )
            
            latency = time.perf_counter() - start_time
            completion_text = response.content[0].text
            
            # Extract usage metrics if provided, else estimate
            input_tok = 0
            output_tok = 0
            if hasattr(response, "usage") and response.usage:
                input_tok = getattr(response.usage, "input_tokens", 0)
                output_tok = getattr(response.usage, "output_tokens", 0)
            else:
                input_tok = token_manager.estimate_tokens(formatted_prompt + system_prompt)
                output_tok = token_manager.estimate_tokens(completion_text)
                
            total_tok = input_tok + output_tok
            cost = token_manager.calculate_cost(input_tok, output_tok)
            
            return AIResponse(
                request_id=request.request_id,
                schema_version=SCHEMA_VERSION,
                model=model_id,
                completion=completion_text,
                raw_response=response,
                token_usage=TokenUsage(
                    input_tokens=input_tok,
                    output_tokens=output_tok,
                    total_tokens=total_tok,
                    estimated_cost=cost
                ),
                execution_time=latency,
                success=True,
                validation_status="UNVALIDATED"
            )
            
        except asyncio.TimeoutError:
            latency = time.perf_counter() - start_time
            logger.warning(f"Claude API execution timed out after {timeout_sec}s. Correlation ID: {request.request_id}")
            return AIResponse(
                request_id=request.request_id,
                schema_version=SCHEMA_VERSION,
                model=model_id,
                completion="",
                token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0),
                execution_time=latency,
                success=False,
                validation_status="UNVALIDATED",
                error="Claude API request timed out"
            )
            
        except Exception as e:
            latency = time.perf_counter() - start_time
            err_msg = str(e)
            if "not found" in err_msg.lower() or "404" in err_msg or "not_found_error" in err_msg.lower():
                logger.error(f"CRITICAL CONFIGURATION ERROR: The configured Claude model '{model_id}' is unavailable or invalid. Please check the ANTHROPIC_MODEL configuration. Error: {e}")
            else:
                logger.error(f"Claude API query failed. Correlation ID: {request.request_id}. Error: {e}")
            return AIResponse(
                request_id=request.request_id,
                schema_version=SCHEMA_VERSION,
                model=model_id,
                completion="",
                token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0),
                execution_time=latency,
                success=False,
                validation_status="UNVALIDATED",
                error=str(e)
            )
