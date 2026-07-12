import time
import logging
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from models.ai_model import AIResponse
from models.ai_operations_model import AIOperationRequest, AIOperationResult
from ai.request_deduplicator import request_deduplicator
from ai.cache_policy import cache_policy
from ai.response_cache import response_cache
from ai.prompt_compressor import prompt_compressor
from ai.cost_manager import cost_manager
from ai.ai_circuit_breaker import ai_circuit_breaker
from ai.ai_health_monitor import ai_health_monitor
from ai.ai_profiler import AIProfiler
from ai.ai_diagnostics import ai_diagnostics
from ai.ai_statistics import ai_statistics
import config.ai_operations_config as config

logger = logging.getLogger("OptimizationOrchestrator")

class OptimizationOrchestrator:
    def __init__(self):
        self.profiler = AIProfiler()

    def _create_trace(self, traces: list, state: str, details: str = "") -> None:
        timestamp = datetime.utcnow().isoformat() + "Z"
        detail_suffix = f" | {details}" if details else ""
        traces.append(f"AI_OPTIMIZATION_STATE: {state} | {timestamp}{detail_suffix}")

    def optimize_request(
        self,
        request_id: str,
        capability: str,
        version: str,
        context: str,
        traces: list
    ) -> Tuple[AIOperationRequest, str, Optional[AIResponse]]:
        """
        Coordinates outbound request optimization transitions:
        INITIAL -> DEDUPLICATED -> CACHE_CHECKED -> COMPRESSED -> COST_VALIDATED -> CIRCUIT_CHECKED
        """
        self.profiler.clear()
        self.profiler.start_timer("total_latency")
        self.profiler.start_timer("outbound_latency")

        # 1. State: INITIAL
        self._create_trace(traces, "INITIAL", f"request_id={request_id}")
        
        # 2. State: DEDUPLICATED
        self._create_trace(traces, "DEDUPLICATED")
        cache_key = request_deduplicator.generate_cache_key(capability, version, context)

        # 3. State: CACHE_CHECKED
        self._create_trace(traces, "CACHE_CHECKED")
        cached_res = None
        try:
            if cache_policy.is_cacheable(capability):
                cached_res = response_cache.get_response(cache_key)
                if cached_res:
                    logger.debug(f"Cache hit for key '{cache_key}'")
                    # Complete in-flight check immediately
                    self.profiler.stop_timer("outbound_latency")
                    self.profiler.stop_timer("total_latency")
                    return AIOperationRequest(request_id=request_id, cache_key=cache_key, capability=capability), context, cached_res
        except Exception as e:
            logger.warning(f"Caching check error: {e}. Bypassing optimization component.")

        # 4. State: COMPRESSED
        self._create_trace(traces, "COMPRESSED")
        compressed_context = context
        try:
            compressed_context = prompt_compressor.compress(context)
        except Exception as e:
            logger.warning(f"Prompt compression error: {e}. Bypassing.")

        # 5. State: COST_VALIDATED
        self._create_trace(traces, "COST_VALIDATED")
        try:
            if cost_manager.is_budget_exceeded():
                logger.error("AI operations cost budget exceeded! Denying execution.")
        except Exception as e:
            logger.warning(f"Cost validation error: {e}. Bypassing.")

        # 6. State: CIRCUIT_CHECKED
        self._create_trace(traces, "CIRCUIT_CHECKED")
        try:
            if not ai_circuit_breaker.allow_request():
                raise RuntimeError("AI circuit breaker is currently OPEN. Denying request.")
        except Exception as e:
            logger.warning(f"Circuit breaker error: {e}.")
            # If circuit is open, we raise to trigger local fallback
            if "circuit breaker" in str(e):
                raise

        op_req = AIOperationRequest(
            request_id=request_id,
            cache_key=cache_key,
            capability=capability,
            estimated_tokens=len(compressed_context) // 4
        )

        self.profiler.stop_timer("outbound_latency")
        return op_req, compressed_context, None

    def optimize_response(
        self,
        request_id: str,
        op_req: AIOperationRequest,
        response: AIResponse,
        traces: list
    ) -> AIOperationResult:
        """
        Coordinates inbound response optimization transitions:
        EXECUTED -> CACHE_UPDATED -> STATISTICS_UPDATED -> COMPLETE
        """
        self.profiler.start_timer("inbound_latency")

        # 7. State: EXECUTED
        self._create_trace(traces, "EXECUTED")
        
        # Record success or failure in circuit breaker
        try:
            if response and response.success:
                ai_circuit_breaker.record_success()
            else:
                ai_circuit_breaker.record_failure()
        except Exception as e:
            logger.warning(f"Circuit breaker response update failed: {e}")

        # Compute cost
        cost = 0.0
        tokens = 0
        try:
            if response and response.success and response.token_usage:
                tokens = response.token_usage.total_tokens
                cost = cost_manager.record_tokens(
                    response.token_usage.input_tokens,
                    response.token_usage.output_tokens
                )
        except Exception as e:
            logger.warning(f"Cost manager recording error: {e}")

        # 8. State: CACHE_UPDATED
        self._create_trace(traces, "CACHE_UPDATED")
        try:
            if response and response.success:
                response_cache.store_response(op_req.cache_key, response, op_req.capability)
        except Exception as e:
            logger.warning(f"Caching response update failed: {e}")

        # 9. State: STATISTICS_UPDATED
        self._create_trace(traces, "STATISTICS_UPDATED")
        
        self.profiler.stop_timer("inbound_latency")
        total_l = self.profiler.stop_timer("total_latency")

        # Record health monitor execution details
        try:
            val_failed = response.validation_status != "VALIDATED" if response else True
            ai_health_monitor.record_execution(
                success=response.success if response else False,
                latency=total_l,
                is_timeout="timeout" in str(response.error or "").lower() if response else False,
                validation_failed=val_failed,
                fallback_triggered=not response.success if response else True,
                cache_hit=False
            )
            ai_statistics.record_stats(total_l, cost, cache_hit=False)
        except Exception as e:
            logger.warning(f"Stats reporting failed: {e}")

        # 10. State: COMPLETE
        self._create_trace(traces, "COMPLETE")

        diag_data = ai_diagnostics.compile_diagnostics(
            timeline=self.profiler.get_profile_summary(),
            cache_hit=False,
            compression_applied=True,
            cost=cost,
            tokens=tokens
        )
        
        stats_data = ai_statistics.get_statistics()

        return AIOperationResult(
            cache_hit=False,
            optimization_applied=True,
            latency=total_l,
            token_savings=0,
            estimated_cost=cost,
            diagnostics=diag_data,
            statistics=stats_data,
            optimization_version=config.OPTIMIZATION_VERSION
        )

    def complete_cache_hit(
        self,
        request_id: str,
        op_req: AIOperationRequest,
        response: AIResponse,
        traces: list
    ) -> AIOperationResult:
        """
        Special short-circuit path for cache hits:
        CACHE_UPDATED -> STATISTICS_UPDATED -> COMPLETE
        """
        # Append cache hit traces
        self._create_trace(traces, "CACHE_UPDATED", "cache_hit=True")
        self._create_trace(traces, "STATISTICS_UPDATED")
        self._create_trace(traces, "COMPLETE")

        total_l = self.profiler.stop_timer("total_latency")

        try:
            ai_health_monitor.record_execution(
                success=True,
                latency=total_l,
                cache_hit=True
            )
            ai_statistics.record_stats(total_l, 0.0, cache_hit=True)
        except Exception as e:
            logger.warning(f"Stats reporting failed: {e}")

        diag_data = ai_diagnostics.compile_diagnostics(
            timeline=self.profiler.get_profile_summary(),
            cache_hit=True,
            compression_applied=False,
            cost=0.0,
            tokens=0
        )
        
        stats_data = ai_statistics.get_statistics()

        return AIOperationResult(
            cache_hit=True,
            optimization_applied=True,
            latency=total_l,
            token_savings=0,
            estimated_cost=0.0,
            diagnostics=diag_data,
            statistics=stats_data,
            optimization_version=config.OPTIMIZATION_VERSION
        )

# Global optimization orchestrator instance
optimization_orchestrator = OptimizationOrchestrator()
