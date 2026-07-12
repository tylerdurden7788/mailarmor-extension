import unittest
import asyncio
import time
from typing import Dict, Any, List
from ai.ai_cache import ai_cache
from ai.cache_policy import cache_policy
from ai.response_cache import response_cache
from ai.request_deduplicator import request_deduplicator
from ai.prompt_compressor import prompt_compressor
from ai.cost_manager import cost_manager
from ai.ai_circuit_breaker import ai_circuit_breaker
from ai.ai_health_monitor import ai_health_monitor
from ai.ai_statistics import ai_statistics
from ai.optimization_orchestrator import optimization_orchestrator
from models.ai_model import AIResponse, TokenUsage
from models.evidence_model import EvidenceReport, Evidence
from models.decision_model import DecisionModel
from ai.orchestrator import AIOrchestrator
import config.ai_operations_config as config

class MockContent:
    def __init__(self, text: str):
        self.text = text

class MockMessage:
    def __init__(self, text: str):
        self.content = [MockContent(text)]
        self.usage = None

class MockMessages:
    def __init__(self, should_fail: bool = False, response_text: str = ""):
        self.should_fail = should_fail
        self.response_text = response_text
        self.calls = 0

    async def create(self, **kwargs) -> MockMessage:
        self.calls += 1
        if self.should_fail:
            raise RuntimeError("Claude execution error")
        return MockMessage(self.response_text)

class MockAnthropicClient:
    def __init__(self, should_fail: bool = False, response_text: str = ""):
        self.messages = MockMessages(should_fail, response_text)

class TestAIOperations(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ai_cache.clear()
        cost_manager.clear()
        ai_circuit_breaker.state = "HEALTHY"
        ai_circuit_breaker.failure_count = 0
        ai_health_monitor.clear()
        ai_statistics.clear()

    def test_cache_lru_and_ttl(self):
        # 1. LRU Eviction Check
        orig_max = config.CACHE_MAX_SIZE
        config.CACHE_MAX_SIZE = 2
        try:
            ai_cache.set("key1", "val1")
            ai_cache.set("key2", "val2")
            ai_cache.set("key3", "val3")
            
            self.assertIsNone(ai_cache.get("key1")) # Evicted!
            self.assertEqual(ai_cache.get("key2"), "val2")
            self.assertEqual(ai_cache.get("key3"), "val3")
        finally:
            config.CACHE_MAX_SIZE = orig_max

        # 2. TTL Expiry check
        orig_ttl = config.CACHE_TTL_SEC
        config.CACHE_TTL_SEC = 0 # Expire instantly
        try:
            ai_cache.set("key_temp", "val_temp")
            self.assertIsNone(ai_cache.get("key_temp"))
        finally:
            config.CACHE_TTL_SEC = orig_ttl

    def test_cache_only_fully_validated(self):
        token_u = TokenUsage(input_tokens=10, output_tokens=10, total_tokens=20, estimated_cost=0.01)
        
        # Valid response: Cacheable
        val_resp = AIResponse(
            request_id="1",
            schema_version="1.0.0",
            model="claude-3",
            completion="{}",
            success=True,
            validation_status="VALIDATED",
            token_usage=token_u,
            execution_time=0.05
        )
        response_cache.store_response("key_valid", val_resp, "email_threat_analysis")
        self.assertIsNotNone(response_cache.get_response("key_valid"))

        # Fallback response: Never cache
        fallback_resp = AIResponse(
            request_id="2",
            schema_version="1.0.0",
            model="fallback-local-rules",
            completion="{}",
            success=False,
            validation_status="VALIDATED",
            execution_time=0.0,
            token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0)
        )
        response_cache.store_response("key_fallback", fallback_resp, "email_threat_analysis")
        self.assertIsNone(response_cache.get_response("key_fallback"))

        # Validation failed response: Never cache
        invalid_resp = AIResponse(
            request_id="3",
            schema_version="1.0.0",
            model="claude-3",
            completion="{}",
            success=True,
            validation_status="VALIDATION_FAILED",
            execution_time=0.05,
            token_usage=TokenUsage(input_tokens=0, output_tokens=0, total_tokens=0, estimated_cost=0.0)
        )
        response_cache.store_response("key_invalid", invalid_resp, "email_threat_analysis")
        self.assertIsNone(response_cache.get_response("key_invalid"))

    def test_request_deduplication(self):
        key1 = request_deduplicator.generate_cache_key("email_threat_analysis", "1.0", "Context body")
        key2 = request_deduplicator.generate_cache_key("email_threat_analysis", "1.0", "Context body")
        key3 = request_deduplicator.generate_cache_key("email_threat_analysis", "1.0", "Context body 2")
        
        self.assertEqual(key1, key2)
        self.assertNotEqual(key1, key3)

    def test_prompt_compressor(self):
        # 1. Less than threshold chars -> no compression
        short_prompt = "Short prompt text."
        self.assertEqual(prompt_compressor.compress(short_prompt), short_prompt)

        # 2. Exceeds threshold -> compression occurs
        orig_threshold = config.COMPRESSION_THRESHOLD_CHARS
        config.COMPRESSION_THRESHOLD_CHARS = 10
        try:
            raw = "Trigger BR_001 triggered.\nTrigger BR_001 triggered.\nTrigger CT_002 triggered."
            comp = prompt_compressor.compress(raw)
            # Duplicate triggers line should be merged, spacing normalized
            self.assertIn("Trigger BR_001 triggered.", comp)
            self.assertIn("Trigger CT_002 triggered.", comp)
            # The duplicate line "Trigger BR_001 triggered." should only appear once
            self.assertEqual(comp.count("Trigger BR_001 triggered."), 1)
        finally:
            config.COMPRESSION_THRESHOLD_CHARS = orig_threshold

    def test_cost_calculation_and_budget_warnings(self):
        cost = cost_manager.calculate_cost(input_tokens=1000, output_tokens=2000)
        # 1000 * 3.0/1M + 2000 * 15.0/1M = 0.003 + 0.030 = 0.033
        self.assertAlmostEqual(cost, 0.033)

        cost_manager.record_tokens(1000, 2000)
        self.assertAlmostEqual(cost_manager.monthly_spend, 0.033)
        self.assertFalse(cost_manager.is_budget_exceeded())

        # Exceed budget
        orig_limit = config.MONTHLY_COST_LIMIT
        config.MONTHLY_COST_LIMIT = 0.01
        try:
            self.assertTrue(cost_manager.is_budget_exceeded())
        finally:
            config.MONTHLY_COST_LIMIT = orig_limit

    def test_circuit_breaker_states(self):
        self.assertEqual(ai_circuit_breaker.state, "HEALTHY")
        
        # Increment failures to DEGRADED
        ai_circuit_breaker.record_failure()
        ai_circuit_breaker.record_failure()
        ai_circuit_breaker.record_failure()
        self.assertEqual(ai_circuit_breaker.state, "DEGRADED")

        # Trip to OPEN
        ai_circuit_breaker.record_failure()
        ai_circuit_breaker.record_failure()
        self.assertEqual(ai_circuit_breaker.state, "OPEN")
        self.assertFalse(ai_circuit_breaker.allow_request())

        # Reset success
        ai_circuit_breaker.record_success()
        self.assertEqual(ai_circuit_breaker.state, "HEALTHY")
        self.assertTrue(ai_circuit_breaker.allow_request())

    def test_optimization_orchestrator_state_transitions(self):
        traces = []
        op_req, opt_prompt, cached_res = optimization_orchestrator.optimize_request(
            request_id="opt-test-123",
            capability="email_threat_analysis",
            version="1.0.0",
            context="Verify domain address",
            traces=traces
        )
        
        self.assertIsNone(cached_res)
        self.assertEqual(opt_prompt, "Verify domain address")
        self.assertTrue(any("AI_OPTIMIZATION_STATE: INITIAL" in trace for trace in traces))
        self.assertTrue(any("AI_OPTIMIZATION_STATE: CIRCUIT_CHECKED" in trace for trace in traces))

        # Update stats on response completion
        token_u = TokenUsage(input_tokens=10, output_tokens=10, total_tokens=20, estimated_cost=0.01)
        resp = AIResponse(
            request_id="opt-test-123",
            schema_version="1.0.0",
            model="claude-3",
            completion="{}",
            success=True,
            validation_status="VALIDATED",
            token_usage=token_u,
            execution_time=0.1
        )
        
        op_result = optimization_orchestrator.optimize_response(
            request_id="opt-test-123",
            op_req=op_req,
            response=resp,
            traces=traces
        )

        self.assertTrue(any("AI_OPTIMIZATION_STATE: COMPLETE" in trace for trace in traces))
        self.assertFalse(op_result.cache_hit)
        self.assertEqual(ai_health_monitor.total_requests, 1)
        self.assertEqual(ai_statistics.cache_misses_count, 1)

    async def test_end_to_end_orchestration_caching(self):
        report = EvidenceReport(
            evidence_list=[
                Evidence(
                    evidence_id="1",
                    analyzer_name="BrandAnalyzer",
                    category="URL",
                    severity="HIGH",
                    triggered_rule="BR_001",
                    explanation="Suspicious brand spoofing",
                    recommendation="None"
                )
            ]
        )
        model = DecisionModel(
            evidence_report=report,
            classified_evidence=report.evidence_list,
            correlated_evidence=report.evidence_list,
            confidence=0.9,
            risk_level="High",
            attack_types=["Phishing"],
            metadata={"request_id": "test-caching-999"}
        )

        response_text = "{\"verdict\": \"dangerous\", \"confidence\": 0.95, \"attack_type\": \"Phishing\", \"user_explanation\": \"User safety info\", \"technical_explanation\": \"Technical details\", \"uncertainties\": [], \"schema_version\": \"1.0.0\"}"
        mock_client = MockAnthropicClient(should_fail=False, response_text=response_text)
        orchestrator = AIOrchestrator(mock_client)
        
        # 1. First execution: Cache Miss, queries mock Claude
        res1, traces1 = await orchestrator.analyze_decision_model(model)
        self.assertTrue(res1.success)
        self.assertEqual(mock_client.messages.calls, 1)
        self.assertTrue(any("AI_OPTIMIZATION_STATE: COMPLETE" in trace for trace in traces1))

        # 2. Second execution: Cache Hit, bypasses Claude completely!
        res2, traces2 = await orchestrator.analyze_decision_model(model)
        self.assertTrue(res2.success)
        self.assertEqual(mock_client.messages.calls, 1) # Still 1! No new call!
        self.assertTrue(any("AI_OPTIMIZATION_STATE: COMPLETE" in trace for trace in traces2))

if __name__ == "__main__":
    unittest.main()
