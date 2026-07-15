import unittest
import asyncio
from typing import List, Dict, Any
from models.evidence_model import EvidenceReport, Evidence
from models.decision_model import DecisionModel
from models.ai_model import AIRequest, AIResponse, TokenUsage
from ai.orchestrator import AIOrchestrator
from ai.context_builder import ai_context_builder
from ai.prompt_manager import prompt_manager
from ai.prompt_registry import prompt_registry, PromptMetadata
from ai.token_manager import token_manager
from ai.response_parser import response_parser
from ai.response_validator import response_validator
from ai.retry_manager import retry_manager
from ai.fallback_handler import fallback_handler
from ai.ai_metrics import ai_metrics
import config.ai_config as ai_config

class MockContent:
    def __init__(self, text: str):
        self.text = text

class MockMessage:
    def __init__(self, text: str):
        self.content = [MockContent(text)]
        self.usage = None

class MockMessages:
    def __init__(self, behavior: str = "success", response_text: str = ""):
        self.behavior = behavior
        self.response_text = response_text
        self.calls = 0

    async def create(self, **kwargs) -> MockMessage:
        self.calls += 1
        if self.behavior == "success":
            return MockMessage(self.response_text)
        elif self.behavior == "timeout":
            raise asyncio.TimeoutError("Anthropic API timeout mock")
        elif self.behavior == "rate_limit":
            # Throw dynamic rate limit error
            class RateLimitError(Exception):
                pass
            raise RateLimitError("Anthropic rate limit 429 mock")
        else:
            raise RuntimeError("Generic mock API error")

class MockAnthropicClient:
    def __init__(self, behavior: str = "success", response_text: str = ""):
        self.messages = MockMessages(behavior, response_text)

class TestAIOrchestration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Clear caching and operational states to ensure complete test isolation
        from ai.ai_cache import ai_cache
        ai_cache.clear()
        from ai.cost_manager import cost_manager
        cost_manager.clear()
        from ai.ai_circuit_breaker import ai_circuit_breaker
        ai_circuit_breaker.state = "HEALTHY"
        ai_circuit_breaker.failure_count = 0

        # Create a basic DecisionModel for testing
        self.report = EvidenceReport(
            evidence_list=[
                Evidence(
                    evidence_id="1",
                    analyzer_name="BrandAnalyzer",
                    category="URL",
                    severity="HIGH",
                    confidence=0.9,
                    triggered_rule="BR_001",
                    technical_details={"priority": "HIGH"},
                    explanation="Suspicious brand domain spoofing",
                    recommendation="Do not enter credentials"
                ),
                Evidence(
                    evidence_id="2",
                    analyzer_name="ContentAnalyzer",
                    category="CONTENT",
                    severity="LOW",
                    confidence=0.5,
                    triggered_rule="CT_001",
                    technical_details={"priority": "LOW"},
                    explanation="Urgent language patterns",
                    recommendation="Review carefully"
                )
            ]
        )
        self.model = DecisionModel(
            evidence_report=self.report,
            classified_evidence=self.report.evidence_list,
            correlated_evidence=self.report.evidence_list,
            confidence=0.8,
            risk_level="High",
            attack_types=["Phishing"],
            ioc_consensus={"spoof-brand.com": {"provider_count": 3, "agreement_score": 1.0, "severity": "HIGH", "freshness": "LIVE"}},
            metadata={"request_id": "test-correlation-id-123"}
        )

    def test_context_builder(self):
        ctx = ai_context_builder.build_context(self.model)
        self.assertEqual(ctx["risk_level"], "High")
        self.assertEqual(ctx["confidence_score"], 0.8)
        self.assertEqual(len(ctx["evidence"]), 2)
        # Verify low-priority and high-priority flags exist
        self.assertEqual(ctx["evidence"][0]["rule_id"], "BR_001")
        self.assertEqual(ctx["evidence"][1]["rule_id"], "CT_001")

    def test_token_budget_trimming(self):
        # Initial context has 2 items
        ctx = ai_context_builder.build_context(self.model)
        prompt_meta = prompt_registry.get_prompt("email_threat_analysis", "1.0.0")
        
        # Enforce budget of size to trigger trimming
        # Lowest priority trigger is CT_001 (LOW), highest is BR_001 (HIGH)
        trimmed = token_manager.enforce_budget_and_trim(
            context=ctx,
            prompt_template=prompt_meta.template,
            schema_version="1.0.0",
            budget=550  # Choose budget that forces popping the low priority evidence
        )
        
        # Low priority CT_001 should be trimmed, BR_001 preserved!
        self.assertEqual(len(trimmed["evidence"]), 1)
        self.assertEqual(trimmed["evidence"][0]["rule_id"], "BR_001")

    def test_response_parser_markdown_and_whitespace(self):
        raw_output = """
Some conversational text.
```json
{
  "attack_type": "Spear Phishing",
  "confidence": 0.95,
  "user_explanation": "Warning",
  "technical_explanation": "Detailed threat",
  "uncertainties": [],
  "schema_version": "1.0.0"
}
```
Conversational footer.
"""
        parsed = response_parser.parse_response(raw_output)
        self.assertEqual(parsed["attack_type"], "Spear Phishing")
        self.assertEqual(parsed["confidence"], 0.95)
        self.assertEqual(parsed["schema_version"], "1.0.0")

    def test_response_validator(self):
        prompt_meta = prompt_registry.get_prompt("email_threat_analysis", "1.0.0")
        valid_json = {
            "attack_type": "Phishing",
            "confidence": 0.9,
            "user_explanation": "User Alert",
            "technical_explanation": "Technical info",
            "uncertainties": [],
            "schema_version": "1.0.0"
        }
        status = response_validator.validate_response(valid_json, prompt_meta.expected_schema)
        self.assertEqual(status, "VALIDATED")

        # Invalid: missing field
        invalid_json = valid_json.copy()
        del invalid_json["attack_type"]
        with self.assertRaises(ValueError):
            response_validator.validate_response(invalid_json, prompt_meta.expected_schema)

        # Invalid: bad confidence range
        bad_conf_json = valid_json.copy()
        bad_conf_json["confidence"] = 1.5
        with self.assertRaises(ValueError):
            response_validator.validate_response(bad_conf_json, prompt_meta.expected_schema)

        # Invalid: unsupported schema version
        bad_ver_json = valid_json.copy()
        bad_ver_json["schema_version"] = "2.0.0"
        with self.assertRaises(ValueError):
            response_validator.validate_response(bad_ver_json, prompt_meta.expected_schema)

    def test_retry_manager_transient_failures(self):
        # 1. Transient exceptions
        self.assertTrue(retry_manager.is_retry_eligible(asyncio.TimeoutError()))
        self.assertTrue(retry_manager.is_retry_eligible(ConnectionError()))
        
        # Dynamic check for anthropic exception naming
        class AnthropicTimeoutError(Exception):
            pass
        self.assertTrue(retry_manager.is_retry_eligible(AnthropicTimeoutError()))
        
        # 2. Non-transient exceptions
        class AuthenticationError(Exception):
            pass
        self.assertFalse(retry_manager.is_retry_eligible(AuthenticationError()))
        self.assertFalse(retry_manager.is_retry_eligible(ValueError("Invalid schema")))

    def test_fallback_handler(self):
        fallback = fallback_handler.get_fallback_verdict(self.model, "Mock error message")
        self.assertEqual(fallback["attack_type"], "Phishing")
        self.assertEqual(fallback["confidence"], 0.8)
        self.assertIn("AI orchestration failed over to local fallback", fallback["technical_explanation"])

    async def test_orchestrator_successful_state_transitions(self):
        # Set up mock response
        response_text = """{
            "attack_type": "Spear Phishing",
            "confidence": 0.92,
            "user_explanation": "Safety Alert",
            "technical_explanation": "Flagged",
            "uncertainties": [],
            "schema_version": "1.0.0"
        }"""
        mock_client = MockAnthropicClient(behavior="success", response_text=response_text)
        orchestrator = AIOrchestrator(mock_client)
        
        response, traces = await orchestrator.analyze_decision_model(self.model)
        
        self.assertTrue(response.success)
        self.assertEqual(response.validation_status, "VALIDATED")
        self.assertEqual(response.parsed_json["attack_type"], "Spear Phishing")
        self.assertEqual(response.request_id, "test-correlation-id-123")
        
        # Verify state machine traces
        expected_states = [
            "AI_ORCHESTRATOR_STATE: INITIAL",
            "AI_ORCHESTRATOR_STATE: CONTEXT_READY",
            "AI_ORCHESTRATOR_STATE: PROMPT_READY",
            "AI_ORCHESTRATOR_STATE: REQUEST_SENT",
            "AI_ORCHESTRATOR_STATE: RESPONSE_RECEIVED",
            "AI_ORCHESTRATOR_STATE: PARSED",
            "AI_ORCHESTRATOR_STATE: VALIDATED",
            "AI_ORCHESTRATOR_STATE: COMPLETE"
        ]
        for state in expected_states:
            self.assertTrue(any(state in trace for trace in traces), f"Missing trace state: {state}")

    async def test_orchestrator_transient_retry_and_fallback(self):
        # Set up mock client that times out
        mock_client = MockAnthropicClient(behavior="timeout")
        orchestrator = AIOrchestrator(mock_client)
        
        # Modify ai_config retries and delays for faster test execution
        orig_retries = ai_config.RETRY_COUNT
        orig_delay = ai_config.RETRY_DELAY_SEC
        ai_config.RETRY_COUNT = 1
        ai_config.RETRY_DELAY_SEC = 0.01
        
        try:
            response, traces = await orchestrator.analyze_decision_model(self.model)
            
            # Should fail over to local rules fallback
            self.assertFalse(response.success)
            self.assertEqual(response.model, "fallback-local-rules")
            self.assertEqual(response.parsed_json["attack_type"], "Phishing")
            self.assertEqual(response.parsed_json["confidence"], 0.8)
            
            # Verify retry attempts
            self.assertEqual(mock_client.messages.calls, 2)  # 1 try + 1 retry
            
            # Verify fallback states recorded in traces
            self.assertTrue(any("AI_ORCHESTRATOR_STATE: FALLBACK" in trace for trace in traces))
            self.assertTrue(any("AI_ORCHESTRATOR_STATE: COMPLETE" in trace for trace in traces))
        finally:
            ai_config.RETRY_COUNT = orig_retries
            ai_config.RETRY_DELAY_SEC = orig_delay

if __name__ == "__main__":
    unittest.main()
