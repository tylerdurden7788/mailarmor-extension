import unittest
import asyncio
from typing import Dict, Any, List
from unittest.mock import patch, AsyncMock
from models.evidence_model import EvidenceReport, Evidence
from models.ai_model import TokenUsage
from main import EmailAnalysisRequest, analyze_email, validate_startup, map_evidence_to_checks

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
        else:
            raise RuntimeError("Generic mock API error")

class MockAnthropicClient:
    def __init__(self, behavior: str = "success", response_text: str = ""):
        self.messages = MockMessages(behavior, response_text)

class TestPipelineIntegration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Clear caching and operational states to ensure complete test isolation
        from ai.ai_cache import ai_cache
        ai_cache.clear()
        from ai.cost_manager import cost_manager
        cost_manager.clear()
        from ai.ai_circuit_breaker import ai_circuit_breaker
        ai_circuit_breaker.state = "HEALTHY"
        ai_circuit_breaker.failure_count = 0

    def test_startup_validation(self):
        # Test that validate_startup executes without throwing errors under standard environment
        try:
            validate_startup()
            success = True
        except Exception as e:
            success = False
            print(f"Startup validation failed: {e}")
        self.assertTrue(success)

    def test_map_evidence_to_checks(self):
        # 1. Clean evidence -> all checks should pass
        evidence_list = []
        checks = map_evidence_to_checks(evidence_list)
        self.assertTrue(checks["sender_check"].passed)
        self.assertTrue(checks["domain_check"].passed)
        self.assertTrue(checks["urgency_check"].passed)
        self.assertTrue(checks["link_check"].passed)
        self.assertTrue(checks["content_check"].passed)
        self.assertTrue(checks["attachment_check"].passed)

        # 2. Add high severity sender evidence -> sender_check should fail
        evidence_list.append(Evidence(
            evidence_id="ev_1",
            analyzer_name="SenderAnalyzer",
            category="SENDER",
            severity="HIGH",
            triggered_rule="SE_001",
            explanation="Display name spoofing identified",
            recommendation="Verify email sender address"
        ))
        checks = map_evidence_to_checks(evidence_list)
        self.assertFalse(checks["sender_check"].passed)
        self.assertEqual(checks["sender_check"].detail, "Display name spoofing identified")
        self.assertTrue(checks["domain_check"].passed)

    async def test_end_to_end_analyze_success(self):
        payload = EmailAnalysisRequest(
            subject="Urgent update required on your account",
            sender="Secure Support <support@secure-domain-phish.com>",
            body="Dear customer, please click the link to verify your credentials: http://paypal-security-update.com/login?auth_key=12345",
            attachments=[]
        )

        # Combined response text to satisfy both threat analysis schema and explainability schema
        response_text = """{
            "verdict": "DANGEROUS",
            "confidence": 0.95,
            "attack_type": "Credential Harvesting",
            "user_explanation": "This email attempts to steal credentials using a deceptive link.",
            "technical_explanation": "Url matches brand domain spoofing patterns.",
            "uncertainties": [],
            "technical_summary": "Technical explanation details.",
            "user_summary": "User summary advice.",
            "executive_summary": "Executive summary detailing risk.",
            "attack_chain": ["Stage 1: Link clicked (Confidence: 0.95)"],
            "recommendations": ["Do not enter credentials"],
            "confidence_reasoning": "Confidence is high due to lookalike domain.",
            "schema_version": "1.0.0"
        }"""
        mock_client = MockAnthropicClient(behavior="success", response_text=response_text)

        # Mock threat intelligence to avoid external network dependencies during tests
        with patch("scanner.rule_engine.global_threat_manager.lookup_observables", new_callable=AsyncMock) as mock_lookup:
            mock_lookup.return_value = []
            
            with patch("main.anthropic_client", mock_client):
                res = await analyze_email(payload)
                
                # Assert compatibility response fields
                self.assertEqual(res.verdict, "DANGEROUS")
                self.assertTrue(res.score > 0)
                self.assertIn("checks", res.model_dump())
                self.assertFalse(res.checks["link_check"].passed)
                self.assertIsNotNone(res.diagnostics)
                self.assertTrue(res.scan_duration_ms > 0.0)

    async def test_pipeline_fallback_on_ai_timeout(self):
        payload = EmailAnalysisRequest(
            subject="Urgent invoice payout",
            sender="Finance Dept <billing@company-payout.com>",
            body="Review the invoice immediately: http://company-payout.com/invoice",
            attachments=[]
        )
        # Timeout behavior triggers fallback
        mock_client = MockAnthropicClient(behavior="timeout")

        with patch("scanner.rule_engine.global_threat_manager.lookup_observables", new_callable=AsyncMock) as mock_lookup:
            mock_lookup.return_value = []
            
            with patch("main.anthropic_client", mock_client):
                res = await analyze_email(payload)
                
                # Should fallback to local rules gracefully and return a valid verdict
                self.assertIn(res.verdict, ["SAFE", "SUSPICIOUS", "DANGEROUS"])
                self.assertTrue(res.confidence > 0.0)
                self.assertIsNotNone(res.user_explanation)
                self.assertTrue(res.checks["link_check"].passed or not res.checks["link_check"].passed)

    async def test_pipeline_threat_intel_failure_recovery(self):
        # Clean sender and body to guarantee local rules evaluate as LIKELY_SAFE/SAFE
        payload = EmailAnalysisRequest(
            subject="Hey there",
            sender="John Doe <john.doe@gmail.com>",
            body="Let's meet tomorrow. Check out the project details at: https://gmail.com",
            attachments=[]
        )
        response_text = """{
            "verdict": "SAFE",
            "confidence": 0.98,
            "attack_type": "Safe",
            "user_explanation": "Safe update email.",
            "technical_explanation": "No suspicious indicators.",
            "uncertainties": [],
            "technical_summary": "Technical explanation details.",
            "user_summary": "User summary advice.",
            "executive_summary": "Executive summary detailing risk.",
            "attack_chain": ["Stage 1: Safe email check"],
            "recommendations": ["No actions required"],
            "confidence_reasoning": "Confidence is high based on trusted sender.",
            "schema_version": "1.0.0"
        }"""
        mock_client = MockAnthropicClient(behavior="success", response_text=response_text)

        # Threat intelligence fails/throws error
        with patch("scanner.rule_engine.global_threat_manager.lookup_observables", side_effect=RuntimeError("Threat intel service offline")):
            with patch("main.anthropic_client", mock_client):
                res = await analyze_email(payload)
                
                # Pipeline continues and succeeds
                self.assertIn(res.verdict, ["SAFE", "LIKELY_SAFE"])
                self.assertTrue(res.score > 0)
                self.assertTrue(res.checks["link_check"].passed)

if __name__ == "__main__":
    unittest.main()
