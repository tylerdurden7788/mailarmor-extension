import unittest
import asyncio
from typing import Dict, Any, List
from models.evidence_model import EvidenceReport, Evidence
from models.decision_model import DecisionModel
from models.explanation_model import ExplanationResponse
from ai.explainability_orchestrator import ExplainabilityOrchestrator
from ai.attack_chain_builder import attack_chain_builder
from ai.analyst_report_builder import analyst_report_builder
from ai.executive_summary_builder import executive_summary_builder
from ai.user_summary_builder import user_summary_builder
from ai.confidence_explainer import confidence_explainer
from ai.recommendation_builder import recommendation_builder
from ai.report_formatter import report_formatter
from ai.prompt_registry import prompt_registry
import config.explanation_config as config

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
            raise RuntimeError("API query timeout or failure")
        return MockMessage(self.response_text)

class MockAnthropicClient:
    def __init__(self, should_fail: bool = False, response_text: str = ""):
        self.messages = MockMessages(should_fail, response_text)

class TestAIExplainability(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Setup basic mock models
        self.report = EvidenceReport(
            evidence_list=[
                Evidence(
                    evidence_id="1",
                    analyzer_name="BrandAnalyzer",
                    category="URL",
                    severity="HIGH",
                    confidence=0.95,
                    triggered_rule="BR_001",
                    technical_details={"priority": "HIGH"},
                    explanation="Suspicious brand domain spoofing",
                    recommendation="Verify domain address"
                ),
                Evidence(
                    evidence_id="2",
                    analyzer_name="ContentAnalyzer",
                    category="CONTENT",
                    severity="MEDIUM",
                    confidence=0.70,
                    triggered_rule="CT_002",
                    technical_details={"priority": "MEDIUM"},
                    explanation="Urgent language patterns",
                    recommendation="Handle carefully"
                )
            ]
        )
        self.model = DecisionModel(
            evidence_report=self.report,
            classified_evidence=self.report.evidence_list,
            correlated_evidence=self.report.evidence_list,
            confidence=0.85,
            risk_level="High",
            verdict="DANGEROUS",
            attack_types=["Phishing"],
            metadata={"request_id": "test-explainability-correlation-123"}
        )

    def test_local_attack_chain_builder(self):
        chain = attack_chain_builder.build_attack_chain(self.model)
        self.assertEqual(len(chain), 2)
        # Verify chronological ordering (URL/domain authentication entry nodes first)
        self.assertIn("Suspicious brand domain spoofing", chain[0])
        self.assertIn("Confidence: 0.95", chain[0])
        self.assertIn("[BR_001]", chain[0])

        self.assertIn("Urgent language patterns", chain[1])
        self.assertIn("Confidence: 0.70", chain[1])
        self.assertIn("[CT_002]", chain[1])

    def test_local_analyst_report_builder(self):
        report = analyst_report_builder.build_analyst_report(self.model)
        self.assertIn("BR_001", report)
        self.assertIn("CT_002", report)
        self.assertIn("BrandAnalyzer", report)
        self.assertIn("Confidence: 0.95", report)

    def test_local_executive_summary_builder(self):
        report = executive_summary_builder.build_executive_summary(self.model)
        self.assertIn("[BR_001]", report)
        self.assertIn("[CT_002]", report)
        self.assertIn("High", report)

    def test_local_user_summary_builder(self):
        report = user_summary_builder.build_user_summary(self.model)
        self.assertIn("[BR_001]", report)
        self.assertIn("[CT_002]", report)
        self.assertIn("pretend to be a brand", report)

    def test_local_confidence_explainer(self):
        explanation = confidence_explainer.explain_confidence(self.model)
        self.assertIn("0.85", explanation)
        self.assertIn("moderate agreement", explanation)

    def test_local_recommendation_builder(self):
        recs = recommendation_builder.build_recommendations(self.model)
        self.assertIn("Do not click links or enter credentials on linked sites.", recs)
        self.assertIn("Verify the sender's identity through a secondary, out-of-band channel.", recs)

    def test_report_formatter(self):
        response = ExplanationResponse(
            technical_summary="Technical analyst summary [BR_001]",
            user_summary="Caution user summary [CT_002]",
            executive_summary="Business summary",
            attack_chain=["Stage 1 (Confidence: 0.9) [BR_001]"],
            recommendations=["mitigation step 1"],
            confidence_reasoning="attribution info",
            schema_version="1.0.0"
        )
        md = report_formatter.format_report(response, "markdown")
        self.assertIn("Technical Summary (Analyst Report)", md)
        self.assertIn("Technical analyst summary [BR_001]", md)
        
        js = report_formatter.format_report(response, "json")
        self.assertIn("technical_summary", js)

    async def test_explainability_orchestrator_success(self):
        response_text = """{
            "technical_summary": "Technical detail summary [BR_001] [CT_002]",
            "user_summary": "User safety warning [BR_001] [CT_002]",
            "executive_summary": "Executive briefing",
            "attack_chain": ["Spoofed Domain Detected (Confidence: 0.95) [BR_001]"],
            "recommendations": ["Do not click links"],
            "confidence_reasoning": "Attributed to high agreement",
            "schema_version": "1.0.0"
        }"""
        mock_client = MockAnthropicClient(should_fail=False, response_text=response_text)
        orchestrator = ExplainabilityOrchestrator(mock_client)
        
        exp_res, traces = await orchestrator.generate_explanations(self.model)
        
        self.assertEqual(exp_res.technical_summary, "Technical detail summary [BR_001] [CT_002]")
        self.assertEqual(exp_res.attack_chain[0], "Spoofed Domain Detected (Confidence: 0.95) [BR_001]")
        
        # Verify traces
        self.assertTrue(any("AI_EXPLAINABILITY_STATE: INITIAL" in trace for trace in traces))
        self.assertTrue(any("AI_EXPLAINABILITY_STATE: AI_ANALYSIS" in trace for trace in traces))
        self.assertTrue(any("AI_EXPLAINABILITY_STATE: VALIDATED" in trace for trace in traces))
        self.assertTrue(any("AI_EXPLAINABILITY_STATE: COMPLETE" in trace for trace in traces))

    async def test_explainability_orchestrator_fallback(self):
        # Triggers local fallback due to API failure
        mock_client = MockAnthropicClient(should_fail=True)
        orchestrator = ExplainabilityOrchestrator(mock_client)
        
        exp_res, traces = await orchestrator.generate_explanations(self.model)
        
        # Assert fallback generated outputs populated correctly
        self.assertIn("[BR_001]", exp_res.technical_summary)
        self.assertEqual(len(exp_res.attack_chain), 2)
        
        # Verify traces recorded warning and fallback transitions
        self.assertTrue(any("AI_EXPLAINABILITY_STATE: FALLBACK" in trace for trace in traces))
        self.assertTrue(any("WARNING" in trace for trace in traces))

if __name__ == "__main__":
    unittest.main()
