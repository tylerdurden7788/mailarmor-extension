import unittest
import asyncio
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone

from models.evidence_model import EvidenceReport, Evidence
from models.decision_model import DecisionModel
from models.threat_intelligence_model import ProviderResult, ThreatEvidence, ThreatObservable
from decision.decision_engine import DecisionEngine
from decision.evidence_classifier import EvidenceClassifier
from decision.correlation_engine import CorrelationEngine
from decision.confidence_engine import ConfidenceEngine
from decision.risk_engine import RiskEngine
from decision.claude_context_builder import ClaudeContextBuilder
from decision.explainability_engine import ExplainabilityEngine
from decision.recommendation_engine import RecommendationEngine
from scanner.rule_engine import RuleEngine
from models.email_model import Email, Link

class TestThreatFusion(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def test_evidence_classification_threat_intel(self):
        # Create a raw threat intelligence evidence
        raw_ev = Evidence(
            evidence_id="ev_vt_test",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="CRITICAL",
            triggered_rule="TI_001",
            technical_details={"observable_queried": "unsafe.com", "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
            confidence=0.90,
            explanation="Malicious domain",
            recommendation="Block"
        )
        report = EvidenceReport(evidence_list=[raw_ev])
        model = DecisionModel(evidence_report=report)
        
        # Classify
        model_classified = EvidenceClassifier.classify(model)
        classified_ev = model_classified.classified_evidence[0]
        
        # Verify classification properties
        self.assertEqual(classified_ev.provider_reliability, 0.95) # VirusTotal reliability
        self.assertEqual(classified_ev.freshness, "LIVE")
        self.assertEqual(classified_ev.technical_details["priority"], "Critical")
        self.assertEqual(classified_ev.technical_details["quality"], "Verified")

    def test_correlation_and_consensus_building(self):
        # Create multiple threat intelligence items for the same domain target
        ev1 = Evidence(
            evidence_id="ev_vt_test",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="CRITICAL",
            triggered_rule="TI_001",
            technical_details={"domain": "badsite.com", "tags": ["PhishingCampaign1"]},
            confidence=0.90,
            explanation="Malicious domain",
            recommendation="Block"
        )
        ev2 = Evidence(
            evidence_id="ev_pt_test",
            analyzer_name="PhishTank",
            category="THREAT_INT",
            severity="HIGH",
            triggered_rule="TI_002",
            technical_details={"domain": "badsite.com", "tags": ["CredentialHarvesting"]},
            confidence=0.85,
            explanation="Phishing page detected",
            recommendation="Block"
        )
        
        report = EvidenceReport(evidence_list=[ev1, ev2])
        model = DecisionModel(evidence_report=report)
        
        # Classify & Correlate
        model = EvidenceClassifier.classify(model)
        model = CorrelationEngine.correlate(model)
        
        # Expect 1 primary correlated threat consensus evidence
        self.assertEqual(len(model.correlated_evidence), 1)
        consensus_ev = model.correlated_evidence[0]
        
        # Verify target is grouped and consensus is stored
        self.assertEqual(consensus_ev.analyzer_name, "ThreatConsensus")
        self.assertEqual(consensus_ev.agreement_score, 1.0) # both providers agreed on detection
        self.assertEqual(consensus_ev.technical_details["provider_count"], 2)
        self.assertIn("VirusTotal", consensus_ev.supporting_providers)
        self.assertIn("PhishTank", consensus_ev.supporting_providers)
        self.assertIn("PhishingCampaign1", consensus_ev.technical_details["campaign_tags"])
        self.assertIn("CredentialHarvesting", consensus_ev.technical_details["campaign_tags"])

    def test_confidence_engine_with_threat_intelligence(self):
        # Test confidence penalty on contradictions
        local_ev = Evidence(
            evidence_id="ev_local_brand",
            analyzer_name="BrandAnalyzer",
            category="BRAND",
            severity="HIGH",
            triggered_rule="BRD_001",
            technical_details={"domain": "spoofsite.com"},
            confidence=0.80,
            explanation="Brand spoofing detected",
            recommendation="Block"
        )
        # Threat intel says safe (agreement_score = 0.0)
        threat_ev = Evidence(
            evidence_id="ev_vt_domain",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="INFO",
            triggered_rule="TI_004",
            technical_details={"domain": "spoofsite.com"},
            confidence=0.50,
            explanation="No detections",
            recommendation="None"
        )
        
        report = EvidenceReport(evidence_list=[local_ev, threat_ev])
        model = DecisionModel(evidence_report=report)
        model = EvidenceClassifier.classify(model)
        model = CorrelationEngine.correlate(model)
        
        # Run confidence engine
        model = ConfidenceEngine.calculate(model)
        
        # Expect local evidence has relationship 'contradicts'
        correlated_local = [ev for ev in model.correlated_evidence if ev.category == "BRAND"][0]
        self.assertEqual(correlated_local.technical_details["correlation_relationship"], "contradicts")
        
        # Confidence score should have a penalty applied
        self.assertTrue(model.confidence < 0.80) # Less than base local high confidence

    def test_risk_level_safety_override(self):
        # Scenario 1: Threat intelligence indicates high threat, but NO local critical/high findings
        threat_ev = Evidence(
            evidence_id="ev_vt_malicious",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="CRITICAL",
            triggered_rule="TI_001",
            technical_details={"domain": "suspicious-domain.com"},
            confidence=0.90,
            explanation="Known malicious site",
            recommendation="Block"
        )
        report = EvidenceReport(evidence_list=[threat_ev])
        model = DecisionModel(evidence_report=report)
        model = EvidenceClassifier.classify(model)
        model = CorrelationEngine.correlate(model)
        model = ConfidenceEngine.calculate(model)
        
        # Assess risk
        model = RiskEngine.assess(model)
        
        # Risk level should be capped to Medium (verdict SUSPICIOUS) since there is no local high/critical evidence
        self.assertEqual(model.risk_level, "Medium")

    def test_explainability_and_recommendations_with_threat_intel(self):
        ev = Evidence(
            evidence_id="ev_vt_test",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="CRITICAL",
            triggered_rule="TI_001",
            technical_details={"domain": "badsite.com", "tags": ["PhishingCampaign1"]},
            confidence=0.90,
            explanation="Malicious domain",
            recommendation="Block"
        )
        report = EvidenceReport(evidence_list=[ev])
        model = DecisionModel(
            evidence_report=report,
            verdict="SUSPICIOUS"
        )
        model = EvidenceClassifier.classify(model)
        model = CorrelationEngine.correlate(model)
        model = ExplainabilityEngine.generate(model)
        model = RecommendationEngine.generate(model)
        
        # Confirm threat intelligence provider names are cited in technical explanation
        self.assertIn("VirusTotal", model.technical_explanation)
        
        # Confirm user-facing explanation references campaign or reputation or multiple malicious providers
        self.assertTrue(
            "reputation" in model.user_explanation.lower() or 
            "malicious" in model.user_explanation.lower() or
            "campaign" in model.user_explanation.lower()
        )

    @patch("scanner.rule_engine.global_threat_manager.lookup_observables")
    def test_integrated_rule_engine_pipeline(self, mock_lookup):
        # Mock threat lookup response
        mock_lookup.return_value = [
            ProviderResult(
                provider_name="VirusTotal",
                provider_status="SUCCESS",
                evidence=[
                    ThreatEvidence(
                        provider="VirusTotal",
                        observable="malicious-domain.com",
                        observable_type="Domain",
                        classification="Malicious",
                        severity="CRITICAL",
                        provider_confidence=0.95,
                        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        technical_details={"tags": ["phishing"]}
                    )
                ],
                lookup_time_ms=10.0,
                cache_hit=False,
                timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
        ]
        
        # Run integrated pipeline
        email = Email(
            sender_header="attacker@spoof.com",
            subject="Action required",
            body_text="Please visit http://malicious-domain.com/login",
            urls=[
                Link(
                    actual_url="http://malicious-domain.com/login",
                    display_text="Click here"
                )
            ]
        )
        
        async def run_test():
            report = await RuleEngine.run_analysis(email)
            # Find the threat intelligence evidence in report
            ti_ev = [ev for ev in report.evidence_list if ev.category == "THREAT_INT"]
            self.assertTrue(len(ti_ev) > 0)
            self.assertEqual(ti_ev[0].analyzer_name, "VirusTotal")
            self.assertEqual(ti_ev[0].severity, "CRITICAL")
            self.assertEqual(ti_ev[0].triggered_rule, "TI_001")
            
        self.loop.run_until_complete(run_test())

if __name__ == "__main__":
    unittest.main()
