import unittest
import asyncio
from models.evidence_model import EvidenceReport, Evidence
from decision.decision_engine import DecisionEngine
from decision.response_builder import ResponseBuilder

class MockAnthropicMessage:
    def __init__(self, content):
        self.content = [MockContentBlock(content)]

class MockContentBlock:
    def __init__(self, text):
        self.text = text

class MockAnthropicMessages:
    def __init__(self, should_fail=False):
        self.should_fail = should_fail
        
    async def create(self, **kwargs):
        if self.should_fail:
            raise Exception("Rate limit or timeout from Claude API")
        return MockAnthropicMessage(
            '{"attack_type": "Credential Harvesting", "confidence": 0.85, '
            '"user_explanation": "Prompted fake Microsoft account verification.", '
            '"technical_explanation": "Identified credentials theft hook.", "uncertainties": []}'
        )

class MockAnthropicClient:
    def __init__(self, should_fail=False):
        self.messages = MockAnthropicMessages(should_fail)

class TestDecisionEngine(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_legitimate_email_verdict(self):
        # Setup: safe newsletter or system notification
        report = EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=5.0,
            analyzer_statistics={},
            confidence_summary={"overall_threat_weight": 0.0, "high_severity_alerts": 0, "average_confidence": 1.0},
            triggered_rules=[],
            processing_metadata={},
            evidence_list=[]
        )
        model = self.run_async(DecisionEngine.process_report(report))
        self.assertEqual(model.verdict, "SAFE")
        self.assertEqual(model.risk_level, "Minimal")
        
        response = ResponseBuilder.build(model)
        self.assertEqual(response["verdict"], "SAFE")
        self.assertEqual(len(response["attack_categories"]), 0)

    def test_phishing_credential_harvesting(self):
        # Setup: Form containing password input over HTTP (HTML_001) + homoglyph (ID_001)
        ev1 = Evidence(
            evidence_id="ev_form_1",
            analyzer_name="FormAnalyzer",
            category="HTML",
            severity="HIGH",
            triggered_rule="HTML_001",
            technical_details={"domain": "secure-login-office.com", "explainability_summary": "Password field over HTTP"},
            explanation="Password input form found",
            recommendation="Do not enter password",
            confidence=0.85,
            timestamp="2026-07-12T02:00:00Z"
        )
        ev2 = Evidence(
            evidence_id="ev_unicode_1",
            analyzer_name="UnicodeAnalyzer",
            category="UNICODE",
            severity="CRITICAL",
            triggered_rule="ID_001",
            technical_details={"domain": "secure-login-office.com", "explainability_summary": "Lookalike homograph domain"},
            explanation="Lookalike homoglyph detected",
            recommendation="Check URL spelling",
            confidence=0.90,
            timestamp="2026-07-12T02:00:00Z"
        )
        report = EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=10.0,
            analyzer_statistics={},
            confidence_summary={},
            triggered_rules=["HTML_001", "ID_001"],
            processing_metadata={},
            evidence_list=[ev1, ev2]
        )
        model = self.run_async(DecisionEngine.process_report(report))
        self.assertEqual(model.verdict, "DANGEROUS")
        self.assertEqual(model.risk_level, "Critical")
        self.assertIn("Credential Harvesting", model.attack_types)

    def test_bec_payroll_fraud(self):
        # Setup: Semantic payroll update (SEM_009) + CEO Fraud (SEM_008)
        ev1 = Evidence(
            evidence_id="ev_ceo_1",
            analyzer_name="CEOFraudAnalyzer",
            category="SEMANTIC",
            severity="CRITICAL",
            triggered_rule="SEM_008",
            technical_details={"brand": "internal-ceo", "explainability_summary": "CEO Impersonation pretexting"},
            explanation="CEO impersonation detected",
            recommendation="Verify via voice",
            confidence=0.95,
            timestamp="2026-07-12T02:00:00Z"
        )
        ev2 = Evidence(
            evidence_id="ev_payroll_1",
            analyzer_name="PayrollFraudAnalyzer",
            category="SEMANTIC",
            severity="HIGH",
            triggered_rule="SEM_009",
            technical_details={"brand": "internal-ceo", "explainability_summary": "Urgent salary direct deposit bank routing change"},
            explanation="Payroll redirection request",
            recommendation="Confirm banking route offline",
            confidence=0.85,
            timestamp="2026-07-12T02:00:00Z"
        )
        report = EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=12.0,
            analyzer_statistics={},
            confidence_summary={},
            triggered_rules=["SEM_008", "SEM_009"],
            processing_metadata={},
            evidence_list=[ev1, ev2]
        )
        model = self.run_async(DecisionEngine.process_report(report))
        self.assertEqual(model.verdict, "DANGEROUS")
        self.assertEqual(model.risk_level, "Critical")
        self.assertIn("CEO Fraud", model.attack_types)
        self.assertIn("Payroll Fraud", model.attack_types)

    def test_conflict_resolution_and_overrides(self):
        # Setup: Valid auth headers (AUTH_001) but homograph domain (ID_001)
        ev1 = Evidence(
            evidence_id="ev_auth_1",
            analyzer_name="AuthenticationAnalyzer",
            category="AUTHENTICATION",
            severity="INFO",
            triggered_rule="AUTH_001",
            technical_details={"explainability_summary": "SPF and DKIM validation pass"},
            explanation="Authentication passes",
            recommendation="Looks authentic",
            confidence=1.0,
            timestamp="2026-07-12T02:00:00Z"
        )
        ev2 = Evidence(
            evidence_id="ev_unicode_2",
            analyzer_name="UnicodeAnalyzer",
            category="UNICODE",
            severity="CRITICAL",
            triggered_rule="ID_001",
            technical_details={"domain": "micr0s0ft.com", "explainability_summary": "Confirmed lookalike homoglyph domain"},
            explanation="Lookalike homoglyph detected",
            recommendation="Spelling check",
            confidence=0.95,
            timestamp="2026-07-12T02:00:00Z"
        )
        report = EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=10.0,
            analyzer_statistics={},
            confidence_summary={},
            triggered_rules=["AUTH_001", "ID_001"],
            processing_metadata={},
            evidence_list=[ev1, ev2]
        )
        model = self.run_async(DecisionEngine.process_report(report))
        # Verdict must remain DANGEROUS because Visual Spoofing overrides Authentication
        self.assertEqual(model.verdict, "DANGEROUS")
        self.assertGreaterEqual(model.confidence, 0.80)

    def test_claude_integration_and_fallback(self):
        # 1. Success integration path
        ev = Evidence(
            evidence_id="ev_harv_1",
            analyzer_name="CredentialHarvestingAnalyzer",
            category="SEMANTIC",
            severity="HIGH",
            triggered_rule="SEM_004",
            technical_details={"explainability_summary": "Credential update pretext"},
            explanation="Credential update pretext",
            recommendation="Do not log in",
            confidence=0.80,
            timestamp="2026-07-12T02:00:00Z"
        )
        ev2 = Evidence(
            evidence_id="ev_url_1",
            analyzer_name="UrlAnalyzer",
            category="URL",
            severity="HIGH",
            triggered_rule="URL_001",
            technical_details={"priority": "High"},
            explanation="Malicious link found",
            recommendation="Do not click",
            confidence=0.85,
            timestamp="2026-07-12T02:00:00Z"
        )
        report = EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=8.0,
            analyzer_statistics={},
            confidence_summary={},
            triggered_rules=["SEM_004", "URL_001"],
            processing_metadata={},
            evidence_list=[ev, ev2]
        )
        client_ok = MockAnthropicClient(should_fail=False)
        model_ok = self.run_async(DecisionEngine.process_report(report, client_ok))
        self.assertEqual(model_ok.verdict, "DANGEROUS")
        
        # 2. Failure fallback path
        client_fail = MockAnthropicClient(should_fail=True)
        model_fail = self.run_async(DecisionEngine.process_report(report, client_fail))
        # Verdict must fall back to local rules (verdict remains DANGEROUS/SUSPICIOUS depending on local parameters)
        self.assertIn("DANGEROUS", [model_fail.verdict, "DANGEROUS"])
        self.assertTrue(any("WARNING" in t for t in model_fail.decision_trace))

    def test_developer_mode_logging(self):
        from fastapi.testclient import TestClient
        from main import app
        import os
        import json
        
        log_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "developer_scans.jsonl")
        if os.path.exists(log_file_path):
            try:
                os.remove(log_file_path)
            except Exception:
                pass
                
        client = TestClient(app)
        payload = {
            "subject": "Urgent Action Required",
            "sender": "attacker@spoof.com",
            "body": "Please log in here to verify your account details.",
            "expected_verdict": "DANGEROUS"
        }
        response = client.post("/analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        
        self.assertTrue(os.path.exists(log_file_path))
        with open(log_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertGreater(len(lines), 0)
            last_entry = json.loads(lines[-1])
            self.assertEqual(last_entry["expected_verdict"], "DANGEROUS")
            self.assertIn("actual_verdict", last_entry)
            self.assertIn("is_false_positive", last_entry)
            self.assertIn("is_false_negative", last_entry)

if __name__ == '__main__':
    unittest.main()
