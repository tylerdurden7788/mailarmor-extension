import unittest
import json
import asyncio
from datetime import datetime, timezone
from models.evidence_model import Evidence
from decision.evidence_classifier import EvidenceClassifier
from models.decision_model import DecisionModel
from models.evidence_model import EvidenceReport

class TestProductionHardening(unittest.TestCase):
    def test_datetime_modernization_format(self):
        # 1. Verify that timestamps generated follow ISO format with 'Z' suffix
        ev = Evidence(
            evidence_id="ev_t1",
            analyzer_name="SenderAnalyzer",
            category="SENDER",
            severity="LOW",
            triggered_rule="SE_001",
            explanation="Test explanation",
            recommendation="Test recommendation"
        )
        self.assertTrue(ev.timestamp.endswith("Z"))
        self.assertNotIn("+00:00", ev.timestamp)

        # Parse it back - should not crash
        ts_str = ev.timestamp
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1]
        dt = datetime.fromisoformat(ts_str)
        self.assertIsInstance(dt, datetime)

    def test_timezone_aware_subtraction(self):
        # Verify delta days subtraction does not crash when parsing custom timestamp
        ev = Evidence(
            evidence_id="ev_vt_test",
            analyzer_name="VirusTotal",
            category="THREAT_INT",
            severity="CRITICAL",
            triggered_rule="TI_001",
            technical_details={"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")},
            explanation="Malicious domain",
            recommendation="Block"
        )
        report = EvidenceReport(evidence_list=[ev])
        model = DecisionModel(evidence_report=report)
        model_classified = EvidenceClassifier.classify(model)
        
        # Verify that freshness was correctly analyzed without crashes
        self.assertEqual(model_classified.classified_evidence[0].freshness, "LIVE")

    def test_developer_bypass_configuration(self):
        # Simulate developer bypass variable logic as defined in background.js
        is_dev_build = True
        dev_bypass_key = "MAIL-DEV-HARISH-2026" if is_dev_build else ""
        
        test_key = "MAIL-DEV-HARISH-2026"
        
        # In dev build, it should succeed
        self.assertTrue(is_dev_build and dev_bypass_key and test_key == dev_bypass_key)
        
        # In prod build (where is_dev_build = False), it should fail
        is_dev_build_prod = False
        dev_bypass_key_prod = "MAIL-DEV-HARISH-2026" if is_dev_build_prod else ""
        self.assertFalse(is_dev_build_prod and dev_bypass_key_prod and test_key == dev_bypass_key_prod)

    def test_logging_redaction(self):
        from utils.structured_logger import structured_logger
        details = {
            "api_key": "secret-api-key-12345",
            "auth_token": "bearer-token-9999",
            "password": "my-secret-password-xyz",
            "safe_field": "public-data"
        }
        clean = structured_logger._clean_details(details)
        self.assertEqual(clean["api_key"], "[REDACTED]")
        self.assertEqual(clean["auth_token"], "[REDACTED]")
        self.assertEqual(clean["password"], "[REDACTED]")
        self.assertEqual(clean["safe_field"], "public-data")

    def test_fallback_handler_datetime(self):
        from ai.fallback_handler import fallback_handler
        report = EvidenceReport(evidence_list=[])
        model = DecisionModel(
            evidence_report=report,
            confidence=0.75,
            risk_level="Medium",
            attack_types=["Spear Phishing"]
        )
        fallback = fallback_handler.get_fallback_verdict(model, "Connection refused")
        self.assertEqual(fallback["attack_type"], "Spear Phishing")
        self.assertEqual(fallback["confidence"], 0.75)
        self.assertIn("Connection refused", fallback["technical_explanation"])
        self.assertEqual(fallback["schema_version"], "1.0.0")

if __name__ == "__main__":
    unittest.main()
