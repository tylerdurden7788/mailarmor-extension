import unittest
import asyncio
from models.email_model import Email
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine

class TestSemanticIntelligence(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_scenario_bec_payroll_fraud(self):
        # Scenario: BEC requesting urgent salary direct deposit routing bank changes
        payload = {
            "subject": "Direct Deposit Update Request",
            "sender": "john.ceo@external-mail.com",
            "body": "Hello Finance, I need you to immediately change my direct deposit routing details for my next salary payment. As CEO, I need this resolved ASAP today.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_005", report.triggered_rules) # BEC
        self.assertIn("SEM_007", report.triggered_rules) # Payment Diversion
        self.assertIn("SEM_008", report.triggered_rules) # CEO Fraud
        self.assertIn("SEM_009", report.triggered_rules) # Payroll Fraud
        self.assertIn("SEM_003", report.triggered_rules) # SE tactics (Urgency, Authority)

    def test_scenario_credential_harvesting(self):
        # Scenario: Microsoft account verification notice log-in
        payload = {
            "subject": "Action Required: Microsoft Account Suspension warning",
            "sender": "admin@office365-verify.com",
            "body": "Warning: Your Microsoft account will be suspended within 24 hours. Log in immediately to verify your credentials and reset password to prevent lockout.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_004", report.triggered_rules) # Credential Harvesting
        self.assertIn("SEM_010", report.triggered_rules) # Account Takeover
        self.assertIn("SEM_026", report.triggered_rules) # Brand Abuse (Microsoft mentioned from office365-verify.com)

    def test_scenario_oauth_consent_phishing(self):
        # Scenario: Third-party app requesting OAuth consent/scopes
        payload = {
            "subject": "Review requested: Grant app permissions",
            "sender": "app@permissions-oauth.com",
            "body": "Please review this request to grant full app scopes to read email and folders via oauth consent.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_011", report.triggered_rules) # OAuth Consent

    def test_scenario_mfa_harvesting(self):
        # Scenario: MFA OTP passcode harvesting pretext
        payload = {
            "subject": "Verify one-time passcode OTP",
            "sender": "verification@chase-security.com",
            "body": "Input the OTP one-time verification passcode code now to confirm your transaction details.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_012", report.triggered_rules) # MFA Harvesting
        self.assertIn("SEM_016", report.triggered_rules) # Banking Scam

    def test_scenario_qr_phishing(self):
        # Scenario: QR Code scan pretext
        payload = {
            "subject": "Security matrix matrix code update",
            "sender": "helpdesk@company-it.com",
            "body": "Please scan this QR code with your mobile device to complete system configuration.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_013", report.triggered_rules) # QR Phishing

    def test_scenario_delivery_scam(self):
        # Scenario: FedEx delivery delayed action required within 24h
        payload = {
            "subject": "Shipment Alert: FedEx parcel update",
            "sender": "alert@fedex-shipping-confirm.com",
            "body": "FedEx package delivery delayed. Action required within 24 hours. Input tracking or pay address fee to release.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_015", report.triggered_rules) # Delivery Scam

    def test_scenario_extortion_blackmail(self):
        # Scenario: Webcam video leak extortion demand
        payload = {
            "subject": "Security compromise: webcam recording threat",
            "sender": "hacker@extortion-network.com",
            "body": "I have compromised your webcam spyware and recorded you. Send $1000 in bitcoin to wallet address to prevent leak.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_025", report.triggered_rules) # Blackmail Extortion
        self.assertIn("SEM_018", report.triggered_rules) # Crypto Scam

    def test_scenario_tax_scam(self):
        # Scenario: IRS tax refund audit
        payload = {
            "subject": "Tax refund notice: check available",
            "sender": "refund@irs-government.com",
            "body": "IRS Revenue Service tax refund is ready. Log in immediately to verify routing details.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertIn("SEM_022", report.triggered_rules) # Tax Scam

    def test_scenario_romance_job_charity_scams(self):
        # Scenario: Romance plea, job career check, charity plea
        payload_romance = {
            "subject": "Dearest, need your help",
            "sender": "lonely@romance-dating.com",
            "body": "My dear sweetheart, I want to meet you but need you to transfer money to my bank details.",
            "attachments": []
        }
        email_romance = EmailParser.parse_api_payload(payload_romance)
        report_romance = self.run_async(RuleEngine.run_analysis(email_romance))
        self.assertIn("SEM_019", report_romance.triggered_rules) # Romance Scam
        
        payload_job = {
            "subject": "Hiring Work From Home Career offer",
            "sender": "hr@job-recruit.com",
            "body": "We are hiring for work from home position. You won a salary bonus. Deposit check details to confirm.",
            "attachments": []
        }
        email_job = EmailParser.parse_api_payload(payload_job)
        report_job = self.run_async(RuleEngine.run_analysis(email_job))
        self.assertIn("SEM_020", report_job.triggered_rules) # Job Scam

        payload_charity = {
            "subject": "Disaster Relief urgent appeal",
            "sender": "relief@charity-support.org",
            "body": "Please donate direct deposit funds to help disaster victims.",
            "attachments": []
        }
        email_charity = EmailParser.parse_api_payload(payload_charity)
        report_charity = self.run_async(RuleEngine.run_analysis(email_charity))
        self.assertIn("SEM_021", report_charity.triggered_rules) # Charity Scam

    def test_scenario_legit_calendar_newsletter(self):
        # Legitimate corporate communications (low threat, zero triggers)
        payload = {
            "subject": "Weekly Newsletter",
            "sender": "newsletter@company.com",
            "body": "Hi team, here is the weekly recap. No login is requested. Enjoy your weekend.",
            "attachments": []
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertNotIn("SEM_004", report.triggered_rules)
        self.assertNotIn("SEM_005", report.triggered_rules)

if __name__ == '__main__':
    unittest.main()
