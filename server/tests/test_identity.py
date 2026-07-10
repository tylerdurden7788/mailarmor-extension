import unittest
import asyncio
from models.email_model import Email
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine

class TestIdentityVerification(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_scenario_1_legitimate_gmail(self):
        # Legitimate Gmail sender, no brand spoofing
        payload = {
            "subject": "Hey! Long time no see",
            "sender": "Alice Smith <alice.smith@gmail.com>",
            "body": "Hi, just checking in to see how you are doing."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Verify no brand spoofing or free email impersonation is triggered
        triggered = report.triggered_rules
        self.assertNotIn("BRD_001", triggered)
        self.assertNotIn("SND_003", triggered)

    def test_scenario_2_legitimate_microsoft(self):
        # Official Microsoft domain for Microsoft brand
        payload = {
            "subject": "Security Alert",
            "sender": "Microsoft Security <security@microsoft.com>",
            "body": "Please review your recent logins."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Should NOT trigger brand impersonation (as it is official)
        self.assertNotIn("BRD_001", report.triggered_rules)

    def test_scenario_3_legitimate_paypal(self):
        # Official PayPal domain for PayPal brand
        payload = {
            "subject": "Receipt for your payment",
            "sender": "PayPal Support <support@paypal.com>",
            "body": "Thank you for using PayPal."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Should NOT trigger brand impersonation
        self.assertNotIn("BRD_001", report.triggered_rules)

    def test_scenario_4_display_name_spoofing(self):
        # Free provider impersonating PayPal
        payload = {
            "subject": "Update your credentials",
            "sender": "PayPal Support <resolution-paypal@gmail.com>",
            "body": "Your account has been restricted. Action required."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand impersonation AND free provider impersonation
        self.assertIn("BRD_001", report.triggered_rules)
        self.assertIn("SND_003", report.triggered_rules)

    def test_scenario_5_reply_to_mismatch(self):
        # Reply-To differs from From header
        payload = {
            "subject": "Project Proposal",
            "sender": "Alice Smith <alice@gmail.com>",
            "body": "Here is the proposal."
        }
        email = EmailParser.parse_api_payload(payload)
        # Manually set reply_to
        email.reply_to = "attacker@gmail.com"
        
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger Reply-To mismatch
        self.assertIn("SND_001", report.triggered_rules)

    def test_scenario_6_homograph_domains(self):
        # Homoglyph spoof using Cyrillic small letter a (U+0430)
        # pаypal.com
        payload = {
            "subject": "Account suspension warning",
            "sender": "PayPal <security@p\u0430ypal.com>",
            "body": "Login immediately."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger Unicode homoglyph AND brand impersonation
        self.assertIn("UNI_001", report.triggered_rules)
        self.assertIn("BRD_001", report.triggered_rules)

    def test_scenario_7_punycode_domains(self):
        # Punycode format spoof (xn--pypal-43d.com -> pаypal.com)
        payload = {
            "subject": "Security notice",
            "sender": "Security Team <info@xn--pypal-43d.com>",
            "body": "Review changes."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger Unicode homoglyph/Punycode rule
        self.assertTrue(any(r in report.triggered_rules for r in ["UNI_001", "UNI_002"]))

    def test_scenario_8_fake_paypal(self):
        # Unofficial lookalike domain claiming brand
        payload = {
            "subject": "Verify your identity",
            "sender": "PayPal Support <billing@paypal-update-login.com>",
            "body": "Confirm card details."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand impersonation (unofficial domain for brand display name)
        self.assertIn("BRD_001", report.triggered_rules)

    def test_scenario_9_fake_microsoft(self):
        # Unofficial domain claiming Microsoft
        payload = {
            "subject": "Urgent Outlook Update",
            "sender": "Microsoft Admin <verification@microsoft-alert.support>",
            "body": "Immediate update needed."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand impersonation
        self.assertIn("BRD_001", report.triggered_rules)

    def test_scenario_10_fake_amazon(self):
        # Amazon display name with fake billing department on unofficial domain
        payload = {
            "subject": "Order Confirmation",
            "sender": "Amazon Prime Billing <orders@amazon-support-desk.com>",
            "body": "Your order was processed successfully."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand impersonation AND fake department rule
        self.assertIn("BRD_001", report.triggered_rules)
        self.assertIn("BRD_002", report.triggered_rules)

    def test_scenario_11_excessive_subdomains(self):
        # Nested labels count > 4
        payload = {
            "subject": "Alert",
            "sender": "Alert <security.update.login.accounts.domain.com>",
            "body": "Verify account details."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger excessive subdomains
        self.assertIn("DOM_003", report.triggered_rules)

    def test_scenario_12_mixed_unicode_domains(self):
        # Homoglyph spoof using Cyrillic small letter i (U+0456)
        # mіcrosoft.com
        payload = {
            "subject": "Office billing notice",
            "sender": "Microsoft Team <billing@m\u0456crosoft.com>",
            "body": "Verify payment method."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger Unicode homoglyph AND brand impersonation
        self.assertIn("UNI_001", report.triggered_rules)
        self.assertIn("BRD_001", report.triggered_rules)

    def test_scenario_13_header_inconsistencies(self):
        # From domain, Sender domain, and Message-ID domain mismatch
        payload = {
            "subject": "Direct Deposit Notice",
            "sender": "Company Support <info@company.com>",
            "body": "Your statement is ready."
        }
        email = EmailParser.parse_api_payload(payload)
        email.sender_header = "mailer@otherdomain.com"
        email.message_id = "<123@anothertarget.com>"
        
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger Header Inconsistency
        self.assertIn("HDR_001", report.triggered_rules)

    def test_scenario_14_legitimate_newsletters(self):
        # Stripe newsletter using mailchimp relay (allowed exceptions)
        payload = {
            "subject": "Monthly product digest",
            "sender": "Stripe <billing@stripe.com>",
            "body": "Here is what's new."
        }
        email = EmailParser.parse_api_payload(payload)
        # Shared org or common exception domains
        email.sender_header = "stripe@mail.stripe.com"
        email.message_id = "<123@mailchimpapp.net>"
        
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Should NOT trigger inconsistent headers
        self.assertNotIn("HDR_001", report.triggered_rules)

    def test_scenario_15_legitimate_multi_domain_organizations(self):
        # Official regional domain (google.co.uk) representing Google
        payload = {
            "subject": "Google Account Recovery",
            "sender": "Google Support <support@google.co.uk>",
            "body": "Recovery code is 123456."
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Should NOT trigger brand impersonation (since google.co.uk is recognized)
        self.assertNotIn("BRD_001", report.triggered_rules)

if __name__ == '__main__':
    unittest.main()
