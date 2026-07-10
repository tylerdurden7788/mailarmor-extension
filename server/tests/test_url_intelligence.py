import unittest
import asyncio
from unittest.mock import patch
from models.email_model import Email, Link
from scanner.email_parser import EmailParser
from scanner.rule_engine import RuleEngine

class TestURLIntelligence(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_1_google_urls(self, mock_trace):
        # Legitimate Google search/drive link (should be clean)
        mock_trace.return_value = ["https://drive.google.com/drive/folders/12345?usp=sharing"]
        
        payload = {
            "subject": "Shared Drive",
            "sender": "partner@gmail.com",
            "body": "Check this out: https://drive.google.com/drive/folders/12345?usp=sharing"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Verify no suspicious URL triggers
        self.assertNotIn("URL_002", report.triggered_rules)
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_2_microsoft_urls(self, mock_trace):
        mock_trace.return_value = ["https://teams.microsoft.com/l/meetup-join/123"]
        payload = {
            "subject": "Meeting",
            "sender": "colleague@microsoft.com",
            "body": "Join here: https://teams.microsoft.com/l/meetup-join/123"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_002", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_3_github_urls(self, mock_trace):
        mock_trace.return_value = ["https://github.com/tylerdurden7788/mailarmor-extension"]
        payload = {
            "subject": "Pull Request",
            "sender": "dev@github.com",
            "body": "Check PR: https://github.com/tylerdurden7788/mailarmor-extension"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_002", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_4_aws_signed_urls(self, mock_trace):
        # AWSAccessKeyId inside query parameters on trusted amazonaws domain (should be bypassed)
        aws_url = "https://my-bucket.s3.amazonaws.com/invoice.pdf?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=vjbyPxybdZaNmGa%2ByT272YEAiv4%3D&Expires=1700000000"
        mock_trace.return_value = [aws_url]
        payload = {
            "subject": "Your Invoice",
            "sender": "billing@amazon.com",
            "body": f"Download invoice: {aws_url}"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Verify that credential token leaks do not fire for trusted Amazon AWS flows
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_5_azure_urls(self, mock_trace):
        mock_trace.return_value = ["https://mystorage.blob.core.windows.net/containers/file.txt"]
        payload = {
            "subject": "Storage Blob",
            "sender": "admin@microsoft.com",
            "body": "Link: https://mystorage.blob.core.windows.net/containers/file.txt"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_6_dropbox_urls(self, mock_trace):
        mock_trace.return_value = ["https://www.dropbox.com/s/12345/document.pdf?dl=0"]
        payload = {
            "subject": "File Share",
            "sender": "friend@gmail.com",
            "body": "Here: https://www.dropbox.com/s/12345/document.pdf?dl=0"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_7_onedrive_urls(self, mock_trace):
        mock_trace.return_value = ["https://onedrive.live.com/download?cid=123&authkey=456"]
        payload = {
            "subject": "OneDrive Direct Link",
            "sender": "office@live.com",
            "body": "Download: https://onedrive.live.com/download?cid=123&authkey=456"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_8_oauth_redirect_urls(self, mock_trace):
        # OAuth flow parameters on trusted google domain (should be bypassed)
        oauth_url = "https://accounts.google.com/o/oauth2/auth?client_id=123&redirect_uri=https://my-oauth-app.com/callback&response_type=code"
        mock_trace.return_value = [oauth_url]
        payload = {
            "subject": "Log in to App",
            "sender": "oauth@my-oauth-app.com",
            "body": f"Authenticate: {oauth_url}"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Verify OIDC/OAuth redirect flow parameters do not trigger credential/token warnings
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_9_tracking_urls(self, mock_trace):
        # Tracking tokens (utm parameters & fbclid) (should be bypassed)
        track_url = "https://newsletter.com/track?utm_source=email&utm_campaign=summer&fbclid=IwAR123"
        mock_trace.return_value = [track_url]
        payload = {
            "subject": "Weekly Newsletter",
            "sender": "marketing@newsletter.com",
            "body": f"Read here: {track_url}"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_10_cdn_urls(self, mock_trace):
        mock_trace.return_value = ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"]
        payload = {
            "subject": "Script tag",
            "sender": "webmaster@company.com",
            "body": "Download CDN: https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        self.assertNotIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_11_url_shorteners(self, mock_trace):
        mock_trace.return_value = ["https://bit.ly/3abc", "https://google.com"]
        payload = {
            "subject": "Short Link",
            "sender": "friend@gmail.com",
            "body": "Click: https://bit.ly/3abc"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger shortener warning
        self.assertIn("URL_003", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_12_ip_address_urls(self, mock_trace):
        mock_trace.return_value = ["http://192.168.1.1/login"]
        payload = {
            "subject": "Router configuration",
            "sender": "admin@gmail.com",
            "body": "Access panel: http://192.168.1.1/login"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger raw IP address warning
        self.assertIn("URL_002", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_13_homograph_domains(self, mock_trace):
        # Cyrillic small letter a
        mock_trace.return_value = ["https://p\u0430ypal.com/signin"]
        payload = {
            "subject": "Update account details",
            "sender": "support@paypal.com",
            "body": "Access security center: https://p\u0430ypal.com/signin"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger homograph warning
        self.assertIn("UNI_001", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_14_punycode_domains(self, mock_trace):
        mock_trace.return_value = ["https://xn--pypal-43d.com/login"]
        payload = {
            "subject": "Login update",
            "sender": "member@paypal.com",
            "body": "Link: https://xn--pypal-43d.com/login"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        self.assertTrue(any(r in report.triggered_rules for r in ["UNI_001", "UNI_002"]))

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_15_typosquatting_domains(self, mock_trace):
        # typosquatting of Microsoft using Levenshtein distance
        mock_trace.return_value = ["https://microsoftt.com/login"]
        payload = {
            "subject": "Office 365 alert",
            "sender": "alert@microsoft.com",
            "body": "Link: https://microsoftt.com/login"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger brand typosquatting
        self.assertIn("BRD_001", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_16_encoded_urls(self, mock_trace):
        mock_trace.return_value = ["https://example.com/login%2fadmin"]
        payload = {
            "subject": "Encoded",
            "sender": "test@gmail.com",
            "body": "Go: https://example.com/login%2fadmin"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Verify it parses correctly without crashing
        self.assertNotIn("GEN_ERR", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_17_double_encoded_urls(self, mock_trace):
        # %252f is double encoding of / (%25 -> %)
        mock_trace.return_value = ["https://example.com/login%252fadmin"]
        payload = {
            "subject": "Double encoded",
            "sender": "test@gmail.com",
            "body": "Go: https://example.com/login%252fadmin"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger double percent encoding warning
        self.assertIn("URL_010", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_18_redirect_chains(self, mock_trace):
        # Redirect chain loops back to start (loop)
        mock_trace.return_value = ["https://hop1.com", "https://hop2.com", "https://hop1.com"]
        payload = {
            "subject": "Loop Redirect",
            "sender": "tester@test.com",
            "body": "Loop: https://hop1.com"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger loop/infinite redirect chain warning
        self.assertIn("URL_007", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_19_credential_leakage_urls(self, mock_trace):
        # Plain username password in URL
        mock_trace.return_value = ["http://admin:secret123@untrusted-domain.com/dashboard"]
        payload = {
            "subject": "Leaked login details",
            "sender": "spammer@gmail.com",
            "body": "Try: http://admin:secret123@untrusted-domain.com/dashboard"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger critical credential leak warning
        self.assertIn("URL_006", report.triggered_rules)

    @patch('utils.url_resolver.URLRedirectResolver._trace_redirects_sync')
    def test_scenario_20_suspicious_query_parameters(self, mock_trace):
        # Sensitive jwt token parameter on untrusted domain
        mock_trace.return_value = ["https://untrusted-site.com/auth?token=12345"]
        payload = {
            "subject": "Auth Statement",
            "sender": "test@untrusted-site.com",
            "body": "Token link: https://untrusted-site.com/auth?token=12345"
        }
        email = EmailParser.parse_api_payload(payload)
        report = self.run_async(RuleEngine.run_analysis(email))
        
        # Must trigger sensitive token leak warning
        self.assertIn("URL_006", report.triggered_rules)

if __name__ == '__main__':
    unittest.main()
