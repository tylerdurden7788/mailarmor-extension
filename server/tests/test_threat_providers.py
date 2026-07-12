import unittest
import asyncio
import time
from unittest.mock import patch, MagicMock, AsyncMock
from models.threat_intelligence_model import ThreatObservable, ThreatEvidence, ProviderResult
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.provider_manager import ProviderManager
from threat_intelligence.providers.whois_provider import WHOISProvider
from threat_intelligence.providers.dns_provider import DNSProvider
from threat_intelligence.providers.certificate_provider import CertificateProvider
from threat_intelligence.providers.google_safe_browsing_provider import GoogleSafeBrowsingProvider
from threat_intelligence.providers.phishtank_provider import PhishTankProvider
from threat_intelligence.providers.openphish_provider import OpenPhishProvider
from threat_intelligence.providers.urlhaus_provider import URLHausProvider
from threat_intelligence.providers.abuseipdb_provider import AbuseIPDBProvider
from threat_intelligence.providers.virustotal_provider import VirusTotalProvider
from threat_intelligence.providers.cisco_talos_provider import CiscoTalosProvider
from threat_intelligence.providers.alienvault_provider import AlienvaultOTXProvider
from threat_intelligence.providers.spamhaus_provider import SpamhausProvider
from threat_intelligence.providers.asn_provider import ASNProvider
from config.provider_config import PROVIDER_CONFIGS

class TestThreatProviders(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    @patch("threat_intelligence.http_client.http_client.request")
    def test_whois_provider(self, mock_request):
        # Mock RDAP JSON response
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap"]]]}],
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}
                ]
            },
            "error_message": None
        }
        
        provider = WHOISProvider()
        obs = ThreatObservable(value="example.com", type="Domain")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "WHOIS")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(len(res.evidence), 1)
        self.assertEqual(res.evidence[0].technical_details["registrar"], "NameCheap")
        self.assertEqual(res.evidence[0].technical_details["creation_date"], "2020-01-01")

    @patch("asyncio.get_event_loop")
    @patch("asyncio.create_subprocess_shell")
    def test_dns_provider(self, mock_subproc, mock_get_loop):
        # Mock loop.getaddrinfo and nslookup subprocess
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(return_value=[
            (2, 1, 6, "", ("93.184.216.34", 0))
        ])
        mock_get_loop.return_value = mock_loop
        
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"nameserver = ns1.example.com", b""))
        mock_subproc.return_value = mock_proc
        
        provider = DNSProvider()
        obs = ThreatObservable(value="example.com", type="Domain")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "DNS")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertIn("93.184.216.34", res.evidence[0].technical_details["a_records"])

    @patch("asyncio.get_event_loop")
    def test_certificate_provider(self, mock_get_loop):
        # Mock executor to return certificate dict
        mock_loop = MagicMock()
        mock_loop.run_in_executor = AsyncMock(return_value={
            "issuer": [[("commonName", "DigiCert")]],
            "subject": [[("commonName", "example.com")]],
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2027 GMT",
            "subjectAltName": [("DNS", "example.com")]
        })
        mock_get_loop.return_value = mock_loop
        
        provider = CertificateProvider()
        obs = ThreatObservable(value="example.com", type="Domain")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "Certificate")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].technical_details["issuer"], "DigiCert")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_google_safe_browsing_provider(self, mock_request):
        # Mock GSB match
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {
                "matches": [
                    {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL"}
                ]
            },
            "error_message": None
        }
        
        # Temp force API key set
        PROVIDER_CONFIGS["GoogleSafeBrowsing"]["api_key"] = "test_key"
        
        provider = GoogleSafeBrowsingProvider()
        obs = ThreatObservable(value="http://unsafe.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "GoogleSafeBrowsing")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].classification, "malicious")
        self.assertEqual(res.evidence[0].severity, "HIGH")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_phishtank_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {
                "results": {
                    "in_database": True,
                    "valid": True,
                    "verified": True,
                    "phish_detail_page": "http://phishtank.com/123"
                }
            },
            "error_message": None
        }
        
        provider = PhishTankProvider()
        obs = ThreatObservable(value="http://phishtest.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "PhishTank")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].classification, "malicious")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_openphish_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {"url": "http://openphishtest.com", "phish": True, "brand": "Microsoft"},
            "error_message": None
        }
        
        PROVIDER_CONFIGS["OpenPhish"]["api_key"] = "test_key"
        
        provider = OpenPhishProvider()
        obs = ThreatObservable(value="http://openphishtest.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "OpenPhish")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].technical_details["brand"], "Microsoft")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_urlhaus_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {"query_status": "ok", "url_status": "online"},
            "error_message": None
        }
        
        provider = URLHausProvider()
        obs = ThreatObservable(value="http://urlhaustest.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "URLHaus")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].severity, "HIGH")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_abuseipdb_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {"data": {"abuseConfidenceScore": 80, "ipAddress": "1.2.3.4"}},
            "error_message": None
        }
        
        PROVIDER_CONFIGS["AbuseIPDB"]["api_key"] = "test_key"
        
        provider = AbuseIPDBProvider()
        obs = ThreatObservable(value="1.2.3.4", type="IP Address")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "AbuseIPDB")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].classification, "malicious")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_virustotal_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 8, "suspicious": 2},
                        "reputation": -50
                    }
                }
            },
            "error_message": None
        }
        
        PROVIDER_CONFIGS["VirusTotal"]["api_key"] = "test_key"
        
        provider = VirusTotalProvider()
        obs = ThreatObservable(value="http://virustotaltest.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "VirusTotal")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].severity, "HIGH")
        self.assertEqual(res.evidence[0].technical_details["reputation"], -50)

    @patch("threat_intelligence.http_client.http_client.request")
    def test_cisco_talos_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {"reputation": "Poor", "category": {"description": "Malicious Domains"}},
            "error_message": None
        }
        
        provider = CiscoTalosProvider()
        obs = ThreatObservable(value="talostest.com", type="Domain")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "CiscoTalos")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].classification, "malicious")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_alienvault_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {
                "pulse_info": {
                    "pulses": [
                        {"tags": ["phishing"], "targeted_countries": ["US"]}
                    ]
                }
            },
            "error_message": None
        }
        
        provider = AlienvaultOTXProvider()
        obs = ThreatObservable(value="alienvaulttest.com", type="Domain")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "AlienvaultOTX")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertIn("phishing", res.evidence[0].technical_details["tags"])

    @patch("asyncio.get_event_loop")
    def test_spamhaus_provider(self, mock_get_loop):
        # Mock ZEN DNSBL listing return
        mock_loop = MagicMock()
        mock_loop.getaddrinfo = AsyncMock(return_value=[
            (2, 1, 6, "", ("127.0.0.4", 0))
        ])
        mock_get_loop.return_value = mock_loop
        
        provider = SpamhausProvider()
        obs = ThreatObservable(value="1.2.3.4", type="IP Address")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "Spamhaus")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].classification, "malicious")

    @patch("threat_intelligence.http_client.http_client.request")
    def test_asn_provider(self, mock_request):
        mock_request.return_value = {
            "status": "SUCCESS",
            "data": {"org": "AS15169 Google LLC", "country": "US"},
            "error_message": None
        }
        
        provider = ASNProvider()
        obs = ThreatObservable(value="8.8.8.8", type="IP Address")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_name, "ASN")
        self.assertEqual(res.provider_status, "SUCCESS")
        self.assertEqual(res.evidence[0].technical_details["asn"], "AS15169")
        self.assertEqual(res.evidence[0].technical_details["organization"], "Google LLC")

    def test_missing_api_keys(self):
        # Temporarily clear key
        PROVIDER_CONFIGS["GoogleSafeBrowsing"]["api_key"] = ""
        
        provider = GoogleSafeBrowsingProvider()
        obs = ThreatObservable(value="http://test.com", type="URL")
        res = self.run_async(provider.lookup(obs))
        
        self.assertEqual(res.provider_status, "UNAVAILABLE")
        self.assertEqual(len(res.evidence), 0)
        self.assertIn("key missing", res.error_message)

if __name__ == '__main__':
    unittest.main()
