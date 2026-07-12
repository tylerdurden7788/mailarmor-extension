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

def register_all(registry):
    registry.register("WHOIS", WHOISProvider())
    registry.register("DNS", DNSProvider())
    registry.register("Certificate", CertificateProvider())
    registry.register("GoogleSafeBrowsing", GoogleSafeBrowsingProvider())
    registry.register("PhishTank", PhishTankProvider())
    registry.register("OpenPhish", OpenPhishProvider())
    registry.register("URLHaus", URLHausProvider())
    registry.register("AbuseIPDB", AbuseIPDBProvider())
    registry.register("VirusTotal", VirusTotalProvider())
    registry.register("CiscoTalos", CiscoTalosProvider())
    registry.register("AlienvaultOTX", AlienvaultOTXProvider())
    registry.register("Spamhaus", SpamhausProvider())
    registry.register("ASN", ASNProvider())
