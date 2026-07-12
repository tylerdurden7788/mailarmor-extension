import os

# Default framework settings
DEFAULT_TIMEOUT_SEC = 2.0
DEFAULT_RETRY_COUNT = 1
DEFAULT_CACHE_TTL_SEC = 300 # 5 minutes

# Registry configurations for the 13 threat intelligence providers
PROVIDER_CONFIGS = {
    "WHOIS": {
        "enabled": True,
        "timeout": 3.0,
        "retry_count": 1,
        "cache_ttl": 86400,  # 24 hours
        "supported_observables": ["Domain"],
        "rate_limit_delay": 1.0,
        "url": ""
    },
    "DNS": {
        "enabled": True,
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 3600,   # 1 hour
        "supported_observables": ["Domain", "IP Address"],
        "rate_limit_delay": 0.0,
        "url": ""
    },
    "Certificate": {
        "enabled": True,
        "timeout": 2.5,
        "retry_count": 1,
        "cache_ttl": 3600,   # 1 hour
        "supported_observables": ["Domain"],
        "rate_limit_delay": 0.0,
        "url": ""
    },
    "GoogleSafeBrowsing": {
        "enabled": True,
        "api_key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 300,
        "supported_observables": ["URL", "Domain"],
        "rate_limit_delay": 0.0,
        "url": "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    },
    "PhishTank": {
        "enabled": True,
        "api_key": os.getenv("PHISHTANK_API_KEY", ""),
        "timeout": 2.5,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["URL", "Domain"],
        "rate_limit_delay": 1.0,
        "url": "https://checkurl.phishtank.com/checkurl/"
    },
    "OpenPhish": {
        "enabled": True,
        "api_key": os.getenv("OPENPHISH_API_KEY", ""),
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["URL", "Domain"],
        "rate_limit_delay": 0.5,
        "url": "https://api.openphish.com/v2/lookup"
    },
    "URLHaus": {
        "enabled": True,
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 300,
        "supported_observables": ["URL", "Domain"],
        "rate_limit_delay": 0.1,
        "url": "https://urlhaus-api.abuse.ch/v1/url/"
    },
    "AbuseIPDB": {
        "enabled": True,
        "api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["IP Address"],
        "rate_limit_delay": 0.2,
        "url": "https://api.abuseipdb.com/api/v2/check"
    },
    "VirusTotal": {
        "enabled": True,
        "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "timeout": 3.0,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["URL", "Domain", "IP Address", "File Hash"],
        "rate_limit_delay": 15.0,  # Strict VT public API delay
        "url": "https://www.virustotal.com/api/v3"
    },
    "CiscoTalos": {
        "enabled": True,
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["Domain", "IP Address"],
        "rate_limit_delay": 0.5,
        "url": "https://talosintelligence.com/sb_api/query_lookup"
    },
    "AlienvaultOTX": {
        "enabled": True,
        "api_key": os.getenv("ALIENVAULT_OTX_API_KEY", ""),
        "timeout": 2.5,
        "retry_count": 1,
        "cache_ttl": 600,
        "supported_observables": ["URL", "Domain", "IP Address", "File Hash"],
        "rate_limit_delay": 0.1,
        "url": "https://otx.alienvault.com/api/v1/indicators"
    },
    "Spamhaus": {
        "enabled": True,
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 300,
        "supported_observables": ["Domain", "IP Address"],
        "rate_limit_delay": 0.0,
        "url": ""
    },
    "ASN": {
        "enabled": True,
        "timeout": 2.0,
        "retry_count": 1,
        "cache_ttl": 86400,  # 24 hours
        "supported_observables": ["IP Address", "Domain"],
        "rate_limit_delay": 0.0,
        "url": "https://ipinfo.io"
    }
}
