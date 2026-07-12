import os

# Default framework settings
DEFAULT_TIMEOUT_SEC = 2.0
DEFAULT_RETRY_COUNT = 2
DEFAULT_CACHE_TTL_SEC = 300 # 5 minutes

# Registry configurations for future threat intelligence providers
PROVIDER_CONFIGS = {
    "VirusTotal": {
        "enabled": False,
        "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "timeout": 3.0,
        "retry_count": 2,
        "cache_ttl": 600,
        "supported_observables": ["Domain", "URL", "IP Address", "File Hash"]
    },
    "GoogleSafeBrowsing": {
        "enabled": False,
        "api_key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", ""),
        "timeout": 2.0,
        "retry_count": 2,
        "cache_ttl": 300,
        "supported_observables": ["Domain", "URL"]
    },
    "PhishTank": {
        "enabled": False,
        "api_key": os.getenv("PHISHTANK_API_KEY", ""),
        "timeout": 2.5,
        "retry_count": 2,
        "cache_ttl": 600,
        "supported_observables": ["Domain", "URL"]
    },
    "URLHaus": {
        "enabled": False,
        "timeout": 2.0,
        "retry_count": 2,
        "cache_ttl": 300,
        "supported_observables": ["Domain", "URL"]
    },
    "AbuseIPDB": {
        "enabled": False,
        "api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "timeout": 2.0,
        "retry_count": 2,
        "cache_ttl": 300,
        "supported_observables": ["IP Address"]
    }
}
