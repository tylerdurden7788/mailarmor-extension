# Suspicious Top Level Domains
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "gdn", "date", "space", "faith", "science",
    "country", "stream", "men", "bid", "loan", "win", "club", "buzz", "vip",
    "cc", "fit", "gq", "cf", "tk", "ml", "ga"
}

# Severity risk weight mapping
RISK_WEIGHTS = {
    "INFO": 0.0,
    "LOW": 10.0,
    "MEDIUM": 25.0,
    "HIGH": 60.0,
    "CRITICAL": 100.0
}

# Scanning limits/thresholds
MAX_FREE_SCANS = 10

# Dangerous attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif", ".cpl", ".wsf",
    ".jar", ".msi", ".lnk", ".reg", ".ps1"
}

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"
}

# Office macro-enabled extensions
OFFICE_MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}
