# Decision Rules configuration registry

RULE_PRECEDENCE = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Informational": 5,
    "Benign": 6
}

# Mapping of rule IDs to their priority
RULE_PRIORITY_MAP = {
    # Identity Verification Rules
    "ID_001": "Critical", # Domain spoofing (homoglyph/lookalike)
    "ID_002": "High",     # Display name mismatch
    "ID_003": "Medium",   # Fake sender domain
    
    # URL Intelligence Rules
    "URL_001": "High",     # Suspicious link path/subdomain
    "URL_002": "Medium",   # Suspicious query params (redirects/JWT/nested)
    "URL_003": "Medium",   # Credential keywords in URL
    "URL_004": "High",     # Mismatched display vs destination URL
    "URL_005": "Critical", # Phishing simulation match
    
    # HTML & UI Intelligence Rules
    "HTML_001": "High",     # Password field in non-secure form
    "HTML_002": "Medium",   # Suspicious hidden fields
    "HTML_003": "Medium",   # Meta refresh redirect
    "HTML_004": "High",     # Hidden elements overlapping content
    "HTML_005": "Medium",   # Zero font size text (invisible text)
    "HTML_006": "Critical", # Executable content download trigger
    
    # Attachment Intelligence Rules
    "ATT_001": "Critical", # Dangerous executable attachment
    "ATT_002": "High",     # Office macro attachment
    "ATT_003": "High",     # Double extension
    "ATT_004": "Medium",   # Encrypted/Locked archive
    "ATT_005": "Critical", # File signature/magic mismatch
    "ATT_006": "High",     # PDF containing JavaScript or launch action
    "ATT_007": "High",     # Zip bomb or limit exceeded
    "ATT_008": "High",     # Office macro/DDE trigger
    "ATT_009": "Critical", # Dangerous script payload
    "ATT_010": "High",     # SVG event script payload
    "ATT_011": "Critical", # Nested sub-executable hidden inside document
    
    # Semantic Rules
    "SEM_004": "High",     # Credential Harvesting pretext
    "SEM_005": "High",     # Business Email Compromise (BEC)
    "SEM_006": "High",     # Invoice Fraud
    "SEM_007": "High",     # Payment Diversion
    "SEM_008": "Critical", # CEO Impersonation (CEO Fraud)
    "SEM_009": "High",     # Payroll Fraud
    "SEM_010": "Medium",   # Account Takeover warning
    "SEM_011": "High",     # OAuth Consent phishing
    "SEM_012": "High",     # MFA push code request
    "SEM_013": "High",     # QR scan instruction
    "SEM_014": "Medium",   # Helpdesk tech support scam
    "SEM_015": "Medium",   # Parcel delivery scam
    "SEM_016": "High",     # Bank security alert scam
    "SEM_018": "High",     # Cryptocurrency scam wallet redirection
    "SEM_022": "High",     # IRS/Tax Scam
    "SEM_025": "Critical", # Extortion blackmail webcam recording
    "SEM_026": "High",     # Brand Abuse display name mismatch
    
    # Threat Intelligence Rules (Part 8C)
    "TI_001": "Critical",  # Confirmed malicious hash/URI (VirusTotal, GSB)
    "TI_002": "High",      # High-confidence phishing feed alert (PhishTank, OpenPhish)
    "TI_003": "Medium",    # Suspicious reputation/abuse score (AbuseIPDB, Cisco Talos)
    "TI_004": "Informational" # General domain/DNS telemetry (WHOIS, DNS, Certificate, ASN)
}

# Threat Intelligence Provider Reliability weights
PROVIDER_RELIABILITY = {
    "WHOIS": 0.90,
    "DNS": 0.95,
    "Certificate": 0.90,
    "GoogleSafeBrowsing": 0.98,
    "PhishTank": 0.92,
    "OpenPhish": 0.95,
    "URLHaus": 0.95,
    "AbuseIPDB": 0.85,
    "VirusTotal": 0.95,
    "CiscoTalos": 0.90,
    "AlienvaultOTX": 0.85,
    "Spamhaus": 0.95,
    "ASN": 0.90
}

# Analyzer reliability scores (0.0 to 1.0)
ANALYZER_RELIABILITY = {
    "UnicodeAnalyzer": 0.95,
    "FileSignatureAnalyzer": 0.95,
    "ExecutableAnalyzer": 0.95,
    "UrlAnalyzer": 0.85,
    "HtmlAnalyzer": 0.85,
    "DOMAnalyzer": 0.85,
    "FormAnalyzer": 0.90,
    "CSSAnalyzer": 0.80,
    "JavaScriptAnalyzer": 0.80,
    "AttachmentAnalyzer": 0.90,
    "MIMEAnalyzer": 0.90,
    "ArchiveAnalyzer": 0.90,
    "OfficeDocumentAnalyzer": 0.90,
    "PDFAnalyzer": 0.90,
    "ScriptAnalyzer": 0.90,
    "ImageAnalyzer": 0.80,
    "IntentAnalyzer": 0.70,
    "VictimActionAnalyzer": 0.70,
    "SocialEngineeringAnalyzer": 0.70,
    "CredentialHarvestingAnalyzer": 0.85,
    "BusinessEmailCompromiseAnalyzer": 0.85,
    "CEOFraudAnalyzer": 0.90,
    "InvoiceFraudAnalyzer": 0.85,
    "PaymentDiversionAnalyzer": 0.85,
    "PayrollFraudAnalyzer": 0.85,
    "AccountTakeoverAnalyzer": 0.80,
    "OAuthConsentAnalyzer": 0.85,
    "MFAHarvestingAnalyzer": 0.85,
    "QRPhishingAnalyzer": 0.85,
    "TechnicalSupportScamAnalyzer": 0.80,
    "DeliveryScamAnalyzer": 0.80,
    "BankingScamAnalyzer": 0.85,
    "TaxScamAnalyzer": 0.85,
    "BlackmailExtortionAnalyzer": 0.90,
    "BrandAbuseAnalyzer": 0.85
}

# Conflict resolution overrides
# Defines which tags suppress or adjust others
CONFLICT_POLICIES = {
    # If SPF/DKIM is valid, but homograph is confirmed -> homograph rules override Auth
    "override_auth_on_homograph": True,
    # If the email is internal corporate and matches verified exceptions -> downgrade generic warnings
    "allow_internal_exceptions": True
}

# Risk verification boundaries
CONFIDENCE_THRESHOLDS = {
    "Very High": 0.80,
    "High": 0.60,
    "Moderate": 0.40,
    "Low": 0.20
}

# Verdict limits based on risk level and confidence
VERDICT_MAPPINGS = {
    # (Risk Level, Confidence Tier) -> Verdict
    ("Critical", "High"): "DANGEROUS",
    ("Critical", "Moderate"): "DANGEROUS",
    ("High", "High"): "DANGEROUS",
    ("High", "Moderate"): "DANGEROUS",
    ("Medium", "High"): "SUSPICIOUS",
    ("Medium", "Moderate"): "SUSPICIOUS",
    ("Low", "High"): "LIKELY_SAFE",
    ("Minimal", "High"): "SAFE"
}
