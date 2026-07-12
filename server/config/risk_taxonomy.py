# Risk Taxonomy constants and categories

TAXONOMY_CATEGORIES = [
    "Credential Harvesting",
    "Business Email Compromise",
    "CEO Fraud",
    "Payroll Fraud",
    "Invoice Fraud",
    "Wire Transfer Fraud",
    "Gift Card Scam",
    "Banking Scam",
    "Tax Scam",
    "Delivery Scam",
    "Package Scam",
    "Cloud Storage Abuse",
    "OAuth Abuse",
    "Account Takeover",
    "Password Reset Abuse",
    "Brand Impersonation",
    "Technical Support Scam",
    "Romance Scam",
    "Investment Scam",
    "Lottery Scam",
    "Malware Delivery",
    "Executable Delivery",
    "Macro Malware",
    "PDF Exploit",
    "QR Phishing",
    "Browser Notification Abuse",
    "MFA Harvesting",
    "Identity Theft",
    "Unknown"
]

# Mapping rules to specific attack categories
RULE_TAXONOMY_MAP = {
    "ID_001": ["Brand Impersonation", "Identity Theft"],
    "ID_002": ["Brand Impersonation"],
    
    "URL_004": ["Credential Harvesting"],
    "URL_005": ["Credential Harvesting"],
    
    "HTML_001": ["Credential Harvesting"],
    "HTML_006": ["Malware Delivery", "Executable Delivery"],
    
    "ATT_001": ["Malware Delivery", "Executable Delivery"],
    "ATT_002": ["Malware Delivery", "Macro Malware"],
    "ATT_003": ["Malware Delivery"],
    "ATT_005": ["Malware Delivery"],
    "ATT_006": ["Malware Delivery", "PDF Exploit"],
    "ATT_008": ["Malware Delivery", "Macro Malware"],
    "ATT_009": ["Malware Delivery"],
    "ATT_011": ["Malware Delivery", "Executable Delivery"],
    
    "SEM_004": ["Credential Harvesting"],
    "SEM_005": ["Business Email Compromise"],
    "SEM_006": ["Invoice Fraud"],
    "SEM_007": ["Wire Transfer Fraud"],
    "SEM_008": ["CEO Fraud", "Business Email Compromise"],
    "SEM_009": ["Payroll Fraud"],
    "SEM_010": ["Account Takeover"],
    "SEM_011": ["OAuth Abuse"],
    "SEM_012": ["MFA Harvesting"],
    "SEM_013": ["QR Phishing"],
    "SEM_014": ["Technical Support Scam"],
    "SEM_015": ["Delivery Scam", "Package Scam"],
    "SEM_016": ["Banking Scam"],
    "SEM_018": ["Cryptocurrency Scam"],
    "SEM_022": ["Tax Scam"],
    "SEM_025": ["Blackmail", "Extortion"],
    "SEM_026": ["Brand Impersonation"],
    
    # Threat Intelligence Rules (Part 8C)
    "TI_001": ["Malware Delivery", "Executable Delivery"],
    "TI_002": ["Credential Harvesting", "Brand Impersonation"],
    "TI_003": ["Unknown"],
    "TI_004": ["Unknown"]
}
