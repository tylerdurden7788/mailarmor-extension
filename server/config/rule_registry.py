RULE_REGISTRY = {
    # Sender Rules
    "SND_001": {
        "category": "SENDER",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The Reply-To address differs from the From address.",
        "recommendation": "Check if the reply-to address looks like an unofficial account before replying."
    },
    "SND_002": {
        "category": "SENDER",
        "severity": "LOW",
        "priority": 4,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Sender name includes a title resembling a known system or corporate role.",
        "recommendation": "Verify whether this display name belongs to the actual sender domain."
    },
    "SND_003": {
        "category": "SENDER",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Free email provider (like Gmail or Outlook) is impersonating a registered organization.",
        "recommendation": "Legitimate organizations do not send official correspondence from free personal accounts. Treat this email with caution."
    },
    "SND_004": {
        "category": "SENDER",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The email headers specify multiple inconsistent sender identities.",
        "recommendation": "Confirm identity through official bookmarks. Inconsistent identities are an impersonation signal."
    },
    
    # Domain Rules
    "DOM_001": {
        "category": "DOMAIN",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The sender domain is extremely new (registered less than 30 days ago).",
        "recommendation": "Be extremely cautious. Freshly registered domains are frequently used for rapid phishing runs."
    },
    "DOM_002": {
        "category": "DOMAIN",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The sender domain belongs to a high-risk suspicious TLD.",
        "recommendation": "Verify the authenticity of the message since trusted providers rarely use this TLD."
    },
    "DOM_003": {
        "category": "DOMAIN",
        "severity": "LOW",
        "priority": 4,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The domain has an excessive number of subdomain nesting levels.",
        "recommendation": "Be careful when clicking links on deeply nested subdomains, which are often used to hide the root host."
    },
    "DOM_004": {
        "category": "DOMAIN",
        "severity": "LOW",
        "priority": 4,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The domain name formatting or structure appears anomalous.",
        "recommendation": "Check the domain carefully. Malformed hostnames indicate suspicious origins."
    },
    
    # URL Rules
    "URL_001": {
        "category": "URL",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Actual hyperlink destination mismatches the text displayed.",
        "recommendation": "Verify through the official website and do not click embedded links."
    },
    "URL_002": {
        "category": "URL",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Contains links pointing to raw IP addresses instead of named domains.",
        "recommendation": "Avoid interacting with IP-based URLs; report as phishing."
    },
    "URL_003": {
        "category": "URL",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Links use a known URL shortener service.",
        "recommendation": "Inspect shorteners with precaution; they are often used to hide malicious targets."
    },
    "URL_004": {
        "category": "URL",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The URL contains open redirect parameters or path complexity.",
        "recommendation": "Do not trust target redirect URLs; verify destination directly."
    },
    "URL_005": {
        "category": "URL",
        "severity": "LOW",
        "priority": 5,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The URL uses unencrypted HTTP instead of secure HTTPS.",
        "recommendation": "Never input passwords or sensitive data on pages without HTTPS encryption."
    },
    "URL_006": {
        "category": "URL",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Sensitive credentials or access tokens detected inside URL parameters.",
        "recommendation": "Ignore and delete. Private tokens should never be exposed inside links."
    },
    "URL_007": {
        "category": "URL",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Redirect loop or infinite redirect chain detected.",
        "recommendation": "Ignore and delete. Do not click links that engage in circular redirects."
    },
    "URL_008": {
        "category": "URL",
        "severity": "LOW",
        "priority": 4,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The hyperlink host has excessive subdomain levels.",
        "recommendation": "Verify lookalike domains carefully before entering login parameters."
    },
    "URL_009": {
        "category": "URL",
        "severity": "LOW",
        "priority": 5,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The hyperlink host contains excessively high character entropy.",
        "recommendation": "Be cautious of random hostnames, which are common signatures of DGA domains."
    },
    "URL_010": {
        "category": "URL",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Double percent encoding obfuscation detected.",
        "recommendation": "Do not click. Encoded characters are frequently used to hide exploits."
    },
    
    # Authentication Rules
    "AUTH_001": {
        "category": "AUTHENTICATION",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "DMARC authentication failed.",
        "recommendation": "DMARC failure indicates the message may have been spoofed. Proceed with care."
    },
    "AUTH_002": {
        "category": "AUTHENTICATION",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "SPF or DKIM validation failed.",
        "recommendation": "Verification failures suggest origin spoofing. Do not trust sender credentials blindly."
    },
    "AUTH_003": {
        "category": "AUTHENTICATION",
        "severity": "INFO",
        "priority": 5,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Authentication information unavailable in the headers.",
        "recommendation": "Verification headers were not found. Treat sender identity with baseline awareness."
    },
    
    # Brand Rules
    "BRD_001": {
        "category": "BRAND",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Sender name references a prominent brand, but domain is unofficial.",
        "recommendation": "This is a brand spoofing signature. Access your account via official bookmarks instead."
    },
    "BRD_002": {
        "category": "BRAND",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "The sender claims affiliation with a department (like Billing or Security) of a trusted brand, but the domain is unofficial.",
        "recommendation": "Verify payment requests using trusted channels or call support directly. Do not follow instructions in the email."
    },
    
    # Content Rules
    "CNT_001": {
        "category": "CONTENT",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Email text contains high-pressure urgency words or payment prompts.",
        "recommendation": "Phishing emails often employ fake deadlines to force hasty actions. Take your time to verify."
    },
    
    # HTML Rules
    "HTML_001": {
        "category": "HTML",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Forms containing credential or password inputs detected.",
        "recommendation": "Never fill out password forms embedded directly inside emails."
    },
    "HTML_002": {
        "category": "HTML",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Suspicious JavaScript or Meta Refresh redirects embedded.",
        "recommendation": "Do not allow the page to auto-redirect. Close the email tab if it prompts downloads."
    },
    "HTML_003": {
        "category": "HTML",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "HTML contains hidden CSS overlays, invisible text or zero-font elements.",
        "recommendation": "Attackers use hidden styling to bypass security keyword filters. Treat content with caution."
    },
    "HTML_004": {
        "category": "HTML",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Hidden iframe or clickjacking overlay detected.",
        "recommendation": "Be careful when clicking. Invisible overlays can intercept actions and steal credentials."
    },
    "HTML_005": {
        "category": "HTML",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Obfuscated or dynamically evaluated JavaScript detected.",
        "recommendation": "Avoid interacting with interactive widgets. Obfuscation is used to hide exploits."
    },
    "HTML_006": {
        "category": "HTML",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Remote script loaded from an untrusted or non-matching domain.",
        "recommendation": "Treat interactive controls with care. External scripts can modify page behaviors dynamically."
    },
    "HTML_007": {
        "category": "HTML",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Duplicate forms or malformed DOM structure detected.",
        "recommendation": "Check forms carefully. Phishing templates often duplicate containers to overlay input prompts."
    },
    "HTML_008": {
        "category": "HTML",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Visual brand impersonation or secure lock icon abuse detected.",
        "recommendation": "This email contains indicators of visual UI deception. Do not enter credentials."
    },
    "HTML_009": {
        "category": "HTML",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Meta refresh tag or base URL tag override detected.",
        "recommendation": "Do not allow the page to auto-redirect. Verify destination address manually."
    },
    
    # Attachment Rules
    "ATT_001": {
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Dangerous executable or script attachments detected.",
        "recommendation": "Do not download or open executable files; they can run malware on your device."
    },
    "ATT_002": {
        "category": "ATTACHMENT",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Office documents with macro-enabled file extensions found.",
        "recommendation": "Ensure macros are disabled when opening external Office documents."
    },
    "ATT_003": {
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Attachment has a double extension.",
        "recommendation": "Double extensions are used to trick users into opening scripts. Do not execute."
    },
    "ATT_004": {
        "category": "ATTACHMENT",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Password-protected archive attachment found.",
        "recommendation": "Secure gateways cannot inspect locked archives. Verify authenticity directly with sender."
    },
    "ATT_005": {
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Attachment has a file signature/magic byte mismatch.",
        "recommendation": "Masked file types are a common delivery method for malware. Do not open."
    },
    "ATT_006": {
        "category": "ATTACHMENT",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Suspicious active content or JavaScript found in PDF.",
        "recommendation": "Phishing PDFs containing auto-launch events or scripts can compromise your device."
    },
    "ATT_007": {
        "category": "ATTACHMENT",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Archive limit exceeded or zip bomb pattern identified.",
        "recommendation": "Highly compressed or deeply nested archives can crash security scanners. Handle with caution."
    },
    "ATT_008": {
        "category": "ATTACHMENT",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Office document contains macros or OLE/DDE links.",
        "recommendation": "Do not enable macros or trust external templates when opening this document."
    },
    "ATT_009": {
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Dangerous script or system installer payload found.",
        "recommendation": "Scripts and system installer packages (MSI, ISO) should not be opened via email."
    },
    "ATT_010": {
        "category": "ATTACHMENT",
        "severity": "HIGH",
        "priority": 2,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Embedded script or event handlers in SVG file.",
        "recommendation": "SVG images can execute arbitrary javascript payloads when rendered. Verify sender."
    },
    "ATT_011": {
        "category": "ATTACHMENT",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Hidden embedded executable or binary stream found.",
        "recommendation": "Files containing hidden sub-executables are extremely high-risk. Delete the file."
    },
    
    # Unicode Rules
    "UNI_001": {
        "category": "UNICODE",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Domain name contains confusable lookalike characters (Homoglyphs).",
        "recommendation": "This is an active homoglyph spoofing attack. Do not trust the display domain name."
    },
    "UNI_002": {
        "category": "UNICODE",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Punycode domain detected representing internationalized name.",
        "recommendation": "Punycode (xn--) can hide lookalike letters. Check details to confirm actual target."
    },
    
    # Header Consistency Rules
    "HDR_001": {
        "category": "HEADER_CONSISTENCY",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Inconsistencies detected between sender-related headers (e.g. From vs Reply-To/Return-Path/Message-ID).",
        "recommendation": "Avoid clicking links or replying. Multi-header discrepancies are common in spoofed mail."
    },
    "HDR_002": {
        "category": "HEADER_CONSISTENCY",
        "severity": "MEDIUM",
        "priority": 3,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Sender domain does not match mail servers listed in the Received path.",
        "recommendation": "Treat origins as unverified if the transport path doesn't align with the sender's claimed organization."
    },
    
    # Reputation Rules
    "REP_001": {
        "category": "REPUTATION",
        "severity": "CRITICAL",
        "priority": 1,
        "lifecycle_status": "PRODUCTION",
        "explanation": "Domain listed as malicious in reputation lookup databases.",
        "recommendation": "Do not open any links or provide information. The host has a known bad reputation."
    },
    
    # Fallback Rules
    "GEN_ERR": {
        "category": "GENERAL",
        "severity": "INFO",
        "priority": 5,
        "lifecycle_status": "PRODUCTION",
        "explanation": "An analyzer encountered an execution exception during analysis.",
        "recommendation": "A sub-check failed. Primary structural safety checks are still active."
    }
}
