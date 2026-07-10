RULE_REGISTRY = {
    # Sender Rules
    "SND_001": {
        "category": "SENDER",
        "severity": "MEDIUM",
        "explanation": "The Reply-To address differs from the From address.",
        "recommendation": "Check if the reply-to address looks like an unofficial account before replying."
    },
    "SND_002": {
        "category": "SENDER",
        "severity": "LOW",
        "explanation": "Sender name includes a title resembling a known system or corporate role.",
        "recommendation": "Verify whether this display name belongs to the actual sender domain."
    },
    
    # Domain Rules
    "DOM_001": {
        "category": "DOMAIN",
        "severity": "HIGH",
        "explanation": "The sender domain is extremely new (registered less than 30 days ago).",
        "recommendation": "Be extremely cautious. Freshly registered domains are frequently used for rapid phishing runs."
    },
    "DOM_002": {
        "category": "DOMAIN",
        "severity": "MEDIUM",
        "explanation": "The sender domain belongs to a high-risk suspicious TLD.",
        "recommendation": "Verify the authenticity of the message since trusted providers rarely use this TLD."
    },
    
    # URL Rules
    "URL_001": {
        "category": "URL",
        "explanation": "Actual hyperlink destination mismatches the text displayed.",
        "recommendation": "Hover over links to verify they go where they claim before clicking.",
        "severity": "HIGH"
    },
    "URL_002": {
        "category": "URL",
        "explanation": "Contains links pointing to raw IP addresses instead of named domains.",
        "recommendation": "Avoid interacting with IP-based URLs; legitimate senders almost always use registered domains.",
        "severity": "HIGH"
    },
    "URL_003": {
        "category": "URL",
        "explanation": "Links use a known URL shortener service.",
        "recommendation": "Inspect shorteners with precaution; they are often used to hide malicious targets.",
        "severity": "MEDIUM"
    },
    "URL_004": {
        "category": "URL",
        "explanation": "The URL contains suspicious credential parameters or path complexity.",
        "recommendation": "Check the address bar closely to ensure credentials aren't being intercepted.",
        "severity": "MEDIUM"
    },
    "URL_005": {
        "category": "URL",
        "explanation": "The URL uses unencrypted HTTP instead of secure HTTPS.",
        "recommendation": "Never input passwords or sensitive data on pages without HTTPS encryption.",
        "severity": "LOW"
    },
    
    # Authentication Rules
    "AUTH_001": {
        "category": "AUTHENTICATION",
        "explanation": "DMARC authentication failed.",
        "recommendation": "DMARC failure indicates the message may have been spoofed. Proceed with care.",
        "severity": "HIGH"
    },
    "AUTH_002": {
        "category": "AUTHENTICATION",
        "explanation": "SPF or DKIM validation failed.",
        "recommendation": "Verification failures suggest origin spoofing. Do not trust sender credentials blindly.",
        "severity": "MEDIUM"
    },
    "AUTH_003": {
        "category": "AUTHENTICATION",
        "explanation": "Authentication information unavailable in the headers.",
        "recommendation": "Verification headers were not found. Treat sender identity with baseline awareness.",
        "severity": "INFO"
    },
    
    # Brand Rules
    "BRD_001": {
        "category": "BRAND",
        "explanation": "Sender name references a prominent brand, but domain is unofficial.",
        "recommendation": "This is a brand spoofing signature. Access your account via official bookmarks instead.",
        "severity": "CRITICAL"
    },
    
    # Content Rules
    "CNT_001": {
        "category": "CONTENT",
        "explanation": "Email text contains high-pressure urgency words or payment prompts.",
        "recommendation": "Phishing emails often employ fake deadlines to force hasty actions. Take your time to verify.",
        "severity": "MEDIUM"
    },
    
    # HTML Rules
    "HTML_001": {
        "category": "HTML",
        "explanation": "Forms containing credential or password inputs detected.",
        "recommendation": "Never fill out password forms embedded directly inside emails.",
        "severity": "CRITICAL"
    },
    "HTML_002": {
        "category": "HTML",
        "explanation": "Suspicious JavaScript or Meta Refresh redirects embedded.",
        "recommendation": "Do not allow the page to auto-redirect. Close the email tab if it prompts downloads.",
        "severity": "HIGH"
    },
    "HTML_003": {
        "category": "HTML",
        "explanation": "HTML contains hidden CSS overlays, invisible text or zero-font elements.",
        "recommendation": "Attackers use hidden styling to bypass security keyword filters. Treat content with caution.",
        "severity": "MEDIUM"
    },
    
    # Attachment Rules
    "ATT_001": {
        "category": "ATTACHMENT",
        "explanation": "Dangerous executable or script attachments detected.",
        "recommendation": "Do not download or open executable files; they can run malware on your device.",
        "severity": "CRITICAL"
    },
    "ATT_002": {
        "category": "ATTACHMENT",
        "explanation": "Office documents with macro-enabled file extensions found.",
        "recommendation": "Ensure macros are disabled when opening external Office documents.",
        "severity": "HIGH"
    },
    "ATT_003": {
        "category": "ATTACHMENT",
        "explanation": "Attachment has a double extension.",
        "recommendation": "Double extensions are used to trick users into opening scripts. Do not execute.",
        "severity": "CRITICAL"
    },
    "ATT_004": {
        "category": "ATTACHMENT",
        "explanation": "Password-protected archive attachment found.",
        "recommendation": "Secure gateways cannot inspect locked archives. Verify authenticity directly with sender.",
        "severity": "MEDIUM"
    },
    
    # Unicode Rules
    "UNI_001": {
        "category": "UNICODE",
        "explanation": "Domain name contains confusable lookalike characters (Homoglyphs).",
        "recommendation": "This is an active homoglyph spoofing attack. Do not trust the display domain name.",
        "severity": "CRITICAL"
    },
    "UNI_002": {
        "category": "UNICODE",
        "explanation": "Punycode domain detected representing internationalized name.",
        "recommendation": "Punycode (xn--) can hide lookalike letters. Check details to confirm actual target.",
        "severity": "MEDIUM"
    },
    
    # Reputation Rules
    "REP_001": {
        "category": "REPUTATION",
        "explanation": "Domain listed as malicious in reputation lookup databases.",
        "recommendation": "Do not open any links or provide information. The host has a known bad reputation.",
        "severity": "CRITICAL"
    },
    
    # Fallback Rules
    "GEN_ERR": {
        "category": "GENERAL",
        "explanation": "An analyzer encountered an execution exception during analysis.",
        "recommendation": "A sub-check failed. Primary structural safety checks are still active.",
        "severity": "INFO"
    }
}
