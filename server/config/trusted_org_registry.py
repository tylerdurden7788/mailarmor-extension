TRUSTED_ORGANIZATIONS = {
    "google": {
        "org_name": "Google LLC",
        "official_domains": ["google.com", "gmail.com", "accounts.google.com", "support.google.com"],
        "trusted_subdomains": ["accounts.google.com", "support.google.com", "mail.google.com"],
        "aliases": ["google", "gmail", "youtube", "android"],
        "regional_domains": ["google.co.uk", "google.co.in", "google.de", "google.fr", "google.co.jp"],
        "historical_domains": ["google-security.old"],
        "trusted_departments": ["security", "accounts", "support", "billing", "workspace", "help"],
        "trusted_display_names": ["Google", "Google Accounts", "Gmail Team", "Google Security", "Google Support"]
    },
    "microsoft": {
        "org_name": "Microsoft Corporation",
        "official_domains": ["microsoft.com", "outlook.com", "live.com", "office.com", "office365.com", "hotmail.com"],
        "trusted_subdomains": ["account.microsoft.com", "login.live.com", "support.microsoft.com"],
        "aliases": ["microsoft", "outlook", "live", "office", "xbox", "windows"],
        "regional_domains": ["microsoft.co.uk", "microsoft.de", "outlook.co.uk"],
        "historical_domains": [],
        "trusted_departments": ["security", "account", "support", "billing", "admin", "team", "subscription"],
        "trusted_display_names": ["Microsoft", "Microsoft Security", "Outlook Team", "Office 365", "Microsoft Support"]
    },
    "paypal": {
        "org_name": "PayPal Inc.",
        "official_domains": ["paypal.com", "paypal-portal.com"],
        "trusted_subdomains": ["security.paypal.com", "billing.paypal.com", "history.paypal.com"],
        "aliases": ["paypal", "pypl"],
        "regional_domains": ["paypal.co.uk", "paypal.com.au", "paypal.de", "paypal.fr", "paypal.co.in"],
        "historical_domains": ["paypal-security-alert.com"],
        "trusted_departments": ["billing", "security", "support", "resolution", "accounts", "compliance"],
        "trusted_display_names": ["PayPal", "PayPal Support", "PayPal Resolution Center", "PayPal Security"]
    },
    "amazon": {
        "org_name": "Amazon.com Inc.",
        "official_domains": ["amazon.com", "aws.amazon.com"],
        "trusted_subdomains": ["aws.amazon.com", "pay.amazon.com"],
        "aliases": ["amazon", "aws", "amzn"],
        "regional_domains": ["amazon.co.uk", "amazon.co.in", "amazon.de", "amazon.co.jp", "amazon.ca"],
        "historical_domains": [],
        "trusted_departments": ["billing", "security", "support", "prime", "store", "account", "orders"],
        "trusted_display_names": ["Amazon", "Amazon Support", "Amazon Prime", "AWS Security", "Amazon Orders"]
    },
    "netflix": {
        "org_name": "Netflix Inc.",
        "official_domains": ["netflix.com"],
        "trusted_subdomains": ["help.netflix.com"],
        "aliases": ["netflix"],
        "regional_domains": ["netflix.co.uk", "netflix.ca"],
        "historical_domains": [],
        "trusted_departments": ["billing", "support", "account", "info"],
        "trusted_display_names": ["Netflix", "Netflix Billing", "Netflix Support"]
    },
    "stripe": {
        "org_name": "Stripe Inc.",
        "official_domains": ["stripe.com"],
        "trusted_subdomains": ["dashboard.stripe.com"],
        "aliases": ["stripe"],
        "regional_domains": [],
        "historical_domains": [],
        "trusted_departments": ["billing", "support", "security", "merchant"],
        "trusted_display_names": ["Stripe", "Stripe Support", "Stripe Billing"]
    }
}

def find_organization_by_domain(domain: str) -> tuple[str, dict]:
    """
    Finds a trusted organization by matching official, regional, historical domains or subdomains.
    Returns (org_key, org_info) or (None, None)
    """
    if not domain:
        return None, None
    domain = domain.lower()
    
    for org_key, org_info in TRUSTED_ORGANIZATIONS.items():
        # Check official domains
        if domain in org_info["official_domains"] or domain in org_info["regional_domains"] or domain in org_info["historical_domains"]:
            return org_key, org_info
            
        # Check subdomains / suffixes
        for official in org_info["official_domains"]:
            if domain.endswith("." + official):
                return org_key, org_info
        for regional in org_info["regional_domains"]:
            if domain.endswith("." + regional):
                return org_key, org_info
                
    return None, None

def find_organization_by_name(display_name: str) -> tuple[str, dict]:
    """
    Finds a trusted organization if the display name claims that brand.
    Returns (org_key, org_info) or (None, None)
    """
    if not display_name:
        return None, None
    display_name_lower = display_name.lower()
    
    for org_key, org_info in TRUSTED_ORGANIZATIONS.items():
        # Check aliases
        for alias in org_info["aliases"]:
            if alias in display_name_lower:
                return org_key, org_info
        # Check trusted display names
        for name in org_info["trusted_display_names"]:
            if name.lower() in display_name_lower:
                return org_key, org_info
                
    return None, None
