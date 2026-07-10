import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.trusted_org_registry import find_organization_by_name, find_organization_by_domain

class SenderAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Parse clean sender details
        from_raw = email.from_header
        from_email = ""
        sender_display_name = ""
        
        # Parse display name and email address
        match = re.search(r'^(.*?)\s*<([^>]+)>', from_raw)
        if match:
            sender_display_name = match.group(1).strip(' \'"')
            from_email = match.group(2).strip()
        else:
            from_email = from_raw.strip()
            
        from_domain = extract_domain(from_email)
        
        # Free providers list
        free_providers = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com"}
        
        # 2. Check: Free email provider impersonating a registered organization
        if sender_display_name:
            # Query Trusted Organization registry to see if the display name claims a brand
            org_key, org_info = find_organization_by_name(sender_display_name)
            if org_key and from_domain in free_providers:
                # Free provider used to claim a registered brand identity!
                evidence_list.append(create_evidence(
                    analyzer_name="SenderAnalyzer",
                    rule_id="SND_003",
                    technical_details={
                        "display_name": sender_display_name,
                        "claimed_organization": org_info["org_name"],
                        "from_address": from_email,
                        "confidence_justification": f"High confidence because display name claimed official brand '{org_info['org_name']}' but used a free personal provider '{from_domain}'."
                    },
                    confidence=0.85
                ))
            elif org_key:
                # Organization claimed, check if domain belongs to the organization
                sender_org_key, _ = find_organization_by_domain(from_domain)
                if sender_org_key != org_key:
                    # Inconsistent organizational identity (From domain doesn't match claimed display name)
                    evidence_list.append(create_evidence(
                        analyzer_name="SenderAnalyzer",
                        rule_id="SND_004",
                        technical_details={
                            "display_name": sender_display_name,
                            "claimed_organization": org_info["org_name"],
                            "from_domain": from_domain,
                            "confidence_justification": f"Medium-high confidence: display name claims brand '{org_info['org_name']}' but the email originates from an unrelated domain '{from_domain}'."
                        },
                        confidence=0.75
                    ))

        # 3. Check: Reply-To address mismatch
        reply_to_raw = email.reply_to
        if reply_to_raw:
            reply_match = re.search(r'<([^>]+)>', reply_to_raw)
            reply_email = reply_match.group(1) if reply_match else reply_to_raw
            reply_email = reply_email.strip()
            
            if reply_email and from_email and reply_email.lower() != from_email.lower():
                evidence_list.append(create_evidence(
                    analyzer_name="SenderAnalyzer",
                    rule_id="SND_001",
                    technical_details={
                        "from_address": from_email,
                        "reply_to_address": reply_email,
                        "confidence_justification": "Medium confidence: Reply-To address differs from the From address. Often indicates redirection for credential harvesting."
                    },
                    confidence=0.65
                ))
                
        # 4. Check: Generic system or corporate role spoofing
        if sender_display_name:
            suspicious_roles = ["support", "security", "billing", "admin", "accounts", "service", "system", "notification", "alert"]
            for role in suspicious_roles:
                if role in sender_display_name.lower():
                    # Check if domain belongs to a known trusted organization to avoid false positives on official services
                    org_key, _ = find_organization_by_domain(from_domain)
                    if not org_key and from_domain not in {"google.com", "microsoft.com", "github.com"}:
                        evidence_list.append(create_evidence(
                            analyzer_name="SenderAnalyzer",
                            rule_id="SND_002",
                            technical_details={
                                "display_name": sender_display_name,
                                "matched_role": role,
                                "from_domain": from_domain,
                                "confidence_justification": f"Low confidence: display name contains generic corporate role '{role}' on an untrusted domain '{from_domain}'."
                            },
                            confidence=0.50
                        ))
                        break
                        
        return evidence_list
