import re
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from scanner.evidence import create_evidence
from utils.domain_utils import extract_domain
from config.trusted_org_registry import find_organization_by_domain

class HeaderConsistencyAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # 1. Extract primary From domain
        from_domain = extract_domain(email.from_header)
        if not from_domain:
            return evidence_list
            
        from_org, _ = find_organization_by_domain(from_domain)
        
        inconsistent_headers = {}
        
        # 2. Check: From vs Sender
        if email.sender_header:
            sender_domain = extract_domain(email.sender_header)
            if sender_domain and sender_domain != from_domain:
                # Check if they share the same organization
                sender_org, _ = find_organization_by_domain(sender_domain)
                if not from_org or from_org != sender_org:
                    inconsistent_headers["Sender"] = sender_domain
                    
        # 3. Check: From vs Return-Path
        if email.return_path:
            return_domain = extract_domain(email.return_path)
            if return_domain and return_domain != from_domain:
                return_org, _ = find_organization_by_domain(return_domain)
                if not from_org or from_org != return_org:
                    inconsistent_headers["Return-Path"] = return_domain
                    
        # 4. Check: From vs Message-ID
        if email.message_id:
            # Extract domain from Message-ID (e.g. <123@domain.com> -> domain.com)
            match = re.search(r'@([^>]+)>', email.message_id)
            msg_id_domain = match.group(1).strip().lower() if match else ""
            if msg_id_domain and msg_id_domain != from_domain:
                msg_org, _ = find_organization_by_domain(msg_id_domain)
                if not from_org or from_org != msg_org:
                    # Ignore common mailing list/service boundaries like google.com, amazonses.com for newsletters
                    if msg_id_domain not in {"google.com", "amazonses.com", "salesforce.com", "mailchimpapp.net"}:
                        inconsistent_headers["Message-ID"] = msg_id_domain
                        
        if inconsistent_headers:
            evidence_list.append(create_evidence(
                analyzer_name="HeaderConsistencyAnalyzer",
                rule_id="HDR_001",
                technical_details={
                    "from_domain": from_domain,
                    "inconsistent_fields": inconsistent_headers,
                    "confidence_justification": f"Medium confidence: discrepancies found between From domain '{from_domain}' and header fields: {inconsistent_headers}."
                },
                confidence=0.65
            ))
            
        # 5. Check: Received chain vs From domain
        # If Received chain exists, check if From domain matches server hops.
        # This is supporting, low-severity evidence.
        if email.received_chain:
            # Check the rawReceived headers for mismatching transfer nodes
            mismatched_hops = []
            for i, hop in enumerate(email.received_chain):
                raw = hop.raw.lower()
                # Check if the hop claims to originate from a completely different domain
                # e.g., if mail claims from paypal.com but received hops contain only random Russian or compromised hosting domains
                # We check for general domain keyword mismatches
                if from_domain and from_domain not in raw:
                    # Check if organization domain is in raw hop to avoid false positives
                    if not from_org:
                        mismatched_hops.append(f"Hop #{i+1}")
                    else:
                        # Org check
                        org_match = False
                        for org_domain in [from_domain, "google.com", "microsoft.com", "outlook.com"]:
                            if org_domain in raw:
                                org_match = True
                                break
                        if not org_match:
                            mismatched_hops.append(f"Hop #{i+1}")
                            
            # Trigger received path inconsistency warning
            # Limit count to avoid false alerts on standard relays
            if len(mismatched_hops) > 1 and len(email.received_chain) > 1:
                evidence_list.append(create_evidence(
                    analyzer_name="HeaderConsistencyAnalyzer",
                    rule_id="HDR_002",
                    technical_details={
                        "from_domain": from_domain,
                        "mismatched_hops_count": len(mismatched_hops),
                        "confidence_justification": f"Low confidence: email transit path (Received chain) doesn't contain matching organization domain '{from_domain}'."
                    },
                    confidence=0.40
                ))
                
        return evidence_list
