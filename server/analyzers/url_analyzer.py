import re
from urllib.parse import urlparse
from analyzers.base_analyzer import BaseAnalyzer
from models.email_model import Email
from models.evidence_model import Evidence
from models.url_model import URLContext, ParsedURL
from scanner.evidence import create_evidence
from utils.url_utils import is_ip_address_url, is_shortened_url
from utils.similarity_strategies import LevenshteinDistanceStrategy, VisualConfusableStrategy
from config.trusted_org_registry import TRUSTED_ORGANIZATIONS, find_organization_by_domain

class UrlAnalyzer(BaseAnalyzer):
    async def analyze(self, email: Email, context: dict = None) -> list[Evidence]:
        evidence_list = []
        
        # If no URLContext is provided or parsed URLs are empty, exit early
        if not context or not isinstance(context, URLContext) or not context.parsed_urls:
            return evidence_list
            
        parsed_urls = context.parsed_urls
        redirect_chains = context.redirect_chains or {}
        
        # Instantiate similarity strategies
        levenshtein = LevenshteinDistanceStrategy()
        visual_confusable = VisualConfusableStrategy()
        
        for parsed_url in parsed_urls:
            raw = parsed_url.raw_url
            normalized = parsed_url.normalized_url
            host = parsed_url.host
            root_domain = parsed_url.root_domain
            
            # Setup custom metadata details
            metadata = {
                "analyzer_version": "2.0.0",
                "rule_version": "2.0.0",
                "cache_status": context.cache_provenance.get(raw, "MISS"),
                "data_source": "Normalized Email Link Extraction"
            }
            
            # 1. Check: Display Href Mismatch (URL_001)
            # Find display mismatch by looking at matching link in email
            for link in email.urls:
                if link.actual_url == raw and link.has_mismatch:
                    evidence_list.append(self._create_url_evidence(
                        rule_id="URL_001",
                        tech_details={"raw_url": raw, "display_text": link.display_text, "metadata": metadata},
                        confidence=0.85
                    ))
                    
            # 2. Check: IP address Host (URL_002)
            if is_ip_address_url(normalized):
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_002",
                    tech_details={"normalized_url": normalized, "host": host, "metadata": metadata},
                    confidence=0.90
                ))
                
            # 3. Check: URL Shorteners (URL_003)
            if is_shortened_url(raw):
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_003",
                    tech_details={"raw_url": raw, "metadata": metadata},
                    confidence=0.60
                ))
                
            # 4. Check: Redirect analysis & Loop detection (URL_007)
            chain = redirect_chains.get(raw, [])
            if len(chain) > 1:
                # Loop detection: check if visited same URL twice
                has_loop = len(chain) != len(set(chain))
                if has_loop or len(chain) >= 5:
                    evidence_list.append(self._create_url_evidence(
                        rule_id="URL_007",
                        tech_details={"raw_url": raw, "redirect_chain": chain, "has_loop": has_loop, "metadata": metadata},
                        confidence=0.95
                    ))
                elif not is_shortened_url(raw):
                    # Standard redirect warning (supporting evidence)
                    evidence_list.append(self._create_url_evidence(
                        rule_id="URL_004",
                        tech_details={"raw_url": raw, "redirect_chain": chain, "metadata": metadata},
                        confidence=0.50
                    ))
                    
            # 5. Check: Unencrypted HTTP (URL_005)
            if parsed_url.scheme == "http":
                # Check if it belongs to a trusted oauth/cloud flow that might allow it locally
                if root_domain not in {"localhost", "127.0.0.1"}:
                    evidence_list.append(self._create_url_evidence(
                        rule_id="URL_005",
                        tech_details={"normalized_url": normalized, "metadata": metadata},
                        confidence=0.40
                    ))
                    
            # 6. Check: Credential Leakage / Auth tokens (URL_006)
            has_credentials = bool(parsed_url.username or parsed_url.password)
            
            # Check query parameters for token semantics (JWT, Session, OAuth, SAML, CSRF)
            query_keys = parsed_url.query_params.keys()
            sensitive_params = []
            oauth_or_sso = False
            
            for k in query_keys:
                k_lower = k.lower()
                # Detect token/session variables
                if any(p in k_lower for p in ["token", "session", "jwt", "csrf", "saml", "auth_key", "secret"]):
                    sensitive_params.append(k)
                # Detect legitimate SSO/OAuth flags
                if any(p in k_lower for p in ["code", "state", "client_id", "redirect_uri", "response_type"]):
                    oauth_or_sso = True
                    
            # Bypass warnings for trusted domains to minimize false positives
            is_trusted_flow = False
            org_key, _ = find_organization_by_domain(root_domain)
            if org_key or root_domain in {"github.com", "dropbox.com", "microsoft.com", "google.com", "amazonaws.com"}:
                is_trusted_flow = True
                
            if has_credentials or (sensitive_params and not is_trusted_flow):
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_006",
                    tech_details={
                        "normalized_url": normalized,
                        "has_credentials": has_credentials,
                        "sensitive_parameters": sensitive_params,
                        "oauth_sso_semantics": oauth_or_sso,
                        "metadata": metadata
                    },
                    confidence=0.95
                ))
                
            # 7. Check: Open Redirect Semantics (URL_004)
            # Detect nested URLs inside query parameters designed to redirect
            open_redirect_url = ""
            for val in parsed_url.query_params.values():
                val_str = str(val).lower()
                if val_str.startswith("http://") or val_str.startswith("https://"):
                    # Extracted nested redirect target
                    open_redirect_url = val
                    break
                    
            if open_redirect_url and not is_trusted_flow:
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_004",
                    tech_details={
                        "normalized_url": normalized,
                        "open_redirect_destination": open_redirect_url,
                        "metadata": metadata
                    },
                    confidence=0.75
                ))
                
            # 8. Check: Excessive subdomains (URL_008)
            if len(parsed_url.subdomains) > 3:
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_008",
                    tech_details={"host": host, "subdomains_count": len(parsed_url.subdomains), "metadata": metadata},
                    confidence=0.50
                ))
                
            # 9. Check: Character Entropy (URL_009)
            if parsed_url.character_entropy > 4.5 and not is_trusted_flow:
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_009",
                    tech_details={"host": host, "entropy": parsed_url.character_entropy, "metadata": metadata},
                    confidence=0.55
                ))
                
            # 10. Check: Double Percent Encoding Obfuscation (URL_010)
            # If the parser warnings mention excessive encoding or double escape sequences
            if "%" in normalized or any("percent encoding" in w for w in context.metadata.get("warnings", [])):
                evidence_list.append(self._create_url_evidence(
                    rule_id="URL_010",
                    tech_details={"normalized_url": normalized, "metadata": metadata},
                    confidence=0.70
                ))
                
            # 11. Check: Typosquatting / Domain Similarity check (BRD_001)
            # Compare the URL root domain against all official brand domains
            for brand_key, brand_info in TRUSTED_ORGANIZATIONS.items():
                official_domains = brand_info.get("official_domains", [])
                for official in official_domains:
                    if root_domain != official:
                        # Check similarity
                        sim_score = levenshtein.calculate_similarity(root_domain, official)
                        vis_score = visual_confusable.calculate_similarity(root_domain, official)
                        
                        if vis_score > 0.95:
                            # Confusable match (Homoglyph)
                            evidence_list.append(self._create_url_evidence(
                                rule_id="UNI_001",
                                tech_details={
                                    "url_domain": root_domain,
                                    "spoofed_brand": brand_key,
                                    "official_domain": official,
                                    "visual_confusable_match": True,
                                    "metadata": metadata
                                },
                                confidence=0.98
                            ))
                        elif sim_score > 0.80:
                            # Typosquatting lookalike match
                            evidence_list.append(self._create_url_evidence(
                                rule_id="BRD_001",
                                tech_details={
                                    "url_domain": root_domain,
                                    "spoofed_brand": brand_key,
                                    "official_domain": official,
                                    "typosquatting_similarity_score": sim_score,
                                    "metadata": metadata
                                },
                                confidence=0.90
                            ))
                            
        return evidence_list

    def _create_url_evidence(self, rule_id: str, tech_details: dict, confidence: float) -> Evidence:
        """Helper factory mapping rule metadata checks."""
        return create_evidence(
            analyzer_name="UrlAnalyzer",
            rule_id=rule_id,
            technical_details=tech_details,
            confidence=confidence
        )
