import time
import asyncio
import traceback
from datetime import datetime, timezone
from typing import List, Dict, Any

from models.email_model import Email
from models.evidence_model import Evidence, EvidenceReport
from models.url_model import URLContext, ParsedURL
from scanner.plugin_manager import plugin_manager
from scanner.evidence import create_evidence
from scanner.evidence_collector import EvidenceCollector
from scanner.url_parser import URLParser
from utils.url_resolver import URLRedirectResolver

# Import and instantiate all active analyzers to register them
from analyzers.sender_analyzer import SenderAnalyzer
from analyzers.domain_analyzer import DomainAnalyzer
from analyzers.url_analyzer import UrlAnalyzer
from analyzers.authentication_analyzer import AuthenticationAnalyzer
from analyzers.brand_analyzer import BrandAnalyzer
from analyzers.content_analyzer import ContentAnalyzer
from analyzers.html_analyzer import HtmlAnalyzer
from analyzers.attachment_analyzer import AttachmentAnalyzer
from analyzers.unicode_analyzer import UnicodeAnalyzer
from analyzers.reputation_analyzer import ReputationAnalyzer
from analyzers.qr_analyzer import QRAnalyzer
from analyzers.ocr_image_analyzer import OcrImageAnalyzer
from analyzers.header_consistency_analyzer import HeaderConsistencyAnalyzer

# HTML Analyzers & Parser
from scanner.html_parser import StandardHTMLDOMParser
from analyzers.dom_analyzer import DOMAnalyzer
from analyzers.form_analyzer import FormAnalyzer
from analyzers.css_analyzer import CSSAnalyzer
from analyzers.javascript_analyzer import JavaScriptAnalyzer
from analyzers.iframe_analyzer import IframeAnalyzer
from analyzers.meta_analyzer import MetaAnalyzer
from analyzers.resource_analyzer import ResourceAnalyzer
from analyzers.ui_deception_analyzer import UIDeceptionAnalyzer

# Register them into the plugin_manager on module import
plugin_manager.register("SenderAnalyzer", SenderAnalyzer())
plugin_manager.register("DomainAnalyzer", DomainAnalyzer())
plugin_manager.register("UrlAnalyzer", UrlAnalyzer())
plugin_manager.register("AuthenticationAnalyzer", AuthenticationAnalyzer())
plugin_manager.register("BrandAnalyzer", BrandAnalyzer())
plugin_manager.register("ContentAnalyzer", ContentAnalyzer())
plugin_manager.register("HtmlAnalyzer", HtmlAnalyzer())
plugin_manager.register("AttachmentAnalyzer", AttachmentAnalyzer())
plugin_manager.register("UnicodeAnalyzer", UnicodeAnalyzer())
plugin_manager.register("ReputationAnalyzer", ReputationAnalyzer())
plugin_manager.register("QRAnalyzer", QRAnalyzer())
plugin_manager.register("OcrImageAnalyzer", OcrImageAnalyzer())
plugin_manager.register("HeaderConsistencyAnalyzer", HeaderConsistencyAnalyzer())

plugin_manager.register("DOMAnalyzer", DOMAnalyzer())
plugin_manager.register("FormAnalyzer", FormAnalyzer())
plugin_manager.register("CSSAnalyzer", CSSAnalyzer())
plugin_manager.register("JavaScriptAnalyzer", JavaScriptAnalyzer())
plugin_manager.register("IframeAnalyzer", IframeAnalyzer())
plugin_manager.register("MetaAnalyzer", MetaAnalyzer())
plugin_manager.register("ResourceAnalyzer", ResourceAnalyzer())
plugin_manager.register("UIDeceptionAnalyzer", UIDeceptionAnalyzer())

# Attachment Analyzers & Components
from models.attachment_model import AttachmentContext, ParsedAttachment
from scanner.attachment_parser import AttachmentParser
from scanner.attachment_feature_extractor import AttachmentFeatureExtractor

from analyzers.mime_analyzer import MIMEAnalyzer
from analyzers.file_signature_analyzer import FileSignatureAnalyzer
from analyzers.extension_analyzer import ExtensionAnalyzer
from analyzers.archive_analyzer import ArchiveAnalyzer
from analyzers.office_document_analyzer import OfficeDocumentAnalyzer
from analyzers.pdf_analyzer import PDFAnalyzer
from analyzers.executable_analyzer import ExecutableAnalyzer
from analyzers.script_analyzer import ScriptAnalyzer
from analyzers.embedded_content_analyzer import EmbeddedContentAnalyzer
from analyzers.image_analyzer import ImageAnalyzer
from analyzers.ocr_analyzer import OCRAnalyzer
from analyzers.malware_provider_analyzer import MalwareProviderAnalyzer
from analyzers.sandbox_provider_analyzer import SandboxProviderAnalyzer

plugin_manager.register("MIMEAnalyzer", MIMEAnalyzer())
plugin_manager.register("FileSignatureAnalyzer", FileSignatureAnalyzer())
plugin_manager.register("ExtensionAnalyzer", ExtensionAnalyzer())
plugin_manager.register("ArchiveAnalyzer", ArchiveAnalyzer())
plugin_manager.register("OfficeDocumentAnalyzer", OfficeDocumentAnalyzer())
plugin_manager.register("PDFAnalyzer", PDFAnalyzer())
plugin_manager.register("ExecutableAnalyzer", ExecutableAnalyzer())
plugin_manager.register("ScriptAnalyzer", ScriptAnalyzer())
plugin_manager.register("EmbeddedContentAnalyzer", EmbeddedContentAnalyzer())
plugin_manager.register("ImageAnalyzer", ImageAnalyzer())
plugin_manager.register("OCRAnalyzer", OCRAnalyzer())
plugin_manager.register("MalwareProviderAnalyzer", MalwareProviderAnalyzer())
plugin_manager.register("SandboxProviderAnalyzer", SandboxProviderAnalyzer())

# Semantic Content Analyzers
from models.semantic_model import SemanticContext
from scanner.semantic_feature_extractor import SemanticFeatureExtractor

from analyzers.intent_analyzer import IntentAnalyzer
from analyzers.victim_action_analyzer import VictimActionAnalyzer
from analyzers.social_engineering_analyzer import SocialEngineeringAnalyzer
from analyzers.credential_harvesting_analyzer import CredentialHarvestingAnalyzer
from analyzers.business_email_compromise_analyzer import BusinessEmailCompromiseAnalyzer
from analyzers.invoice_fraud_analyzer import InvoiceFraudAnalyzer
from analyzers.payment_diversion_analyzer import PaymentDiversionAnalyzer
from analyzers.ceo_fraud_analyzer import CEOFraudAnalyzer
from analyzers.payroll_fraud_analyzer import PayrollFraudAnalyzer
from analyzers.account_takeover_analyzer import AccountTakeoverAnalyzer
from analyzers.oauth_consent_analyzer import OAuthConsentAnalyzer
from analyzers.mfa_harvesting_analyzer import MFAHarvestingAnalyzer
from analyzers.qr_phishing_analyzer import QRPhishingAnalyzer
from analyzers.technical_support_scam_analyzer import TechnicalSupportScamAnalyzer
from analyzers.delivery_scam_analyzer import DeliveryScamAnalyzer
from analyzers.banking_scam_analyzer import BankingScamAnalyzer
from analyzers.investment_scam_analyzer import InvestmentScamAnalyzer
from analyzers.cryptocurrency_scam_analyzer import CryptocurrencyScamAnalyzer
from analyzers.romance_scam_analyzer import RomanceScamAnalyzer
from analyzers.job_scam_analyzer import JobScamAnalyzer
from analyzers.charity_scam_analyzer import CharityScamAnalyzer
from analyzers.tax_scam_analyzer import TaxScamAnalyzer
from analyzers.refund_scam_analyzer import RefundScamAnalyzer
from analyzers.giveaway_lottery_analyzer import GiveawayLotteryAnalyzer
from analyzers.blackmail_extortion_analyzer import BlackmailExtortionAnalyzer
from analyzers.brand_abuse_analyzer import BrandAbuseAnalyzer

plugin_manager.register("IntentAnalyzer", IntentAnalyzer())
plugin_manager.register("VictimActionAnalyzer", VictimActionAnalyzer())
plugin_manager.register("SocialEngineeringAnalyzer", SocialEngineeringAnalyzer())
plugin_manager.register("CredentialHarvestingAnalyzer", CredentialHarvestingAnalyzer())
plugin_manager.register("BusinessEmailCompromiseAnalyzer", BusinessEmailCompromiseAnalyzer())
plugin_manager.register("InvoiceFraudAnalyzer", InvoiceFraudAnalyzer())
plugin_manager.register("PaymentDiversionAnalyzer", PaymentDiversionAnalyzer())
plugin_manager.register("CEOFraudAnalyzer", CEOFraudAnalyzer())
plugin_manager.register("PayrollFraudAnalyzer", PayrollFraudAnalyzer())
plugin_manager.register("AccountTakeoverAnalyzer", AccountTakeoverAnalyzer())
plugin_manager.register("OAuthConsentAnalyzer", OAuthConsentAnalyzer())
plugin_manager.register("MFAHarvestingAnalyzer", MFAHarvestingAnalyzer())
plugin_manager.register("QRPhishingAnalyzer", QRPhishingAnalyzer())
plugin_manager.register("TechnicalSupportScamAnalyzer", TechnicalSupportScamAnalyzer())
plugin_manager.register("DeliveryScamAnalyzer", DeliveryScamAnalyzer())
plugin_manager.register("BankingScamAnalyzer", BankingScamAnalyzer())
plugin_manager.register("InvestmentScamAnalyzer", InvestmentScamAnalyzer())
plugin_manager.register("CryptocurrencyScamAnalyzer", CryptocurrencyScamAnalyzer())
plugin_manager.register("RomanceScamAnalyzer", RomanceScamAnalyzer())
plugin_manager.register("JobScamAnalyzer", JobScamAnalyzer())
plugin_manager.register("CharityScamAnalyzer", CharityScamAnalyzer())
plugin_manager.register("TaxScamAnalyzer", TaxScamAnalyzer())
plugin_manager.register("RefundScamAnalyzer", RefundScamAnalyzer())
plugin_manager.register("GiveawayLotteryAnalyzer", GiveawayLotteryAnalyzer())
plugin_manager.register("BlackmailExtortionAnalyzer", BlackmailExtortionAnalyzer())
plugin_manager.register("BrandAbuseAnalyzer", BrandAbuseAnalyzer())

# Shared global resolver instance for redirect caching
redirect_resolver = URLRedirectResolver(max_depth=5, timeout_sec=1.5)

# Threat Intelligence Framework Setup
from models.threat_intelligence_model import ThreatObservable
from threat_intelligence.provider_registry import ProviderRegistry
from threat_intelligence.provider_cache import ProviderCache
from threat_intelligence.provider_health import ProviderHealthMonitor
from threat_intelligence.provider_manager import ProviderManager

global_threat_registry = ProviderRegistry()
global_threat_cache = ProviderCache()
global_threat_health = ProviderHealthMonitor()
global_threat_manager = ProviderManager(global_threat_registry, global_threat_cache, global_threat_health)

# Auto-register all concrete providers
from threat_intelligence.providers import register_all
register_all(global_threat_registry)
global_threat_registry.validate()

class RuleEngine:
    @staticmethod
    async def run_analysis(email: Email) -> EvidenceReport:
        """
        Executes all registered analyzers concurrently.
        First, constructs an immutable URLContext sharing parsed URLs and resolved redirect chains.
        """
        start_time = time.perf_counter()
        
        # 1. Construct URLContext
        parsed_urls: List[ParsedURL] = []
        redirect_chains: Dict[str, List[str]] = {}
        cache_provenance: Dict[str, str] = {}
        parsing_errors: List[str] = []
        normalization_warnings: List[str] = []
        
        # Gather all raw URLs
        raw_urls = [link.actual_url for link in email.urls if link.actual_url]
        
        # Truncate URLs > 2048 characters to prevent Denial of Service
        cleaned_raw_urls = []
        for raw in raw_urls:
            if len(raw) > 2048:
                normalization_warnings.append(f"URL exceeds 2048 characters. Truncated URL: {raw[:50]}...")
                cleaned_raw_urls.append(raw[:2048])
            else:
                cleaned_raw_urls.append(raw)
                
        # Resolve redirects and parse concurrently
        redirect_tasks = [redirect_resolver.resolve(raw) for raw in cleaned_raw_urls]
        resolved_chains = await asyncio.gather(*redirect_tasks)
        
        for raw, chain in zip(cleaned_raw_urls, resolved_chains):
            redirect_chains[raw] = chain
            cache_provenance[raw] = "HIT" if raw in redirect_resolver.cache else "MISS"
            
            # Parse final redirected target url
            final_target = chain[-1] if chain else raw
            try:
                parsed_obj, warnings = URLParser.parse(final_target, original_url=raw)
                parsed_urls.append(parsed_obj)
                normalization_warnings.extend(warnings)
            except Exception as e:
                parsing_errors.append(f"Failed to parse URL '{final_target}': {e}")
                
        # Initialize immutable URLContext
        url_context = URLContext(
            parsed_urls=parsed_urls,
            redirect_chains=redirect_chains,
            cache_provenance=cache_provenance,
            metadata={
                "warnings": normalization_warnings,
                "errors": parsing_errors
            },
            performance_limits={
                "max_url_length": 2048,
                "max_redirect_depth": 5,
                "max_decoding_depth": 3,
                "timeout_sec": 1.5
            }
        )
        
        # Construct HTMLContext using StandardHTMLDOMParser
        html_context = StandardHTMLDOMParser(max_depth=32, max_nodes=1000).parse(email.body_html)
        
        # Construct AttachmentContext using AttachmentParser & Feature Extractor
        parsed_attachments = []
        extracted_features = {}
        max_size = 10 * 1024 * 1024
        archive_limits = {
            "max_depth": 3,
            "max_files": 100,
            "max_uncompressed_bytes": 100 * 1024 * 1024
        }
        for att in email.attachments:
            parsed_att = AttachmentParser.parse_attachment(att)
            parsed_attachments.append(parsed_att)
            if parsed_att.size_bytes <= max_size:
                features = AttachmentFeatureExtractor.extract_features(att, parsed_att, archive_limits)
                extracted_features[att.filename] = features
                
        attachment_context = AttachmentContext(
            attachments=parsed_attachments,
            extracted_features=extracted_features,
            max_attachment_size=max_size,
            archive_limits=archive_limits
        )
        
        # Construct SemanticContext
        semantic_context = SemanticFeatureExtractor.extract_features(email.body_text, email.body_html)
        
        # 2. Asynchronous execution of registered analyzers
        analyzers = plugin_manager.get_analyzers()
        analyzer_names = plugin_manager.get_analyzer_names()
        
        html_analyzers_set = {
            "DOMAnalyzer", "FormAnalyzer", "CSSAnalyzer", "JavaScriptAnalyzer",
            "IframeAnalyzer", "MetaAnalyzer", "ResourceAnalyzer", "UIDeceptionAnalyzer",
            "HtmlAnalyzer"
        }
        
        attachment_analyzers_set = {
            "AttachmentAnalyzer", "MIMEAnalyzer", "FileSignatureAnalyzer", "ExtensionAnalyzer",
            "ArchiveAnalyzer", "OfficeDocumentAnalyzer", "PDFAnalyzer", "ExecutableAnalyzer",
            "ScriptAnalyzer", "EmbeddedContentAnalyzer", "ImageAnalyzer", "OCRAnalyzer",
            "MalwareProviderAnalyzer", "SandboxProviderAnalyzer", "QRAnalyzer", "OcrImageAnalyzer"
        }
        
        semantic_analyzers_set = {
            "IntentAnalyzer", "VictimActionAnalyzer", "SocialEngineeringAnalyzer", "CredentialHarvestingAnalyzer",
            "BusinessEmailCompromiseAnalyzer", "InvoiceFraudAnalyzer", "PaymentDiversionAnalyzer", "CEOFraudAnalyzer",
            "PayrollFraudAnalyzer", "AccountTakeoverAnalyzer", "OAuthConsentAnalyzer", "MFAHarvestingAnalyzer",
            "QRPhishingAnalyzer", "TechnicalSupportScamAnalyzer", "DeliveryScamAnalyzer", "BankingScamAnalyzer",
            "InvestmentScamAnalyzer", "CryptocurrencyScamAnalyzer", "RomanceScamAnalyzer", "JobScamAnalyzer",
            "CharityScamAnalyzer", "TaxScamAnalyzer", "RefundScamAnalyzer", "GiveawayLotteryAnalyzer",
            "BlackmailExtortionAnalyzer", "BrandAbuseAnalyzer"
        }
        
        tasks = []
        for name, analyzer in zip(analyzer_names, analyzers):
            if name in html_analyzers_set:
                selected_ctx = html_context
            elif name in attachment_analyzers_set:
                selected_ctx = attachment_context
            elif name in semantic_analyzers_set:
                selected_ctx = semantic_context
            else:
                selected_ctx = url_context
            tasks.append(RuleEngine._run_single_analyzer(name, analyzer, email, selected_ctx))
            
        results = await asyncio.gather(*tasks)
        
        # 3. Aggregate evidence
        raw_evidence: List[Evidence] = []
        analyzer_stats: Dict[str, Any] = {}
        
        for name, (success, evidence, err_msg, duration) in zip(analyzer_names, results):
            analyzer_stats[name] = {
                "status": "SUCCESS" if success else "FAILED",
                "execution_time_ms": duration,
                "evidence_count": len(evidence) if success else 0,
                "error": err_msg
            }
            if success:
                raw_evidence.extend(evidence)
            else:
                raw_evidence.append(create_evidence(
                    analyzer_name=name,
                    rule_id="GEN_ERR",
                    technical_details={"analyzer_name": name, "error_details": err_msg, "execution_time_ms": duration}
                ))
                
        # Collect observables from parsed context (URL and Domain)
        observables = []
        seen_observables = set()
        
        for url_item in parsed_urls:
            raw_u = url_item.raw_url
            if raw_u and raw_u not in seen_observables:
                seen_observables.add(raw_u)
                observables.append(ThreatObservable(value=raw_u, type="URL"))
            
            # Extract domain
            domain = url_item.host
            if domain and domain not in seen_observables:
                seen_observables.add(domain)
                observables.append(ThreatObservable(value=domain, type="Domain"))
            
        # Dispatch query to ProviderManager
        if observables:
            try:
                threat_results = await global_threat_manager.lookup_observables(observables)
                for res in threat_results:
                    for te in res.evidence:
                        # Map rule ID based on severity
                        rule_id = "TI_004"
                        if te.severity == "CRITICAL":
                            rule_id = "TI_001"
                        elif te.severity in ["HIGH", "MEDIUM"]:
                            rule_id = "TI_002"
                        elif te.severity == "LOW":
                            rule_id = "TI_003"
                            
                        # Build technical details including provider metadata
                        tech_details = dict(te.technical_details) if te.technical_details else {}
                        tech_details.update({
                            "provider": res.provider_name,
                            "confidence": te.provider_confidence,
                            "timestamp": te.timestamp,
                            "observable_queried": te.observable,
                            "provider_version": "1.0.0",
                            "execution_time_ms": res.lookup_time_ms
                        })
                        if "freshness" not in tech_details:
                            tech_details["freshness"] = "LIVE"
                        
                        evidence_obj = Evidence(
                            evidence_id=f"ev_{res.provider_name}_{abs(hash(te.observable))}_{abs(hash(te.classification))}",
                            analyzer_name=res.provider_name,
                            category="THREAT_INT",
                            severity=te.severity,
                            triggered_rule=rule_id,
                            technical_details=tech_details,
                            confidence=te.provider_confidence,
                            risk_contribution=0.0,
                            explanation=f"Threat intelligence check for {te.observable} via {res.provider_name} returned classification: {te.classification}.",
                            recommendation="Verify this threat indicator.",
                            timestamp=te.timestamp
                        )
                        raw_evidence.append(evidence_obj)
            except Exception as e:
                # Log warning and fail safe
                import logging
                logging.getLogger("RuleEngine").warning(f"Error querying threat intelligence providers: {e}")

        # Deduplicate, merge and correlate evidence
        processed_evidence = EvidenceCollector.collect_and_process(raw_evidence)
        
        triggered_rules = list(set(ev.triggered_rule for ev in processed_evidence))
        
        scan_duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        total_risk = sum(ev.risk_contribution for ev in processed_evidence)
        high_severity_count = sum(1 for ev in processed_evidence if ev.severity in ["HIGH", "CRITICAL"])
        
        confidence_summary = {
            "overall_threat_weight": total_risk,
            "high_severity_alerts": high_severity_count,
            "average_confidence": sum(ev.confidence for ev in processed_evidence) / len(processed_evidence) if processed_evidence else 1.0
        }
        
        return EvidenceReport(
            schema_version="3.0.0",
            rule_version="3.0.0",
            analyzer_version="3.0.0",
            scan_duration_ms=scan_duration_ms,
            analyzer_statistics=analyzer_stats,
            confidence_summary=confidence_summary,
            triggered_rules=triggered_rules,
            processing_metadata={
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "active_analyzers_count": len(analyzers),
                "successful_analyzers_count": sum(1 for stat in analyzer_stats.values() if stat["status"] == "SUCCESS")
            },
            evidence_list=processed_evidence
        )

    @staticmethod
    async def _run_single_analyzer(name: str, analyzer: Any, email: Email, context: URLContext) -> tuple[bool, List[Evidence], str, float]:
        """
        Runs a single analyzer asynchronously and records its execution duration in ms.
        """
        start_time = time.perf_counter()
        try:
            evidence = await analyzer.analyze(email, context)
            duration = (time.perf_counter() - start_time) * 1000.0
            return True, evidence, "", duration
        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000.0
            err_trace = traceback.format_exc()
            print(f"[RuleEngine] Error executing analyzer {name}: {e}\n{err_trace}")
            return False, [], f"{e}: {traceback.format_list(traceback.extract_tb(e.__traceback__))[-1].strip()}", duration
