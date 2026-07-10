import time
import asyncio
import traceback
from datetime import datetime
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

# Shared global resolver instance for redirect caching
redirect_resolver = URLRedirectResolver(max_depth=5, timeout_sec=1.5)

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
        
        # 2. Asynchronous execution of registered analyzers
        analyzers = plugin_manager.get_analyzers()
        analyzer_names = plugin_manager.get_analyzer_names()
        
        tasks = []
        for name, analyzer in zip(analyzer_names, analyzers):
            tasks.append(RuleEngine._run_single_analyzer(name, analyzer, email, url_context))
            
        results = await asyncio.gather(*tasks)
        
        # 3. Aggregate evidence
        raw_evidence: List[Evidence] = []
        analyzer_stats: Dict[str, Any] = {}
        
        for name, (success, evidence, err_msg) in zip(analyzer_names, results):
            analyzer_stats[name] = {
                "status": "SUCCESS" if success else "FAILED",
                "evidence_count": len(evidence) if success else 0,
                "error": err_msg
            }
            if success:
                raw_evidence.extend(evidence)
            else:
                raw_evidence.append(create_evidence(
                    analyzer_name=name,
                    rule_id="GEN_ERR",
                    technical_details={"analyzer_name": name, "error_details": err_msg}
                ))
                
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
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "active_analyzers_count": len(analyzers),
                "successful_analyzers_count": sum(1 for stat in analyzer_stats.values() if stat["status"] == "SUCCESS")
            },
            evidence_list=processed_evidence
        )

    @staticmethod
    async def _run_single_analyzer(name: str, analyzer: Any, email: Email, context: URLContext) -> tuple[bool, List[Evidence], str]:
        """
        Runs a single analyzer asynchronously.
        """
        try:
            evidence = await analyzer.analyze(email, context)
            return True, evidence, ""
        except Exception as e:
            err_trace = traceback.format_exc()
            print(f"[RuleEngine] Error executing analyzer {name}: {e}\n{err_trace}")
            return False, [], f"{e}: {traceback.format_list(traceback.extract_tb(e.__traceback__))[-1].strip()}"
