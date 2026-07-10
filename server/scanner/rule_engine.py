import time
import asyncio
import traceback
from datetime import datetime
from typing import List, Dict, Any

from models.email_model import Email
from models.evidence_model import Evidence, EvidenceReport
from scanner.plugin_manager import plugin_manager
from scanner.evidence import create_evidence
from scanner.evidence_collector import EvidenceCollector

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

class RuleEngine:
    @staticmethod
    async def run_analysis(email: Email) -> EvidenceReport:
        """
        Executes all registered analyzers concurrently.
        Captures any exception from individual analyzers to ensure complete pipeline resilience.
        """
        start_time = time.perf_counter()
        
        analyzers = plugin_manager.get_analyzers()
        analyzer_names = plugin_manager.get_analyzer_names()
        
        # Prepare list of tasks
        tasks = []
        for name, analyzer in zip(analyzer_names, analyzers):
            tasks.append(RuleEngine._run_single_analyzer(name, analyzer, email))
            
        # Execute asynchronously in parallel
        results = await asyncio.gather(*tasks)
        
        # Aggregate results
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
                # Add default error indicator evidence for developers
                raw_evidence.append(create_evidence(
                    analyzer_name=name,
                    rule_id="GEN_ERR",
                    technical_details={"analyzer_name": name, "error_details": err_msg}
                ))
                
        # Run Evidence Collector to deduplicate, merge and correlate
        processed_evidence = EvidenceCollector.collect_and_process(raw_evidence)
        
        triggered_rules = list(set(ev.triggered_rule for ev in processed_evidence))
        
        scan_duration_ms = (time.perf_counter() - start_time) * 1000.0
        
        # Calculate summary statistics
        total_risk = sum(ev.risk_contribution for ev in processed_evidence)
        high_severity_count = sum(1 for ev in processed_evidence if ev.severity in ["HIGH", "CRITICAL"])
        
        confidence_summary = {
            "overall_threat_weight": total_risk,
            "high_severity_alerts": high_severity_count,
            "average_confidence": sum(ev.confidence for ev in processed_evidence) / len(processed_evidence) if processed_evidence else 1.0
        }
        
        return EvidenceReport(
            schema_version="2.0.0",
            rule_version="2.0.0",
            analyzer_version="2.0.0",
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
    async def _run_single_analyzer(name: str, analyzer: Any, email: Email) -> tuple[bool, List[Evidence], str]:
        """
        Runs a single analyzer, wrapping it to catch any exceptions.
        """
        try:
            evidence = await analyzer.analyze(email)
            return True, evidence, ""
        except Exception as e:
            err_trace = traceback.format_exc()
            print(f"[RuleEngine] Error executing analyzer {name}: {e}\n{err_trace}")
            return False, [], f"{e}: {traceback.format_list(traceback.extract_tb(e.__traceback__))[-1].strip()}"
