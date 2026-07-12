from models.explanation_model import ExplanationResponse

class ReportFormatter:
    def format_report(self, response: ExplanationResponse, output_format: str = "markdown") -> str:
        """
        Formats the ExplanationResponse object into JSON or Markdown structure.
        """
        fmt = output_format.lower()
        if fmt == "json":
            return response.model_dump_json(indent=2)

        # Markdown representation
        chain_lines = "\n".join([f"{idx + 1}. {stage}" for idx, stage in enumerate(response.attack_chain)])
        recs_lines = "\n".join([f"- {rec}" for rec in response.recommendations])

        return f"""# MailArmour Threat Analysis Report (Schema: {response.schema_version})

## 1. Executive Summary
{response.executive_summary}

## 2. Technical Summary (Analyst Report)
{response.technical_summary}

## 3. End-User Safety Advice
{response.user_summary}

## 4. Chronological Attack Chain
{chain_lines}

## 5. Confidence Attribution
{response.confidence_reasoning}

## 6. Actionable Mitigation Steps
{recs_lines}
"""

# Global report formatter instance
report_formatter = ReportFormatter()
