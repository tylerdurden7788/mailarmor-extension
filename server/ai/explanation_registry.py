from typing import Dict, Any, Optional

class ExplanationRegistry:
    def __init__(self):
        self._types: Dict[str, Dict[str, Any]] = {}

    def register_type(self, name: str, description: str, audience: str) -> None:
        self._types[name] = {
            "name": name,
            "description": description,
            "audience": audience
        }

    def get_type(self, name: str) -> Optional[Dict[str, Any]]:
        return self._types.get(name)

# Global registry instance
explanation_registry = ExplanationRegistry()

# Standard registrations
explanation_registry.register_type("technical_report", "SOC analyst deep dive summary", "SOC Analyst")
explanation_registry.register_type("executive_summary", "Management-facing brief summary", "Executive Management")
explanation_registry.register_type("user_summary", "User advice with safety recommendations", "End User")
explanation_registry.register_type("attack_chain", "Chronological attack progression chain", "SOC Analyst")
explanation_registry.register_type("soc_report", "SOC-tailored incident analysis report", "SOC Analyst")
explanation_registry.register_type("incident_summary", "General incident description overview", "SOC Analyst")
