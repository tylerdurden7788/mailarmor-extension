from typing import Dict, Any
from ai.prompt_registry import prompt_registry

class PromptManager:
    def format_prompt(self, name: str, version: str, context: Dict[str, Any], schema_version: str) -> str:
        prompt_meta = prompt_registry.get_prompt(name, version)
        if not prompt_meta:
            raise ValueError(f"Prompt '{name}' with version '{version}' is not registered.")
            
        # Format prompt template injecting context and schema version
        try:
            return prompt_meta.template.format(
                context=context,
                schema_version=schema_version
            )
        except KeyError as e:
            # Fallback in case of custom templates with different keys
            return prompt_meta.template.replace("{context}", str(context)).replace("{schema_version}", schema_version)

# Global prompt manager instance
prompt_manager = PromptManager()
