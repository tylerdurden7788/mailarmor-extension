from ai.prompt_registry import prompt_registry

class VersionManager:
    def is_compatible(self, prompt_name: str, version: str) -> bool:
        """Checks if the requested prompt name and version are registered and compatible."""
        prompt = prompt_registry.get_prompt(prompt_name, version)
        return prompt is not None

# Global version manager instance
version_manager = VersionManager()
