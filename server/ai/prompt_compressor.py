import re
import logging
import config.ai_operations_config as config

logger = logging.getLogger("PromptCompressor")

class PromptCompressor:
    def compress(self, context: str) -> str:
        """
        Compresses prompt context (removes repeated duplicate lines or sentences, 
        and compresses consecutive spacing) while preserving rule IDs.
        """
        if len(context) < config.COMPRESSION_THRESHOLD_CHARS:
            return context

        # 1. Deduplicate identical lines/evidence bullet points
        lines = context.splitlines()
        seen = set()
        deduped_lines = []
        for line in lines:
            trimmed = line.strip()
            # If it's a rule trigger line, check if we've seen it exactly
            if trimmed:
                if trimmed in seen:
                    continue
                seen.add(trimmed)
            deduped_lines.append(line)

        compressed = "\n".join(deduped_lines)
        
        # 2. Compress spacing/whitespace
        compressed = re.sub(r'[ \t]+', ' ', compressed)
        compressed = re.sub(r'\n+', '\n', compressed)
        
        logger.debug(f"Compressed context size from {len(context)} to {len(compressed)} chars.")
        return compressed

# Global prompt compressor instance
prompt_compressor = PromptCompressor()
