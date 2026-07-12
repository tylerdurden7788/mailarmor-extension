from typing import Dict, Any, List

SUPPORTED_SCHEMA_VERSIONS = {"1.0.0"}

class ResponseValidator:
    def validate_response(self, parsed_json: Dict[str, Any], expected_schema: Dict[str, Any]) -> str:
        """
        Validates the parsed JSON response against the expected schema and supported versions.
        Returns: 'VALIDATED' if correct, raises ValueError on error.
        """
        # 1. Validate schema_version
        schema_ver = parsed_json.get("schema_version")
        if not schema_ver:
            raise ValueError("Response missing required field: 'schema_version'")
        if schema_ver not in SUPPORTED_SCHEMA_VERSIONS:
            # Let's support backward compatibility for any 1.x.x schema versions
            if not schema_ver.startswith("1."):
                raise ValueError(f"Unsupported schema version: '{schema_ver}'. Supported: {SUPPORTED_SCHEMA_VERSIONS}")

        # 2. Validate required fields
        required_fields: List[str] = expected_schema.get("required", [])
        for field in required_fields:
            if field not in parsed_json:
                raise ValueError(f"Response missing required schema field: '{field}'")

        # 3. Validate types and value constraints
        properties = expected_schema.get("properties", {})
        for field, spec in properties.items():
            if field not in parsed_json:
                continue
                
            val = parsed_json[field]
            expected_type = spec.get("type")
            
            if expected_type == "string":
                if not isinstance(val, str):
                    raise ValueError(f"Field '{field}' must be a string, got {type(val)}")
            elif expected_type == "number":
                if not isinstance(val, (int, float)):
                    raise ValueError(f"Field '{field}' must be a number, got {type(val)}")
                # Check min/max constraints
                min_val = spec.get("minimum")
                max_val = spec.get("maximum")
                if min_val is not None and val < min_val:
                    raise ValueError(f"Field '{field}' value {val} is below minimum {min_val}")
                if max_val is not None and val > max_val:
                    raise ValueError(f"Field '{field}' value {val} is above maximum {max_val}")
            elif expected_type == "array":
                if not isinstance(val, list):
                    raise ValueError(f"Field '{field}' must be an array/list, got {type(val)}")
                item_spec = spec.get("items", {})
                item_type = item_spec.get("type")
                if item_type == "string":
                    for item in val:
                        if not isinstance(item, str):
                            raise ValueError(f"Array '{field}' items must be strings, got {type(item)}")

        return "VALIDATED"

# Global response validator instance
response_validator = ResponseValidator()
