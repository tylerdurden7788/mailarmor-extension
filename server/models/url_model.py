from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional

class ParsedURL(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    scheme: str
    host: str
    root_domain: str
    public_suffix: str
    subdomains: List[str]
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    path: str
    query_params: Dict[str, str]
    fragment: Optional[str] = None
    file_extension: Optional[str] = None
    length: int
    character_entropy: float
    raw_url: str
    normalized_url: str

class URLContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    parsed_urls: List[ParsedURL]
    redirect_chains: Dict[str, List[str]] = Field(default_factory=dict)
    cache_provenance: Dict[str, str] = Field(default_factory=dict) # URL to "HIT" or "MISS"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    performance_limits: Dict[str, Any] = Field(default_factory=dict)
