from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from models.email_model import Link

class HTMLInput(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    type: Optional[str] = None
    name: Optional[str] = None
    id: Optional[str] = None
    value: Optional[str] = None
    is_hidden: bool = False
    dom_path: Optional[str] = None

class HTMLForm(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    action: Optional[str] = None
    method: Optional[str] = None
    inputs: List[HTMLInput] = Field(default_factory=list)
    dom_path: Optional[str] = None

class HTMLButton(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    text: str = ""
    type: Optional[str] = None
    class_name: Optional[str] = None
    dom_path: Optional[str] = None

class HTMLScript(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    src: Optional[str] = None
    content: Optional[str] = None
    dom_path: Optional[str] = None

class HTMLStyle(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    content: str = ""
    media: Optional[str] = None
    dom_path: Optional[str] = None

class HTMLIframe(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    src: Optional[str] = None
    sandbox: Optional[str] = None
    width: Optional[str] = None
    height: Optional[str] = None
    is_hidden: bool = False
    dom_path: Optional[str] = None

class HTMLResource(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    src: str
    resource_type: str # e.g. "image", "script", "style", "font", "favicon", "media", "object", "data_uri"
    dom_path: Optional[str] = None

class DOMNode(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    node_id: str
    tag: str
    attributes: Dict[str, str] = Field(default_factory=dict)
    children: List["DOMNode"] = Field(default_factory=list)
    parent_id: Optional[str] = None
    dom_path: str
    inner_text: str = ""

class DocumentGraph(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    parent_map: Dict[str, str] = Field(default_factory=dict) # node_id -> parent_node_id
    sibling_map: Dict[str, List[str]] = Field(default_factory=dict) # node_id -> list of sibling node_ids
    by_tag_map: Dict[str, List[str]] = Field(default_factory=dict) # tag -> list of node_ids
    
    # Advanced mappings representing general relationships (nodes, URLs, scripts, brands, evidence)
    elements_map: Dict[str, Any] = Field(default_factory=dict)
    brand_association_map: Dict[str, str] = Field(default_factory=dict)

class HTMLContext(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    root_node: Optional[DOMNode] = None
    forms: List[HTMLForm] = Field(default_factory=list)
    inputs: List[HTMLInput] = Field(default_factory=list)
    buttons: List[HTMLButton] = Field(default_factory=list)
    links: List[Link] = Field(default_factory=list)
    images: List[HTMLResource] = Field(default_factory=list)
    scripts: List[HTMLScript] = Field(default_factory=list)
    styles: List[HTMLStyle] = Field(default_factory=list)
    meta_tags: List[Dict[str, str]] = Field(default_factory=list)
    base_tags: List[Dict[str, str]] = Field(default_factory=list)
    iframes: List[HTMLIframe] = Field(default_factory=list)
    embedded_resources: List[HTMLResource] = Field(default_factory=list)
    
    # Refined relationship graph and warnings/provenance metadata
    document_graph: Optional[DocumentGraph] = None
    parser_backend: str = "StandardHTMLDOMParser"
    parser_recovery_actions: List[str] = Field(default_factory=list)
    extraction_metadata: Dict[str, Any] = Field(default_factory=dict)
    canonicalization_warnings: List[str] = Field(default_factory=list)
    ignored_nodes: List[str] = Field(default_factory=list)
    traversal_cache: Dict[str, Any] = Field(default_factory=dict)
    dom_statistics: Dict[str, Any] = Field(default_factory=dict)
    
    parser_warnings: List[str] = Field(default_factory=list)
    normalization_metadata: Dict[str, Any] = Field(default_factory=dict)
    performance_metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Placeholders for future rendering/vision integration
    rendered_screenshot: Optional[str] = None
    ocr_output: Optional[str] = None
    visual_hash: Optional[str] = None
    screenshot_metadata: Optional[Dict[str, Any]] = None
