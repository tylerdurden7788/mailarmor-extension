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

class DOMRelationshipGraph(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    parent_map: Dict[str, str] = Field(default_factory=dict) # node_id -> parent_node_id
    sibling_map: Dict[str, List[str]] = Field(default_factory=dict) # node_id -> list of sibling node_ids
    by_tag_map: Dict[str, List[str]] = Field(default_factory=dict) # tag -> list of node_ids

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
    relationship_graph: Optional[DOMRelationshipGraph] = None
    parser_warnings: List[str] = Field(default_factory=list)
    normalization_metadata: Dict[str, Any] = Field(default_factory=dict)
    performance_metadata: Dict[str, Any] = Field(default_factory=dict)
