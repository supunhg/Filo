from typing import Any, Optional
from pydantic import BaseModel, Field


class Signature(BaseModel):
    """File signature specification"""
    offset: int = Field(description="Byte offset from file start")
    hex: str = Field(description="Hex string signature (e.g., '89504E47')")
    description: str = Field(description="Human-readable description")
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence weight")
    offset_max: Optional[int] = Field(default=None, description="Maximum offset to scan (creates range from offset to offset_max)")


class ChunkSpec(BaseModel):
    """Chunk/block specification for structured formats"""
    id: str = Field(description="Chunk identifier")
    required: bool = Field(default=False, description="Whether chunk is required")
    position: Optional[int] = Field(default=None, description="Expected position in file")
    min_count: int = Field(default=1, description="Minimum occurrences")
    validation: Optional[str] = Field(default=None, description="Validation function name")


class Structure(BaseModel):
    """File structure specification"""
    chunks: list[ChunkSpec] = Field(default_factory=list, description="Chunk specifications")
    endianness: Optional[str] = Field(default=None, description="big or little")
    header_size: Optional[int] = Field(default=None, description="Fixed header size in bytes")


class Footer(BaseModel):
    """File footer signature"""
    hex: str = Field(description="Hex string signature")
    description: str = Field(description="Human-readable description")


class Template(BaseModel):
    """Header generation template"""
    hex: str = Field(description="Template hex with {{variable}} placeholders")
    variables: dict[str, str] = Field(
        default_factory=dict, description="Variable types (e.g., uint32be)"
    )


class RepairStrategy(BaseModel):
    """Repair strategy specification"""
    name: str = Field(description="Strategy function name")
    priority: int = Field(description="Priority order (lower = higher priority)")
    description: Optional[str] = Field(default=None, description="Strategy description")


class ValidationCommand(BaseModel):
    """External validation command"""
    command: list[str] = Field(description="Command with {file} placeholder")
    success_codes: list[int] = Field(default_factory=lambda: [0], description="Success exit codes")
    description: str = Field(description="Validation description")


class FormatSpec(BaseModel):
    """Complete file format specification"""
    format: str = Field(description="Format identifier (e.g., 'png')")
    version: str = Field(description="Format version")
    mime: list[str] = Field(description="MIME types")
    category: str = Field(description="Format category (e.g., 'raster_image')")
    confidence_weight: float = Field(
        default=0.9, ge=0.0, le=1.0, description="Overall format confidence weight"
    )
    extensions: list[str] = Field(default_factory=list, description="Common file extensions")
    
    # Detection
    signatures: list[Signature] = Field(default_factory=list, description="File signatures")
    footers: list[Footer] = Field(default_factory=list, description="Footer signatures")
    
    # Structure
    structure: Optional[Structure] = Field(default=None, description="File structure")
    
    # Templates
    templates: dict[str, Template] = Field(
        default_factory=dict, description="Header generation templates"
    )
    
    # Repair
    repair_strategies: list[RepairStrategy] = Field(
        default_factory=list, description="Repair strategies"
    )
    
    # Validation
    validation: list[ValidationCommand] = Field(
        default_factory=list, description="External validation commands"
    )
    
    # Metadata
    description: Optional[str] = Field(default=None, description="Format description")
    references: list[str] = Field(default_factory=list, description="Specification URLs")


class DetectionResult(BaseModel):
    """Result of format detection"""
    format: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence")
    weight: float = Field(default=1.0, description="Module weight")


class AnalysisResult(BaseModel):
    """Complete analysis result"""
    primary_format: str
    confidence: float = Field(ge=0.0, le=1.0)
    alternative_formats: list[tuple[str, float]] = Field(
        default_factory=list, description="Other possible formats with confidence"
    )
    evidence_chain: list[dict[str, Any]] = Field(
        default_factory=list, description="Decision tree evidence"
    )
    file_size: int
    entropy: Optional[float] = None
    checksum_sha256: str
