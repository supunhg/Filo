import logging
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union, List, Tuple

from filo.formats import FormatDatabase
from filo.models import FormatSpec

logger = logging.getLogger(__name__)


@dataclass
class RepairReport:
    """Report of repair operation."""
    success: bool
    strategy_used: str
    original_size: int
    repaired_size: int
    changes_made: list[str]
    warnings: list[str]
    confidence: float = 0.0
    validation_result: Optional[str] = None
    chunks_repaired: int = 0


class RepairEngine:
    """
    File repair and header reconstruction engine.
    
    Implements multiple strategies for repairing corrupted files.
    """
    
    def __init__(self, database: Optional[FormatDatabase] = None) -> None:
        """
        Initialize repair engine.
        
        Args:
            database: Optional format database
        """
        self.database = database or FormatDatabase()
        self._register_advanced_strategies()
        logger.info(f"RepairEngine initialized with {self.database.count()} formats")
    
    def _register_advanced_strategies(self) -> None:
        """Register format-specific advanced repair strategies."""
        self.advanced_strategies = {
            "png": [
                self._repair_png_chunks,
                self._repair_png_crc,
                self._reconstruct_png_ihdr,
            ],
            "jpeg": [
                self._repair_jpeg_markers,
                self._add_jpeg_eoi,
            ],
            "zip": [
                self._repair_zip_directory,
                self._reconstruct_zip_headers,
            ],
            "pdf": [
                self._repair_pdf_xref,
                self._add_pdf_eof,
            ],
        }
    
    def repair(
        self,
        data: bytes,
        format_name: str,
        strategy: str = "auto",
    ) -> tuple[bytes, RepairReport]:
        """
        Repair corrupted file data.
        
        Args:
            data: Corrupted file data
            format_name: Target format for repair
            strategy: Repair strategy ('auto', 'advanced', or specific strategy name)
        
        Returns:
            Tuple of (repaired_data, repair_report)
        """
        spec = self.database.get_format(format_name)
        if not spec:
            raise ValueError(f"Unknown format: {format_name}")
        
        # Try advanced strategies first if available
        if strategy == "auto" or strategy == "advanced":
            if format_name in self.advanced_strategies:
                for repair_func in self.advanced_strategies[format_name]:
                    try:
                        repaired, report = repair_func(data)
                        if report.success:
                            logger.info(f"Advanced repair successful: {repair_func.__name__}")
                            return repaired, report
                    except Exception as e:
                        logger.debug(f"Advanced strategy {repair_func.__name__} failed: {e}")
        
        if strategy == "advanced":
            return data, RepairReport(
                success=False,
                strategy_used="advanced",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["No advanced strategies succeeded"],
            )
        
        if strategy == "auto":
            # Try standard strategies in priority order
            for repair_strategy in sorted(spec.repair_strategies, key=lambda s: s.priority):
                try:
                    repaired, report = self._apply_strategy(
                        data, spec, repair_strategy.name
                    )
                    if report.success:
                        return repaired, report
                except Exception as e:
                    logger.warning(f"Strategy {repair_strategy.name} failed: {e}")
            
            # No strategy succeeded
            return data, RepairReport(
                success=False,
                strategy_used="none",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["All repair strategies failed"],
            )
        else:
            return self._apply_strategy(data, spec, strategy)
    
    def _apply_strategy(
        self, data: bytes, spec: FormatSpec, strategy_name: str
    ) -> tuple[bytes, RepairReport]:
        """Apply a specific repair strategy."""
        # Dispatch to strategy methods
        method_name = f"_strategy_{strategy_name}"
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            return method(data, spec)
        
        # Generic strategies
        if strategy_name == "generate_minimal_header":
            return self._strategy_generate_minimal_header(data, spec)
        elif strategy_name == "add_pdf_header":
            return self._strategy_add_pdf_header(data, spec)
        elif strategy_name == "add_zip_header":
            return self._strategy_add_zip_header(data, spec)
        else:
            raise ValueError(f"Unknown repair strategy: {strategy_name}")
    
    def _strategy_generate_minimal_header(
        self, data: bytes, spec: FormatSpec
    ) -> tuple[bytes, RepairReport]:
        """Generate minimal valid header for file."""
        changes = []
        warnings = []
        
        # Get default template
        if "default" not in spec.templates:
            warnings.append("No default template available")
            return data, RepairReport(
                success=False,
                strategy_used="generate_minimal_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=warnings,
            )
        
        template = spec.templates["default"]
        
        # For now, use template as-is (without variable substitution)
        # TODO: Implement variable substitution based on file content
        header_hex = template.hex.split("{{")[0]  # Take part before first variable
        header_bytes = bytes.fromhex(header_hex)
        
        # Check if header is already present
        if data.startswith(header_bytes[:len(header_hex)//2]):
            warnings.append("Header already present")
            return data, RepairReport(
                success=False,
                strategy_used="generate_minimal_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=warnings,
            )
        
        # Prepend header
        repaired = header_bytes + data
        changes.append(f"Added {len(header_bytes)} byte header")
        
        return repaired, RepairReport(
            success=True,
            strategy_used="generate_minimal_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
        )
    
    def _strategy_add_pdf_header(
        self, data: bytes, spec: FormatSpec
    ) -> tuple[bytes, RepairReport]:
        """Add PDF header to file."""
        pdf_header = b"%PDF-1.7\r\n"
        changes = []
        
        if data.startswith(b"%PDF"):
            return data, RepairReport(
                success=False,
                strategy_used="add_pdf_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=["PDF header already present"],
            )
        
        repaired = pdf_header + data
        changes.append("Added PDF-1.7 header")
        
        return repaired, RepairReport(
            success=True,
            strategy_used="add_pdf_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=[],
        )
    
    def _strategy_add_zip_header(
        self, data: bytes, spec: FormatSpec
    ) -> tuple[bytes, RepairReport]:
        """Add ZIP local file header."""
        zip_header = bytes.fromhex("504B0304")
        changes = []
        
        if data.startswith(zip_header):
            return data, RepairReport(
                success=False,
                strategy_used="add_zip_header",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=changes,
                warnings=["ZIP header already present"],
            )
        
        repaired = zip_header + data
        changes.append("Added ZIP local file header")
        
        return repaired, RepairReport(
            success=True,
            strategy_used="add_zip_header",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=[],
        )
    
    def repair_file(
        self,
        file_path: Union[str, Path],
        format_name: str,
        strategy: str = "auto",
        output_path: Optional[Union[str, Path]] = None,
        create_backup: bool = True,
    ) -> tuple[bytes, RepairReport]:
        """
        Repair a file from disk.
        
        Args:
            file_path: Path to corrupted file
            format_name: Target format for repair
            strategy: Repair strategy to use
            output_path: Where to write repaired file (None = overwrite original)
            create_backup: Whether to create .bak backup
        
        Returns:
            Tuple of (repaired_data, repair_report)
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read original data
        with open(path, "rb") as f:
            data = f.read()
        
        # Repair
        repaired_data, report = self.repair(data, format_name, strategy)
        
        # Write output
        if report.success:
            if output_path is None:
                output_path = path
            
            output_path = Path(output_path)
            
            # Create backup if requested
            if create_backup and output_path == path:
                backup_path = path.with_suffix(path.suffix + ".bak")
                backup_path.write_bytes(data)
                logger.info(f"Created backup: {backup_path}")
            
            # Write repaired file
            output_path.write_bytes(repaired_data)
            logger.info(f"Wrote repaired file: {output_path}")
        
        return repaired_data, report
    
    # Advanced PNG Repair Strategies
    
    def _repair_png_chunks(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair PNG chunk structure and CRCs."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_chunks",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a PNG file"],
            )
        
        changes = []
        warnings = []
        repaired = bytearray(data[:8])  # Keep PNG signature
        pos = 8
        chunks_repaired = 0
        
        while pos < len(data) - 12:
            try:
                # Read chunk length
                if pos + 4 > len(data):
                    break
                chunk_len = struct.unpack(">I", data[pos:pos+4])[0]
                
                if pos + 12 + chunk_len > len(data):
                    warnings.append(f"Truncated chunk at offset {pos}")
                    break
                
                # Read chunk type and data
                chunk_type = data[pos+4:pos+8]
                chunk_data = data[pos+8:pos+8+chunk_len]
                chunk_crc = struct.unpack(">I", data[pos+8+chunk_len:pos+12+chunk_len])[0]
                
                # Recalculate CRC
                calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
                
                if calc_crc != chunk_crc:
                    changes.append(f"Fixed CRC for {chunk_type.decode('ascii', errors='ignore')} chunk")
                    chunks_repaired += 1
                    chunk_crc = calc_crc
                
                # Write chunk
                repaired.extend(struct.pack(">I", chunk_len))
                repaired.extend(chunk_type)
                repaired.extend(chunk_data)
                repaired.extend(struct.pack(">I", chunk_crc))
                
                pos += 12 + chunk_len
                
                # Stop at IEND
                if chunk_type == b"IEND":
                    break
                    
            except Exception as e:
                warnings.append(f"Error at offset {pos}: {e}")
                break
        
        if not changes and not chunks_repaired:
            return data, RepairReport(
                success=False,
                strategy_used="repair_png_chunks",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["No repairs needed"],
            )
        
        return bytes(repaired), RepairReport(
            success=True,
            strategy_used="repair_png_chunks",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=changes,
            warnings=warnings,
            chunks_repaired=chunks_repaired,
            confidence=0.9,
        )
    
    def _repair_png_crc(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Fix all PNG chunk CRCs."""
        return self._repair_png_chunks(data)
    
    def _reconstruct_png_ihdr(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Reconstruct missing or corrupted PNG IHDR chunk."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            # Add PNG signature if missing
            data = b"\x89PNG\r\n\x1a\n" + data
        
        changes = []
        
        # Check if IHDR exists at position 8
        if len(data) < 33 or data[12:16] != b"IHDR":
            # Reconstruct minimal IHDR
            # Try to infer dimensions from IDAT chunks
            width, height = 800, 600  # Default fallback
            
            ihdr_data = struct.pack(">II", width, height)  # Width, Height
            ihdr_data += b"\x08\x02\x00\x00\x00"  # bit_depth=8, color_type=2 (RGB), compression=0, filter=0, interlace=0
            
            ihdr_chunk = struct.pack(">I", 13)  # Length
            ihdr_chunk += b"IHDR"
            ihdr_chunk += ihdr_data
            ihdr_chunk += struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xffffffff)
            
            # Insert after PNG signature
            repaired = data[:8] + ihdr_chunk + data[8:]
            changes.append("Reconstructed IHDR chunk with default dimensions")
            
            return repaired, RepairReport(
                success=True,
                strategy_used="reconstruct_png_ihdr",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Used default dimensions 800x600"],
                confidence=0.6,
            )
        
        return data, RepairReport(
            success=False,
            strategy_used="reconstruct_png_ihdr",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["IHDR already present"],
        )
    
    # Advanced JPEG Repair Strategies
    
    def _repair_jpeg_markers(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair JPEG markers and structure."""
        if not data.startswith(b"\xff\xd8"):
            # Add SOI marker
            data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + data
            changes = ["Added JPEG SOI and JFIF markers"]
        else:
            changes = []
        
        # Check for EOI marker
        if not data.endswith(b"\xff\xd9"):
            data += b"\xff\xd9"
            changes.append("Added JPEG EOI marker")
        
        if changes:
            return data, RepairReport(
                success=True,
                strategy_used="repair_jpeg_markers",
                original_size=len(data) - sum(len(c) for c in changes),
                repaired_size=len(data),
                changes_made=changes,
                warnings=[],
                confidence=0.85,
            )
        
        return data, RepairReport(
            success=False,
            strategy_used="repair_jpeg_markers",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["No repairs needed"],
        )
    
    def _add_jpeg_eoi(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Add JPEG end-of-image marker."""
        if data.endswith(b"\xff\xd9"):
            return data, RepairReport(
                success=False,
                strategy_used="add_jpeg_eoi",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["EOI marker already present"],
            )
        
        repaired = data + b"\xff\xd9"
        return repaired, RepairReport(
            success=True,
            strategy_used="add_jpeg_eoi",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added EOI marker (0xFFD9)"],
            warnings=[],
            confidence=0.95,
        )
    
    # Advanced ZIP Repair Strategies
    
    def _repair_zip_directory(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair ZIP central directory."""
        if not data.startswith(b"PK\x03\x04"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_zip_directory",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a ZIP file"],
            )
        
        changes = []
        warnings = []
        
        # Look for end of central directory
        eocd_sig = b"PK\x05\x06"
        eocd_pos = data.rfind(eocd_sig)
        
        if eocd_pos == -1:
            # Reconstruct EOCD
            eocd = eocd_sig
            eocd += b"\x00" * 18  # Minimal EOCD structure
            repaired = data + eocd
            changes.append("Reconstructed End of Central Directory")
            
            return repaired, RepairReport(
                success=True,
                strategy_used="repair_zip_directory",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Reconstructed minimal EOCD - file may not be fully accessible"],
                confidence=0.5,
            )
        
        return data, RepairReport(
            success=False,
            strategy_used="repair_zip_directory",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["Central directory appears intact"],
        )
    
    def _reconstruct_zip_headers(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Reconstruct ZIP local file headers."""
        if data.startswith(b"PK\x03\x04"):
            return data, RepairReport(
                success=False,
                strategy_used="reconstruct_zip_headers",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["ZIP header already present"],
            )
        
        # Add minimal ZIP local file header
        header = b"PK\x03\x04"  # Local file header signature
        header += b"\x14\x00"    # Version needed
        header += b"\x00\x00"    # General purpose bit flag
        header += b"\x00\x00"    # Compression method (stored)
        header += b"\x00" * 8    # Modification time/date
        header += b"\x00" * 12   # CRC-32, sizes
        header += b"\x00\x00"    # File name length
        header += b"\x00\x00"    # Extra field length
        
        repaired = header + data
        
        return repaired, RepairReport(
            success=True,
            strategy_used="reconstruct_zip_headers",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added ZIP local file header"],
            warnings=["File may require additional repair"],
            confidence=0.6,
        )
    
    # Advanced PDF Repair Strategies
    
    def _repair_pdf_xref(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Repair or reconstruct PDF cross-reference table."""
        if not data.startswith(b"%PDF"):
            return data, RepairReport(
                success=False,
                strategy_used="repair_pdf_xref",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["Not a PDF file"],
            )
        
        changes = []
        
        # Check for xref table
        if b"xref" not in data:
            # Add minimal xref and trailer
            xref = b"\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n"
            xref += str(len(data)).encode() + b"\n%%EOF"
            repaired = data + xref
            changes.append("Added minimal cross-reference table")
            
            return repaired, RepairReport(
                success=True,
                strategy_used="repair_pdf_xref",
                original_size=len(data),
                repaired_size=len(repaired),
                changes_made=changes,
                warnings=["Reconstructed minimal xref - PDF may have limited functionality"],
                confidence=0.5,
            )
        
        return data, RepairReport(
            success=False,
            strategy_used="repair_pdf_xref",
            original_size=len(data),
            repaired_size=len(data),
            changes_made=[],
            warnings=["xref table appears present"],
        )
    
    def _add_pdf_eof(self, data: bytes) -> Tuple[bytes, RepairReport]:
        """Add PDF end-of-file marker."""
        if data.rstrip().endswith(b"%%EOF"):
            return data, RepairReport(
                success=False,
                strategy_used="add_pdf_eof",
                original_size=len(data),
                repaired_size=len(data),
                changes_made=[],
                warnings=["EOF marker already present"],
            )
        
        repaired = data.rstrip() + b"\n%%EOF"
        return repaired, RepairReport(
            success=True,
            strategy_used="add_pdf_eof",
            original_size=len(data),
            repaired_size=len(repaired),
            changes_made=["Added %%EOF marker"],
            warnings=[],
            confidence=0.9,
        )
