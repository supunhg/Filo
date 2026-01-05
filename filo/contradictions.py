"""
Contradiction detection for identifying format anomalies and suspicious structures.

This module detects when files exhibit contradictory traits that may indicate:
- Corrupted files
- Malware/polyglots
- Format confusion attacks
- Embedded malicious content
"""

import logging
from typing import Optional
from filo.models import Contradiction

logger = logging.getLogger(__name__)


class ContradictionDetector:
    """Detects structural contradictions and format anomalies."""
    
    @staticmethod
    def check_png_compression(data: bytes) -> Optional[Contradiction]:
        """Check if PNG has valid zlib compression in IDAT chunks."""
        if len(data) < 33:  # Minimum PNG size
            return None
        
        # Find IDAT chunk
        pos = 8  # After PNG signature
        idat_found = False
        
        try:
            while pos < len(data) - 12:
                if pos + 8 > len(data):
                    break
                    
                # Read chunk length and type
                chunk_length = int.from_bytes(data[pos:pos+4], 'big')
                chunk_type = data[pos+4:pos+8]
                
                if chunk_type == b'IDAT':
                    idat_found = True
                    # Try to decompress zlib stream
                    import zlib
                    idat_data = data[pos+8:pos+8+chunk_length]
                    
                    try:
                        zlib.decompress(idat_data)
                    except zlib.error as e:
                        return Contradiction(
                            severity="error",
                            claimed_format="png",
                            issue="Invalid compression stream",
                            details=f"IDAT chunk contains invalid zlib data: {str(e)}",
                            category="compression"
                        )
                    break
                
                # Move to next chunk
                pos += 12 + chunk_length
                
        except Exception as e:
            logger.debug(f"PNG compression check failed: {e}")
        
        return None
    
    @staticmethod
    def check_zip_ooxml_structure(data: bytes, namelist: list[str]) -> Optional[Contradiction]:
        """Check if ZIP claiming to be OOXML has required structure."""
        has_content_types = any('[content_types].xml' in name.lower() for name in namelist)
        
        if has_content_types:
            # This claims to be OOXML format
            has_rels = any('_rels/.rels' in name.lower() for name in namelist)
            
            if not has_rels:
                return Contradiction(
                    severity="warning",
                    claimed_format="ooxml",
                    issue="Missing mandatory _rels/.rels",
                    details="OOXML format requires _rels/.rels but it's absent",
                    category="missing"
                )
            
            # Check for specific format markers
            has_word = any('word/document.xml' in name.lower() for name in namelist)
            has_ppt = any('ppt/presentation.xml' in name.lower() for name in namelist)
            has_xl = any('xl/workbook.xml' in name.lower() for name in namelist)
            
            # If it has Content_Types but no actual document
            if not (has_word or has_ppt or has_xl):
                return Contradiction(
                    severity="warning",
                    claimed_format="ooxml",
                    issue="Missing core document file",
                    details="Has [Content_Types].xml but no document.xml, presentation.xml, or workbook.xml",
                    category="structure"
                )
        
        return None
    
    @staticmethod
    def check_embedded_formats(data: bytes, primary_format: str, **context) -> list[Contradiction]:
        """Detect suspicious embedded format signatures."""
        contradictions = []
        
        # For ZIP-based formats, also check inside compressed members
        if primary_format in ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt', 'odp', 'ods', 'epub']:
            try:
                import zipfile
                import io
                
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    for name in zf.namelist()[:20]:  # Check first 20 files
                        try:
                            member_data = zf.read(name)
                            # Check first 10KB of each member
                            check_data = member_data[:min(len(member_data), 10240)]
                            
                            # Suspicious patterns
                            suspicious_patterns = {
                                b'\x7fELF': ('ELF executable', 'embedded'),
                                b'MZ': ('PE/DOS executable', 'embedded'),
                                b'\xca\xfe\xba\xbe': ('Mach-O executable', 'embedded'),
                                b'#!/bin/sh': ('Shell script', 'embedded'),
                                b'#!/bin/bash': ('Bash script', 'embedded'),
                                b'<?php': ('PHP script', 'embedded'),
                            }
                            
                            for pattern, (format_name, category) in suspicious_patterns.items():
                                offset = check_data.find(pattern)
                                if offset != -1 and offset < 8192:  # Within first 8KB
                                    contradictions.append(Contradiction(
                                        severity="critical",
                                        claimed_format=primary_format,
                                        issue=f"Embedded {format_name} signature",
                                        details=f"Found {format_name} in ZIP member '{name}' at offset {offset}",
                                        category=category
                                    ))
                                    break  # One per member
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"ZIP member check failed: {e}")
        
        # Also check main file data (for non-ZIP or polyglots)
        # Skip first 512 bytes (legitimate headers)
        search_data = data[512:min(len(data), 10240)]  # Search next 10KB
        
        # Suspicious magic bytes to look for
        suspicious_patterns = {
            b'\x7fELF': ('ELF executable', 'embedded'),
            b'MZ': ('PE/DOS executable', 'embedded'),
            b'\x4d\x5a\x90': ('PE executable', 'embedded'),
            b'\xca\xfe\xba\xbe': ('Mach-O executable', 'embedded'),
            b'#!/bin/sh': ('Shell script', 'embedded'),
            b'#!/bin/bash': ('Bash script', 'embedded'),
            b'<?php': ('PHP script', 'embedded'),
        }
        
        for pattern, (format_name, category) in suspicious_patterns.items():
            offset = search_data.find(pattern)
            if offset != -1:
                contradictions.append(Contradiction(
                    severity="critical",
                    claimed_format=primary_format,
                    issue=f"Embedded {format_name} signature",
                    details=f"Found {format_name} magic bytes at offset {512 + offset}",
                    category=category
                ))
        
        return contradictions
    
    @staticmethod
    def check_zip_structure_integrity(data: bytes) -> Optional[Contradiction]:
        """Check ZIP structural integrity."""
        try:
            import zipfile
            import io
            
            zip_buffer = io.BytesIO(data)
            with zipfile.ZipFile(zip_buffer, 'r') as zf:
                # Test ZIP integrity
                corrupt_files = []
                for name in zf.namelist()[:10]:  # Check first 10 files
                    try:
                        zf.testzip()
                        break
                    except Exception as e:
                        corrupt_files.append(name)
                
                if corrupt_files:
                    return Contradiction(
                        severity="error",
                        claimed_format="zip",
                        issue="Corrupted ZIP entries",
                        details=f"ZIP structure corruption detected in: {', '.join(corrupt_files[:3])}",
                        category="structure"
                    )
        except Exception as e:
            logger.debug(f"ZIP integrity check failed: {e}")
        
        return None
    
    @staticmethod
    def check_jpeg_structure(data: bytes) -> Optional[Contradiction]:
        """Check JPEG marker sequence validity."""
        if len(data) < 10:
            return None
        
        # JPEG should start with SOI (0xFFD8)
        if data[0:2] != b'\xff\xd8':
            return None
        
        # Check for common structural issues
        pos = 2
        has_sof = False
        has_sos = False
        
        try:
            while pos < len(data) - 2:
                if data[pos] != 0xFF:
                    # Not a marker
                    break
                
                marker = data[pos+1]
                
                # Start of Frame markers
                if marker in [0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7]:
                    has_sof = True
                
                # Start of Scan
                if marker == 0xDA:
                    has_sos = True
                    break
                
                # End of Image
                if marker == 0xD9:
                    break
                
                # Skip marker
                if marker in [0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8]:
                    # Standalone markers (no length)
                    pos += 2
                else:
                    # Read length
                    if pos + 3 >= len(data):
                        break
                    length = (data[pos+2] << 8) | data[pos+3]
                    pos += 2 + length
            
            # JPEG should have SOF and SOS markers
            if has_sof and not has_sos:
                return Contradiction(
                    severity="warning",
                    claimed_format="jpeg",
                    issue="Missing Start of Scan (SOS) marker",
                    details="JPEG has SOF but no SOS marker - likely truncated",
                    category="structure"
                )
            
        except Exception as e:
            logger.debug(f"JPEG structure check failed: {e}")
        
        return None
    
    @staticmethod
    def check_pdf_structure(data: bytes) -> Optional[Contradiction]:
        """Check PDF structural validity."""
        if len(data) < 8:
            return None
        
        # PDF should start with %PDF-
        if not data.startswith(b'%PDF-'):
            return None
        
        # Check for EOF marker
        if b'%%EOF' not in data[-1024:]:
            return Contradiction(
                severity="warning",
                claimed_format="pdf",
                issue="Missing EOF marker",
                details="PDF lacks %%EOF marker in last 1KB - may be truncated or corrupted",
                category="structure"
            )
        
        return None
    
    @staticmethod
    def detect_all(data: bytes, primary_format: str, **context) -> list[Contradiction]:
        """Run all contradiction checks and return findings."""
        contradictions = []
        
        # Format-specific checks
        if primary_format == 'png':
            contradiction = ContradictionDetector.check_png_compression(data)
            if contradiction:
                contradictions.append(contradiction)
        
        elif primary_format == 'jpeg':
            contradiction = ContradictionDetector.check_jpeg_structure(data)
            if contradiction:
                contradictions.append(contradiction)
        
        elif primary_format == 'pdf':
            contradiction = ContradictionDetector.check_pdf_structure(data)
            if contradiction:
                contradictions.append(contradiction)
        
        elif primary_format in ['docx', 'xlsx', 'pptx']:
            # Check OOXML structure if we have namelist
            namelist = context.get('namelist', [])
            if namelist:
                contradiction = ContradictionDetector.check_zip_ooxml_structure(data, namelist)
                if contradiction:
                    contradictions.append(contradiction)
        
        elif primary_format == 'zip':
            contradiction = ContradictionDetector.check_zip_structure_integrity(data)
            if contradiction:
                contradictions.append(contradiction)
        
        # Universal checks
        # Check for embedded executables (malware triage)
        if primary_format in ['zip', 'docx', 'xlsx', 'pptx', 'pdf', 'png', 'jpeg']:
            embedded = ContradictionDetector.check_embedded_formats(data, primary_format)
            contradictions.extend(embedded)
        
        return contradictions
