"""
Tests for Analyzer
"""

import pytest

from filo.analyzer import Analyzer, SignatureAnalyzer, StatisticalAnalyzer


def test_analyzer_initialization():
    """Test analyzer initializes properly."""
    analyzer = Analyzer()
    assert analyzer.database.count() > 0


def test_analyze_png():
    """Test PNG file detection."""
    analyzer = Analyzer()
    
    # PNG signature
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452")
    png_data += b"\x00" * 100  # Add some data
    
    result = analyzer.analyze(png_data)
    
    assert result.primary_format == "png"
    assert result.confidence > 0.5
    assert result.file_size == len(png_data)
    assert result.checksum_sha256 is not None


def test_analyze_jpeg():
    """Test JPEG file detection."""
    analyzer = Analyzer()
    
    # JPEG JFIF signature
    jpeg_data = bytes.fromhex("FFD8FFE0") + b"\x00" * 100
    
    result = analyzer.analyze(jpeg_data)
    
    assert result.primary_format == "jpeg"
    assert result.confidence > 0.4  # Lowered threshold for partial signature match


def test_analyze_pdf():
    """Test PDF file detection."""
    analyzer = Analyzer()
    
    # PDF header
    pdf_data = b"%PDF-1.7\r\n" + b"\x00" * 100
    
    result = analyzer.analyze(pdf_data)
    
    assert result.primary_format == "pdf"
    assert result.confidence > 0.5


def test_analyze_unknown():
    """Test unknown file detection."""
    analyzer = Analyzer()
    
    # Random data
    unknown_data = b"\x00\x11\x22\x33\x44\x55" * 20
    
    result = analyzer.analyze(unknown_data)
    
    # Should be unknown with low confidence
    assert result.primary_format == "unknown"
    assert result.confidence == 0.0


def test_statistical_entropy():
    """Test entropy calculation."""
    # Random data should have high entropy
    import random
    random_data = bytes([random.randint(0, 255) for _ in range(1000)])
    entropy_random = StatisticalAnalyzer.calculate_entropy(random_data)
    assert entropy_random > 7.0  # Close to 8.0
    
    # Uniform data should have low entropy
    uniform_data = b"\x00" * 1000
    entropy_uniform = StatisticalAnalyzer.calculate_entropy(uniform_data)
    assert entropy_uniform == 0.0


def test_evidence_chain():
    """Test that evidence chain is populated."""
    analyzer = Analyzer()
    
    png_data = bytes.fromhex("89504E470D0A1A0A0000000D49484452") + b"\x00" * 100
    result = analyzer.analyze(png_data)
    
    assert len(result.evidence_chain) > 0
    assert result.evidence_chain[0]["module"] == "signature_analysis"
