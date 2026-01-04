import hashlib
import logging
from pathlib import Path
from typing import Optional, Union
import mmap

from filo.formats import FormatDatabase
from filo.models import AnalysisResult, DetectionResult

logger = logging.getLogger(__name__)

try:
    from filo.ml import MLDetector, LearningExample, PatternMatch
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class SignatureAnalyzer:
    def __init__(self, database: FormatDatabase) -> None:
        self.database = database
        self._signature_cache = {}
    """Signature-based file format detection."""
    
    def __init__(self, database: FormatDatabase) -> None:
        self.database = database
    
    def analyze(self, data: bytes, max_bytes: int = 8192) -> list[DetectionResult]:
        """
        Analyze file signatures.
        
        Args:
            data: File data to analyze
            max_bytes: Maximum bytes to scan for signatures
        
        Returns:
            List of detection results with confidence scores
        """
        results: list[DetectionResult] = []
        scan_data = data[:max_bytes]
        
        for format_spec in self.database._formats.values():
            evidence = []
            total_weight = 0.0
            matched_weight = 0.0
            
            # Check signatures
            for sig in format_spec.signatures:
                total_weight += sig.weight
                
                if sig.offset >= len(data):
                    continue
                
                # Convert hex string to bytes
                sig_bytes = bytes.fromhex(sig.hex)
                end_offset = sig.offset + len(sig_bytes)
                
                if end_offset <= len(scan_data):
                    if scan_data[sig.offset:end_offset] == sig_bytes:
                        matched_weight += sig.weight
                        evidence.append(
                            f"Signature match at offset {sig.offset}: {sig.description}"
                        )
            
            # Calculate confidence
            if total_weight > 0:
                confidence = (matched_weight / total_weight) * format_spec.confidence_weight
                
                if confidence > 0.3:  # Minimum threshold
                    results.append(
                        DetectionResult(
                            format=format_spec.format,
                            confidence=confidence,
                            evidence=evidence,
                            weight=1.0,
                        )
                    )
        
        return sorted(results, key=lambda r: r.confidence, reverse=True)


class StructuralAnalyzer:
    def __init__(self, database: FormatDatabase) -> None:
        self.database = database
    
    def analyze(self, data: bytes, suspected_format: Optional[str] = None) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        
        # If we have a suspected format, validate its structure
        if suspected_format and suspected_format in self.database:
            spec = self.database.get_format(suspected_format)
            if spec and spec.structure:
                evidence = []
                confidence = 0.8  # Base confidence for structural match
                
                # Check header size
                if spec.structure.header_size:
                    if len(data) >= spec.structure.header_size:
                        evidence.append(f"Valid header size: {spec.structure.header_size} bytes")
                    else:
                        confidence *= 0.5
                        evidence.append("File too small for expected header")
                
                # Check footer signatures
                for footer in spec.footers:
                    footer_bytes = bytes.fromhex(footer.hex)
                    if data.endswith(footer_bytes):
                        confidence = min(1.0, confidence + 0.15)
                        evidence.append(f"Footer match: {footer.description}")
                
                if evidence:
                    results.append(
                        DetectionResult(
                            format=suspected_format,
                            confidence=confidence,
                            evidence=evidence,
                            weight=0.8,
                        )
                    )
        
        return results


class StatisticalAnalyzer:
    @staticmethod
    def calculate_entropy(data: bytes, sample_size: int = 2048) -> float:
        if not data:
            return 0.0
        
        sample = data[:min(sample_size, len(data))]
        
        frequencies = [0] * 256
        for byte in sample:
            frequencies[byte] += 1
        
        import math
        entropy = 0.0
        data_len = len(sample)
        
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy


class Analyzer:
    def __init__(
        self, 
        database: Optional[FormatDatabase] = None,
        use_ml: bool = True
    ) -> None:
        self.database = database or FormatDatabase()
        self.signature_analyzer = SignatureAnalyzer(self.database)
        self.structural_analyzer = StructuralAnalyzer(self.database)
        self.statistical_analyzer = StatisticalAnalyzer()
        
        self.ml_detector: Optional['MLDetector'] = None
        if use_ml and ML_AVAILABLE:
            try:
                self.ml_detector = MLDetector()
                logger.info("ML detector enabled")
            except Exception as e:
                logger.warning(f"ML detector failed to initialize: {e}")
        
        logger.info(f"Analyzer initialized with {self.database.count()} formats")
    
    def analyze(self, data: bytes) -> AnalysisResult:
        checksum = hashlib.sha256(data).hexdigest()[:16]
        
        sig_results = self.signature_analyzer.analyze(data)
        
        if sig_results and sig_results[0].confidence > 0.95:
            entropy = self.statistical_analyzer.calculate_entropy(data[:2048])
            
            return AnalysisResult(
                primary_format=sig_results[0].format,
                confidence=sig_results[0].confidence,
                alternative_formats=[(r.format, r.confidence) for r in sig_results[1:3]],
                evidence_chain=[{
                    "module": "signature_analysis",
                    "format": sig_results[0].format,
                    "confidence": sig_results[0].confidence,
                    "evidence": sig_results[0].evidence,
                    "weight": 1.0,
                }],
                file_size=len(data),
                entropy=entropy,
                checksum_sha256=checksum,
            )
        
        struct_results = []
        if sig_results:
            struct_results = self.structural_analyzer.analyze(
                data, suspected_format=sig_results[0].format
            )
        
        entropy = self.statistical_analyzer.calculate_entropy(data[:2048])
        
        ml_results = []
        if self.ml_detector:
            ml_results = self.ml_detector.predict(data, entropy, len(data))
        
        format_scores: dict[str, float] = {}
        evidence_chain: list[dict] = []
        
        for result in sig_results:
            format_scores[result.format] = format_scores.get(result.format, 0.0) + (
                result.confidence * result.weight * 0.6
            )
            evidence_chain.append({
                "module": "signature_analysis",
                "format": result.format,
                "confidence": result.confidence,
                "evidence": result.evidence,
                "weight": result.weight,
            })
        
        for result in struct_results:
            format_scores[result.format] = format_scores.get(result.format, 0.0) + (
                result.confidence * result.weight * 0.4
            )
            evidence_chain.append({
                "module": "structural_analysis",
                "format": result.format,
                "confidence": result.confidence,
                "evidence": result.evidence,
                "weight": result.weight,
            })
        
        for fmt, ml_confidence in ml_results:
            format_scores[fmt] = format_scores.get(fmt, 0.0) + (ml_confidence * 0.2)
            evidence_chain.append({
                "module": "ml_prediction",
                "format": fmt,
                "confidence": ml_confidence,
                "evidence": ["Learned pattern match"],
                "weight": 0.2,
            })
        
        # Determine primary format
        if format_scores:
            primary_format = max(format_scores, key=format_scores.get)  # type: ignore
            confidence = min(1.0, format_scores[primary_format])
            
            alternatives = [
                (fmt, score) for fmt, score in format_scores.items() if fmt != primary_format
            ]
            alternatives.sort(key=lambda x: x[1], reverse=True)
        else:
            primary_format = "unknown"
            confidence = 0.0
            alternatives = []
        
        return AnalysisResult(
            primary_format=primary_format,
            confidence=confidence,
            alternative_formats=alternatives,
            evidence_chain=evidence_chain,
            file_size=len(data),
            entropy=entropy,
            checksum_sha256=checksum,
        )
    
    def teach(self, data: bytes, correct_format: str, incorrect_guess: Optional[str] = None) -> None:
        if not self.ml_detector:
            logger.warning("ML detector not available for teaching")
            return
        
        entropy = self.statistical_analyzer.calculate_entropy(data[:8192])
        file_hash = hashlib.sha256(data).hexdigest()
        
        patterns = []
        spec = self.database.get_format(correct_format)
        if spec:
            for sig in spec.signatures:
                sig_bytes = bytes.fromhex(sig.hex)
                if len(data) > sig.offset + len(sig_bytes):
                    if data[sig.offset:sig.offset + len(sig_bytes)] == sig_bytes:
                        patterns.append(PatternMatch(
                            offset=sig.offset,
                            pattern=sig_bytes,
                            format=correct_format,
                            weight=sig.weight
                        ))
        
        incorrect_formats = []
        if incorrect_guess:
            incorrect_formats.append(incorrect_guess)
        
        example = LearningExample(
            file_hash=file_hash,
            patterns=patterns,
            correct_format=correct_format,
            file_size=len(data),
            entropy=entropy,
            incorrect_formats=incorrect_formats
        )
        
        self.ml_detector.learn(example)
        logger.info(f"Learned from example: {correct_format}")
    
    def analyze_file(self, file_path: Union[str, Path]) -> AnalysisResult:
        path = Path(file_path)
        file_size = path.stat().st_size
        
        if file_size > 10 * 1024 * 1024:
            with open(path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                    data = bytes(mmapped[:min(1024 * 1024, file_size)])
        else:
            with open(path, "rb") as f:
                data = f.read()
        
        return self.analyze(data)
