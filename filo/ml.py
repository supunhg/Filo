import json
import pickle
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    offset: int
    pattern: bytes
    format: str
    weight: float = 1.0


@dataclass
class LearningExample:
    file_hash: str
    patterns: List[PatternMatch] = field(default_factory=list)
    correct_format: str = ""
    file_size: int = 0
    entropy: float = 0.0
    incorrect_formats: List[str] = field(default_factory=list)


class MLDetector:
    def __init__(self, model_path: Optional[Path] = None) -> None:
        if model_path is None:
            model_path = Path(__file__).parent.parent / "models" / "learned_patterns.pkl"
        
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.pattern_weights: Dict[Tuple[int, bytes, str], float] = {}
        self.negative_patterns: Dict[Tuple[int, bytes, str], float] = {}
        self.format_confidence_boost: Dict[str, float] = defaultdict(float)
        self.format_stats: Dict[str, Dict[str, float]] = defaultdict(lambda: {
            "count": 0,
            "avg_entropy": 0.0,
            "avg_size": 0.0
        })
        
        self.load_model()
    
    def load_model(self) -> None:
        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.pattern_weights = data.get("patterns", {})
                    self.negative_patterns = data.get("negative_patterns", {})
                    self.format_confidence_boost = defaultdict(float, data.get("confidence_boost", {}))
                    self.format_stats = defaultdict(
                        lambda: {"count": 0, "avg_entropy": 0.0, "avg_size": 0.0},
                        data.get("stats", {})
                    )
                logger.info(f"Loaded ML model with {len(self.pattern_weights)} patterns")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")
    
    def save_model(self) -> None:
        try:
            with open(self.model_path, "wb") as f:
                pickle.dump({
                    "patterns": dict(self.pattern_weights),
                    "negative_patterns": dict(self.negative_patterns),
                    "confidence_boost": dict(self.format_confidence_boost),
                    "stats": dict(self.format_stats)
                }, f)
            logger.info(f"Saved ML model to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save ML model: {e}")
    
    def learn(self, example: LearningExample) -> None:
        for pattern in example.patterns:
            key = (pattern.offset, pattern.pattern, example.correct_format)
            current_weight = self.pattern_weights.get(key, 0.0)
            self.pattern_weights[key] = min(1.0, current_weight + 0.15)
        
        for incorrect_fmt in example.incorrect_formats:
            for pattern in example.patterns:
                neg_key = (pattern.offset, pattern.pattern, incorrect_fmt)
                self.negative_patterns[neg_key] = self.negative_patterns.get(neg_key, 0.0) + 0.1
        
        self.format_confidence_boost[example.correct_format] += 0.05
        
        stats = self.format_stats[example.correct_format]
        count = stats["count"]
        stats["avg_entropy"] = (stats["avg_entropy"] * count + example.entropy) / (count + 1)
        stats["avg_size"] = (stats["avg_size"] * count + example.file_size) / (count + 1)
        stats["count"] = count + 1
        
        self.save_model()
    
    def predict(self, data: bytes, entropy: float, file_size: int) -> List[Tuple[str, float]]:
        if not self.pattern_weights:
            return []
        
        format_scores: Dict[str, float] = defaultdict(float)
        
        scan_length = min(8192, len(data))
        
        for (offset, pattern, fmt), weight in self.pattern_weights.items():
            if offset >= scan_length:
                continue
            
            end_offset = offset + len(pattern)
            if end_offset <= len(data) and data[offset:end_offset] == pattern:
                format_scores[fmt] += weight
                
                neg_key = (offset, pattern, fmt)
                if neg_key in self.negative_patterns:
                    format_scores[fmt] -= self.negative_patterns[neg_key] * 0.5
        
        for fmt, stats in self.format_stats.items():
            if stats["count"] < 3:
                continue
            
            entropy_diff = abs(entropy - stats["avg_entropy"])
            size_ratio = min(file_size, stats["avg_size"]) / max(file_size, stats["avg_size"], 1)
            
            if entropy_diff < 2.0:
                format_scores[fmt] += 0.2
            if size_ratio > 0.5:
                format_scores[fmt] += 0.1
        
        for fmt in format_scores:
            format_scores[fmt] += self.format_confidence_boost.get(fmt, 0.0)
        
        results = sorted(format_scores.items(), key=lambda x: x[1], reverse=True)
        
        if results:
            max_score = results[0][1]
            if max_score > 0:
                results = [(fmt, min(1.0, score / max_score)) for fmt, score in results]
        
        return results[:3]
    
    def extract_patterns(self, data: bytes, max_patterns: int = 10) -> List[bytes]:
        patterns = []
        
        for size in [4, 8, 16]:
            for offset in range(0, min(1024, len(data) - size), size):
                pattern = data[offset:offset + size]
                if len(set(pattern)) > 1:
                    patterns.append(pattern)
        
        return patterns[:max_patterns]
