# Filo Examples

This directory contains example scripts demonstrating Filo's capabilities.

## Running Examples

```bash
# Basic usage examples
python usage_examples.py

# Or with the installed package
python -c "from examples.usage_examples import *; example_basic_analysis()"
```

## Examples Included

### 1. Basic Usage (`usage_examples.py`)
Demonstrates core analysis and repair functionality.

### 2. Advanced Repair (`advanced_repair_demo.py`)
Showcases the 21 repair strategies with real examples.

### 3. File Carving (`carving_demo.py`)
Extracts embedded files from disk images and concatenated data.

### 4. Confidence Breakdown Demo (`confidence_breakdown_demo.py`) ⭐
Demonstrates auditable confidence scoring with --explain flag:
- Shows how each analyzer contributes to detection
- Percentage breakdown (+/- penalties)
- Court-ready transparency for digital forensics

### 5. Contradiction Detection Demo (`contradiction_demo.py`) 🔒⭐
Security-focused demonstrations for malware triage:
- Embedded executable detection (ELF, PE, Mach-O)
- OOXML structure validation
- PNG compression validation
- PDF/JPEG structure checks
- Polyglot detection
- JSON output for automation

### 6. New Features Demo (`features_demo.py`)
Comprehensive demonstration of v0.2.0 features:
- Batch processing with parallel execution
- JSON/SARIF export for CI/CD
- Container detection (ZIP/TAR)
- Performance profiling
- Enhanced CLI output with color coding

### 5. Benchmarking (`benchmark.py`)
Performance testing across different file sizes and formats.

### 6. Format Testing (`test_new_formats.py`)
Utility for testing custom format specifications.

## Running the v0.2.0 Features Demo

```bash
# Run comprehensive features demonstration
python examples/features_demo.py
```

This will showcase all 5 new features with Rich console output.

## Creating Your Own Examples

```python
from filo import Analyzer, RepairEngine
from filo.batch import analyze_directory
from filo.export import export_to_file
from filo.container import analyze_archive

# Analyze a single file
analyzer = Analyzer()
result = analyzer.analyze_file("mystery_file.bin")
print(f"Format: {result.primary_format} ({result.confidence:.0%})")

# Batch process directory
batch_result = analyze_directory("./data")
print(f"Analyzed {batch_result.analyzed_count} files")

# Export results
export_to_file(result, "report.json", format="json")

# Analyze container
container = analyze_archive("archive.zip")
for entry in container.entries:
    print(f"{entry.path}: {entry.format}")

# Repair a file
engine = RepairEngine()
engine.repair_file("corrupted.png", format_name="png", output_path="fixed.png")
```

## Additional Resources

- [Quick Start Guide](../QUICKSTART.md)
- [Advanced Repair Documentation](../docs/ADVANCED_REPAIR.md)
- [New Features Guide](../docs/NEW_FEATURES.md)
- [Architecture Overview](../ARCHITECTURE.md)
