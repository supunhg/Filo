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

### 1. Basic Analysis
Demonstrates how to analyze a file and interpret results.

### 2. File Repair
Shows how to repair corrupted files with missing headers.

### 3. Format Database
Illustrates querying the format specification database.

### 4. Multi-Format Detection
Tests detection across multiple file formats.

## Creating Your Own Examples

```python
from filo import Analyzer, RepairEngine

# Analyze a file
analyzer = Analyzer()
result = analyzer.analyze_file("mystery_file.bin")
print(f"Format: {result.primary_format} ({result.confidence:.0%})")

# Repair a file
engine = RepairEngine()
engine.repair_file("corrupted.png", format_name="png", output_path="fixed.png")
```
