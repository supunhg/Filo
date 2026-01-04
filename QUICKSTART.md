# Filo Quick Start Guide

Welcome to Filo! This guide will get you up and running in 5 minutes.

## Installation

```bash
# Clone the repository
git clone https://github.com/filo/forensics
cd forensics

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install
pip install -e .
```

## Basic Usage

### 1. Analyze a File

Identify what type of file you're dealing with:

```bash
filo analyze mysterious_file.bin
```

**Example Output:**
```
Detected Format: png
Confidence: 82.6%

File Size: 116 bytes
Entropy: 0.89 bits/byte
SHA256: 667eea...
```

### 2. List Available Formats

See what formats Filo can detect:

```bash
filo formats list
```

**Example Output:**
```
┌────────┬──────────────┬────────────────┬────────────┐
│ Format │ Category     │ Extensions     │ Signatures │
├────────┼──────────────┼────────────────┼────────────┤
│ png    │ raster_image │ png            │          2 │
│ jpeg   │ raster_image │ jpg, jpeg, jpe │          3 │
│ pdf    │ document     │ pdf            │          2 │
│ zip    │ archive      │ zip            │          3 │
...
```

### 3. Get Format Details

Learn about a specific format:

```bash
filo formats show png
```

**Example Output:**
```
Format: png
Version: 1.2
Category: raster_image

Signatures (2):
  • Offset 0: 89504E470D0A1A0A - PNG signature
  • Offset 8: 0000000D49484452 - IHDR chunk start

Repair Strategies:
  1. reconstruct_from_chunks
  2. generate_minimal_header
```

### 4. Repair Corrupted Files

Fix files with missing or corrupted headers:

```bash
filo repair corrupted.pdf --format=pdf -o repaired.pdf
```

**Example Output:**
```
Status: SUCCESS
Strategy Used: add_pdf_header
Original Size: 34 bytes
Repaired Size: 44 bytes

Changes Made:
  • Added PDF-1.7 header
```

### 5. JSON Output for Scripting

Get machine-readable output:

```bash
filo analyze file.bin --json | jq '.format'
```

### 6. Offline ML Learning

Teach Filo when it makes mistakes (fully offline, no cloud):

```bash
# Filo misidentified a file
filo analyze mystery.bin
# Output: png (40% confidence) - Wrong!

# Teach it the correct format
filo teach mystery.bin --format=jpeg

# Now it learns and improves
filo analyze mystery.bin
# Output: jpeg (95% confidence) - Correct!
```

The more you use it and correct it, the better it gets. All learning stays local in `models/learned_patterns.pkl`.

## Python API

Use Filo programmatically:

```python
from filo import Analyzer, RepairEngine

# Analyze a file
analyzer = Analyzer()
result = analyzer.analyze_file("mystery.bin")
print(f"Format: {result.primary_format} ({result.confidence:.0%})")

# Repair a file
engine = RepairEngine()
repaired, report = engine.repair_file(
    "corrupted.png",
    format_name="png",
    output_path="fixed.png"
)

if report.success:
    print(f"Repaired successfully using {report.strategy_used}")
```

## CTF Challenge Example

Common CTF workflow:

```bash
# You receive a file called "challenge"
file challenge
# Output: challenge: data

# Use Filo to identify it
filo analyze challenge
# Output: Detected Format: png (Confidence: 45%)

# Repair it
filo repair challenge --format=png -o flag.png

# Open it
xdg-open flag.png  # Shows the flag!
```

## Advanced Features

### Deep Analysis

```bash
filo analyze --deep suspicious.bin
```

### Multiple Files

```bash
find . -type f -exec filo analyze --json {} + | jq
```

### Format Filtering

```bash
filo formats list --category=raster_image
```

## Current Capabilities

✅ **Detection**
- 10 common formats (PNG, JPEG, GIF, PDF, ZIP, RAR, ELF, PE, MP3, MP4)
- Signature-based analysis
- Structural validation
- Entropy calculation
- Offline ML learning (improves with use)

✅ **Repair**
- Header reconstruction
- Multiple repair strategies per format
- Automatic strategy selection
- Safe backup creation

✅ **ML Learning**
- Learns from your corrections
- Fully offline (no telemetry, no cloud)
- Incremental pattern learning
- Local model storage

✅ **Intelligence**
- Format specification database
- MIME type mapping
- Extension mapping
- Evidence chain tracking

## What's Next?

Filo is in active development. See [ARCHITECTURE.md](../ARCHITECTURE.md) for the full vision.

**Coming Soon:**
- File carving from disk images
- More format specifications (targeting 500+)
- Advanced container format support
- Machine learning-based classification
- REST API
- Plugin system

## Getting Help

```bash
# General help
filo --help

# Command-specific help
filo analyze --help
filo repair --help
filo formats --help
```

## Contributing

Found a corrupted file that Filo can't handle? Want to add a new format?

1. Add a format specification in `filo/formats/yourformat.yaml`
2. Add tests in `tests/`
3. Submit a PR!

See format specifications in [filo/formats/](../filo/formats/) for examples.

---

**Happy Hunting! 🔍**
