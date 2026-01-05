# Embedded Object Detection

**Detect files hidden inside files - malware hunter candy.**

## Overview

Embedded Object Detection finds files hidden within other files, even when malformed. This is critical for:

- **Malware Analysis**: Detect droppers, packers, and polyglots
- **Forensic Investigation**: Find hidden payloads in documents
- **Security Triage**: Identify suspicious file combinations
- **Steganography Detection**: Locate files appended after EOF

## Quick Start

```bash
# Analyze file for embedded objects
filo analyze suspicious.exe

# Example output:
# 🔍 Embedded Artifacts:
#   • Offset 0x8F23: ZIP (prob. 94%)
#     1,234 bytes - ZIP at offset 0x8F23 (1,234 bytes)
#     Signature: 50 4b 03 04...
```

## Detection Capabilities

### 1. ZIP Inside EXE (Malware Droppers)

```python
from filo import Analyzer

analyzer = Analyzer()
result = analyzer.analyze_file("malware.exe")

for obj in result.embedded_objects:
    if obj.format == "zip" and obj.offset > 0:
        print(f"⚠ Found ZIP archive at {obj.offset:#x}")
        print(f"   Confidence: {obj.confidence:.0%}")
        print(f"   Size: {obj.size} bytes")
```

**Output:**
```
⚠ Found ZIP archive at 0x8f23
   Confidence: 94%
   Size: 45,678 bytes
```

### 2. PNG Appended After EOF (Steganography)

```python
from filo.embedded import EmbeddedDetector

detector = EmbeddedDetector()

# Read file
with open("document.pdf", "rb") as f:
    data = f.read()

# Check for overlay
overlay = detector.detect_overlay(data, "pdf")
if overlay:
    print(f"Hidden data after EOF at offset {overlay.offset:#x}")
    print(f"Format: {overlay.format}")
```

### 3. PDF with Embedded Executables (Exploits)

```python
result = analyzer.analyze_file("invoice.pdf")

for obj in result.embedded_objects:
    if obj.format in ["pe", "elf", "dll"]:
        print(f"🚨 CRITICAL: Executable embedded in PDF!")
        print(f"   Type: {obj.format.upper()}")
        print(f"   Offset: {obj.offset:#x}")
```

### 4. Polyglots (Multiple Valid Formats)

A file that's valid as both ZIP and PE:

```python
embedded = detector.detect_embedded(data, skip_primary=True)

formats_found = {obj.format for obj in embedded}
if len(formats_found) > 1:
    print(f"⚠ Polyglot detected: {', '.join(formats_found)}")
```

## CLI Usage

### Basic Detection

```bash
# Automatic detection
filo analyze suspicious.bin
```

### JSON Output for Automation

```bash
# Get embedded objects in JSON
filo analyze malware.exe --json | jq '.embedded_objects'
```

**Output:**
```json
[
  {
    "offset": 36643,
    "format": "zip",
    "confidence": 0.94,
    "size": 45678,
    "description": "ZIP at offset 0x8F23 (45678 bytes)",
    "data_snippet": "504b0304140000000800"
  }
]
```

### Security Triage Workflow

```bash
# Find all files with embedded executables
for file in *.pdf *.docx *.xlsx; do
  filo analyze "$file" --json | \
    jq -r 'select(.embedded_objects[]? | .format | match("pe|elf|dll")) | .file'
done
```

## Python API

### EmbeddedDetector Class

```python
from filo.embedded import EmbeddedDetector

detector = EmbeddedDetector()

# Detect all embedded objects
embedded = detector.detect_embedded(
    data,
    min_confidence=0.70,  # Minimum confidence threshold
    skip_primary=True      # Skip signature at offset 0
)

for obj in embedded:
    print(f"{obj.format.upper()} at {obj.offset:#x} ({obj.confidence:.0%})")
```

### EmbeddedObject Model

```python
@dataclass
class EmbeddedObject:
    offset: int          # Byte offset where object starts
    format: str          # Detected format (e.g., 'zip', 'pe')
    confidence: float    # Detection confidence (0.0-1.0)
    size: int | None     # Estimated size in bytes
    description: str     # Human-readable description
    data_snippet: bytes  # First 16 bytes for verification
```

### Overlay Detection

```python
# Detect data after logical EOF
overlay = detector.detect_overlay(data, primary_format="pe")

if overlay:
    print(f"Overlay detected at {overlay.offset:#x}")
    print(f"Contains: {overlay.format}")
```

## Real-World Examples

### Example 1: Malware Dropper

**Scenario:** EXE with embedded ZIP containing second-stage payload

```python
result = analyzer.analyze_file("dropper.exe")

print(f"Primary format: {result.primary_format}")
print(f"\nEmbedded artifacts:")

for obj in result.embedded_objects:
    print(f"  • {obj.format.upper()} at {obj.offset:#x}")
    print(f"    Confidence: {obj.confidence:.0%}")
    print(f"    Size: {obj.size:,} bytes")
```

**Output:**
```
Primary format: pe

Embedded artifacts:
  • ZIP at 0x1f400
    Confidence: 94%
    Size: 128,456 bytes
```

### Example 2: Weaponized Document

**Scenario:** DOCX with embedded PE executable

```bash
$ filo analyze invoice.docx

🔍 Embedded Artifacts:
  • Offset 0x2A10: PE (prob. 91%)
    12,288 bytes - PE at offset 0x2A10 (12,288 bytes)
    Signature: 4d 5a 90 00...

⚠ Structural Contradictions Detected:

  🚨 CRITICAL: Embedded executable detected
     Claims: docx
     PE/DLL/EXE embedded in document (potential malware)
     Category: embedded
```

### Example 3: Steganography

**Scenario:** PNG appended to JPEG

```python
with open("photo.jpg", "rb") as f:
    data = f.read()

# Check for overlay
overlay = detector.detect_overlay(data, "jpeg")

if overlay:
    print(f"Hidden {overlay.format.upper()} found after JPEG EOF")
    print(f"Offset: {overlay.offset:#x}")
    print(f"Size: {overlay.size:,} bytes")
    
    # Extract hidden file
    hidden_data = data[overlay.offset:]
    with open("extracted.png", "wb") as out:
        out.write(hidden_data)
```

## Confidence Scoring

Embedded detection uses multi-factor confidence scoring:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Signature Length** | +5-10% | Longer signatures = higher confidence |
| **Alignment** | +2-5% | 512-byte aligned = +5%, 16-byte = +2% |
| **Structural Validation** | +10% | Valid headers (ZIP, PE, ELF) |
| **Base Confidence** | 70% | Starting point for signature match |

**Example:**
- ZIP signature at 512-byte boundary: 70% + 5% (length) + 5% (align) + 10% (valid) = **90%**
- Random ZIP signature: 70% + 5% (length) = **75%**

## Detection Strategies

### 1. Signature Scanning

Scans entire file for known magic bytes at any offset:

```python
# Find all ZIP archives (including inside other files)
for obj in embedded:
    if obj.format == "zip":
        print(f"ZIP found at {obj.offset:#x}")
```

### 2. Overlay Detection

Finds data appended after logical EOF:

```python
# Works for: PE, ELF, ZIP, PDF, PNG
overlay = detector.detect_overlay(data, primary_format)
```

### 3. Polyglot Analysis

Identifies files valid as multiple formats:

```python
formats = {obj.format for obj in embedded}
if "zip" in formats and "pe" in formats:
    print("⚠ Polyglot: Valid as both ZIP and PE")
```

## Integration Examples

### Batch Processing

```python
from pathlib import Path
from filo import Analyzer

analyzer = Analyzer()

for file_path in Path("./suspicious").rglob("*"):
    if file_path.is_file():
        result = analyzer.analyze_file(file_path)
        
        if result.embedded_objects:
            print(f"\n{file_path.name}:")
            for obj in result.embedded_objects:
                print(f"  {obj.format} at {obj.offset:#x}")
```

### YARA Integration

```python
import yara

# First, use Filo to find embedded objects
result = analyzer.analyze_file("sample.exe")

for obj in result.embedded_objects:
    if obj.format == "zip":
        # Extract and scan with YARA
        zip_data = data[obj.offset:obj.offset + obj.size]
        
        rules = yara.compile(filepath="malware.yar")
        matches = rules.match(data=zip_data)
        
        if matches:
            print(f"⚠ YARA match in embedded ZIP: {matches}")
```

### Threat Intelligence

```python
def classify_threat(result):
    """Classify threat level based on embedded objects."""
    threat_level = "SAFE"
    
    for obj in result.embedded_objects:
        # Executable in document = CRITICAL
        if obj.format in ["pe", "elf", "dll"]:
            if result.primary_format in ["pdf", "docx", "xlsx"]:
                threat_level = "CRITICAL"
                break
        
        # Multiple embedded = SUSPICIOUS
        elif len(result.embedded_objects) > 2:
            threat_level = "SUSPICIOUS"
    
    return threat_level
```

## Performance

- **Scan Speed**: ~100 MB/s (signature matching)
- **Memory Usage**: Minimal (streaming supported)
- **False Positives**: <1% with default 70% threshold

## Limitations

1. **Encrypted Containers**: Cannot detect encrypted embedded objects
2. **Custom Formats**: Only detects formats in database
3. **Size Estimation**: Heuristic-based (may be inaccurate)
4. **Compressed Data**: Embedded objects inside compressed archives

## Best Practices

### 1. Adjust Confidence Threshold

```python
# High-security: Low false positives
embedded = detector.detect_embedded(data, min_confidence=0.85)

# Forensics: Catch everything
embedded = detector.detect_embedded(data, min_confidence=0.60)
```

### 2. Verify Detections

```python
# Always verify high-impact detections
for obj in embedded:
    if obj.format in ["pe", "elf", "dll"]:
        # Manual verification
        snippet = data[obj.offset:obj.offset + 100]
        print(f"Hex dump:\n{snippet.hex()}")
```

### 3. Combine with Other Tools

```python
# Filo + VirusTotal
import requests

for obj in result.embedded_objects:
    if obj.format in ["pe", "dll"]:
        # Extract and submit to VT
        exe_data = data[obj.offset:obj.offset + obj.size]
        sha256 = hashlib.sha256(exe_data).hexdigest()
        
        # Query VT API
        vt_response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": API_KEY}
        )
```

## Troubleshooting

### Issue: Too Many False Positives

**Solution:** Increase confidence threshold

```python
embedded = detector.detect_embedded(data, min_confidence=0.85)
```

### Issue: Missing Known Embedded Files

**Solution:** Lower threshold or check format database

```python
# Check if format is supported
from filo.formats import FormatDatabase

db = FormatDatabase()
formats = db.list_formats()
print(f"Supported: {', '.join(formats)}")
```

### Issue: Large Files Taking Too Long

**Solution:** Sample-based scanning

```python
# Only scan first/last chunks
header = data[:10*1024*1024]  # First 10MB
footer = data[-10*1024*1024:]  # Last 10MB

embedded = detector.detect_embedded(header + footer)
```

## API Reference

### EmbeddedDetector

#### `__init__(formats_db=None)`
Initialize detector with optional custom formats database.

#### `detect_embedded(data, min_confidence=0.70, skip_primary=True)`
Detect all embedded objects in binary data.

**Parameters:**
- `data`: Binary data to scan
- `min_confidence`: Minimum confidence threshold (0.0-1.0)
- `skip_primary`: Skip signature at offset 0 (primary format)

**Returns:** List of `EmbeddedObject` instances, sorted by offset

#### `detect_overlay(data, primary_format)`
Detect overlay (data appended after logical EOF).

**Parameters:**
- `data`: Binary data to check
- `primary_format`: Primary file format (e.g., 'pe', 'elf')

**Returns:** `EmbeddedObject` if overlay detected, None otherwise

## See Also

- [Contradiction Detection](CONTRADICTION_DETECTION.md) - Detect malware and polyglots
- [Hash Lineage Tracking](HASH_LINEAGE.md) - Chain-of-custody for evidence
- [Confidence Breakdown](CONFIDENCE_BREAKDOWN.md) - Understand detection logic

## Support

For malware analysis workflows and advanced use cases, see examples in `examples/` directory.
