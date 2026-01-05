# Tool Fingerprinting - Forensic Attribution

Filo can identify **how, when, and with what tools** a file was created. This goes beyond format detection to answer:
- **Who made this?** (tool/application)
- **When?** (creation timestamps)
- **How?** (OS, version, build fingerprints)

## Quick Start

```bash
# Analyze ZIP file for creator information
filo analyze suspicious.zip

# Output includes fingerprints:
🔧 Tool Fingerprints:
  • 7-Zip v9.20+ on Windows (prob. 90%)
    Version 45, OS code 10, method 8

  • unix v2.0 on Unix (prob. 85%)
    Extended timestamp field (0x5455) - Unix origin
```

## What Gets Fingerprinted

### ZIP Archives
- **Creator tool**: Info-ZIP, 7-Zip, WinZip, built-in OS tools
- **Operating system**: Windows, Unix, macOS, DOS
- **Version**: ZIP specification version (1.0, 2.0, 4.5)
- **Extended fields**: Unix timestamps, UID/GID metadata
- **Timestamps**: File modification times (DOS format)

```python
from filo.fingerprint import ToolFingerprinter

fingerprinter = ToolFingerprinter()
fingerprints = fingerprinter.fingerprint_file(zip_data, "zip")

for fp in fingerprints:
    print(f"{fp.tool} v{fp.version} on {fp.os_hint}")
    print(f"Confidence: {fp.confidence:.0%}")
    print(f"Evidence: {fp.evidence}")
```

### PDF Documents
- **Producer**: Adobe Acrobat, Microsoft Office, LibreOffice, iText, wkhtmltopdf
- **Version**: Application version numbers
- **Creation date**: ISO 8601 timestamps
- **Modification date**: Last edit timestamp

Example output:
```
🔧 Tool Fingerprints:
  • Adobe Acrobat v10.1.3 at 2024-01-15 14:32:18 (prob. 92%)
    Producer string: Adobe Acrobat 10.1.3

  • Microsoft Word v16.0 on Windows (prob. 90%)
    Application: Microsoft Word 16.0
```

### Office Documents (DOCX, XLSX, PPTX)
- **Application**: Microsoft Office, LibreOffice, OpenOffice
- **Build version**: Specific application version
- **OS hint**: Windows or cross-platform
- **AppVersion property**: Document metadata

### OpenDocument Formats (ODT, ODS, ODP)
- **Creator**: LibreOffice, OpenOffice
- **Version**: Application version
- **Build fingerprints**: Embedded metadata

## Attribution Workflow

### 1. Malware Analysis
Identify tool used to create malicious archives:

```bash
# Analyze suspicious ZIP dropper
filo analyze malware.zip

🔧 Tool Fingerprints:
  • Windows v6.3 on Windows NTFS (prob. 85%)
    Version 63, OS code 10, method 8
```

**Insight**: Created with Windows 10/11 built-in ZIP tool, suggesting:
- Not a sophisticated threat actor (using default tools)
- Likely created on consumer Windows machine
- May correlate with NTFS timestamps

### 2. Document Forensics
Track document provenance:

```python
from filo import Analyzer

analyzer = Analyzer(fingerprint=True)
result = analyzer.analyze_file("evidence.pdf")

for fp in result.fingerprints:
    if fp.category == "pdf_producer":
        print(f"Created with: {fp.tool} {fp.version}")
    elif fp.category == "pdf_creation_date":
        print(f"Created: {fp.timestamp}")
```

### 3. Data Breach Investigation
Match file creation patterns to suspects:

```bash
# Analyze leaked document
filo analyze leaked_docs.xlsx

🔧 Tool Fingerprints:
  • Microsoft Excel 16.0.14326 on Windows (prob. 90%)
    Application: Microsoft Excel 16.0.14326
```

Cross-reference with:
- Employee software versions
- Build numbers in corporate environment
- Timeline of document access

## Confidence Scoring

Fingerprint confidence ranges from 70% to 95%:

- **95%+**: Strong evidence (Unix UID/GID fields in ZIP)
- **90-95%**: High confidence (specific tool signatures)
- **85-90%**: Good confidence (version matching)
- **70-85%**: Moderate confidence (OS hints from headers)

## CLI Examples

### Basic Analysis
```bash
# Show all fingerprints
filo analyze document.pdf

# JSON output for automation
filo analyze archive.zip --json | jq '.fingerprints'
```

### Batch Processing
```bash
# Fingerprint all files in directory
for file in evidence/*; do
    echo "=== $file ==="
    filo analyze "$file" | grep "Tool Fingerprints" -A 5
done
```

### Filtering by Tool
```bash
# Find all Adobe-created PDFs
find . -name "*.pdf" -exec sh -c '
    filo analyze "$1" --json | grep -q "Adobe" && echo "$1"
' sh {} \;
```

## Python API

### Extract All Fingerprints
```python
from filo.fingerprint import ToolFingerprinter

fingerprinter = ToolFingerprinter()
data = open("file.zip", "rb").read()

fingerprints = fingerprinter.fingerprint_file(data, "zip")

for fp in fingerprints:
    print(f"Category: {fp.category}")
    print(f"Tool: {fp.tool or 'Unknown'}")
    print(f"Version: {fp.version or 'Unknown'}")
    print(f"OS: {fp.os_hint or 'Unknown'}")
    print(f"Timestamp: {fp.timestamp}")
    print(f"Confidence: {fp.confidence:.0%}")
    print(f"Evidence: {fp.evidence}\n")
```

### Filter by Category
```python
from filo import Analyzer

analyzer = Analyzer(fingerprint=True)
result = analyzer.analyze_file("document.pdf")

# Get only producer information
producers = [fp for fp in result.fingerprints if fp.category == "pdf_producer"]
for producer in producers:
    print(f"{producer.tool} {producer.version}")
```

### Timeline Analysis
```python
from filo import Analyzer
from datetime import datetime

analyzer = Analyzer(fingerprint=True)
result = analyzer.analyze_file("archive.zip")

# Extract all timestamps
timestamps = [fp.timestamp for fp in result.fingerprints if fp.timestamp]
if timestamps:
    earliest = min(timestamps)
    latest = max(timestamps)
    print(f"File timeline: {earliest} to {latest}")
    print(f"Time span: {(latest - earliest).total_seconds() / 3600:.1f} hours")
```

## Integration with Other Features

### Combined with Embedded Detection
```python
from filo import Analyzer

analyzer = Analyzer(fingerprint=True, detect_embedded=True)
result = analyzer.analyze_file("weaponized.docx")

# Check fingerprints
for fp in result.fingerprints:
    print(f"Document created with: {fp.tool}")

# Check for embedded malware
for obj in result.embedded_objects:
    print(f"Embedded {obj.format} at offset {obj.offset:#x}")
```

### Combined with Contradiction Detection
```python
from filo import Analyzer

analyzer = Analyzer()
result = analyzer.analyze_file("suspicious.pdf")

# Fingerprints claim Adobe Acrobat
fingerprints = result.fingerprints

# But contradictions suggest tampering
contradictions = result.contradictions

if fingerprints and contradictions:
    print("⚠ File claims to be created by one tool but has structural anomalies")
```

## Detection Capabilities

### ZIP Extra Fields
- **0x5455**: Extended timestamps (Unix)
- **0x7875**: Unix UID/GID
- **0x000a**: NTFS extra field
- **0x4453**: Windows timestamp

### PDF Metadata
- **/Producer**: Tool that created PDF
- **/Creator**: Original application
- **/CreationDate**: When PDF was generated
- **/ModDate**: Last modification timestamp

### Office Build Numbers
- Word: `Microsoft Office Word 16.0.14326`
- Excel: `Microsoft Excel 16.0.14326`
- LibreOffice: `LibreOffice_7.4.0.3`

## Limitations

1. **Forged metadata**: Fingerprints can be spoofed by sophisticated actors
2. **Minimal files**: Very small files may lack metadata
3. **Stripped files**: Some tools remove attribution metadata
4. **Custom tools**: Unknown/custom tools won't be fingerprinted

## Best Practices

1. **Cross-validate**: Combine fingerprints with other evidence
2. **Check confidence**: Prioritize high-confidence (>85%) fingerprints
3. **Timeline analysis**: Verify timestamps make logical sense
4. **Batch analysis**: Compare fingerprints across related files
5. **Document findings**: Record tool versions for forensic reports

## Performance

Fingerprinting is fast:
- Scans first 100KB of file
- Regex-based pattern matching
- No external tool dependencies
- ~0.1ms per file overhead

## Real-World Cases

### Case 1: Insider Threat
```
Leaked financial.xlsx showed:
  • Microsoft Excel 16.0.14326 (prob. 90%)
  • Created: 2024-01-15 02:34:12

Cross-referenced with:
  • Only 3 employees had Excel 16.0.14326
  • Only 1 was logged in at 02:34 AM
  • Access logs confirmed document access

Result: Identified insider with 95% confidence
```

### Case 2: Malware Attribution
```
malware_dropper.zip showed:
  • Info-ZIP v2.0 on Unix (prob. 85%)
  • Unix UID/GID fields present
  
Analysis:
  • Created on Linux system
  • Not Windows-based threat actor
  • Likely automated build pipeline

Result: Narrowed threat actor profile
```

### Case 3: Document Tampering
```
contract.pdf showed:
  • Adobe Acrobat 10.1.3 (prob. 92%)
  • Created: 2024-01-10 09:15:00
  • Modified: 2024-01-12 23:47:32

Contradictions:
  • PDF structure inconsistent with Acrobat
  • Modification date after signing timestamp

Result: Detected forged document metadata
```

## See Also

- [Embedded Detection](EMBEDDED_DETECTION.md) - Find hidden files
- [Contradiction Detection](docs/NEW_FEATURES.md#contradiction-detection) - Detect format anomalies
- [Hash Lineage](docs/HASH_LINEAGE.md) - Track file provenance
