# Format Contradiction Detection

## Overview

Format Contradiction Detection identifies files that **cannot be what they claim to be** by detecting structural anomalies, embedded malicious content, and format violations. This is critical for **malware triage**, **polyglot detection**, and **forensic integrity validation**.

### Why It Matters

**Security Analysis:**
- Detects malware hiding in document formats (e.g., ELF in DOCX)
- Identifies polyglot files exploiting multiple parsers
- Catches format confusion attacks

**Digital Forensics:**
- Validates file integrity for court evidence
- Detects tampering and structural corruption
- Identifies suspicious file modifications

**Incident Response:**
- Rapid triage of potentially malicious files
- Automated detection of common evasion techniques
- Prioritizes files needing deeper analysis

## Contradiction Types

### 1. Compression Contradictions

**PNG with Invalid zlib Compression:**
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: PNG compression stream is invalid
     Claims: png
     Found PNG IHDR chunk but zlib decompression failed for IDAT at offset 33
     Category: compression
```

**What This Means:**
- File has PNG signature and IHDR chunk (correct structure)
- IDAT chunk contains invalid zlib compressed data
- Could indicate: corruption, manual editing, steganography, or malware

**Use Cases:**
- Detecting manually crafted PNG files
- Identifying steganography attempts
- Validating image integrity

### 2. Structure Contradictions

**OOXML Missing Mandatory Files:**
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: OOXML structure incomplete
     Claims: docx
     Missing required file '_rels/.rels' in ZIP structure
     Category: structure

  ⚠ WARNING: OOXML core document missing
     Claims: docx
     Contains '[Content_Types].xml' but missing core document 'word/document.xml'
     Category: structure
```

**What This Means:**
- File has DOCX signature but lacks Office Open XML mandatory files
- `_rels/.rels` is required for all valid OOXML files
- Core document (word/document.xml, xl/workbook.xml) must exist
- Could indicate: manual ZIP creation, malware, incomplete extraction

**Use Cases:**
- Detecting fake Office documents
- Validating document integrity
- Identifying malware using DOCX as container

### 3. Embedded Format Contradictions (CRITICAL)

**Embedded Executable in Document:**
```
⚠ Structural Contradictions Detected:

  🚨 CRITICAL: Embedded ELF executable signature
     Claims: docx
     Found ELF executable in ZIP member 'word/media/exploit.dll' at offset 600
     Category: embedded

  🚨 CRITICAL: Embedded ELF executable signature
     Claims: docx
     Found ELF executable at offset 816
     Category: embedded
```

**What This Means:**
- DOCX file contains ELF (Linux executable) magic bytes
- Detected in both compressed ZIP member AND raw file data
- **CRITICAL severity** - strong indicator of malware
- Could be: payload, dropper, polyglot exploit

**Detected Embedded Formats:**
- **ELF executables** (`\x7fELF`) - Linux/Unix binaries
- **PE executables** (`MZ` + `PE\x00\x00`) - Windows binaries  
- **Mach-O executables** (`\xfe\xed\xfa`) - macOS binaries
- **Shell scripts** (`#!/bin/bash`, `#!/bin/sh`, `#!/usr/bin/env`)

**Use Cases:**
- Malware triage in email attachments
- Detecting weaponized Office documents
- Identifying polyglot files
- APT detection in document repositories

### 4. Missing Element Contradictions

**PDF Without EOF Marker:**
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: PDF end-of-file marker missing
     Claims: pdf
     PDF structure incomplete: missing '%%EOF' marker
     Category: missing
```

**JPEG Without SOS Marker:**
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: JPEG missing Start Of Scan marker
     Claims: jpeg
     Found SOF marker but missing required SOS (Start Of Scan)
     Category: missing
```

**What This Means:**
- File has format signature but incomplete structure
- PDF requires `%%EOF` at end
- JPEG requires both SOF (Start of Frame) and SOS (Start of Scan)
- Could indicate: truncation, corruption, manual editing

## Severity Levels

### WARNING (⚠) - Yellow
- Structural incompleteness
- Missing optional elements that should be present
- Compression errors that could be accidental
- **Action:** Investigate, may be benign corruption

### ERROR (⚠) - Orange  
- Moderate structural violations
- Format inconsistencies
- **Action:** Review carefully, likely intentional

### CRITICAL (🚨) - Red
- **Embedded executables in documents**
- **Severe format violations**
- **Strong malware indicators**
- **Action:** Quarantine immediately, full analysis required

## Usage Examples

### Basic Contradiction Detection

All files are automatically checked for contradictions:

```bash
# Analyze suspicious DOCX
$ filo analyze malicious.docx

Format: docx (confidence: 100.00%)
Evidence:
  - Primary Signature (Extension-aware): .docx [ZIP archive]
  - ZIP Signature: PK\x03\x04 at offset 0
  - OOXML Signature: [Content_Types].xml found in ZIP

⚠ Structural Contradictions Detected:

  🚨 CRITICAL: Embedded ELF executable signature
     Claims: docx
     Found ELF executable in ZIP member 'word/media/exploit.dll' at offset 600
     Category: embedded

  ⚠ WARNING: OOXML structure incomplete
     Claims: docx
     Missing required file '_rels/.rels' in ZIP structure
     Category: structure
```

### JSON Output for Automation

```bash
$ filo analyze malicious.docx --json
```

```json
{
  "format": "docx",
  "confidence": 100.0,
  "evidence": [...],
  "contradictions": [
    {
      "severity": "critical",
      "claimed_format": "docx",
      "issue": "Embedded ELF executable signature",
      "details": "Found ELF executable in ZIP member 'word/media/exploit.dll' at offset 600",
      "category": "embedded"
    },
    {
      "severity": "warning",
      "claimed_format": "docx",
      "issue": "OOXML structure incomplete",
      "details": "Missing required file '_rels/.rels' in ZIP structure",
      "category": "structure"
    }
  ]
}
```

### Batch Analysis for Malware Triage

```bash
# Scan directory for suspicious files
$ filo batch email_attachments/ --json > results.json

# Filter for critical contradictions
$ jq '.results[] | select(.result.contradictions[]? | .severity == "critical")' results.json
```

## Detection Logic

### PNG Compression Validation

1. Locate IHDR chunk (required PNG header)
2. Find all IDAT chunks (compressed image data)
3. Extract zlib streams from IDAT chunks
4. Attempt decompression with zlib
5. Report contradiction if decompression fails

**Why It Matters:** Invalid compression often indicates manual editing, steganography, or malware.

### OOXML Structure Validation

1. Verify ZIP container format
2. Check for `_rels/.rels` (mandatory relationship file)
3. Check for `[Content_Types].xml` (required content types)
4. Verify core document exists:
   - DOCX: `word/document.xml`
   - XLSX: `xl/workbook.xml`
   - PPTX: `ppt/presentation.xml`
5. Report missing mandatory files

**Why It Matters:** Valid Office documents must have complete OOXML structure. Missing files indicate manual creation or malware.

### Embedded Format Detection

**ZIP Member Scanning:**
1. Open ZIP archive
2. Iterate through first 20 members
3. Decompress each member (first 10KB)
4. Scan for executable signatures (ELF, PE, Mach-O, scripts)
5. Report matches with member name and offset

**Raw Data Scanning:**
1. Read entire file into memory
2. Search for executable signatures
3. Report matches with file offset
4. Detects polyglots where executable is at ZIP level

**Why It Matters:** Legitimate documents should not contain executable binaries. This detects:
- Malware payloads in document containers
- Polyglot files (valid ZIP + valid ELF)
- APT techniques hiding executables in Office files

### PDF Structure Validation

1. Locate `%%EOF` marker at file end
2. Check for PDF trailer structure
3. Report if missing

**Why It Matters:** Truncated PDFs may indicate incomplete downloads or manual editing.

### JPEG Structure Validation

1. Find SOF (Start of Frame) marker
2. Search for SOS (Start of Scan) marker
3. Verify both exist
4. Report if SOS missing after SOF

**Why It Matters:** JPEGs require both markers for valid image data. Missing SOS indicates corruption or manipulation.

## Interpretation Guide

### No Contradictions Found
```
Format: png (confidence: 95.30%)
Evidence:
  - Primary Signature (Extension-aware): .png
  - PNG IHDR Chunk: Valid PNG header at offset 8

(No contradictions displayed)
```
✅ **Interpretation:** File structure is valid, no anomalies detected. File is likely benign and correctly formatted.

### Single WARNING
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: PDF end-of-file marker missing
     Claims: pdf
     PDF structure incomplete: missing '%%EOF' marker
     Category: missing
```
⚠️ **Interpretation:** Likely file corruption or incomplete transfer. Could be benign but verify file integrity.

### Multiple WARNINGS
```
⚠ Structural Contradictions Detected:

  ⚠ WARNING: OOXML structure incomplete
     Claims: docx
     Missing required file '_rels/.rels' in ZIP structure
     Category: structure

  ⚠ WARNING: OOXML core document missing
     Claims: docx
     Contains '[Content_Types].xml' but missing core document 'word/document.xml'
     Category: structure
```
🔍 **Interpretation:** Manually created or corrupted file. Investigate origin. Could be malware using DOCX as disguise.

### CRITICAL Severity
```
⚠ Structural Contradictions Detected:

  🚨 CRITICAL: Embedded ELF executable signature
     Claims: docx
     Found ELF executable in ZIP member 'word/media/exploit.dll' at offset 600
     Category: embedded
```
🚨 **INTERPRETATION: QUARANTINE IMMEDIATELY**
- **High probability of malware**
- Embedded executables in documents are NOT normal
- Requires full malware analysis
- Do not open or execute
- Report to security team

## Integration with Confidence Breakdown

Contradictions work alongside confidence scores:

```bash
$ filo analyze suspicious.docx --explain

Format: docx (confidence: 100.00%)

🔍 Confidence Breakdown:
  Primary: ZIP (100.0%)
  + ZIP Signature +40%
  + OOXML Content Types +30%
  + [Content_Types].xml +30%

⚠ Structural Contradictions Detected:

  🚨 CRITICAL: Embedded ELF executable signature
     Claims: docx
     Found ELF executable in ZIP member 'word/media/exploit.dll' at offset 600
     Category: embedded
```

**Key Insight:** High confidence + critical contradictions = **format confusion attack**. File is definitely a ZIP/DOCX, but contains malicious payload.

## Common Use Cases

### 1. Email Attachment Scanning

**Scenario:** Scan all email attachments for embedded executables

```bash
#!/bin/bash
for file in attachments/*; do
    result=$(filo analyze "$file" --json)
    critical=$(echo "$result" | jq '.contradictions[]? | select(.severity == "critical")')
    if [ -n "$critical" ]; then
        echo "🚨 MALWARE DETECTED: $file"
        echo "$critical" | jq .
    fi
done
```

### 2. Document Repository Audit

**Scenario:** Find all Office files with structural problems

```bash
$ filo batch corporate_docs/ --json | \
  jq '.results[] | select(.result.contradictions[]? | .category == "structure")'
```

### 3. Polyglot Detection

**Scenario:** Identify files valid as multiple formats

```bash
# Look for files with high confidence but embedded formats
$ filo analyze suspicious.zip --json | \
  jq 'select(.confidence > 90 and (.contradictions[]? | .category == "embedded"))'
```

### 4. Incident Response Triage

**Scenario:** Rapid assessment of suspicious files

```bash
# Prioritize by severity
$ filo batch incident_files/ --json | \
  jq -r '.results[] | 
         select(.result.contradictions[]? | .severity == "critical") | 
         .file_path' | \
  xargs -I {} echo "URGENT: {}"
```

## Limitations

### False Positives

**Legitimate Use Cases:**
- **Self-extracting archives** may contain embedded executables (expected behavior)
- **Installer packages** (.exe in .zip) for software distribution
- **Development artifacts** (compiled binaries in project archives)

**Mitigation:**
- Check file origin and expected content
- Verify with known-good hashes
- Review context (development vs. email attachment)

### False Negatives

**May Not Detect:**
- **Encrypted payloads** (no detectable signatures)
- **Obfuscated scripts** (Base64 encoded, XOR encrypted)
- **New exploit techniques** (zero-day patterns)
- **Polymorphic malware** (changing signatures)

**Mitigation:**
- Use in combination with other security tools
- Regular signature updates
- Behavioral analysis for unknown threats

### Performance Considerations

**Large ZIP Files:**
- Scans first 20 members only (performance trade-off)
- First 10KB of each member checked
- Large archives (1000+ files) may have unchecked members

**Mitigation:**
- For critical analysis, extract and scan all members separately
- Use dedicated malware scanners for deep inspection

## Best Practices

### Security Operations

1. **Quarantine on CRITICAL** - Always isolate files with critical contradictions
2. **Context Matters** - Expected file source determines risk assessment
3. **Combine Tools** - Use with antivirus, sandboxing, and behavioral analysis
4. **Document Findings** - Log all contradictions for incident reports
5. **Regular Updates** - Monitor for new exploitation techniques

### Forensic Analysis

1. **Preserve Originals** - Never modify suspicious files
2. **Hash Everything** - Record file hashes before analysis
3. **Chain of Custody** - Log all contradiction findings
4. **Multiple Tools** - Corroborate findings with other forensic tools
5. **Expert Review** - Critical contradictions warrant manual analysis

### Development & Testing

1. **Test Legitimate Files** - Verify no false positives on known-good files
2. **Controlled Samples** - Use malware samples from trusted sources only
3. **Sandbox Execution** - Never run files with critical contradictions
4. **Version Control** - Track contradiction detection logic changes
5. **Performance Testing** - Benchmark on large file sets

## Technical Implementation

### Detection Architecture

```python
from filo.contradictions import ContradictionDetector
from filo.models import Contradiction

# Automatic detection during analysis
result = analyzer.analyze(file_path)
if result.contradictions:
    for c in result.contradictions:
        print(f"{c.severity}: {c.issue}")
```

### Custom Contradiction Checks

```python
# Manual contradiction detection
contradictions = ContradictionDetector.detect_all(
    data=file_data,
    detected_format="docx",
    context={"namelist": zip_members}
)

for contradiction in contradictions:
    if contradiction.severity == "critical":
        quarantine_file(file_path)
```

## Future Enhancements

### Planned Features

1. **Macro Detection** - Identify VBA macros in Office documents
2. **ZIP64 Validation** - Detect ZIP64 format inconsistencies
3. **Encrypted Content Detection** - Flag encrypted ZIP members in unexpected files
4. **Multi-Format Polyglots** - Detect files valid as 3+ formats simultaneously
5. **Custom Rules Engine** - User-defined contradiction patterns
6. **ML-Based Anomaly Detection** - Learn normal vs. suspicious patterns

### Customization

```python
# Future: Custom contradiction rules (not yet implemented)
rules = {
    "block_macros": {
        "severity": "critical",
        "pattern": "vbaProject.bin",
        "formats": ["docx", "xlsx", "pptx"]
    }
}
```

## References

### Related Documentation

- [Confidence Breakdown](CONFIDENCE_BREAKDOWN.md) - Auditable confidence scoring
- [Advanced Repair](ADVANCED_REPAIR.md) - Fixing detected contradictions
- [Quickstart Guide](../QUICKSTART.md) - Basic usage examples

### Format Specifications

- **PNG**: [PNG Specification](http://www.libpng.org/pub/png/spec/1.2/PNG-Contents.html)
- **OOXML**: [Office Open XML Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-376/)
- **PDF**: [PDF Reference](https://www.adobe.com/devnet/pdf/pdf_reference.html)
- **JPEG**: [JPEG Standard](https://www.w3.org/Graphics/JPEG/)
- **ELF**: [ELF Format](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- **PE**: [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

### Security Resources

- [MITRE ATT&CK - T1036](https://attack.mitre.org/techniques/T1036/) - Masquerading
- [MITRE ATT&CK - T1027](https://attack.mitre.org/techniques/T1027/) - Obfuscated Files
- [VirusTotal](https://www.virustotal.com/) - Multi-scanner malware detection
- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Malware sandbox

## Support

For questions, issues, or feature requests:
- GitHub Issues: [Filo Issues](https://github.com/tabea/Filo/issues)
- Documentation: [Filo Docs](https://github.com/tabea/Filo/tree/main/docs)
- Examples: [Filo Examples](https://github.com/tabea/Filo/tree/main/examples)
