# Polyglot & Dual-Format Detection

## Overview

Polyglot files are files that are simultaneously valid in multiple file formats. These dual-format or multi-format files are commonly used in:

- **Security evasion**: Bypassing file type filters and scanners
- **Steganography**: Hiding malicious payloads in benign-looking files
- **Attack vectors**: GIFAR (GIF+JAR), PDF with JavaScript, PE+ZIP hybrids
- **File smuggling**: Evading detection by appearing as one format while being another

Filo v0.2.5+ includes sophisticated polyglot detection that validates files against multiple format parsers simultaneously, identifies conflicting format successes, and assesses the security risk of each detected polyglot combination.

## Quick Start

Analyze a file for polyglot structures:

```bash
filo analyze suspicious_file.gif
```

If polyglots are detected, you'll see:

```
⚠ Polyglot Detected:
  • GIF + JAR - GIF + JAR hybrid (GIFAR attack) (prob. 91%)
    Risk: HIGH | Pattern: gifar
    Valid as: gif, jar
```

## Supported Polyglot Patterns

### High Risk Patterns

#### GIFAR (GIF + JAR)
- **Description**: Valid GIF image that is also a valid Java JAR archive
- **Risk**: HIGH - Can bypass image filters and execute Java code
- **Detection**: Validates both GIF structure (header, logical screen descriptor) and JAR/ZIP format (EOCD record)
- **Real-world use**: Historical attack vector for uploading malicious applets disguised as images

```bash
filo analyze demo/gifar_malware.gif
```

#### PDF + JavaScript
- **Description**: PDF document with embedded JavaScript payload
- **Risk**: HIGH - Can execute arbitrary JavaScript code when opened
- **Detection**: Validates PDF structure and scans for JavaScript indicators:
  - `/JavaScript` and `/JS` objects
  - `/OpenAction` and `/AA` (automatic actions)
  - `eval()`, `unescape()`, `String.fromCharCode()` functions
- **Real-world use**: Malware delivery, phishing attacks, exploit kits

```bash
filo analyze demo/malicious_document.pdf
```

#### PE + ZIP
- **Description**: Windows executable that is also a valid ZIP archive
- **Risk**: HIGH - Can execute code while appearing as an archive
- **Detection**: Validates both PE structure (MZ header, PE signature) and ZIP format (central directory)
- **Real-world use**: Malware distribution, polyglot droppers

```bash
filo analyze demo/executable_archive.exe
```

### Medium Risk Patterns

#### PNG + ZIP
- **Description**: Valid PNG image that is also a valid ZIP archive
- **Risk**: MEDIUM - Can hide data in image files
- **Detection**: Validates PNG chunks (IHDR CRC) and ZIP EOCD record
- **Real-world use**: Steganography, data exfiltration

```bash
filo analyze demo/polyglot_advanced.png
```

#### JPEG + ZIP
- **Description**: Valid JPEG image that is also a valid ZIP archive
- **Risk**: MEDIUM - Can hide data in image files
- **Detection**: Validates JPEG markers (SOI, EOI, SOS) and ZIP structure
- **Real-world use**: Steganography, covert channels

```bash
filo analyze demo/image_with_archive.jpg
```

### Low Risk Patterns

#### GIF + ZIP
- **Description**: Valid as both GIF and ZIP
- **Risk**: LOW - Usually benign overlap
- **Detection**: Validates both formats independently

#### JAR + ZIP
- **Description**: JAR files are ZIP files with specific structure
- **Risk**: LOW - Expected relationship
- **Detection**: JAR is a subtype of ZIP

## How It Works

### Multi-Format Validation

The polyglot detector performs independent validation for each supported format:

1. **PNG Validation**
   - Checks PNG signature: `\x89PNG\r\n\x1a\n`
   - Validates IHDR chunk presence
   - Verifies IHDR CRC32 checksum

2. **GIF Validation**
   - Checks GIF signature: `GIF87a` or `GIF89a`
   - Validates logical screen descriptor
   - Checks for valid dimensions

3. **JPEG Validation**
   - Checks JPEG SOI marker: `0xFF 0xD8`
   - Validates marker sequence (APP0, DQT, SOF, SOS)
   - Confirms presence of EOI marker: `0xFF 0xD9`

4. **ZIP Validation**
   - Checks for local file header: `PK\x03\x04`
   - Validates End of Central Directory record: `PK\x05\x06`
   - Verifies EOCD structure

5. **JAR Validation**
   - Validates as ZIP
   - Checks for JAR-specific manifest structure

6. **RAR Validation**
   - Checks RAR v4 or v5 signature
   - Validates header structure

7. **PDF Validation**
   - Checks PDF header: `%PDF`
   - Validates trailer presence: `%%EOF`
   - Checks for PDF objects: `/Type`

8. **PE Validation**
   - Checks MZ DOS header
   - Validates PE offset and signature
   - Verifies PE header structure

9. **ELF Validation**
   - Checks ELF magic: `\x7fELF`
   - Validates class (32-bit/64-bit)
   - Checks endianness and OS ABI

### Confidence Scoring

Each polyglot detection includes a confidence score (0-100%):

- **90-98%**: Both formats have strong validation signals
- **80-89%**: Both formats valid with moderate confidence
- **70-79%**: One or both formats have weaker signals

Calculation factors:
- Number of validated format features
- Structural integrity of each format
- Presence of format-specific markers

### Risk Assessment

Each detected polyglot is assigned a risk level:

| Risk Level | Description | Examples |
|------------|-------------|----------|
| **HIGH** | Serious security concern, likely malicious | GIFAR, PDF+JS, PE+ZIP |
| **MEDIUM** | Potential security issue, investigate further | PNG+ZIP, JPEG+ZIP |
| **LOW** | Benign format overlap, expected behavior | JAR+ZIP, GIF+ZIP |

Risk assessment considers:
- Known attack patterns (GIFAR, PDF+JS)
- Executable + archive combinations
- Format compatibility and expected relationships

## Python API

### Basic Usage

```python
from filo.polyglot import PolyglotDetector

detector = PolyglotDetector()

with open('suspicious_file.gif', 'rb') as f:
    data = f.read()

polyglots = detector.detect_polyglots(data, primary_format='gif')

for polyglot in polyglots:
    print(f"Detected: {' + '.join(polyglot.formats)}")
    print(f"Pattern: {polyglot.pattern}")
    print(f"Risk: {polyglot.risk_level}")
    print(f"Confidence: {polyglot.confidence:.1%}")
    print(f"Description: {polyglot.description}")
    print()
```

### Analyzer Integration

The polyglot detector is automatically integrated into the main analyzer:

```python
from filo.analyzer import Analyzer

analyzer = Analyzer(detect_polyglots=True)  # Enabled by default
result = analyzer.analyze('suspicious_file.gif')

for polyglot in result.polyglots:
    print(f"⚠ Polyglot: {' + '.join(polyglot.formats)}")
    print(f"  Risk: {polyglot.risk_level}")
```

### Disable Polyglot Detection

```python
# Disable polyglot detection for performance
analyzer = Analyzer(detect_polyglots=False)
```

### Individual Format Validators

```python
from filo.polyglot import PolyglotDetector

detector = PolyglotDetector()

# Validate individual formats
is_valid_png = detector._validate_png(data)
is_valid_gif = detector._validate_gif(data)
is_valid_jpeg = detector._validate_jpeg(data)
is_valid_zip = detector._validate_zip(data)
is_valid_pdf = detector._validate_pdf(data)
is_valid_pe = detector._validate_pe(data)

# Check for JavaScript in PDF
has_js = detector._has_js_payload(data)
```

### Get All Valid Formats

```python
valid_formats = detector._get_valid_formats(data)
print(f"File is valid as: {', '.join(valid_formats)}")
```

## JSON Output

Export polyglot detection results in JSON format:

```bash
filo analyze suspicious_file.gif --json output.json
```

JSON structure:

```json
{
  "primary_format": "gif",
  "confidence": 0.541,
  "polyglots": [
    {
      "formats": ["gif", "jar"],
      "pattern": "gifar",
      "confidence": 0.91,
      "description": "GIF + JAR hybrid (GIFAR attack)",
      "risk_level": "high",
      "evidence": "Valid as: gif, jar"
    }
  ]
}
```

## Security Implications

### Attack Vectors

1. **Filter Bypass**
   - Upload polyglot file as benign format (e.g., GIF)
   - Server processes it as malicious format (e.g., JAR)
   - Executes embedded code

2. **Scanner Evasion**
   - Antivirus scans file as image (benign)
   - Application executes file as executable (malicious)
   - Payload remains undetected

3. **Content Type Confusion**
   - HTTP Content-Type: `image/gif`
   - Browser renders as HTML with embedded JavaScript
   - Cross-site scripting (XSS) attack

### Defensive Measures

1. **Validation**
   ```python
   result = analyzer.analyze(uploaded_file)
   if result.polyglots:
       # Reject file or apply strict sanitization
       raise SecurityError("Polyglot file detected")
   ```

2. **Whitelisting**
   ```python
   # Only accept files with no polyglot detections
   if not result.polyglots and result.primary_format in ['jpeg', 'png', 'gif']:
       accept_file()
   ```

3. **Risk-Based Filtering**
   ```python
   high_risk = [p for p in result.polyglots if p.risk_level == 'high']
   if high_risk:
       # Block high-risk polyglots
       reject_file()
   ```

## Demo Files

Filo includes demo polyglot files for testing:

```bash
# Generate demo polyglots
python demo/create_polyglot_files.py

# Test each demo file
filo analyze demo/gifar_malware.gif           # GIF+JAR (HIGH risk)
filo analyze demo/polyglot_advanced.png        # PNG+ZIP (MEDIUM risk)
filo analyze demo/malicious_document.pdf       # PDF+JS (HIGH risk)
filo analyze demo/image_with_archive.jpg       # JPEG+ZIP (MEDIUM risk)
filo analyze demo/executable_archive.exe       # PE+ZIP (HIGH risk)
```

## Limitations

1. **Format Coverage**: Currently supports 9 formats (PNG, GIF, JPEG, ZIP, JAR, RAR, PDF, PE, ELF). Additional formats planned for future releases.

2. **Deep Validation**: Validators perform structural checks but not semantic validation (e.g., won't render images or execute code).

3. **Performance**: Multiple validation passes add processing overhead. Disable with `detect_polyglots=False` for performance-critical applications.

4. **False Positives**: Benign file format overlaps (e.g., JAR+ZIP) are detected but marked as low risk.

5. **Obfuscation**: Advanced obfuscation techniques may evade detection. Use in combination with other security measures.

## Testing

Run polyglot-specific tests:

```bash
pytest tests/test_polyglot.py -v
```

Test individual validators:
```bash
pytest tests/test_polyglot.py::TestFormatValidators -v
```

Test polyglot combinations:
```bash
pytest tests/test_polyglot.py::TestPolyglotDetection -v
```

Test JavaScript detection:
```bash
pytest tests/test_polyglot.py::TestJavaScriptDetection -v
```

## Real-World Examples

### GIFAR Attack (CVE-2007-6682)

Historical vulnerability in Java allowing GIF+JAR polyglots to bypass file upload filters:

```bash
filo analyze suspected_gifar.gif

# Output:
# ⚠ Polyglot Detected:
#   • GIF + JAR - GIF + JAR hybrid (GIFAR attack) (91%)
#     Risk: HIGH | Pattern: gifar
```

### PDF Malware

PDF documents with embedded JavaScript are commonly used for malware delivery:

```bash
filo analyze suspicious.pdf

# Output:
# ⚠ Polyglot Detected:
#   • PDF + JAVASCRIPT - PDF with embedded JavaScript payload (92%)
#     Risk: HIGH | Pattern: pdf_js
```

### Polyglot Web Shell

Image files with embedded ZIP archives containing web shells:

```bash
filo analyze uploaded_avatar.png

# Output:
# ⚠ Polyglot Detected:
#   • PNG + ZIP - PNG + ZIP hybrid (91%)
#     Risk: MEDIUM | Pattern: png_zip
```

## Future Enhancements

Planned improvements for future releases:

- **Additional Formats**: HTML, XML, Office documents (DOCX, XLSX), RTF
- **Advanced Polyglots**: Triple-format files (e.g., GIF+JAR+ZIP)
- **Payload Extraction**: Automatic extraction and analysis of embedded content
- **Signature Database**: Known polyglot malware signatures
- **Machine Learning**: ML-based polyglot detection for unknown patterns
- **Performance**: Parallel format validation, caching, early termination

## References

- [GIFAR: The Dangerous Combination of GIF and JAR](https://www.exploit-db.com/papers/13014)
- [Polyglot Files in Security Research](https://www.blackhat.com/presentations/)
- [PDF Malware Analysis](https://blog.didierstevens.com/programs/pdf-tools/)
- [File Format Fuzzing and Polyglots](https://lcamtuf.coredump.cx/afl/)

## Contributing

To add support for additional polyglot patterns:

1. Add format validator to `PolyglotDetector` class
2. Add pattern to `polyglot_patterns` dictionary
3. Add risk assessment in `_assess_risk()` method
4. Add pattern description in `_get_pattern_description()`
5. Add comprehensive tests in `tests/test_polyglot.py`
6. Update this documentation

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.

---

**Version**: 0.2.5  
**Last Updated**: 2024  
**Author**: Filo Development Team
