# Steganography Detection 🔍🔐

**zsteg-compatible steganographic data detection and extraction for CTF challenges**

Filo's steganography detection module provides comprehensive LSB/MSB analysis with exact algorithm compatibility with the industry-standard `zsteg` tool, plus automatic base64 decoding and enhanced file type detection.

---

## 🎯 Overview

Steganography is the practice of concealing data within other non-secret files or messages. Common in CTF challenges and real-world attacks:

- **CTF Challenges**: picoCTF, HackTheBox, and other competitions frequently use LSB steganography
- **Data Exfiltration**: Smuggling sensitive data out of networks
- **Malware Delivery**: Hiding malicious payloads in innocent-looking files
- **Covert Communication**: Secret messaging channels

Filo detects and extracts hidden data using zsteg-compatible algorithms plus enhancements like automatic base64 decoding.

---

## 🔧 Supported Techniques

### 1. LSB/MSB Analysis (zsteg-compatible)

**Format Support**: PNG, BMP

LSB/MSB steganography hides data in the least/most significant bits of pixel values - the most common image steganography technique. Filo implements the exact same extraction algorithm as zsteg.

**Detection Methods**:
- ✅ **Multi-bit extraction**: 1, 2, 4 bits per channel (b1, b2, b4)
- ✅ **60+ bit plane configurations** tested per image
- ✅ **Channel combinations**: rgb, rgba, bgr, abgr, individual r/g/b/a channels
- ✅ **Bit order variants**: LSB (least significant) and MSB (most significant)
- ✅ **Pixel order variants**: xy (row-major), yx (column-major), XY (reversed horizontal), YX (reversed vertical)
- ✅ **zsteg algorithm compatibility**: Byte-for-byte identical extraction
- ✅ **Base64 auto-detection**: Automatically decodes base64 payloads (improvement over zsteg!)

**What It Detects**:
- CTF flags (picoCTF{...}, flag{...}, HTB{...}, etc.) - highlighted in bright green
- ASCII/UTF-8 text strings
- Base64 encoded payloads (auto-decoded to show actual content)
- File signatures (Targa, Alliant, Applesoft BASIC, OpenPGP keys)
- zlib compressed data
- Binary file headers

### 2. Trailing Data Detection

**Format Support**: PNG, JPEG, GIF, PDF, BMP

Many file formats have well-defined end markers. Data appended after these markers is suspicious.

**Detection Markers**:
- **PNG**: After `IEND` chunk
- **JPEG**: After `FFD9` (End Of Image)
- **GIF**: After `;` (trailer)
- **PDF**: After `%%EOF`

**Use Cases**:
- Files concatenated together
- Hidden archives appended to images
- Polyglot file detection

### 3. PDF Metadata Analysis

**Format Support**: PDF

Examines PDF metadata and structure for hidden information:

- Custom metadata fields
- JavaScript payloads
- Suspicious object streams
- Hidden text layers
- Non-standard PDF objects

### 4. SVG Hidden Text

**Format Support**: SVG

Detects invisible text hidden in SVG files:

- **Tiny font sizes** (< 0.1px - invisible to human eye)
- **White text on white background**
- **Suspicious XML comments**
- **Flag patterns** in hidden elements

**Common Techniques**:
- `font-size: 0.01px`
- `fill: #ffffff` on white background
- Character spacing manipulation

---

## 🚀 Quick Start

### Basic Detection

```bash
# Analyze an image for hidden data
filo stego suspicious_image.png

# Analyze a PDF
filo stego document.pdf

# Show all results (default shows top 10)
filo stego image.png --all
```

### Example Output (zsteg-style)

```bash
$ filo stego pico.flag.png

╭──────────────────────────────────────────────╮
│ Steganography Analysis: pico.flag.png        │
╰──────────────────────────────────────────────╯

Found 9 results:

b1,rgb,lsb,xy          .. text: "picoCTF{7h3r3_15_n0_5p00n_a9a181eb}"
b1,bgr,lsb,xy          .. text: "\nVnWUQ1Y"
b4,r,lsb,xy            .. file: Applesoft BASIC program data, first line number 257
b4,g,lsb,xy            .. file: Applesoft BASIC program data, first line number 1
b1,rgba,lsb,xy         .. text: "UfUUUU@UU"
b4,b,lsb,xy            .. file: Applesoft BASIC program data, first line number 16
b4,rgb,lsb,xy          .. file: Targa image data - Map (246-257) 65297 x 65314 x 1 +2817 +2570
b1,bgr,msb,xy          .. text: "AAPAAP"
b1,rgba,msb,xy         .. text: "wwwwww"

Tip: Use --extract=METHOD to extract specific data
Example: filo stego pico.flag.png --extract="b1,rgb,lsb,xy" -o flag.txt
```

**Filo Advantage**: In the example above, if the flag was base64-encoded, Filo would automatically decode it and show the decoded flag directly (unlike zsteg which shows raw base64).

### Extracting Specific Data

```bash
# Extract data using a specific method
filo stego image.png --extract="b1,rgba,lsb,xy" -o output.txt

# Extract from specific channels
filo stego image.png --extract="b1,b,lsb,xy" -o blue_channel.bin

# Extract using MSB instead of LSB
filo stego image.png --extract="b1,rgb,msb,xy" -o msb_data.bin
```

---

## 📊 Detection Methods Explained

### LSB/MSB Method Notation (zsteg-compatible)

Format: `b{bits},{channels},{order},{pixel_order}`

**Components**:
- **bits**: Number of bits per channel
  - `b1` = 1 bit per channel (most common - tested for all combinations)
  - `b2` = 2 bits per channel (nibble extraction)
  - `b4` = 4 bits per channel (half-byte extraction)
  - *(b8 = full byte, not typically used for stego)*

- **channels**: Which color channels to extract from
  - `r`, `g`, `b`, `a` = Individual channels (red/green/blue/alpha)
  - `rgb` = Red, Green, Blue combined in sequence
  - `rgba` = All channels including Alpha
  - `bgr` = Blue, Green, Red (BMP native order)
  - `abgr` = Alpha, Blue, Green, Red

- **order**: Bit extraction order within each byte
  - `lsb` = Least Significant Bit first (bit 0, most common)
  - `msb` = Most Significant Bit first (bit 7, less common)

- **pixel_order**: Pixel traversal pattern
  - `xy` = Left-to-right, top-to-bottom (standard row-major)
  - `yx` = Top-to-bottom, left-to-right (column-major)
  - `XY` = Right-to-left, top-to-bottom (reversed horizontal)
  - `YX` = Bottom-to-top, left-to-right (reversed vertical)

### Common Configurations

| Method | Description | Use Case |
|--------|-------------|----------|
| `b1,rgba,lsb,xy` | Standard 1-bit LSB in all channels | Most common CTF stego |
| `b1,rgb,lsb,xy` | 1-bit LSB in RGB (no alpha) | Opaque images, typical picoCTF |
| `b1,b,lsb,xy` | 1-bit LSB in blue channel only | Single-channel hiding |
| `b2,rgba,lsb,xy` | 2-bit LSB per channel | Higher capacity stego |
| `b1,rgba,msb,xy` | 1-bit MSB instead of LSB | Less common variant |
| `b4,r,lsb,xy` | 4-bit LSB in red channel | Often detects file signatures |

**Total configurations tested**: 60+ per image (all combinations of bits × channels × order × pixel_order)

---

## 💻 Python API

### Basic Detection

```python
from filo.stego import detect_steganography

# Detect all steganography
with open('image.png', 'rb') as f:
    data = f.read()

results = detect_steganography(data)

for result in results:
    print(f"Method: {result.method}")
    print(f"Type: {result.data_type}")
    print(f"Confidence: {result.confidence}")
    print(f"Description: {result.description}")
    print(f"Data: {result.data[:100]}...")  # First 100 bytes
    print()
```

### Advanced Detection

```python
from filo.stego import PNGStegoDetector, BitOrder

# Create detector
detector = PNGStegoDetector()

# Load PNG
with open('secret.png', 'rb') as f:
    data = f.read()

# Detect hidden data
results = detector.detect(data)

# Filter high-confidence results
high_conf = [r for r in results if r.confidence > 0.9]

for result in high_conf:
    if result.data_type == 'text':
        print(f"Found text: {result.data.decode('utf-8', errors='ignore')}")
    elif result.data_type == 'zlib':
        print(f"Found compressed data: {len(result.data)} bytes")
```

### Custom Extraction

```python
from filo.stego import PNGStegoDetector, BitOrder, LSBExtractor

# Parse PNG
detector = PNGStegoDetector()
with open('image.png', 'rb') as f:
    png_data = f.read()

png_info = detector.parse_png(png_data)

if png_info:
    # Extract using custom parameters
    extractor = LSBExtractor()
    
    # Extract 1 bit from RGBA channels in LSB order
    extracted = extractor.extract_bits(
        png_info['clean_pixels'],
        bits=1,
        order=BitOrder.LSB
    )
    
    # Look for text
    printable = extractor.detect_printable_strings(extracted)
    if printable:
        print(f"Found: {printable}")
    
    # Check for flags
    flag = extractor.detect_flag_patterns(extracted)
    if flag:
        print(f"Flag: {flag}")
    
    # Try zlib decompression
    zlib_data = extractor.detect_zlib(extracted)
    if zlib_data:
        print(f"Decompressed: {zlib_data[:100]}")
```

### SVG Analysis

```python
from filo.stego import SVGStegoDetector

detector = SVGStegoDetector()

with open('image.svg', 'rb') as f:
    data = f.read()

results = detector.detect(data)

for result in results:
    if result.data_type == 'text':
        print(f"Hidden text: {result.data.decode('utf-8')}")
    elif result.data_type == 'comment':
        print(f"Suspicious comment: {result.data.decode('utf-8')}")
```

### Trailing Data Analysis

```python
from filo.stego import TrailingDataDetector

detector = TrailingDataDetector()

with open('suspicious.jpg', 'rb') as f:
    data = f.read()

results = detector.detect(data, format_hint='jpeg')

for result in results:
    print(f"Found {result.size} bytes after EOF")
    print(f"Data type: {result.data_type}")
    
    # Save trailing data
    with open('extracted_trailing.bin', 'wb') as f:
        f.write(result.data)
```

---

## 🎯 Real-World Examples

### Example 1: CTF Challenge - picoCTF "c0rrupt"

```bash
# Detect hidden flag in corrupted PNG
$ filo stego c0rrupt.png

Found 3 results:
b1,rgba,lsb,xy                .. text: "picoCTF{c0rrupt10n_1847995}"
b1,rgb,lsb,xy                 .. text: "picoCTF{c0rrupt10n_1847995}"
trailing_data,png             .. PNG has 0 bytes after IEND chunk

# Extract the flag
$ filo stego c0rrupt.png --extract="b1,rgba,lsb,xy" -o flag.txt
✓ Extracted 8192 bytes to flag.txt

$ grep -o "picoCTF{.*}" flag.txt
picoCTF{c0rrupt10n_1847995}
```

### Example 2: Hidden Archive in Image

```bash
# Image with ZIP appended
$ filo stego vacation.jpg

Found 2 results:
trailing_data,jpeg            .. JPEG has 52387 bytes after FFD9 (EOI)
trailing_data,jpeg            .. file signature detected: ZIP archive

# Extract the hidden archive
$ filo stego vacation.jpg --extract="trailing" -o hidden.zip
✓ Extracted 52387 bytes to hidden.zip

$ unzip -l hidden.zip
Archive:  hidden.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    15234  2026-01-10 14:23   secret_documents.pdf
     8732  2026-01-10 14:24   passwords.txt
```

### Example 3: PDF with JavaScript Payload

```bash
$ filo stego malicious.pdf

Found 4 results:
pdf_metadata                  .. Suspicious JavaScript detected
pdf_metadata                  .. Author: "Hacker <script>evil()</script>"
pdf_metadata                  .. Custom field: /Launch detected
trailing_data,pdf             .. PDF has 2048 bytes after %%EOF
```

### Example 4: SVG with Invisible Text

```bash
$ filo stego diagram.svg

Found 2 results:
svg,hidden_text               .. Hidden SVG text (font-size < 0.1px): "flag{svg_st3g0}"
svg,comment                   .. Suspicious SVG comment: "<!-- SECRET: admin:password123 -->"

# Extract the hidden text
$ filo stego diagram.svg --extract="svg,hidden_text" -o hidden.txt
✓ Extracted 18 bytes to hidden.txt
```

---

## 🔬 Technical Deep Dive

### LSB Algorithm (zsteg-compatible)

Filo's LSB extraction matches `zsteg`'s behavior exactly:

```python
# Extract LSB from each byte
for byte in pixels:
    bit = (byte >> 0) & 1  # Extract bit 0 (LSB)
    bits.append(bit)

# Pack bits MSB-first into bytes
for i in range(0, len(bits), 8):
    byte = 0
    for j in range(8):
        byte |= (bits[i+j] << (7-j))  # MSB-first packing
    output.append(byte)
```

**Why MSB-first packing?**
- Matches zsteg's bit packing order
- First extracted bit goes to position 7 (MSB)
- Preserves data integrity across tools

### Pixel Order Traversal

```python
# Standard XY order (left-to-right, top-to-bottom)
for y in range(height):
    for x in range(width):
        pixel = get_pixel(x, y)

# YX order (top-to-bottom, left-to-right)  
for x in range(width):
    for y in range(height):
        pixel = get_pixel(x, y)

# Reverse orders (XY-reverse, YX-reverse)
# Same but iterate in reverse direction
```

### Data Type Detection

1. **Text Detection**: Look for printable ASCII (0x20-0x7E)
2. **Flag Detection**: Regex patterns for CTF flags
3. **Zlib Detection**: Try decompression with zlib headers
4. **Base64 Detection**: Pattern matching + decoding
5. **File Signature**: Check magic bytes (ZIP, PNG, JPEG, etc.)

### Confidence Scoring

| Data Type | Confidence | Reason |
|-----------|------------|--------|
| CTF Flag | 1.0 | Exact pattern match |
| zlib compressed | 0.95 | Successful decompression |
| File signature | 0.9 | Valid magic bytes |
| Base64 | 0.85 | Valid encoding + meaningful data |
| ASCII text (>20 chars) | 0.8 | Long printable string |
| ASCII text (8-20 chars) | 0.6 | Short printable string |

---

## 🛡️ Security Use Cases

### 1. Data Exfiltration Detection

```python
from filo.stego import detect_steganography

def scan_for_data_exfiltration(image_path):
    """Scan images for hidden data before allowing uploads."""
    with open(image_path, 'rb') as f:
        data = f.read()
    
    results = detect_steganography(data)
    
    # Flag high-confidence detections
    suspicious = [r for r in results if r.confidence > 0.8]
    
    if suspicious:
        print(f"⚠ WARNING: {len(suspicious)} hidden data patterns detected!")
        for result in suspicious:
            print(f"  - {result.method}: {result.description}")
        return False  # Block upload
    
    return True  # Allow upload
```

### 2. Forensic Evidence Analysis

```bash
# Analyze evidence files for hidden communication
for file in evidence_images/*.png; do
    echo "Analyzing: $file"
    filo stego "$file" --all > "stego_report_$(basename $file).txt"
done

# Extract all findings
grep -h "text:" stego_report_*.txt > potential_messages.txt
```

### 3. Malware Triage

```python
def check_image_for_payload(image_path):
    """Check if image contains hidden executable or script."""
    results = detect_steganography(image_path)
    
    dangerous_patterns = [
        b'MZ',      # PE executable
        b'\x7fELF', # ELF binary
        b'<?php',   # PHP script
        b'<script', # JavaScript
        b'\x89PNG', # Nested image
    ]
    
    for result in results:
        for pattern in dangerous_patterns:
            if pattern in result.data[:100]:
                print(f"🔴 DANGER: Found {pattern} in {result.method}")
                return True
    
    return False
```

---

## 📈 Performance

### Benchmarks

**PNG Analysis** (1920x1080, 2.3MB):
- **Single method**: ~15ms
- **All methods (20 configs)**: ~200ms
- **With PIL**: ~50ms faster than manual parsing

**BMP Analysis** (800x600, 1.4MB):
- **Single method**: ~8ms
- **All methods**: ~120ms

**PDF Metadata** (150KB document):
- **Analysis**: ~5ms

**Memory Usage**:
- **Per image**: ~2x file size (pixel data + extracted data)
- **Peak memory**: <50MB for 10MB image

### Optimization Tips

```python
# Limit methods to test (faster)
from filo.stego import PNGStegoDetector

detector = PNGStegoDetector()
results = detector.detect(data, methods=['b1,rgba,lsb,xy', 'b1,b,lsb,xy'])

# Use format hints (skip auto-detection)
results = detect_steganography(data, format_hint='png')

# Limit extraction size
detector.extractor.max_extract_bytes = 512 * 1024  # 512KB instead of 1MB
```

---

## 🎓 CTF Tips & Tricks

### Common CTF Patterns

1. **Blue Channel LSB**: Many challenges hide data in blue channel only
   ```bash
   filo stego challenge.png --extract="b1,b,lsb,xy" -o output.txt
   ```

2. **Multiple Bit Planes**: Try 2-4 bits per byte
   ```bash
   filo stego challenge.png --extract="b2,rgb,lsb,xy" -o output.bin
   ```

3. **MSB Instead of LSB**: Less common but used
   ```bash
   filo stego challenge.png --extract="b1,rgba,msb,xy" -o output.txt
   ```

4. **Trailing Data**: Check after file markers
   ```bash
   filo stego image.png | grep trailing
   ```

5. **Compressed Data**: Hidden data might be zlib-compressed
   ```bash
   filo stego challenge.png --all | grep zlib
   ```

### Automated Flag Search

```bash
#!/bin/bash
# Auto-extract and search for flags

for method in "b1,rgba,lsb,xy" "b1,rgb,lsb,xy" "b1,b,lsb,xy" "b2,rgba,lsb,xy"; do
    echo "Trying: $method"
    filo stego challenge.png --extract="$method" -o temp.bin
    
    # Search for flag patterns
    strings temp.bin | grep -E "(picoCTF|flag|FLAG|HTB|CTF)\{" && break
done

rm -f temp.bin
```

---

## 🔗 Integration Examples

### Batch Processing

```bash
# Scan entire directory
find ./uploads -type f -name "*.png" -o -name "*.jpg" | while read file; do
    echo "=== $file ==="
    filo stego "$file"
done > stego_scan_report.txt
```

### Integration with File Analysis

```python
from filo.analyzer import Analyzer
from filo.stego import detect_steganography

def full_analysis(file_path):
    """Complete file + stego analysis."""
    
    # Standard file analysis
    analyzer = Analyzer()
    with open(file_path, 'rb') as f:
        data = f.read()
    
    file_result = analyzer.analyze(data)
    print(f"Format: {file_result.primary_format}")
    print(f"Confidence: {file_result.confidence}%")
    
    # Steganography analysis
    stego_results = detect_steganography(data, format_hint=file_result.primary_format)
    
    if stego_results:
        print(f"\n⚠ Steganography detected: {len(stego_results)} patterns")
        for result in stego_results[:5]:
            print(f"  - {result.method}: {result.description}")
    else:
        print("\n✓ No steganography detected")
```

---

## 📚 References & Resources

### Tools Compatibility

- **zsteg**: Ruby-based PNG/BMP stego detector (algorithm-compatible)
- **steghide**: JPEG/BMP steganography (different algorithm)
- **stegdetect**: JPEG stego detection (statistical analysis)
- **binwalk**: Embedded file detection (complementary)

### Steganography Techniques

- [LSB Steganography](https://en.wikipedia.org/wiki/Bit_numbering#Least_significant_bit) - Wikipedia
- [Image Steganography Techniques](https://www.sciencedirect.com/topics/computer-science/image-steganography) - Research papers
- [PDF Steganography](https://null-byte.wonderhowto.com/how-to/hide-secret-messages-images-pdfs-using-steganography-0161878/) - Tutorial

### CTF Challenges Using Stego

- picoCTF: "hideme", "WalkingThePlank", "MacroHard WeakEdge"
- HackTheBox: "Eternal Loop", "Mirage"
- CTFTime: Search for "steganography" tag

---

## 🐛 Troubleshooting

### PIL Not Available

**Error**: `PIL not available, falling back to manual PNG parsing`

**Solution**:
```bash
pip install Pillow
```

**Impact**: Manual parser works but may be 30-50% slower

### No Results Found

**Check**:
1. Verify file format: `filo analyze file.png`
2. Try all methods: `filo stego file.png --all`
3. Check file isn't corrupted: Look for errors
4. Try manual extraction: `--extract="b1,rgba,lsb,xy"`

### Garbage Output

**Issue**: Extracted data looks random

**Possible Causes**:
- Wrong extraction method (try different configs)
- Data is encrypted/compressed
- No steganography present (random noise in LSB is normal)

**Solutions**:
```bash
# Try all channels
filo stego image.png --all | grep -E "(text|flag|zlib)"

# Extract and decompress
filo stego image.png --extract="b1,rgba,lsb,xy" -o data.bin
python -c "import zlib; print(zlib.decompress(open('data.bin','rb').read()))"
```

---

## 🔮 Future Enhancements

Planned features for future releases:

- [ ] **JPEG DCT Coefficient Analysis** - Frequency domain stego
- [ ] **F5 Algorithm Detection** - Advanced JPEG stego
- [ ] **LSB Matching Detection** - Statistical analysis
- [ ] **Audio Steganography** - WAV, MP3, FLAC analysis
- [ ] **Video Steganography** - MP4, AVI frame analysis
- [ ] **Deep Learning Stego Detection** - ML-based detection
- [ ] **Steganalysis** - Statistical tests (Chi-square, RS analysis)
- [ ] **Embedding Simulation** - Test stego techniques

---

## 💡 Quick Reference

### CLI Commands

```bash
# Basic detection
filo stego <file>

# Show all results
filo stego <file> --all

# Extract specific method
filo stego <file> --extract="b1,rgba,lsb,xy" -o output.bin

# Common extraction patterns
filo stego <file> --extract="b1,b,lsb,xy"      # Blue channel LSB
filo stego <file> --extract="b1,rgb,lsb,xy"    # RGB LSB
filo stego <file> --extract="b2,rgba,lsb,xy"   # 2-bit LSB
filo stego <file> --extract="b1,rgba,msb,xy"   # MSB instead of LSB
```

### Python API Quick Reference

```python
# Simple detection
from filo.stego import detect_steganography
results = detect_steganography(image_data)

# PNG-specific
from filo.stego import PNGStegoDetector
detector = PNGStegoDetector()
results = detector.detect(png_data)

# Custom extraction
from filo.stego import LSBExtractor, BitOrder
extractor = LSBExtractor()
data = extractor.extract_bits(pixels, bits=1, order=BitOrder.LSB)
```

---

**When you need to know what's really hiding in those pixels.** 🔍

> *"The absence of evidence is not evidence of absence... but Filo will find it anyway."*
