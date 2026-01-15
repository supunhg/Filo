# Filo - Forensic Intelligence & Ligation Orchestrator

**Battle-tested file forensics platform for security professionals**

Filo transforms unknown binary blobs into classified, repairable, and explainable artifacts with offline ML learning capabilities.

## Features

- 🔍 **Deep File Analysis**: Multi-layered signature, structural, and ZIP container analysis
- 🎯 **Smart Format Detection**: Distinguishes DOCX/XLSX/PPTX, ODT/ODP/ODS, ZIP, JAR, APK, EPUB
- 🧠 **Enhanced ML Learning**: Discriminative pattern extraction, rich statistical features, n-gram profiling
- 🔧 **Intelligent Repair**: Reconstruct corrupted headers automatically with 21 repair strategies
- 📊 **Flexible Output**: Concise evidence display (top 3 by default), full details with -a/--all-evidence
- 😎 **Confidence Breakdown**: Auditable detection with --explain flag (court-ready transparency)
- 🛡️ **Contradiction Detection**: Identifies malware, polyglots, structural anomalies (malware triage)
- 🕵️ **Embedded Detection**: Find files hidden inside files - ZIP in EXE, PNG after EOF (malware hunter candy)
- 🔧 **Tool Fingerprinting**: Identify how/when/with what tools a file was created (forensic attribution)
- ⚠️ **Polyglot Detection** *(NEW v0.2.5)*: Detect dual-format files (GIFAR, PNG+ZIP, PDF+JS) with risk assessment
- 🎨 **Steganography Detection** *(NEW v0.2.6)*: LSB/MSB analysis for PNG/BMP, PDF metadata extraction, trailing data detection, flag pattern recognition
- 🌐 **PCAP Analysis** *(NEW v0.2.6)*: Network capture file analysis with protocol detection, string extraction, base64 decoding, flag hunting
- �🚀 **Batch Processing**: Parallel directory analysis with configurable workers
- 🔗 **Hash Lineage Tracking**: Cryptographic chain-of-custody for court evidence
- 📦 **Container Detection**: Deep ZIP-based format inspection for Office and archive formats
- ⚡ **Performance Profiling**: Identify bottlenecks in large-scale analysis
- 🎨 **Enhanced CLI**: Color-coded output, hex dumps, repair suggestions
- 🧹 **Easy Maintenance**: Reset ML model and lineage database with simple commands

## Quick Start

**Option 1: Easy Install (.deb package)**
```bash
# Clone and build
git clone https://github.com/supunhg/Filo
cd Filo
./build-deb.sh

# Install
sudo dpkg -i filo-forensics_0.2.5_all.deb
```

**Option 2: From Source**
```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

**Usage:**
```bash
# Analyze unknown file
filo analyze suspicious.bin

# Detect steganography in images (LSB/MSB analysis, metadata, trailing data)
filo stego image.png
filo stego image.png --extract="b1,rgb,lsb,xy" -o hidden.txt
filo stego document.pdf  # PDF metadata extraction
filo stego photo.jpg     # Trailing data detection

# Analyze PCAP network capture files
filo pcap capture.pcap

# Show detailed confidence breakdown (forensic-grade)
filo analyze --explain file.bin

# Show all detection evidence and embedded artifacts
filo analyze -a -e file.bin

# Analyze with JSON output
filo analyze --json file.bin > report.json

# Teach ML about a file format
filo teach correct_file.zip -f zip

# Batch process directory
filo batch ./directory

# Repair corrupted file
filo repair --format=png broken_image.bin

# Reset ML model or lineage database
filo reset-ml -y
filo reset-lineage -y
```

## Installation

### 📦 Easy Install (Recommended) - Debian/Ubuntu

The easiest way to install Filo is to build and install the `.deb` package:

```bash
# Clone repository
git clone https://github.com/supunhg/Filo
cd Filo

# Build .deb package
./build-deb.sh

# Install
sudo dpkg -i filo-forensics_0.2.3_all.deb

# Start using immediately
filo --version
filo analyze file.bin
```

**Features:**
- ✅ Isolated installation at `/opt/filo/` (no system conflicts)
- ✅ Automatic dependency management
- ✅ Global `filo` command (works from anywhere)
- ✅ No manual virtual environment activation
- ✅ Clean uninstall: `sudo dpkg -r filo-forensics`

**Supported:** Ubuntu 20.04+, Debian 11+, and compatible distributions

**Note:** All user data is stored in `/home/user/.filo/` directory:
- ML model: `/home/user/.filo/learned_patterns.pkl`
- Lineage database: `/home/user/.filo/lineage.db`

### From Source (Development)

```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

### Development Setup

```bash
# Clone and install with dev dependencies
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e ".[dev]"

# Run tests
pytest
```

## Usage Examples

### Python API
```python
from filo import Analyzer, RepairEngine
from filo.batch import analyze_directory
from filo.export import export_to_file
from filo.container import analyze_archive

# Analyze file with ML enabled
analyzer = Analyzer(use_ml=True)
result = analyzer.analyze_file("unknown.bin")
print(f"Detected: {result.primary_format} ({result.confidence:.0%})")
print(f"Alternatives: {result.alternative_formats[:3]}")

# View detection evidence
for evidence in result.evidence_chain[:3]:
    print(f"  {evidence['module']}: {evidence['confidence']:.0%}")

# Teach ML about correct format
with open("sample.zip", "rb") as f:
    analyzer.teach(f.read(), "zip")

# Batch process directory
batch_result = analyze_directory("./data", recursive=True)
print(f"Analyzed {batch_result.analyzed_count} files")

# Export to JSON/SARIF
export_to_file(result, "report.json", format="json")

# Analyze container (DOCX, ZIP, etc.)
container = analyze_archive("document.docx")
for entry in container.entries:
    print(f"{entry.path}: {entry.format}")

# Repair file
repair = RepairEngine()
repaired_data, report = repair.repair_file("corrupt.png")
```

### CLI
```bash
# Analysis with limited evidence (default: top 3)
filo analyze suspicious.bin

# Show all evidence and embedded artifacts
filo analyze -a -e suspicious.bin

# Show detailed confidence breakdown (auditable, court-ready)
filo analyze --explain file.bin

# Combine for full transparency
filo analyze --explain -a -e file.bin

# Disable ML for pure signature detection
filo analyze --no-ml file.bin

# Analysis with JSON output
filo analyze --json suspicious.bin

# Detect embedded files (ZIP in EXE, PNG after EOF)
filo analyze malware.exe -e

# Identify tool/creator fingerprints
filo analyze document.pdf  # Automatically fingerprints

# Batch processing with export
filo batch ./directory --export=sarif --output=scan.sarif

# Teach ML about file formats
filo teach correct_file.zip -f zip
filo teach image.png -f png

# Reset ML model or lineage database
filo reset-ml -y
filo reset-lineage -y

# Export to JSON for scripting
filo analyze --json file.bin | jq '.primary_format'

# Security: Detect embedded malware in documents
filo analyze suspicious.docx  # Automatically checks for contradictions

# Automation: Filter files with critical contradictions
filo analyze *.docx --json | \
  jq 'select(.contradictions[]? | .severity == "critical")'

# Check for hidden files
filo analyze *.png --json | \
  jq 'select(.embedded_objects | length > 0)'

# Chain-of-custody: Query file transformation lineage
filo lineage $(sha256sum repaired.png | cut -d' ' -f1)

# View lineage history
filo lineage-history --operation repair

# Export lineage for court
filo lineage $FILE_HASH --format json --output chain-of-custody.json
```

## Key Improvements

### ZIP-Based Format Detection
Filo now accurately distinguishes between ZIP-based formats by inspecting container contents:
- **Office Open XML**: DOCX, PPTX, XLSX (via `[Content_Types].xml`)
- **OpenDocument**: ODT, ODP, ODS (via `mimetype` file)
- **Archives**: JAR, APK, EPUB, plain ZIP
- **Large files**: Efficient handling of files >10MB using file path access

### Enhanced ML Features
Three major improvements to machine learning detection:
1. **Discriminative Pattern Extraction**: Automatically discovers format-specific byte sequences
2. **Rich Feature Analysis**: 8 statistical features including compression ratio, entropy, byte distribution
3. **N-gram Profiling**: Fuzzy matching using top 100 byte trigrams for similarity detection

### Cleaner Output
Evidence display now shows only the top 3 most relevant items by default:
```bash
# Concise output (default)
filo analyze file.zip

# Full evidence when needed
filo analyze --all-evidence file.zip
```

## Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started in 5 minutes
- [Embedded Detection](docs/EMBEDDED_DETECTION.md) - Find files hidden inside files
- [Tool Fingerprinting](docs/TOOL_FINGERPRINTING.md) - Forensic attribution (who/when/how)
- [Confidence Breakdown](docs/CONFIDENCE_BREAKDOWN.md) - Auditable detection explanations
- [Hash Lineage](docs/HASH_LINEAGE.md) - Chain-of-custody tracking
- [Polyglot Detection](docs/POLYGLOT_DETECTION.md) - Dual-format file detection *(NEW)*
- [Architecture](ARCHITECTURE.md) - Detailed system design
- [Examples](examples/README.md) - Code examples and demos

## What's New in v0.2.6

🎨 **Steganography Detection**

Detect hidden data in image files and documents:

```bash
filo stego image.png

# Output:
# 🔍 Steganography Analysis: image.png
# 
# ✓ Potential Hidden Data Found (3 methods)
# 
# Method: b1,rgb,lsb,xy
#   Confidence: 95% (FLAG PATTERN DETECTED)
#   Data: picoCTF{h1dd3n_1n_LSB}
```

**Features:**
- ✅ **LSB/MSB Detection**: Extract data from least/most significant bits (PNG, BMP)
- ✅ **Multiple Channels**: Test RGB, RGBA, individual channels (r, g, b, a), BGR
- ✅ **Bit Orders**: Both LSB and MSB with row/column-major ordering
- ✅ **PDF Metadata**: Extract hidden flags from Author, Title, Subject, Keywords
- ✅ **Trailing Data**: Detect data after JPEG EOI, PNG IEND, PDF EOF markers
- ✅ **Flag Recognition**: Automatic CTF flag pattern detection (picoCTF{}, flag{}, HTB{})
- ✅ **Auto-Decode**: Automatic base64 and zlib decompression
- ✅ **Extraction**: Save specific channels/methods to files

🌐 **PCAP Network Analysis**

Quick triage for network capture files:

```bash
filo pcap dump.pcap

# Output:
# 📊 Statistics
#   Packets: 1,234
#   Protocols: TCP (800), UDP (400), ICMP (34)
# 
# 🚩 FLAGS FOUND (2)
#   picoCTF{n3tw0rk_f0r3n51c5}
#   flag{hidden_in_packets}
# 
# 📝 Base64 Data
#   cGljb0NURnsuLi59 → picoCTF{...}
```

**Features:**
- ✅ **Protocol Detection**: IPv4, IPv6, TCP, UDP, ICMP, ARP
- ✅ **String Extraction**: ASCII strings from packet payloads
- ✅ **Base64 Decoding**: Automatic detection and decoding
- ✅ **Flag Hunting**: CTF flag pattern search across all packets
- ✅ **HTTP Extraction**: GET/POST requests and headers
- ✅ **Lightweight**: No Wireshark/tshark dependency for quick triage

**New Format Support:**
- 📦 **PCAP/PCAPNG**: Network capture files (little/big-endian)
- 📜 **Shell Archives (shar)**: Self-extracting shell script archives

---

## Previous Releases

<details>
<summary><strong>v0.2.5 - Polyglot & Dual-Format Detection</strong></summary>

⚠️ **Major New Feature: Polyglot & Dual-Format Detection**

Filo can now detect files that are simultaneously valid in multiple formats:

```bash
filo analyze suspicious_image.gif

# Output:
# ⚠ Polyglot Detected:
#   • GIF + JAR - GIF + JAR hybrid (GIFAR attack) (91%)
#     Risk: HIGH | Pattern: gifar
```

**Supported Polyglot Patterns:**
- **GIFAR** (GIF+JAR) - HIGH RISK: Classic attack vector for bypassing image filters
- **PDF + JavaScript** - HIGH RISK: Malicious PDFs with embedded JS payloads
- **PE + ZIP** - HIGH RISK: Windows executables that are also ZIP archives
- **PNG + ZIP** - MEDIUM RISK: Images with hidden ZIP archives
- **JPEG + ZIP** - MEDIUM RISK: JPEG files with embedded archives

**Key Features:**
- ✅ Multi-format validation (PNG, GIF, JPEG, ZIP, JAR, RAR, PDF, PE, ELF)
- ✅ Security risk assessment (HIGH, MEDIUM, LOW)
- ✅ Confidence scoring (70-98%)
- ✅ JavaScript payload detection in PDFs
- ✅ Demo polyglot files for testing
- ✅ Comprehensive test suite (26 new tests)

**Documentation:** See [docs/POLYGLOT_DETECTION.md](docs/POLYGLOT_DETECTION.md) for complete guide

📊 **Test Coverage**: 67% overall (173/173 tests passing, +26 polyglot tests)
🎯 **Supported Formats**: 60+ file formats  
🔬 **Detection Accuracy**: 95%+ on clean files, 70%+ on corrupted files

## Previous Releases

<details>
<summary><strong>v0.2.4 - Embedded Detection & Tool Fingerprinting</strong></summary>

✨ **Enhancements:**
1. **Embedded Object Detection** - Find files hidden inside files (ZIP in EXE, PNG after EOF, polyglots)
2. **Tool Fingerprinting** - Identify creation tools, versions, OS, timestamps (forensic attribution)
3. **Short Flags** - `-a` for all evidence, `-e` for all embedded artifacts
4. **Reset Commands** - `filo reset-ml` and `filo reset-lineage` for easy maintenance
5. **Demo Files** - Sophisticated test files in `demo/` directory
6. **Hash Lineage Tracking** - Cryptographic chain-of-custody for all transformations
7. **Format Contradiction Detection** - Identifies malware, polyglots, embedded executables
8. **Confidence Decomposition** - Auditable detection with --explain flag
9. **ZIP Container Analysis** - Accurate DOCX/XLSX/PPTX/ODT/ODP/ODS detection
10. **Enhanced ML Learning** - Pattern extraction, rich features, n-gram profiling

📊 147/147 tests passing

</details>

## Contributing

We welcome contributions! Priority areas:
- Format specifications (YAML)
- Analysis plugins
- Test corpus samples
- Performance optimizations

## Security & Safety

Filo is designed with security in mind:
- Non-destructive analysis (unless explicitly requested with repair commands)
- Resource-limited processing
- Input-validated at all layers
- No external network calls (fully offline ML)

## Author

Supun Hewagamage ([@supunhg](https://github.com/supunhg))

---

**When you need to know not just *what* something is, but *why* it's that, and *how* to fix it.**
