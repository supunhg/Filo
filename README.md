# Filo - Forensic Intelligence & Ligation Orchestrator

**Battle-tested file forensics platform for security professionals**

Filo transforms unknown binary blobs into classified, repairable, and explainable artifacts with offline ML learning capabilities.

## Features

- 🔍 **Deep File Analysis**: Multi-layered signature, structural, and ZIP container analysis
- 🎯 **Smart Format Detection**: Distinguishes DOCX/XLSX/PPTX, ODT/ODP/ODS, ZIP, JAR, APK, EPUB
- 🧠 **Enhanced ML Learning**: Discriminative pattern extraction, rich statistical features, n-gram profiling
- 🔧 **Intelligent Repair**: Reconstruct corrupted headers automatically with 21 repair strategies
- 📊 **Flexible Output**: Concise evidence display (top 3 by default), full details with --all-evidence
- � **Confidence Breakdown**: Auditable detection with --explain flag (court-ready transparency)- 🛡️ **Contradiction Detection**: Identifies malware, polyglots, structural anomalies (malware triage)- �🚀 **Batch Processing**: Parallel directory analysis with configurable workers
- 🔗 **Hash Lineage Tracking**: Cryptographic chain-of-custody for court evidence (non-negotiable)
- 📦 **Container Detection**: Deep ZIP-based format inspection for Office and archive formats
- ⚡ **Performance Profiling**: Identify bottlenecks in large-scale analysis
- 🎨 **Enhanced CLI**: Color-coded output, hex dumps, repair suggestions

## Quick Start

**Option 1: Easy Install (.deb package)**
```bash
# Clone and build
git clone https://github.com/supunhg/Filo
cd Filo
./build-deb.sh

# Install
sudo dpkg -i filo-forensics_0.2.3_all.deb
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

# Show detailed confidence breakdown (forensic-grade)
filo analyze --explain file.bin

# Show all detection evidence
filo analyze --all-evidence file.bin

# Analyze with JSON output
filo analyze --json file.bin > report.json

# Teach ML about a file format
filo teach correct_file.zip --format zip

# Batch process directory
filo batch ./directory

# Repair corrupted file
filo repair --format=png broken_image.bin
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

# Show detailed confidence breakdown (auditable, court-ready)
filo analyze --explain file.bin

# Show all detection evidence
filo analyze --all-evidence suspicious.bin

# Combine for full transparency
filo analyze --explain --all-evidence file.bin

# Disable ML for pure signature detection
filo analyze --no-ml file.bin

# Analysis with JSON output
filo analyze --json suspicious.bin

# Batch processing with export
filo batch ./directory --export=sarif --output=scan.sarif

# Teach ML about file formats
filo teach correct_file.zip --format zip
filo teach image.png --format png

# Export to JSON for scripting
filo analyze --json file.bin | jq '.primary_format'

# Security: Detect embedded malware in documents
filo analyze suspicious.docx  # Automatically checks for contradictions

# Automation: Filter files with critical contradictions
filo analyze *.docx --json | \
  jq 'select(.contradictions[]? | .severity == "critical")'

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
- [Confidence Breakdown](docs/CONFIDENCE_BREAKDOWN.md) - Auditable detection explanations
- [Architecture](ARCHITECTURE.md) - Detailed system design
- [Examples](examples/README.md) - Code examples and demos

## What's New

✨ **Latest Enhancements:**
1. **Hash Lineage Tracking** - Cryptographic chain-of-custody for all transformations (court-ready)
2. **Format Contradiction Detection** - Identifies malware, polyglots, embedded executables (malware triage)
3. **Confidence Decomposition** - Auditable detection with --explain flag (court-ready transparency)
4. **ZIP Container Analysis** - Accurate DOCX/XLSX/PPTX/ODT/ODP/ODS detection
5. **Enhanced ML Learning** - Pattern extraction, rich features, n-gram profiling
6. **Cleaner CLI Output** - Top 3 evidence items by default, --all-evidence flag
7. **Corrupted File Detection** - Flexible signature matching with fallback patterns
8. **Large File Support** - Efficient >10MB ZIP file handling

📊 **Test Coverage**: 67% overall (10/10 analyzer tests passing)

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
