# ARCHITECTURE.md - Filo v1.0

## Forensic Intelligence & Ligation Orchestrator

---

## 1. Executive Summary

Filo is a **battle-tested file forensics platform** designed for security professionals who operate in ambiguous, adversarial, or corrupted data environments. Unlike conventional file identification tools, Filo provides **deterministic analysis, intelligent repair, and forensic-grade evidence collection** in a single, modular framework.

**Core Value Proposition**: Transform unknown binary blobs into classified, repairable, and explainable artifacts.

---

## 2. Design Philosophy

### 2.1 Guiding Principles

1. **Determinism Over Heuristics**: Every classification must be reproducible and explainable.
2. **Progressive Disclosure**: Simple interface, complex capabilities revealed as needed.
3. **Forensic Integrity**: Never modify originals without explicit instruction and evidence trails.
4. **Adversarial Resilience**: Assume input is malicious, corrupted, or intentionally obfuscated.
5. **Composable Intelligence**: Every component can be used independently or orchestrated.

### 2.2 Non-Goals

* Not a replacement for `file`, `binwalk`, or `xxd` - it complements them
* Not an automated malware analysis sandbox
* Not a data recovery suite for physical media
* Not a GUI tool - API-first, CLI-optimized

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Interface Layer                      │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │    CLI     │  │   REST     │  │  Python SDK      │  │
│  │            │  │            │  │                  │  │
│  └────────────┘  └────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                   Orchestration Engine                   │
│  ┌──────────────────────────────────────────────────┐  │
│  │            Analysis Pipeline Controller           │  │
│  │  • Sequential/Parallel Execution                 │  │
│  │  • Resource Management                           │  │
│  │  • Result Aggregation & Conflict Resolution      │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                    Core Analysis Stack                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │Signature │ │Structural│ │Statistical│ │Semantic  │   │
│  │Analysis  │ │Analysis  │ │Analysis   │ │Analysis  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐               │
│  │   Stego  │ │  PCAP    │ │ Polyglot │               │
│  │Detection │ │Analysis  │ │Detection │               │
│  └──────────┘ └──────────┘ └──────────┘               │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                    Intelligence Layer                    │
│  ┌──────────────────────────────────────────────────┐  │
│  │           Format Intelligence Database           │  │
│  │  • 500+ Format Specifications                   │  │
│  │  • Container & Compound Format Logic            │  │
│  │  • Version & Variant Recognition                │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                     Action Layer                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Header   │ │ Carving  │ │ Repair   │ │Generate  │   │
│  │Injection │ │Engine    │ │Engine    │ │Engine    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
                             │
┌─────────────────────────────────────────────────────────┐
│                   Evidence & Reporting                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Forensic │ │ SARIF    │ │CTF Mode  │ │ Chain of │   │
│  │ Reports  │ │ Output   │ │Reports   │ │ Custody  │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Core Modules

### 4.1 Format Intelligence Database (FID)

**The Brain of Filo**

A machine-readable database of file format specifications that powers all analysis.

```yaml
format: png
version: "1.2"
mime: ["image/png"]
category: raster_image
confidence_weight: 0.9

# Primary signatures with priority weighting
signatures:
  - offset: 0
    hex: "89504E470D0A1A0A"
    description: PNG header
    weight: 1.0
  - offset: 8
    hex: "0000000D49484452"
    description: IHDR chunk start
    weight: 0.7

# Required structural elements
structure:
  chunks:
    - id: "IHDR"
      required: true
      position: 0
      validation: "validate_ihdr"
    - id: "IDAT"
      required: true
      min_count: 1

# Footer signatures (for carving)
footers:
  - hex: "49454E44AE426082"
    description: IEND chunk

# Header generation templates
templates:
  default:
    hex: "89504E470D0A1A0A0000000D49484452{{width_32be}}{{height_32be}}0806000000"
    variables:
      width_32be: "uint32be"
      height_32be: "uint32be"

# Repair strategies
repair_strategies:
  - name: "reconstruct_from_chunks"
    priority: 1
  - name: "generate_minimal_header"
    priority: 2

# Validation commands (external tools)
validation:
  - command: ["pngcheck", "-v", "{file}"]
    success_codes: [0]
    description: "Validate PNG structure"
```

### 4.2 Analysis Stack

#### A. Signature Analysis Module
- Fast byte-pattern matching with SIMD acceleration
- Multi-offset signature support
- Probabilistic matching with confidence scores
- Parallel scanning for large files

#### B. Structural Analysis Module
- Hierarchical format parsing
- Container format dissection (ZIP, TAR, OLE2, etc.)
- Endianness detection
- Checksum/CRC validation

#### C. Statistical Analysis Module
- Shannon, byte-pair, and LZMA entropy calculations
- Byte frequency distribution
- N-gram analysis for language detection
- Compression ratio estimation

#### D. Semantic Analysis Module
- Magic number context analysis
- ASCII/Unicode string extraction with context
- Embedded file detection
- Format-specific semantic validation

### 4.3 Intelligence Layer

#### Container Resolution Engine
- Recursive container unpacking and analysis
- Format disambiguation (DOCX vs PPTX vs XLSX)
- Embedded file relationship mapping
- Malformed container recovery

#### Confidence Arbitration System
- Weighted voting across analysis modules
- Confidence decay for heuristic-only matches
- Conflict resolution with evidence citation
- Minimum threshold enforcement

### 4.4 Action Layer

#### Header Injection Engine
- **Safe mode**: Create new file with reconstructed header
- **In-place mode**: Direct byte manipulation (with backup)
- **Template-based**: Use format-specific templates
- **Adaptive**: Learn from existing file segments

#### File Carving Engine
- Header/footer pair detection
- Content validation during carving
- Overlap detection and resolution
- Carved fragment relationship tracking

#### Repair Engine

**Multi-Level Repair Strategy System**:

- **Level 1**: Header reconstruction only (basic repair)
- **Level 2**: Structure validation and fixing (intermediate)
- **Level 3**: Content-aware repair using format validators (advanced)
- **Level 4**: Format-specific deep repair (expert)

**Advanced Format-Specific Repair Strategies**:

**PNG Repair**:
- Chunk structure validation and repair
- CRC32 recalculation for all chunks
- IHDR (header) chunk reconstruction from image data
- Critical chunk ordering validation
- Confidence: 85-90%

**JPEG Repair**:
- SOI (Start of Image) marker reconstruction
- EOI (End of Image) marker insertion
- JFIF APP0 marker repair
- Segment marker validation
- Confidence: 85-90%

**ZIP Repair**:
- Local file header reconstruction
- Central directory rebuilding from local headers
- End of Central Directory (EOCD) generation
- File entry metadata recovery
- Confidence: 50-70% (depends on corruption level)

**PDF Repair**:
- PDF version header injection
- Cross-reference (xref) table reconstruction
- Trailer and %%EOF marker addition
- Object stream repair
- Minimal catalog/pages tree generation
- Confidence: 50-70%

**Repair Report Structure**:
```python
@dataclass
class RepairReport:
    success: bool
    strategy_used: str  # Which strategy was applied
    original_size: int
    repaired_size: int
    changes_made: list[str]  # Detailed change log
    warnings: list[str]  # Potential issues
    confidence: float  # 0.0-1.0 repair confidence
    validation_result: Optional[str]  # Post-repair validation
    chunks_repaired: int  # Format-specific counter
```

**Features**:
- **Dry-run mode**: Repair simulation without modification
- **Progressive repair**: Try advanced strategies first, fall back to basic
- **Validation**: Post-repair integrity checking
- **Evidence tracking**: Complete audit trail of all changes

#### Generation Engine
- Synthetic file creation for testing/fuzzing
- Format fuzzing with valid structure
- Test corpus generation
- Challenge creation for CTFs

### 4.5 Evidence System

#### Forensic Evidence Chain
```json
{
  "analysis_id": "uuid-v4",
  "input_checksum": "sha256",
  "analysis_timestamp": "iso8601",
  "environment_fingerprint": "os/python/filo-version",
  "module_versions": {...},
  "decision_tree": [
    {
      "module": "signature_analysis",
      "evidence": "0x89504E470D0A1A0A at offset 0",
      "confidence": 0.95,
      "weight": 0.4
    }
  ],
  "final_determination": {
    "format": "png",
    "confidence": 0.92,
    "supporting_evidence": [...]
  }
}
```

#### Report Types
- **Forensic**: Chain of custody, full evidence trail
- **CTF**: Minimal, flag-focused output
- **SARIF**: Standardized security tool output
- **Machine**: JSON with complete analysis data
- **Human**: Markdown with visualizations

---

## 5. Command Line Interface

### 5.1 Core Commands

```bash
# Analysis
filo analyze suspicious.bin
filo analyze --deep memory.dump
filo analyze --recursive capture.pcap

# Carving
filo carve --formats=png,jpg,zip disk.img
filo carve --auto --output-dir=carved/ corrupt.bin

# Repair
filo repair --format=png corrupt_header.bin
filo repair --auto damaged_file.dat
filo repair --dry-run --verbose broken.zip

# Generation
filo generate --format=pdf --count=10 --output=test_files/
filo generate --template=custom.json --var width=800 --var height=600

# Intelligence
filo formats list
filo formats show pdf
filo validate repaired.png
```

### 5.2 Pipeline Mode
```bash
# Chain operations
cat unknown.bin | filo analyze - | filo repair --format=@- - | file -

# Batch processing
find . -type f -exec filo analyze --json {} + | jq '...'
```

### 5.3 CTF Optimizations
```bash
# CTF mode - minimal, fast output
filo ctf analyze challenge.bin
filo ctf repair --hint=png mystery.dat

# Bruteforce headers
filo brute --max-offset=1024 unknown.bin
```

---

## 6. API Design

### 6.1 Python SDK
```python
from filo import Analyzer, RepairEngine

# Simple analysis
analyzer = Analyzer()
result = analyzer.analyze_file("unknown.bin")
print(f"Detected: {result.primary_format} ({result.confidence:.0%})")

# Advanced analysis with callbacks
result = analyzer.analyze(
    data=b"...",
    modules=['signature', 'structural', 'statistical'],
    progress_callback=log_progress
)

# Repair
repair = RepairEngine()
repaired_data, report = repair.repair_file(
    "corrupt.png",
    strategy="reconstruct_from_chunks"
)

# Programmatic format database
from filo.formats import FormatDatabase
db = FormatDatabase()
png_spec = db.get_format("png")
header_template = png_spec.get_template("default")
```

### 6.2 REST API (Optional)
```yaml
POST /api/v1/analyze
Content-Type: multipart/form-data

GET /api/v1/formats
GET /api/v1/formats/{format}

POST /api/v1/repair
{
  "data": "base64...",
  "format": "png",
  "strategy": "auto"
}
```

---

## 7. Plugin System

### 7.1 Plugin Types
1. **Format Plugins**: Add new file format specifications
2. **Analysis Plugins**: Custom analysis modules
3. **Carving Plugins**: Specialized carving algorithms
4. **Repair Plugins**: Format-specific repair logic
5. **Validation Plugins**: External tool integration

### 7.2 Plugin Structure
```python
# plugins/custom_format.py
from filo.plugins import FormatPlugin

class CustomFormat(FormatPlugin):
    name = "my_custom_format"
    version = "1.0"
    
    def detect(self, data: bytes) -> DetectionResult:
        # Custom detection logic
        pass
    
    def validate(self, data: bytes) -> ValidationResult:
        # Custom validation
        pass
    
    def generate_header(self, **kwargs) -> bytes:
        # Header generation
        pass
```

---

## 8. Security & Safety

### 8.1 Security Measures
- Input size limits (configurable)
- Recursion depth limits for containers
- Sandboxed external validator execution
- No automatic code execution
- All file operations are explicit

### 8.2 Safety Features
- Always create backups before modification
- Dry-run mode by default for destructive operations
- Checksum verification of all outputs
- Recovery logs for all operations
- Configurable safety levels (paranoid/normal/aggressive)

### 8.3 Resource Management
- Configurable memory limits
- Timeout protection for long analyses
- Parallel processing with worker limits
- Temporary file cleanup guarantees

---

## 9. Testing & Validation

### 9.1 Test Corpus
- **Golden samples**: 10,000+ known good files across 500+ formats
- **Corrupted variants**: Artificially damaged versions
- **CTF challenges**: Real-world challenge files
- **Adversarial cases**: Intentionally obfuscated files
- **Malware samples**: Safe, sanitized malware files

### 9.2 Validation Pipeline
```yaml
test_types:
  detection:
    - accuracy: >95% for known formats
    - false_positive: <1%
  repair:
    - success_rate: >90% for corruptions
    - safety: 100% no data loss
  performance:
    - average_analysis: <100ms per MB
    - memory_usage: <50MB baseline
```

### 9.3 Continuous Validation
- Daily format specification tests
- Weekly full corpus validation
- Monthly adversarial testing
- Quarterly real-world CTF validation

---

## 10. Deployment & Integration

### 10.1 Installation Options
```bash
# PyPI
pip install filo-forensics

# Docker
docker run --rm -v $(pwd):/data filo analyze /data/file.bin

# Standalone binary (PyInstaller)
curl -L https://github.com/filo/forensics/releases/latest/filo -o /usr/local/bin/filo

# Source
git clone https://github.com/filo/forensics
cd forensics && pip install -e .
```

### 10.2 Integration Examples
- **SOC Pipelines**: Analyze suspicious downloads
- **CTF Platforms**: Automated challenge validation
- **Forensic Workstations**: Integrated toolchain
- **CI/CD**: Artifact validation
- **Malware Analysis**: Initial triage

### 10.3 Performance Profile
- Single file (1MB): <50ms analysis, <5MB RAM
- Disk image (1GB): ~30s with carving, ~100MB RAM
- Parallel batch (100 files): Linear scaling to CPU cores

---

## 11. Development Roadmap

### Phase 1: Core (MVP)
- [ ] Format database with 50 core formats
- [ ] Signature + structural analysis
- [ ] Basic repair engine
- [ ] CLI interface

### Phase 2: Advanced
- [ ] 500+ format database
- [ ] Container intelligence
- [ ] Statistical analysis
- [ ] Python SDK

### Phase 3: Production
- [ ] Plugin system
- [ ] Forensic reporting
- [ ] Performance optimization
- [ ] Comprehensive testing

### Phase 4: Enterprise
- [ ] REST API
- [ ] Distributed processing
- [ ] Advanced carving
- [ ] Machine learning layer

---

## 12. Why Filo Wins

| Scenario | Traditional Tools | Filo |
|----------|------------------|------|
| **Corrupted PNG** | `file`: "data"<br>`binwalk`: nothing | **Detects as PNG**<br>**Repairs header**<br>**Validates structure** |
| **CTF Challenge** | Manual hex editing<br>Trial and error | `filo ctf analyze` → `filo repair` |
| **Forensic Analysis** | Multiple tools<br>Manual correlation | Single toolchain<br>Evidence trail |
| **Unknown Binary** | Guesswork<br>Reverse engineering | **Confidence scores**<br>**Similar format matching** |

---

## 13. Contributing

### 13.1 Priority Contributions
1. **Format specifications** (YAML)
2. **Analysis plugins** for niche formats
3. **Test corpus** samples
4. **Performance optimizations**
5. **Documentation & tutorials**

### 13.2 Code Standards
- Type hints required
- 90%+ test coverage
- Black formatting
- MyPy strict mode
- Performance benchmarks for critical paths

---

## 14. License & Compliance

- **License**: Apache 2.0 (commercial-friendly)
- **Export Control**: EAR99 (no encryption)
- **Privacy**: No telemetry, no external calls
- **Compliance**: Evidence suitable for legal proceedings

---

**Filo**: When you need to know not just *what* something is, but *why* it's that, and *how* to fix it.

---

*Next Steps*: 
1. Clone the skeleton repo: `git clone https://github.com/filo/forensics-skeleton`
2. Implement the format database schema
3. Build the core analyzer with 10 reference formats
4. Test against CTF challenge corpus