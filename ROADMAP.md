# Filo Development Roadmap

This roadmap outlines planned features and improvements for Filo. Items are organized by priority and development phase.

## Version 0.2.3 (January 2026) - Forensic Transparency ✅ **COMPLETED**

### Delivered Features

#### 🔍 Confidence Breakdown
**Status:** ✅ Completed  
**Impact:** High - Court-ready transparency

Auditable confidence scoring with `--explain` flag showing how each analyzer contributes:
- Percentage breakdowns (+/- penalties)
- Primary format with contribution details
- Evidence transparency for expert testimony
- ML similarity scores with context

```bash
filo analyze file.bin --explain
# Primary: DOCX (82%)
# + ZIP structure +25%
# + [Content_Types].xml +30%
# + ML similarity +18%
# - Missing core props -9%
```

**Use Cases:**
- Court evidence with auditable methodology
- Expert witness testimony preparation
- Confidence threshold tuning
- ML model debugging

---

#### 🛡️ Contradiction Detection
**Status:** ✅ Completed  
**Impact:** High - Malware triage

Detects files that cannot be what they claim to be:
- Embedded executables (ELF, PE, Mach-O, scripts)
- Invalid compression (PNG zlib, ZIP corruption)
- Missing mandatory files (OOXML structure)
- Format marker validation (PDF %%EOF, JPEG SOS)
- Severity-based warnings (WARNING ⚠ / CRITICAL 🚨)

```bash
filo analyze suspicious.docx
# 🚨 CRITICAL: Embedded ELF executable signature
#    Found ELF executable in ZIP member 'word/media/exploit.dll'
```

**Use Cases:**
- Malware detection in email attachments
- Polyglot file identification
- Document integrity validation
- APT detection

---

#### 🔗 Hash Lineage Tracking
**Status:** ✅ Completed  
**Impact:** Critical - Chain-of-custody (non-negotiable)

Cryptographic chain-of-custody for all file transformations:
- SHA-256 hash tracking (original → result)
- SQLite-backed lineage database (~/.filo/lineage.db)
- Forward/backward lineage queries
- Court-ready reports (text + JSON export)
- Operation metadata (repair strategy, carve offset, etc.)

```bash
filo repair corrupt.png --format png --output fixed.png
filo lineage $(sha256sum fixed.png | cut -d' ' -f1)
# Complete chain-of-custody report with timestamps

filo lineage-history --operation repair
filo lineage-stats
```

**Use Cases:**
- Legal evidence documentation
- Forensic investigation auditing
- Multi-step processing verification
- Expert witness methodology proof

---

## Version 0.3.0 (Q1 2026) - Core Enhancements

### 🎯 Priority Features

#### Metadata Extraction
**Status:** Planned  
**Complexity:** Medium  
**Impact:** High

Extract and analyze embedded metadata from files:
- EXIF data from images (camera info, GPS, timestamps)
- PDF metadata (author, creator, creation/modification dates)
- Office document properties (author, company, revision history)
- Audio/video metadata (duration, codec, artist, album)
- Executable metadata (version info, compilation timestamps)

```bash
# Extract metadata to JSON
filo metadata image.jpg --export-json metadata.json

# Show metadata in terminal
filo metadata document.pdf

# Batch metadata extraction with timeline
filo batch /evidence --extract-metadata --timeline
```

**Use Cases:**
- Timeline generation for DFIR investigations
- Author/software tracking
- GPS coordinate extraction from photos
- Document provenance verification

---

#### Entropy Visualization & Analysis
**Status:** Planned  
**Complexity:** Medium  
**Impact:** High

Visual entropy analysis for detecting encryption, compression, and obfuscation:
- Byte-level entropy calculation
- ASCII art graphs in terminal
- Anomaly detection (encrypted sections, packed executables)
- Compression boundary identification
- Steganography hints

```bash
# Visual entropy graph
filo entropy file.bin --graph

# Detect anomalies
filo entropy malware.exe --detect-anomalies --threshold 7.5

# Export entropy data
filo entropy disk.img --export-csv entropy.csv --block-size 256
```

**Use Cases:**
- Identify encrypted/packed sections in executables
- Spot steganography in images
- Detect compression algorithms
- Malware analysis (locate encrypted payloads)
- Disk analysis (find encrypted partitions)

---

### Additional v0.3.0 Features

#### Hash Database Integration
**Status:** Planned  
**Complexity:** High  
**Impact:** High

Integrate hash-based file identification:
- NSRL (National Software Reference Library) support
- Custom hash sets (known-good, known-bad)
- Massive performance improvement for large investigations
- Automatic malicious file flagging

```bash
filo analyze --hash-check file.bin --nsrl-db /path/to/nsrl
filo batch /evidence --known-good hashes.txt --skip-known
```

---

#### Parallel Processing
**Status:** Planned  
**Complexity:** Low  
**Impact:** Medium

Multi-threaded batch analysis:
- Worker pool configuration (4-8x speedup)
- Progress bars with ETA
- Graceful per-file error handling

```bash
filo batch /evidence --workers 8 --progress
```

---

#### Configuration File Support
**Status:** Planned  
**Complexity:** Low  
**Impact:** Medium

User configuration via YAML/JSON:
```yaml
# ~/.config/filo/config.yaml
default_confidence: 25
use_ml: true
evidence_limit: 3
export_format: json
batch_workers: 4
```

---

## Version 0.4.0 (Q2 2026) - Advanced Detection

### Fragment Detection
**Status:** Planned  
**Complexity:** High  
**Impact:** High

Detect partial/carved file fragments:
- Header-only detection
- Footer-only detection
- Minimum confidence thresholds (15-20%)
- Critical for disk carving workflows

```bash
filo analyze fragment.bin --fragment-mode --min-confidence 15
filo carve disk.img --enable-fragments --aggressive
```

---

### Polyglot Detection
**Status:** Planned  
**Complexity:** High  
**Impact:** Medium

Detect files valid in multiple formats:
- Security research focus
- PDF/JS combinations
- JAR/ZIP/HTML exploits
- CVE exploitation detection

```bash
filo analyze suspicious.pdf --polyglot-check
```

---

### YARA Integration
**Status:** Planned  
**Complexity:** Medium  
**Impact:** High

Combine format detection with YARA pattern matching:
- Format-aware rule application
- Malware classification
- Custom pattern libraries

```bash
filo analyze malware.exe --yara-rules /rules/ --format-context
```

---

### Advanced Repair Strategies
**Status:** Planned  
**Complexity:** High  
**Impact:** Medium

Enhanced file repair capabilities:
- Reference file templates
- Multi-stage reconstruction
- Content extraction from damaged files

```bash
filo repair corrupted.docx --reference similar.docx --aggressive
filo repair partial.zip --extract-readable --ignore-crc
```

---

## Version 0.5.0 (Q3 2026) - Ecosystem & Integration

### Plugin System
**Status:** Planned  
**Complexity:** High  
**Impact:** Medium

User-defined format extensions:
- Python plugin API
- Custom format definitions
- Company-specific proprietary formats
- Community contributions

```python
# ~/.config/filo/plugins/custom_format.py
from filo.plugin import FormatPlugin

class MyFormat(FormatPlugin):
    name = "custom"
    signatures = [...]
```

---

### Container Recursion
**Status:** Planned  
**Complexity:** Medium  
**Impact:** Medium

Analyze nested containers:
- ZIP in ZIP, TAR.GZ, ISO/ZIP combinations
- Hidden payload detection
- Configurable depth limits

```bash
filo analyze archive.zip --recursive --max-depth 5
```

---

### Interactive TUI
**Status:** Planned  
**Complexity:** High  
**Impact:** Low

Terminal user interface:
- File browser with real-time detection
- Hex viewer with format highlighting
- Interactive evidence exploration

---

### Timeline Generation
**Status:** Planned  
**Complexity:** Medium  
**Impact:** High

DFIR timeline integration:
- Plaso/log2timeline output format
- Temporal analysis of file metadata
- Case investigation workflows

```bash
filo batch /evidence --timeline plaso --output timeline.csv
```

---

## Version 0.6.0 (Q4 2026) - Production Hardening

### Watch Mode
**Status:** Planned  
**Complexity:** Low  
**Impact:** Low

Monitor directories for new files:
```bash
filo watch /incoming --auto-analyze --alert-on suspicious
```

---

### Docker Container
**Status:** Planned  
**Complexity:** Low  
**Impact:** Medium

Containerized deployment:
```bash
docker run -v /evidence:/data filo analyze /data/file.bin
```

---

### Enhanced CSV Export
**Status:** Planned  
**Complexity:** Low  
**Impact:** Low

Comprehensive batch export:
- All evidence items
- File hashes (MD5, SHA-256)
- Timestamps, confidence scores
- Detection chain visualization

---

## Long-Term Vision

### Machine Learning Improvements
- Format variant classification (JPEG: JFIF vs EXIF vs raw)
- Advanced sequence detection
- Neural network-based classification (optional dependency)
- Transfer learning from pre-trained models

### Performance Optimization
- Streaming analysis for large files (>1GB)
- Memory-mapped file I/O
- Caching layer for repeated analysis
- GPU acceleration (optional)

### Web Interface
- Browser-based analysis dashboard
- Collaborative investigation tools
- Report generation with visualizations
- RESTful API

### Format Coverage
- 100+ format definitions
- Video codec detection (H.264, H.265, VP9)
- Database formats (SQLite, MySQL dumps)
- Virtualization formats (VMDK, VDI, VHDX)
- Mobile formats (Android backup, iOS backup)

---

## Community Contributions

We welcome contributions! Priority areas:
1. **Format Definitions**: Add YAML files for new formats
2. **Testing**: Expand test coverage (target 85%+)
3. **Documentation**: Tutorials, use case examples
4. **ML Training Data**: Contribute file samples for better detection
5. **Bug Reports**: Real-world failure cases

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Release Philosophy

- **Minor versions (0.x.0)**: New features, backward compatible
- **Patch versions (0.0.x)**: Bug fixes, performance improvements
- **Breaking changes**: Announced 1 version in advance with deprecation warnings

---

## Feedback & Requests

Have ideas or feature requests? Open an issue on GitHub:
https://github.com/supunhg/Filo/issues

For security vulnerabilities, email: [security contact needed]

---

**Last Updated:** January 4, 2026  
**Current Version:** 0.2.0  
**Next Release:** 0.3.0 (Q1 2026)
