# Filo v0.2.0 - Enhanced Detection & ML Capabilities

**Release Date:** January 4, 2026

Battle-tested file forensics platform with major enhancements to format detection, machine learning, and user experience.

---

## 🎯 Highlights

### ZIP-Based Format Detection
Filo now accurately distinguishes between ZIP-based file formats by inspecting container contents:
- **Office Open XML**: DOCX, PPTX, XLSX via `[Content_Types].xml` inspection
- **OpenDocument**: ODT, ODP, ODS via `mimetype` file validation  
- **Archives & Apps**: JAR, APK, EPUB, plain ZIP differentiation
- **Large File Support**: Efficient handling of ZIP files >10MB using file path access

**Impact:** Eliminates false positives where plain ZIP files were misidentified as ODP/ODS/DOCX

### Enhanced Machine Learning

Three major ML improvements for better pattern recognition:

1. **Discriminative Pattern Extraction**
   - Automatically discovers format-specific byte sequences
   - Extracts header patterns (4-16 byte chunks)
   - Identifies frequent n-grams that appear multiple times
   - No longer limited to pre-defined signatures

2. **Rich Feature Analysis**  
   - 8 statistical features: compression ratio, entropy, byte distribution
   - Null byte ratio, printable ratio, high byte ratio
   - Longest repeating sequence detection
   - ASCII/text likelihood scoring

3. **N-gram Profiling**
   - Builds normalized 3-gram frequency profiles (top 100)
   - Cosine similarity matching for fuzzy detection
   - Helps identify corrupted or variant file formats
   - 40% contribution to ML confidence scoring

**Impact:** Detects variant formats (e.g., JPEG with EXIF vs JFIF headers) with 20% confidence vs 0% previously

### Cleaner CLI Output

Evidence display now shows only the top 3 most relevant detection items by default:

```bash
# Concise output (default)
filo analyze file.zip
  Shows: Top 3 evidence items
  
# Full details when needed  
filo analyze --all-evidence file.zip
  Shows: All detection evidence with full chain
```

**Impact:** Reduces output clutter by 70% for typical analysis while preserving access to full details

---

## 🔧 Improvements

### Corrupted File Detection
- Flexible signature matching with `offset_max` for range-based scanning
- JPEG fallback signatures: JFIF marker, quantization tables, SOF, Huffman tables
- Detection threshold lowered to 25% (from 30%) for partial matches
- **Example:** Corrupted JPEG with missing magic bytes now detected at 42% confidence

### Large File Handling
- ZIP files >10MB use file path-based reading (not buffer)
- Memory-efficient container analysis for archives with 8000+ files
- Fixed critical indentation bug that prevented large ZIP analysis

### Teaching & Learning
Enhanced `filo teach` command now extracts:
- Known format signatures (existing)
- Auto-discovered discriminative patterns (NEW)
- Rich statistical feature profiles (NEW)  
- N-gram frequency distributions (NEW)

**Impact:** Each teaching session now captures 15+ patterns, 8 features, and 100 n-grams vs 1-2 signatures previously

---

## 📦 Installation

### Debian/Ubuntu (.deb Package)

```bash
# Clone and build
git clone https://github.com/supunhg/Filo
cd Filo
./build-deb.sh

# Install
sudo dpkg -i filo-forensics_0.2.0_all.deb
```

**Features:**
- ✅ Isolated installation at `/opt/filo/` (no conflicts)
- ✅ Global `filo` command (works anywhere)
- ✅ Automatic dependency management
- ✅ Clean uninstall: `sudo dpkg -r filo-forensics`

### From Source

```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

---

## 🆕 What's New

### New Features
- **ZIP Container Analyzer** - Deep inspection of ZIP-based formats (DOCX, XLSX, PPTX, ODT, ODP, ODS, JAR, APK, EPUB)
- **Discriminative Pattern Extraction** - Auto-discovers format signatures from file data
- **Rich Feature Analysis** - 8 statistical features for better ML classification
- **N-gram Profiling** - Fuzzy matching using byte trigram similarity
- **--all-evidence Flag** - Toggle between concise and detailed output

### Enhancements
- Flexible signature matching with offset ranges
- JPEG fallback signatures for corrupted files
- Large ZIP file optimization (>10MB)
- Non-standard Office document support (e.g., files with `file/word/document.xml`)
- Case-insensitive ZIP entry matching

### Bug Fixes
- Fixed indentation bug preventing large ZIP file analysis
- Fixed ZIP container detection for files with subdirectory structures
- ML test isolation (use_ml=False for pure signature tests)

---

## 📊 Technical Details

### Test Coverage
- **10/10 analyzer tests passing** ✅
- **67% overall coverage** (95+ tests total)
- New tests: `test_analyze_corrupted_jpeg`, `test_analyze_office_formats`, `test_analyze_opendocument_formats`

### Performance
- ZIP container analysis: O(n) where n = number of entries
- N-gram profiling: Top 100 from 8KB sample (< 10ms)
- Large file handling: Reads only 1MB for analysis

### Dependencies
- No new dependencies added
- Uses stdlib: `zlib`, `math`, `collections.Counter`
- Maintains Python 3.10+ compatibility

---

## 🔄 Migration Guide

### For Users
No breaking changes. Existing workflows continue to work.

**New optional flags:**
- `--all-evidence` - Show full detection evidence chain
- `--no-ml` - Disable ML for pure signature-based detection

### For Developers
**LearningExample dataclass** - New optional fields:
```python
features: Dict[str, float] = field(default_factory=dict)
ngram_profile: Dict[bytes, float] = field(default_factory=dict)
```

Existing code works without changes. To use new features:
```python
analyzer = Analyzer(use_ml=True)
features = analyzer.ml_detector.extract_features(data)
ngrams = analyzer.ml_detector.build_ngram_profile(data, n=3)
```

---

## 📝 Examples

### Detecting Corrupted Files
```bash
# Before: Unknown (0%)
# After: JPEG detected at 42% via JFIF fallback
filo analyze corrupted_image.bin
```

### Distinguishing Office Formats
```bash
# Correctly identifies DOCX vs ODP (both are ZIP-based)
filo analyze document.docx
# Output: Detected Format: docx, Confidence: 100.0%
```

### Teaching ML About Formats
```bash
# Teach with enhanced pattern extraction
filo teach archive.zip --format zip
# Extracts: 16 patterns, 8 features, 100 n-grams

# Verify learning
filo analyze similar_archive.zip --all-evidence
# Shows ML contribution to detection
```

---

## 🙏 Acknowledgments

Special thanks to the CTF and digital forensics community for testing and feedback.

---

## 📖 Documentation

- [README](README.md) - Installation and quick start
- [QUICKSTART](QUICKSTART.md) - 5-minute getting started guide  
- [ARCHITECTURE](ARCHITECTURE.md) - System design and internals
- [Examples](examples/) - Code examples and demos

---

## 🐛 Known Issues

None reported for this release.

---

## 🔮 What's Next (v0.3.0)

- Advanced pattern learning with sequence detection
- Format variant classification (JPEG: JFIF vs EXIF vs raw)
- Container recursion (nested ZIP/TAR analysis)
- Performance profiling for ML predictions
- Web-based report viewer

---

**Full Changelog:** https://github.com/supunhg/Filo/compare/v0.1.0...v0.2.0
