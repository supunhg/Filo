# Changelog

All notable changes to Filo Forensics will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.8] - 2026-01-18

### Added
- **CPU Architecture Detection**: Automatic detection of CPU architecture for executable files
  - ELF executables: 90+ architectures (x86, x86-64, ARM, ARM64, RISC-V, MIPS, PowerPC, Xtensa, SPARC, AVR, etc.)
  - PE/COFF executables: Windows executables (x86, x64, ARM, ARM64, IA-64, etc.)
  - Mach-O executables: macOS/iOS binaries (x86-64, ARM64, PowerPC, etc.)
  - Displays: Architecture name, address width (32/64-bit), endianness, machine code
  - Integrated into `filo analyze` command - shows automatically for executable formats
- Comprehensive test suite: 24 tests covering all major architectures and formats

### Changed
- Architecture information now displayed in analysis output for ELF, PE, and Mach-O files
- Updated models to include `ArchitectureInfo` in `AnalysisResult`

## [0.2.7] - 2026-01-17

### Added
- **Steganography**: Complete zsteg-compatible LSB/MSB extraction
  - 60+ bit plane configurations (b1/b2/b4 × rgb/rgba/bgr/abgr × lsb/msb × xy/yx/XY/YX)
  - Multi-bit extraction for 2-bit and 4-bit channels
  - File type detection (Targa, Alliant, Applesoft BASIC, OpenPGP)
  - Base64 auto-detection and decoding (improvement over zsteg)
  - CLI output formatting matching zsteg style

### Changed
- **Dependencies**: Added Pillow>=10.0.0 for image steganography analysis
- **Stego CLI**: Results filtered by default (use --all for metadata)
- Flag detection now highlights in bright green

### Fixed
- Multi-bit LSB/MSB extraction now correctly packs nibbles and bytes
- Bit extraction order matches zsteg algorithm exactly

## [0.2.6] - 2026-01-15

### Fixed
- **Critical**: Fixed contradiction detection not working for corrupted files
  - Contradiction detector now correctly strips "(corrupted)" suffix from format names
  - Corrupted PNGs, JPEGs, BMPs now properly show structural contradictions
- Fixed missing `_strategy_reconstruct_from_chunks` method in RepairEngine
  - Added implementation for PNG chunk-based reconstruction
  - Resolves "Unknown repair strategy" error when repairing PNG files
- Fixed duplicate "png" key in `advanced_strategies` dictionary
  - Merged PNG repair strategies into single consolidated list

### Changed
- Removed temporary and AI-like comments from codebase
- Improved code cleanliness and production readiness
- Consolidated PNG repair strategies for better organization

### Security
- Enhanced contradiction detection now properly identifies header corruption
- Better detection of embedded executables in image files

## [0.2.5] - 2025-XX-XX

### Added
- Hash-based lineage tracking
- Polyglot file detection
- Tool fingerprinting
- Advanced confidence breakdown system
- Embedded artifact detection

### Improved
- Fuzzy signature matching for corrupted files
- Multi-format container analysis
- ZIP-based format detection (DOCX, XLSX, PPTX, ODT, ODP, ODS)

## [0.2.3] - 2025-XX-XX

### Initial Release
- Core file format detection engine
- Signature-based analysis
- Structural validation
- Basic repair capabilities
- Carving engine
- Batch processing
- Export to JSON/SARIF

[0.2.6]: https://github.com/supunhg/Filo/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/supunhg/Filo/compare/v0.2.3...v0.2.5
[0.2.3]: https://github.com/supunhg/Filo/releases/tag/v0.2.3
