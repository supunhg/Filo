# Filo v0.2.8 Release Notes

**Release Date**: January 18, 2026  
**Focus**: CPU Architecture Detection for Executables

## 🚀 What's New

### 🖥️ CPU Architecture Detection

Filo now automatically detects and reports CPU architecture information for executable files. This feature is invaluable for CTF challenges, malware analysis, and reverse engineering workflows.

**Key Capabilities:**
- **90+ Architectures Supported**: From x86 to exotic embedded processors
- **Three Executable Formats**: ELF (Linux/Unix), PE/COFF (Windows), Mach-O (macOS/iOS)
- **Comprehensive Information**: Architecture name, bits, endianness, machine code
- **Instant CTF Answers**: Solve architecture identification challenges in one command

## 🎯 Supported Architectures

### Common Desktop/Server
- **x86** (32-bit Intel/AMD)
- **x86-64** / AMD64 (64-bit Intel/AMD)
- **ARM** (ARMv7/Aarch32)
- **ARM64** (ARMv8/Aarch64)
- **RISC-V** (32/64/128-bit)
- **MIPS** / MIPS64
- **PowerPC** / PowerPC 64
- **SPARC** / SPARC V9

### Embedded & IoT
- **Tensilica Xtensa** (ESP8266/ESP32 WiFi chips)
- **AVR** (Atmel microcontrollers - Arduino)
- **SuperH** (SH-3, SH-4, SH-5)
- **Motorola 68000** (M68k)
- **ARM Thumb** (compressed ARM instructions)
- **Hitachi H8** series

### Specialized & Legacy
- **Alpha AXP** (DEC Alpha)
- **IA-64** (Intel Itanium)
- **S390/S390x** (IBM mainframes)
- **VAX**, **PDP-10**, **PDP-11**
- **TMS320C6000** (Texas Instruments DSP)
- **Elbrus e2k** (Russian processors)
- **Berkeley Packet Filter** (BPF/eBPF)
- **WDC 65C816** (Apple IIgs, SNES)

## 📖 Usage Examples

### Basic Architecture Detection

```bash
$ filo analyze suspicious_binary

╭──────────────────────────────────╮
│ File Analysis: suspicious_binary │
╰──────────────────────────────────╯

Detected Format: elf
Confidence: 63.6%

🖥️  CPU Architecture:
  • AMD x86-64 (64-bit, Little-endian)
    Format: ELF | Machine Code: 0x003E

File Size: 158,632 bytes
Entropy: 2.26 bits/byte
SHA256: 833d6f9c...
```

### CTF Challenge Example

**Challenge**: Identify the CPU architecture of an unknown executable.

```bash
$ filo analyze astronaut

🖥️  CPU Architecture:
  • Tensilica Xtensa Architecture (32-bit, Little-endian)
    Format: ELF | Machine Code: 0x005E
```

**Answer**: `Xtensa` or `Tensilica Xtensa Architecture` ✅

### Malware Triage

```bash
# Identify malware target platform
$ filo analyze malware.exe

🖥️  CPU Architecture:
  • ARM64 little endian (Aarch64) (64-bit, Little-endian)
    Format: PE | Machine Code: 0xAA64

# Windows on ARM malware detected!
```

### Programmatic Access

```python
from filo.analyzer import FileAnalyzer

analyzer = FileAnalyzer()
result = analyzer.analyze_file("binary_file")

if result.architecture:
    print(f"Architecture: {result.architecture.architecture}")
    print(f"Bits: {result.architecture.bits}")
    print(f"Endian: {result.architecture.endian}")
    print(f"Machine Code: 0x{result.architecture.machine_code:04X}")
```

## 🏗️ Technical Implementation

### ELF Detection
Reads the `e_machine` field at offset 0x12 in the ELF header:
- Supports both 32-bit and 64-bit ELF files
- Handles both little-endian and big-endian byte order
- Maps 90+ machine codes to human-readable names

### PE/COFF Detection
Extracts the `Machine` field from the COFF header:
- Locates PE header via DOS stub offset (0x3C)
- Identifies Windows executable architectures
- Supports legacy and modern Windows platforms

### Mach-O Detection
Parses the `cputype` field from Mach-O header:
- Detects macOS and iOS executable architectures
- Handles universal binaries (shows first architecture)
- Supports both 32-bit and 64-bit Mach-O formats

## 🧪 Testing

Comprehensive test suite with 24 tests covering:
- **12 ELF tests**: x86, x86-64, ARM, ARM64, RISC-V, MIPS, Xtensa, PowerPC, SPARC, unknown codes, error cases
- **4 PE tests**: x86, x64, ARM64, error cases
- **4 Mach-O tests**: x86-64, ARM64, i386, error cases
- **4 Auto-detect tests**: Format identification

**Result**: 100% test pass rate (24/24 tests passing)

## 📚 Documentation

New documentation added:
- **[ARCHITECTURE_DETECTION.md](ARCHITECTURE_DETECTION.md)**: Complete usage guide
  - Supported formats and architectures
  - CTF examples and workflows
  - Technical implementation details
  - API reference and error handling

## 🔄 Changes Since v0.2.7

### Added
- `filo/architecture.py`: Core architecture detector module (343 lines)
- `ArchitectureInfo` model in `filo/models.py`
- Architecture detection integrated into `FileAnalyzer`
- CLI display section for architecture information
- 24 comprehensive tests in `tests/test_architecture.py`

### Modified
- `filo/analyzer.py`: Added architecture detection for executable formats
- `filo/cli.py`: Added architecture display with 🖥️ icon
- `filo/models.py`: Added `ArchitectureInfo` to `AnalysisResult`

### Documentation
- Updated `CHANGELOG.md` with v0.2.8 release notes
- Created `ARCHITECTURE_DETECTION.md` with comprehensive guide
- Updated `README.md` and `QUICKSTART.md` with architecture examples

## 📦 Installation

### .deb Package (Recommended)
```bash
git clone https://github.com/supunhg/Filo
cd Filo
./build-deb.sh
sudo dpkg -i filo-forensics_0.2.8_all.deb
```

### From Source
```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

## 🔮 Future Enhancements

Planned improvements for architecture detection:
- **Fat Binary Support**: Show all architectures in Mach-O universal binaries
- **Android DEX/ART**: Architecture hints from Dalvik/ART bytecode
- **WebAssembly**: WASM module analysis
- **ARM Variants**: Detailed ARMv6/v7/v8 variant detection
- **RISC-V Extensions**: RV32I, RV64GC extension identification

## 🐛 Known Limitations

- **Fat Binaries**: Mach-O universal binaries show only first architecture (multi-arch support planned)
- **Obfuscated Headers**: May fail if executable headers are malformed/encrypted
- **Script Bytecode**: Python/Java bytecode not detected (architecture-independent)

## 🙏 Credits

Architecture detection implementation based on:
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
- [PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Mach-O File Format](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/machine.h)

## 📊 Release Statistics

- **Lines Added**: 1,032
- **New Files**: 3 (architecture.py, test_architecture.py, ARCHITECTURE_DETECTION.md)
- **Modified Files**: 5
- **Tests Added**: 24 (100% passing)
- **Architectures Supported**: 90+
- **Executable Formats**: 3 (ELF, PE, Mach-O)

---

**Previous Release**: [v0.2.7 - zsteg-Compatible Steganography](RELEASE_v0.2.7.md)  
**Full Changelog**: [CHANGELOG.md](CHANGELOG.md)
