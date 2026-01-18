# Filo v0.2.8 - CPU Architecture Detection 🖥️

**Instantly identify CPU architectures for executables - perfect for CTF challenges and malware analysis!**

## 🚀 What's New

Filo now automatically detects and reports CPU architecture information for executable files. This release adds support for **90+ architectures** across three executable formats.

### Key Features

- **🖥️ CPU Architecture Detection**: Automatic identification for ELF, PE/COFF, and Mach-O executables
- **90+ Architectures**: x86, x86-64, ARM, ARM64, RISC-V, MIPS, PowerPC, Xtensa, SPARC, AVR, Alpha, IA-64, and many more
- **Complete Information**: Shows architecture name, address width (32/64-bit), endianness, machine code
- **CTF-Optimized**: Solve architecture identification challenges in one command
- **Zero Configuration**: Works automatically with `filo analyze` command

## 💻 Example Usage

### CTF Challenge - Architecture Astronaut

```bash
$ filo analyze astronaut

╭─────────────────────────────────────────────────────────────────────────────╮
│ File Analysis: /home/tabea/Main/CTF/MetaCTF/ArchitectureAstronaut/astronaut │
╰─────────────────────────────────────────────────────────────────────────────╯

Detected Format: elf
Confidence: 63.6%

🖥️  CPU Architecture:
  • Tensilica Xtensa Architecture (32-bit, Little-endian)
    Format: ELF | Machine Code: 0x005E

File Size: 1,008,324 bytes
Entropy: 0.50 bits/byte
SHA256: 5af2a291f7a175c0
```

**Answer**: `Xtensa` or `Tensilica Xtensa Architecture` ✅

### Regular Executables

```bash
$ filo analyze /usr/bin/ls

🖥️  CPU Architecture:
  • AMD x86-64 (64-bit, Little-endian)
    Format: ELF | Machine Code: 0x003E
```

## 🎯 Supported Architectures

### Common Desktop/Server
x86, x86-64 (AMD64), ARM (32/64-bit), RISC-V, MIPS, PowerPC, SPARC

### Embedded & IoT
Tensilica Xtensa (ESP32), AVR (Arduino), SuperH, Motorola 68000, ARM Thumb, Hitachi H8

### Specialized & Legacy
Alpha AXP, IA-64 (Itanium), S390 (IBM mainframes), VAX, PDP-10/11, TMS320C6000 (DSP), Elbrus e2k, Berkeley Packet Filter (BPF), WDC 65C816 (SNES)

**Full list**: See [ARCHITECTURE_DETECTION.md](https://github.com/supunhg/Filo/blob/main/docs/ARCHITECTURE_DETECTION.md)

## 📦 Installation

### Option 1: .deb Package (Recommended)

Download `filo-forensics_0.2.8_all.deb` from this release and install:

```bash
sudo dpkg -i filo-forensics_0.2.8_all.deb
filo --version
```

### Option 2: From Source

```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

## 📚 Documentation

- **[ARCHITECTURE_DETECTION.md](https://github.com/supunhg/Filo/blob/main/docs/ARCHITECTURE_DETECTION.md)**: Complete architecture detection guide
- **[RELEASE_NOTES_v0.2.8.md](https://github.com/supunhg/Filo/blob/main/docs/RELEASE_NOTES_v0.2.8.md)**: Detailed release notes
- **[CHANGELOG.md](https://github.com/supunhg/Filo/blob/main/docs/CHANGELOG.md)**: Full project changelog
- **[README.md](https://github.com/supunhg/Filo/blob/main/README.md)**: Main project documentation

## 🧪 Testing

All 24 architecture detection tests passing:
- ✅ 12 ELF tests (x86, x86-64, ARM, ARM64, RISC-V, MIPS, Xtensa, PowerPC, SPARC)
- ✅ 4 PE tests (Windows executables)
- ✅ 4 Mach-O tests (macOS/iOS)
- ✅ 4 auto-detection tests
- ✅ Error handling tests

Overall test coverage: **85%+** (all tests passing)

## 🔄 Changes Since v0.2.7

### Added
- `filo/architecture.py`: Core architecture detector (343 lines)
- `ArchitectureInfo` model with architecture, bits, endian, machine_code
- Architecture detection integrated into `FileAnalyzer`
- CLI display section for architecture information
- 24 comprehensive tests
- Complete documentation (ARCHITECTURE_DETECTION.md)

### Changed
- Version bumped to 0.2.8 in all files
- Updated README.md and QUICKSTART.md with architecture examples
- Enhanced .deb package description

### Technical Details
- **Lines Added**: 1,032
- **Architectures Supported**: 90+
- **Executable Formats**: 3 (ELF, PE, Mach-O)
- **Test Pass Rate**: 100% (24/24)

## ✨ Complete Feature Set

Filo v0.2.8 includes all previous features:
- 🖥️ **CPU Architecture Detection** (v0.2.8)
- 🎨 **zsteg-Compatible Steganography** (v0.2.7): 60+ bit plane LSB/MSB extraction
- 🌐 **PCAP Analysis** (v0.2.6): Network capture file analysis
- ⚠️ **Polyglot Detection** (v0.2.5): Dual-format file detection with risk assessment
- 🕵️ **Embedded Detection**: Find files hidden inside files
- 🔧 **Tool Fingerprinting**: Forensic attribution
- 🛡️ **Contradiction Detection**: Malware triage
- 🔗 **Hash Lineage Tracking**: Chain-of-custody
- 🚀 **Batch Processing**: Parallel directory analysis
- 🧠 **Offline ML Learning**: Pattern extraction and training

## 🐛 Known Limitations

- Fat binaries (Mach-O universal) show only first architecture (multi-arch support planned)
- Obfuscated/encrypted headers may fail detection
- Script bytecode (Python/Java) not detected (architecture-independent)

## 🔮 Coming Next (v0.2.9)

- Multi-architecture support for fat binaries
- Android DEX/ART architecture hints
- WebAssembly (WASM) module analysis
- ARM variant detection (ARMv6/v7/v8)
- RISC-V extension identification

## 📊 Stats

- **Downloads**: Track on [Releases](https://github.com/supunhg/Filo/releases)
- **Stars**: Give us a ⭐ if you find Filo useful!
- **Issues**: Report bugs or request features in [Issues](https://github.com/supunhg/Filo/issues)
- **Discussions**: Join us in [Discussions](https://github.com/supunhg/Filo/discussions)

## 🙏 Credits

Architecture detection implementation based on official specifications:
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
- [PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Mach-O File Format](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/machine.h)

---

**Full Changelog**: [v0.2.7...v0.2.8](https://github.com/supunhg/Filo/compare/v0.2.7...v0.2.8)
