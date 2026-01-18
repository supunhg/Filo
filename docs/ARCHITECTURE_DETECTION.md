# Architecture Detection - Filo v0.2.8

Filo now automatically detects and reports CPU architecture information for executable files.

## Overview

When analyzing executable files (ELF, PE/COFF, Mach-O), Filo extracts and displays:
- **CPU Architecture**: The target processor (e.g., "AMD x86-64", "ARM64", "Tensilica Xtensa")
- **Address Width**: 32-bit or 64-bit
- **Endianness**: Little-endian or Big-endian
- **Machine Code**: Raw machine type code from the executable header

This feature is particularly useful for:
- **CTF Challenges**: Quickly identify obscure architectures without needing external tools
- **Malware Analysis**: Determine target platforms for suspicious executables
- **Reverse Engineering**: Confirm architecture before selecting disassembler/debugger
- **Forensic Triage**: Rapidly categorize executable artifacts

## Supported Formats

### ELF (Linux/Unix Executables)
90+ architectures supported, including:

**Common Architectures:**
- x86 (32-bit Intel/AMD)
- AMD x86-64 (64-bit Intel/AMD)
- ARM (up to ARMv7/Aarch32)
- ARM64 (ARMv8/Aarch64)
- RISC-V
- MIPS / MIPS64
- PowerPC / PowerPC 64

**Embedded/Specialized:**
- Tensilica Xtensa (IoT/WiFi chips)
- AVR (Atmel microcontrollers)
- SPARC / SPARC V9
- Alpha AXP
- SuperH (SH-3, SH-4, SH-5)
- M68k (Motorola 68000)
- IA-64 (Intel Itanium)
- S390/S390x (IBM mainframes)

**Exotic/Legacy:**
- VAX, PDP-10, PDP-11
- TMS320C6000 (DSP)
- Elbrus e2k
- WDC 65C816
- Berkeley Packet Filter (BPF)

### PE/COFF (Windows Executables)
- x86 (I386) - 32-bit Windows
- x64 (AMD64/Intel 64) - 64-bit Windows
- ARM / ARMv7 Thumb
- ARM64 (Aarch64) - Windows on ARM
- IA-64 (Itanium)
- RISC-V (32/64/128-bit)
- MIPS (various variants)
- PowerPC
- Alpha AXP
- EFI Byte Code

### Mach-O (macOS/iOS Executables)
- x86 (I386) - 32-bit Intel Mac
- x86_64 - 64-bit Intel Mac
- ARM - 32-bit iOS/legacy
- ARM64 (Aarch64) - Apple Silicon (M1/M2/M3), modern iOS
- PowerPC / PowerPC 64 - Legacy Mac
- VAX, M68k, SPARC - Vintage platforms

## Usage

Architecture detection is **automatic** when analyzing executable files:

```bash
filo analyze suspicious_binary
```

**Example Output:**
```
╭──────────────────────────────────╮
│ File Analysis: suspicious_binary │
╰──────────────────────────────────╯

Detected Format: elf
Confidence: 63.6%

🖥️  CPU Architecture:
  • Tensilica Xtensa Architecture (32-bit, Little-endian)
    Format: ELF | Machine Code: 0x005E

File Size: 1,008,324 bytes
Entropy: 0.50 bits/byte
SHA256: 5af2a291f7a175c0
```

## CTF Example: Architecture Astronaut

**Challenge**: Identify the CPU architecture of an unknown executable.

**Solution**:
```bash
$ filo analyze astronaut

🖥️  CPU Architecture:
  • Tensilica Xtensa Architecture (32-bit, Little-endian)
    Format: ELF | Machine Code: 0x005E
```

**Answer**: `Xtensa` or `Tensilica Xtensa Architecture`

Compare with traditional tools:
```bash
# Old way - multiple tools needed:
$ file astronaut
astronaut: ELF 32-bit LSB executable, Tensilica Xtensa, version 1 (SYSV)...

$ exiftool astronaut | grep CPU
CPU Architecture: 32 bit
CPU Type: Unknown (94)  # Not helpful!

$ readelf -h astronaut | grep Machine
Machine: Unknown (94)   # Still need to look up 0x5E manually

# Filo way - one command:
$ filo analyze astronaut
# Immediately shows: "Tensilica Xtensa Architecture"
```

## Technical Details

### ELF Architecture Detection
Filo reads the `e_machine` field at offset 0x12 in the ELF header and maps it to human-readable names using the official ELF specification.

**Header Structure:**
```
Offset  Field        Value (Xtensa example)
0x00    Magic        7F 45 4C 46 (ELF)
0x04    Class        01 (32-bit)
0x05    Data         01 (Little-endian)
0x12    e_machine    5E 00 (0x005E = Xtensa)
```

### PE Architecture Detection
Reads the `Machine` field from the COFF header (after PE signature).

**PE Structure:**
```
Offset  Field         Value
0x00    DOS Header    4D 5A (MZ)
0x3C    PE Offset     Pointer to PE header
[PE]    Signature     50 45 00 00 (PE\0\0)
[PE+4]  Machine       2-byte architecture code
```

### Mach-O Architecture Detection
Reads the `cputype` field from the Mach-O header.

**Mach-O Structure:**
```
Offset  Field      Value
0x00    Magic      FE ED FA CF (64-bit LE) / CE FA ED FE (64-bit BE)
                   FE ED FA CE (32-bit LE) / CE FA ED FE (32-bit BE)
0x04    CPU Type   4-byte architecture code
```

## Error Handling

- **Unknown Architecture Codes**: Displays as "Unknown (0xXXXX)" with the hex code
- **Non-Executable Files**: Architecture detection only runs for executable formats
- **Corrupted Headers**: Returns None, analysis continues without architecture info
- **Truncated Files**: Safely handles files too short to contain architecture data

## Programmatic Access

```python
from filo.analyzer import FileAnalyzer

analyzer = FileAnalyzer()
result = analyzer.analyze_file("binary_file")

if result.architecture:
    print(f"Architecture: {result.architecture.architecture}")
    print(f"Bits: {result.architecture.bits}")
    print(f"Endian: {result.architecture.endian}")
    print(f"Machine Code: 0x{result.architecture.machine_code:04X}")
    print(f"Format: {result.architecture.format}")
```

**Output:**
```python
Architecture: AMD x86-64
Bits: 64-bit
Endian: Little-endian
Machine Code: 0x003E
Format: ELF
```

## Testing

Run architecture detection tests:
```bash
pytest tests/test_architecture.py -v
```

**Test Coverage:**
- 12 ELF architecture tests (x86, x64, ARM, ARM64, RISC-V, MIPS, Xtensa, PowerPC, SPARC, unknown, error cases)
- 4 PE architecture tests (x86, x64, ARM64, error cases)
- 4 Mach-O architecture tests (x86-64, ARM64, i386, error cases)
- 4 auto-detection tests (format identification)

**Total**: 24 tests, all passing

## Limitations

- **Fat Binaries**: Mach-O universal binaries show only the first architecture (multi-arch support planned)
- **Java/Python/Script Bytecode**: Not detected (architecture-independent formats)
- **WebAssembly (WASM)**: Not yet supported (planned for v0.2.9)
- **Obfuscated Headers**: May fail if executable headers are malformed/encrypted

## Future Enhancements

Planned for future releases:
- Multi-architecture detection for fat binaries (Mach-O universal)
- Android DEX/ART architecture hints
- Java bytecode version detection
- WASM module analysis
- ARM architecture variant detection (ARMv6, ARMv7, ARMv8.x)
- RISC-V extension detection (RV32I, RV64GC, etc.)

## References

- [ELF Specification](https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html)
- [PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Mach-O File Format](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/machine.h)
- [ELF Machine Codes](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h)
