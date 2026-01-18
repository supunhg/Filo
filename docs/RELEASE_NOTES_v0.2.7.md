# Filo v0.2.7 - zsteg-Compatible Steganography Detection

## 🎯 Release Highlights

This release transforms Filo's steganography detection into a **zsteg-compatible CTF powerhouse**, implementing exact algorithm parity with the industry-standard `zsteg` tool while adding intelligent enhancements like automatic base64 decoding.

Perfect for **CTF challenges** (picoCTF, HackTheBox, etc.) and **digital forensics** work requiring LSB/MSB analysis.

---

## ✨ What's New

### 🔍 Complete zsteg Algorithm Compatibility

- **60+ bit plane configurations** tested per image (b1/b2/b4 × rgb/rgba/bgr/abgr × lsb/msb × xy/yx/XY/YX)
- **Multi-bit extraction** for 2-bit and 4-bit channels with correct nibble/byte packing
- **Byte-for-byte identical** extraction compared to zsteg (verified on CTF challenge images)
- **Pixel order variants**: xy (row-major), yx (column-major), XY (reversed horizontal), YX (reversed vertical)

### 🚀 Enhanced Features (Beyond zsteg)

- **🎁 Automatic base64 decoding**: Detects and auto-decodes base64 payloads, showing flags directly
  - Example: Shows `picoCTF{flag}` instead of raw `cGljb0NURntt...` 
  - Saves manual decoding steps during CTF competitions
- **📁 File type detection**: Identifies Targa, Alliant, Applesoft BASIC, OpenPGP Public/Secret Keys
- **🎨 Smart filtering**: Hides metadata noise by default (use `--all` to show everything)
- **🌈 Color-coded output**: Flags highlighted in bright green, text in white, files in cyan

### 🎨 zsteg-Style CLI Output

```
b1,rgb,lsb,xy          .. text: "picoCTF{7h3r3_15_n0_5p00n_a9a181eb}"
b1,bgr,lsb,xy          .. text: "\nVnWUQ1Y"
b4,r,lsb,xy            .. file: Applesoft BASIC program data, first line number 257
b1,rgba,lsb,xy         .. text: "UfUUUU@UU"
```

Clean, compact formatting matching the familiar zsteg tool output.

---

## 🔧 Technical Improvements

### Steganography Engine

- **Fixed multi-bit extraction algorithm**: Nibbles and bytes now packed as values (not individual bit flags)
- **Correct bit order**: MSB-first packing for 1-bit extraction, proper value masking for multi-bit
- **Comprehensive test coverage**: All bit plane combinations validated against zsteg reference output

### Embedded Object Detection

- **Reduced false positives**: Confidence threshold raised from 0.70 to 0.80
- **Smart exclusion rules**: Skips common false positives (e.g., WASM/ICO patterns in ELF binaries)
- **Parent format awareness**: Embedded detector now considers file context

### Dependencies

- **Added**: Pillow >= 10.0.0 for PNG/BMP image processing
- **No breaking changes**: All existing functionality preserved

---

## 📦 Installation

### Debian/Ubuntu (.deb package)

```bash
# Download from GitHub releases
wget https://github.com/supunhg/Filo/releases/download/v0.2.7/filo-forensics_0.2.7_all.deb

# Install
sudo dpkg -i filo-forensics_0.2.7_all.deb

# Verify installation
filo --version
```

### From Source (pip)

```bash
git clone https://github.com/supunhg/Filo.git
cd Filo
git checkout v0.2.7
pip install -e .
```

---

## 🚀 Quick Start Examples

### Detect Hidden Flags in CTF Images

```bash
# Analyze PNG for hidden data
filo stego challenge.png

# Show all results (including metadata)
filo stego image.png --all

# Extract specific bit plane
filo stego image.png --extract="b1,rgba,lsb,xy" -o flag.txt
```

### Real-World CTF Example

**Input**: `pico.flag.png` from picoCTF challenge

**Output**:
```
Found 9 results:

b1,rgb,lsb,xy          .. text: "picoCTF{7h3r3_15_n0_5p00n_a9a181eb}"
b4,r,lsb,xy            .. file: Applesoft BASIC program data, first line number 257
b1,rgba,lsb,xy         .. text: "UfUUUU@UU"
```

**Advantage over zsteg**: If flag was base64-encoded, Filo auto-decodes it! 🎉

---

## 📊 Testing Results

Validated against CTF challenge images:
- ✅ **pico.flag.png**: Flag detected in `b1,rgb,lsb,xy` (matches zsteg exactly)
- ✅ **red.png**: Base64 auto-decoded to show flag (improvement over zsteg)
- ✅ **Multi-bit extraction**: b2, b4 bit planes work correctly (fixed nibble packing)
- ✅ **File signatures**: OpenPGP, Targa, Alliant detection working

---

## 🔄 Migration Guide

**No breaking changes!** All existing Filo commands work as before.

**New users**: Use `filo stego` for CTF steganography challenges - it's now zsteg-compatible with enhancements.

**Existing stego users**: 
- Default output is now filtered (cleaner). Use `--all` for previous behavior.
- Base64 payloads are auto-decoded (saves you a step!).

---

## 📚 Documentation Updates

- **[CHANGELOG.md](docs/CHANGELOG.md)**: Full v0.2.7 release notes
- **[STEGANOGRAPHY_DETECTION.md](docs/STEGANOGRAPHY_DETECTION.md)**: Complete rewrite with zsteg compatibility details
- **[.gitignore](.gitignore)**: Added `.venv/` to prevent tracking dev environments

---

## 🐛 Bug Fixes

- Fixed multi-bit LSB/MSB extraction (b2, b4 now correctly pack nibbles/bytes)
- Fixed bit extraction order to match zsteg algorithm
- Reduced embedded object false positives in binary executables

---

## 🙏 Acknowledgments

- **zsteg** by @zed-0xff: Reference implementation for LSB/MSB algorithms
- **picoCTF**: Test images for validation (pico.flag.png, red.png)

---

## 📝 Full Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for complete version history.

---

## 🔗 Links

- **GitHub Repository**: https://github.com/supunhg/Filo
- **Documentation**: https://github.com/supunhg/Filo/tree/main/docs
- **Issues**: https://github.com/supunhg/Filo/issues
- **Releases**: https://github.com/supunhg/Filo/releases

---

**Package Checksums** (for verification):

```bash
# SHA256 checksum of filo-forensics_0.2.7_all.deb
sha256sum filo-forensics_0.2.7_all.deb
```

---

Released: January 18, 2026  
Version: 0.2.7  
License: Apache-2.0
