# Filo - Forensic Intelligence & Ligation Orchestrator

**Battle-tested file forensics platform for security professionals**

Filo transforms unknown binary blobs into classified, repairable, and explainable artifacts with offline ML learning capabilities.

## Features

- 🔍 **Deep File Analysis**: Signature, structural, and statistical analysis
- 🔧 **Intelligent Repair**: Reconstruct corrupted headers automatically  
- 🧠 **Offline ML Learning**: Learns from corrections, fully offline
- 🎯 **CTF-Optimized**: Purpose-built for capture-the-flag challenges
- 📊 **Forensic Reports**: Chain-of-custody evidence trails
- 🧩 **Extensible**: Plugin system for custom formats
- ⚡ **Fast**: Sub-100ms analysis for typical files

## Quick Start

```bash
# Install
pip install filo-forensics

# Analyze unknown file
filo analyze suspicious.bin

# Repair corrupted file
filo repair --format=png broken_image.bin

# Carve files from disk image
filo carve --formats=png,jpg,zip disk.img

# Teach Filo (ML learning)
filo teach challenge_file.bin --format=png
```

## Installation

### From Source
```bash
git clone https://github.com/supunhg/Filo
cd Filo
pip install -e .
```

### Development
```bash
pip install -e ".[dev]"
pytest
```

## Usage Examples

### Python API
```python
from filo import Analyzer, RepairEngine

# Analyze file
analyzer = Analyzer()
result = analyzer.analyze_file("unknown.bin")
print(f"Detected: {result.primary_format} ({result.confidence:.0%})")

# Teach from correction
analyzer.teach(data, correct_format="png")

# Repair file
repair = RepairEngine()
repaired_data, report = repair.repair_file("corrupt.png")
```

### CLI
```bash
# Deep analysis
filo analyze --deep memory.dump

# Batch processing
find . -type f -exec filo analyze --json {} + | jq

# Generate test files
filo generate --format=pdf --count=10 --output=test_files/
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design.

## Contributing

We welcome contributions! Priority areas:
- Format specifications (YAML)
- Analysis plugins
- Test corpus samples
- Performance optimizations


## Author

Supun Hewagamage ([@supunhg](https://github.com/supunhg))fault
- Non-destructive (unless explicitly requested)
- Resource-limited
- Input-validated

---

**When you need to know not just *what* something is, but *why* it's that, and *how* to fix it.**
