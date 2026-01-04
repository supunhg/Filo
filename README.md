# Filo - Forensic Intelligence & Ligation Orchestrator

**Battle-tested file forensics platform for security professionals**

Filo transforms unknown binary blobs into classified, repairable, and explainable artifacts with offline ML learning capabilities.

## Features

- 🔍 **Deep File Analysis**: Signature, structural, and statistical analysis
- 🔧 **Intelligent Repair**: Reconstruct corrupted headers automatically with 21 repair strategies
- 🧠 **Offline ML Learning**: Learns from corrections, fully offline
- 🎯 **CTF-Optimized**: Purpose-built for capture-the-flag challenges
- 📊 **Export Reports**: JSON and SARIF output for CI/CD integration
- 🚀 **Batch Processing**: Parallel directory analysis with configurable workers
- 📦 **Container Detection**: Recursive ZIP/TAR analysis with nested support
- ⚡ **Performance Profiling**: Identify bottlenecks in large-scale analysis
- 🎨 **Enhanced CLI**: Color-coded output, hex dumps, repair suggestions

## Quick Start

```bash
# Install
pip install -e .

# Analyze unknown file
filo analyze suspicious.bin

# Analyze with hex dump and export
filo analyze --hex-dump --export=json --output=report.json file.bin

# Batch process directory
filo batch ./directory

# Analyze container (ZIP/TAR)
filo analyze --container archive.zip

# Repair corrupted file
filo repair --format=png broken_image.bin

# Profile performance
filo profile large_file.dat
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
from filo.batch import analyze_directory
from filo.export import export_to_file
from filo.container import analyze_archive

# Analyze file
analyzer = Analyzer()
result = analyzer.analyze_file("unknown.bin")
print(f"Detected: {result.primary_format} ({result.confidence:.0%})")

# Batch process directory
batch_result = analyze_directory("./data", recursive=True)
print(f"Analyzed {batch_result.analyzed_count} files")

# Export to JSON/SARIF
export_to_file(result, "report.json", format="json")

# Analyze container
container = analyze_archive("archive.zip")
for entry in container.entries:
    print(f"{entry.path}: {entry.format}")

# Repair file
repair = RepairEngine()
repaired_data, report = repair.repair_file("corrupt.png")
```

### CLI
```bash
# Enhanced analysis with hex dump
filo analyze --hex-dump --hex-bytes=128 suspicious.bin

# Batch processing with export
filo batch ./directory --export=sarif --output=scan.sarif

# Container analysis
filo analyze --container archive.zip

# Performance profiling
filo profile --top=20 large_dataset.bin

# Export to JSON for scripting
filo analyze --export=json file.bin | jq '.primary_format'
```

## Documentation

- [Quick Start Guide](QUICKSTART.md) - Get started in 5 minutes
- [Architecture](ARCHITECTURE.md) - Detailed system design
- [Advanced Repair](docs/ADVANCED_REPAIR.md) - Repair engine documentation
- [New Features (v0.2.0)](docs/NEW_FEATURES.md) - Latest features guide
- [Examples](examples/README.md) - Code examples and demos

## What's New in v0.2.0

✨ **5 Major Features Added:**
1. **Batch Processing** - Parallel directory analysis (91% coverage)
2. **Export Reports** - JSON/SARIF output (99% coverage)
3. **Container Detection** - ZIP/TAR recursive analysis (78% coverage)
4. **Performance Profiling** - Bottleneck identification (97% coverage)
5. **Enhanced CLI** - Color-coded output, hex dumps, suggestions

📊 **Test Coverage**: 67% overall (95 tests passing)

See [docs/NEW_FEATURES.md](docs/NEW_FEATURES.md) for complete details.

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
