# New Features - v0.2.0

This document describes the 5 major features added to Filo in version 0.2.0.

## 🚀 Feature Overview

### 1. Batch Processing
**Efficiently analyze entire directories with parallel processing**

- **Module**: `filo.batch`
- **Coverage**: 91%
- **Key Classes**: `BatchProcessor`, `BatchConfig`, `BatchResult`

**Features**:
- Parallel file processing using `ThreadPoolExecutor`
- Configurable worker threads (default: CPU count)
- File filtering by size, patterns, extensions
- Include/exclude pattern matching with fnmatch
- Recursive and non-recursive directory scanning
- Progress callbacks for real-time updates
- Detailed batch statistics (total, analyzed, failed, duration)

**Usage**:
```python
from filo.batch import analyze_directory

# Simple usage
result = analyze_directory("./data")

# Advanced configuration
result = analyze_directory(
    "./data",
    recursive=True,
    max_workers=8,
    max_file_size=10_000_000,  # 10MB limit
    exclude_patterns=["*.log", "*.tmp"],
    include_patterns=["*.bin", "*.dat"],
    progress_callback=lambda current, total: print(f"{current}/{total}")
)

print(f"Analyzed {result.analyzed_count} files in {result.duration:.2f}s")
```

**CLI**:
```bash
filo batch ./directory
filo batch --recursive --max-workers=8 --max-size=10485760 ./data
```

---

### 2. Export Reports
**JSON and SARIF output for integration with other tools**

- **Module**: `filo.export`
- **Coverage**: 99%
- **Key Classes**: `JSONExporter`, `SARIFExporter`

**Features**:
- JSON export with pretty printing
- SARIF 2.1.0 compliance for static analysis tools
- Single result and batch result export
- GitHub Advanced Security compatible
- VS Code SARIF viewer compatible
- Detailed metadata and timestamps

**Supported Formats**:
- **JSON**: Custom format with full analysis details
- **SARIF**: Static Analysis Results Interchange Format 2.1.0

**Usage**:
```python
from filo import Analyzer
from filo.export import JSONExporter, SARIFExporter, export_to_file

analyzer = Analyzer()
result = analyzer.analyze_file("file.bin")

# Export to JSON
json_exporter = JSONExporter()
json_data = json_exporter.export_result(result)
export_to_file(result, "report.json", format="json")

# Export to SARIF
sarif_exporter = SARIFExporter()
sarif_data = sarif_exporter.export_result(result)
export_to_file(result, "report.sarif", format="sarif")
```

**CLI**:
```bash
filo analyze --export=json --output=report.json file.bin
filo analyze --export=sarif --output=report.sarif file.bin
filo batch --export=json --output=batch_report.json ./directory
```

---

### 3. Container Detection
**Detect and recursively analyze ZIP/TAR/ISO archives**

- **Module**: `filo.container`
- **Coverage**: 78%
- **Key Classes**: `ContainerDetector`, `ContainerAnalysis`

**Features**:
- ZIP, TAR, and TAR.GZ detection
- Recursive archive analysis
- Nested container detection with depth limits
- Entry-by-entry format analysis
- Container statistics (total entries, analyzed, formats)
- Integration with file analysis pipeline

**Supported Containers**:
- ZIP archives
- TAR archives
- TAR.GZ compressed archives
- ISO images (detection only)

**Usage**:
```python
from filo.container import analyze_archive, ContainerDetector

# Detect if file is a container
detector = ContainerDetector()
is_container = detector.is_container(b"\x50\x4b\x03\x04...")  # ZIP magic

# Analyze archive contents
analysis = analyze_archive("archive.zip")
print(f"Container type: {analysis.container_type}")
print(f"Total entries: {analysis.total_entries}")

for entry in analysis.entries:
    print(f"  {entry.path}: {entry.format} ({entry.size} bytes)")
```

**CLI**:
```bash
filo analyze --container archive.zip
filo batch --containers ./archives
```

---

### 4. Performance Profiling
**Identify bottlenecks in large file analysis**

- **Module**: `filo.profiler`
- **Coverage**: 97%
- **Key Classes**: `Profiler`, `ProfileReport`, `TimingResult`

**Features**:
- Operation timing with context managers
- Function decoration for automatic profiling
- cProfile integration for detailed profiling
- Operation statistics (total time, call count, average)
- Sorted timing reports
- Enable/disable profiling globally

**Usage**:
```python
from filo.profiler import Profiler, profile_session

# Manual profiling
profiler = Profiler()
profiler.start()

# Your code here
profiler.time_operation("operation_name")

report = profiler.stop()
print(report.format_report())

# Context manager for profiling sessions
with profile_session() as profiler:
    # Analyze files
    for file in files:
        with profiler.time_operation(f"analyze_{file}"):
            analyzer.analyze_file(file)
    
    report = profiler.get_report()
    print(report.format_report())
```

**CLI**:
```bash
filo profile file.dat
filo profile --top=20 large_file.bin
```

---

### 5. Better CLI Output
**Color-coded confidence, hex dumps, repair suggestions**

- **Module**: `filo.cli` (enhanced)
- **Coverage**: 0% (manual testing required)
- **Key Features**: Enhanced output formatting

**Features**:
- Color-coded confidence levels (green/yellow/red)
- Hex dump display for binary inspection
- Automatic repair suggestions for low confidence
- Rich console output with tables and panels
- Progress bars for batch operations
- Format distribution visualization

**Confidence Colors**:
- 🟢 Green: ≥ 80% (High confidence)
- 🟡 Yellow: 50-80% (Medium confidence)
- 🔴 Red: < 50% (Low confidence)

**Usage**:
```bash
# Enhanced output with colors
filo analyze file.bin

# Show hex dump
filo analyze --hex-dump file.bin

# Show hex dump with custom size
filo analyze --hex-dump --hex-bytes=128 file.bin

# Combined with other features
filo analyze --hex-dump --container --export=json archive.zip
```

---

## 📊 Test Coverage

| Module | Coverage | Tests |
|--------|----------|-------|
| `batch.py` | 91% | 8 |
| `export.py` | 99% | 8 |
| `container.py` | 78% | 9 |
| `profiler.py` | 97% | 11 |
| **Total New** | **89%** | **36** |

**Overall Project Coverage**: 67% (95 tests passing)

---

## 🎯 Quick Start

### Installation
```bash
pip install -e .
```

### Run Demo
```bash
python examples/features_demo.py
```

### CLI Examples
```bash
# Batch process a directory
filo batch ./data

# Export analysis to JSON
filo analyze --export=json --output=report.json file.bin

# Analyze a container
filo analyze --container archive.zip

# Profile performance
filo profile large_file.dat

# Show hex dump
filo analyze --hex-dump suspicious.bin

# Combine features
filo batch --export=sarif --output=scan.sarif --containers ./archives
```

---

## 🔧 API Reference

### Batch Processing
```python
from filo.batch import BatchProcessor, BatchConfig, analyze_directory

config = BatchConfig(
    max_workers=4,
    recursive=True,
    max_file_size=10_000_000,
    exclude_patterns=["*.log"]
)

processor = BatchProcessor(config)
result = processor.process_directory("./data")

# Or use convenience function
result = analyze_directory("./data", recursive=True)
```

### Export
```python
from filo.export import export_to_file

# JSON export
export_to_file(result, "report.json", format="json", pretty=True)

# SARIF export
export_to_file(result, "report.sarif", format="sarif", overwrite=True)
```

### Container Analysis
```python
from filo.container import ContainerDetector, analyze_archive

detector = ContainerDetector()
if detector.is_container(data):
    analysis = analyze_archive(path, max_depth=3)
```

### Profiling
```python
from filo.profiler import profile_session

with profile_session() as profiler:
    with profiler.time_operation("analysis"):
        result = analyzer.analyze_file("file.bin")
    
    print(profiler.get_report().format_report())
```

---

## 🎨 Output Examples

### Batch Processing
```
     Batch Processing Results     
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Metric      ┃            Value ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ Total Files │               42 │
│ Analyzed    │               42 │
│ Failed      │                0 │
│ Duration    │            0.15s │
│ Speed       │   280.0 files/sec│
└─────────────┴──────────────────┘

Format Distribution:
  • png: 15
  • jpeg: 12
  • pdf: 8
  • zip: 7
```

### Container Analysis
```
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Property       ┃ Value ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Container Type │ ZIP   │
│ Total Entries  │ 15    │
│ Analyzed       │ 15    │
└────────────────┴───────┘

Container Contents:
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┓
┃ Path       ┃     Size ┃ Type ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━┩
│ image.png  │ 1.2 MB   │ png  │
│ doc.pdf    │ 523 KB   │ pdf  │
│ data.bin   │ 50 bytes │ file │
└────────────┴──────────┴──────┘
```

### Profiling Results
```
Profiling Results:
Total Duration: 0.3642s
┏━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┓
┃ Operation    ┃ Time (s) ┃ Calls ┃  Avg (s) ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━┩
│ analyze_file │   0.2841 │   100 │ 0.002841 │
│ load_model   │   0.0512 │     1 │ 0.051200 │
│ extract_sigs │   0.0289 │   100 │ 0.000289 │
└──────────────┴──────────┴───────┴──────────┘
```

---

## 🚀 Next Steps

These 5 features were identified as Quick Wins in the roadmap. Potential next priorities:

1. **Plugin System** - Extensible architecture for custom analyzers
2. **Configuration Files** - YAML/TOML config support
3. **Watch Mode** - Monitor directories for changes
4. **Advanced ML** - Deep learning model integration
5. **Web UI** - Browser-based interface

See [ARCHITECTURE.md](../ARCHITECTURE.md) for the complete roadmap.
