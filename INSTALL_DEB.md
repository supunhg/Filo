# Filo Debian Package Installation Guide

This guide explains how to install Filo using the `.deb` package for easy, system-wide installation.

> 📦 **Quick Install**: Just want to install? Jump to [Installation](#installation).
>
> 🔧 **Build Package**: Want to build from source? See [Building the Package](#building-the-package).
>
> 📚 **Alternative**: For non-Debian systems or development, see the [main branch](https://github.com/supunhg/Filo/tree/main) for source installation.

## Overview

The Filo `.deb` package provides:
- **Isolated Environment**: Installs in `/opt/filo/` with its own Python virtual environment
- **No Conflicts**: Doesn't interfere with system Python or other packages
- **Global Command**: Provides `filo` command accessible from anywhere
- **Automatic Dependencies**: Installs all required Python packages automatically
- **Easy Removal**: Clean uninstallation with `dpkg -r` or `dpkg --purge`

## Building the Package

### Prerequisites

```bash
# Required system packages
sudo apt-get update
sudo apt-get install -y dpkg-dev python3 python3-pip python3-venv
```

### Build Instructions

1. **Clone the repository and switch to release branch:**
   ```bash
   git clone https://github.com/supunhg/Filo
   cd Filo
   git checkout release
   ```

2. **Build the .deb package:**
   ```bash
   ./build-deb.sh
   ```

   This creates `filo-forensics_0.2.0_all.deb` in the current directory.

## Installation

### Install the Package

```bash
# Install using dpkg
sudo dpkg -i filo-forensics_0.2.0_all.deb

# If you get dependency errors, run:
sudo apt-get install -f
```

### What Gets Installed

```
/opt/filo/                          # Main installation directory
├── filo/                           # Python package
├── tests/                          # Test suite
├── examples/                       # Example scripts
├── docs/                           # Documentation
├── models/                         # ML models directory
├── venv/                           # Isolated Python environment
├── pyproject.toml                  # Package metadata
├── setup.py                        # Installation script
└── README.md                       # Documentation

/usr/local/bin/filo                 # Global command wrapper
```

### Verify Installation

```bash
# Check version
filo --version

# Run help
filo --help

# Test analysis
echo "Test" > test.txt
filo analyze test.txt
```

## Usage

After installation, you can use `filo` from anywhere:

```bash
# Basic analysis
filo analyze suspicious.bin

# Batch processing
filo batch ./directory

# Export to JSON
filo analyze --json file.bin > report.json

# Performance profiling
filo profile large_file.dat

# Repair file
filo repair --format=png corrupted.png

# Get help
filo --help
```

## Environment Details

### Isolated Installation

The package installs Filo in a **completely isolated** environment:

- **Location**: `/opt/filo/`
- **Virtual Environment**: `/opt/filo/venv/`
- **Python Packages**: Installed only in the virtual environment
- **No System Pollution**: Doesn't modify system Python or pip

### How It Works

The `/usr/local/bin/filo` wrapper script:
1. Checks if Filo is properly installed
2. Activates the virtual environment at `/opt/filo/venv/`
3. Executes the real `filo` command with all your arguments
4. Returns the output to you

This means:
- ✅ No need to manually activate virtual environments
- ✅ Works from any directory
- ✅ Isolated from system Python
- ✅ No conflicts with other Python packages

## Updating

### Update to New Version

```bash
# Download new .deb package
wget https://github.com/supunhg/Filo/releases/download/v0.3.0/filo-forensics_0.3.0_all.deb

# Install (will upgrade existing installation)
sudo dpkg -i filo-forensics_0.3.0_all.deb
```

### Manual Update from Source

```bash
cd /opt/filo
sudo -H /opt/filo/venv/bin/pip install --upgrade -e .
```

## Removal

### Remove Package (Keep Configuration)

```bash
sudo dpkg -r filo-forensics
```

This removes:
- `/usr/local/bin/filo` wrapper
- The package from dpkg database

This keeps:
- `/opt/filo/` directory
- All data and models

### Complete Removal (Purge)

```bash
sudo dpkg --purge filo-forensics
```

This removes **everything**:
- `/usr/local/bin/filo` wrapper
- `/opt/filo/` directory
- All configuration and data

## Troubleshooting

### Command Not Found

```bash
# Check if package is installed
dpkg -l | grep filo-forensics

# Check if wrapper exists
ls -l /usr/local/bin/filo

# Reinstall if necessary
sudo dpkg -i filo-forensics_*.deb
```

### Permission Errors

```bash
# Fix permissions
sudo chmod -R 755 /opt/filo
sudo chmod +x /usr/local/bin/filo
```

### Virtual Environment Issues

```bash
# Recreate virtual environment
sudo rm -rf /opt/filo/venv
sudo python3 -m venv /opt/filo/venv
sudo /opt/filo/venv/bin/pip install -e /opt/filo
```

### Dependency Issues

```bash
# Fix broken dependencies
sudo apt-get install -f

# Ensure Python 3.10+ is installed
python3 --version

# Install required system packages
sudo apt-get install python3 python3-pip python3-venv
```

### ImportError or Module Not Found

```bash
# Reinstall dependencies
sudo /opt/filo/venv/bin/pip install --force-reinstall -e /opt/filo
```

## Advanced Usage

### Access Python API Directly

```bash
# Activate the environment
source /opt/filo/venv/bin/activate

# Use Python API
python3 << EOF
from filo import Analyzer
analyzer = Analyzer()
result = analyzer.analyze_file("test.bin")
print(f"Format: {result.primary_format}")
EOF

# Deactivate when done
deactivate
```

### Run Tests

```bash
# Activate environment
source /opt/filo/venv/bin/activate

# Run tests
cd /opt/filo
pytest tests/

# Deactivate
deactivate
```

### Run Examples

```bash
# Activate environment
source /opt/filo/venv/bin/activate

# Run examples
cd /opt/filo
python examples/features_demo.py

# Deactivate
deactivate
```

## System Requirements

### Minimum Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, or compatible Linux distribution
- **Python**: 3.10 or higher
- **RAM**: 512 MB minimum, 1 GB recommended
- **Disk**: 200 MB for installation + space for analysis data
- **Architecture**: amd64 (x86_64)

### Recommended Requirements

- **OS**: Ubuntu 22.04+ or Debian 12+
- **Python**: 3.11 or 3.12
- **RAM**: 2 GB or more
- **Disk**: 1 GB or more
- **CPU**: Multi-core for batch processing

## Package Information

### Dependencies

The package automatically installs:
- `pyyaml>=6.0` - YAML parsing
- `click>=8.1.0` - CLI framework
- `rich>=13.0.0` - Terminal output
- `pydantic>=2.0.0` - Data validation

### Package Details

```bash
# Show package information
dpkg -s filo-forensics

# List installed files
dpkg -L filo-forensics

# Check package status
dpkg --status filo-forensics
```

## Support

- **Documentation**: https://github.com/supunhg/Filo
- **Issues**: https://github.com/supunhg/Filo/issues
- **Quick Start**: `/opt/filo/QUICKSTART.md`
- **Examples**: `/opt/filo/examples/`

## License

Apache License 2.0 - See `/opt/filo/LICENSE` for details.
