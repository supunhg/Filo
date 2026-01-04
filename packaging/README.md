# Filo .deb Packaging

This directory contains files for building the Filo .deb package.

## Build Package

From the repository root:

```bash
./build-deb.sh
```

This creates `filo-forensics_0.2.0_all.deb` in the root directory.

## Install

```bash
sudo dpkg -i filo-forensics_0.2.0_all.deb
```

The package installs to `/opt/filo/` with a global `filo` command at `/usr/local/bin/filo`.

## Uninstall

```bash
sudo dpkg -r filo-forensics
```

## Package Structure

- `DEBIAN/control` - Package metadata and dependencies
- `DEBIAN/postinst` - Post-installation script (creates venv, installs filo)
- `DEBIAN/prerm` - Pre-removal script (removes executable wrapper)
- `DEBIAN/postrm` - Post-removal script (cleanup on purge)
