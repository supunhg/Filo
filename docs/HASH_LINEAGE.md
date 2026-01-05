# Hash Lineage Tracking - Chain-of-Custody

## Overview

Hash Lineage Tracking maintains **cryptographic chain-of-custody** for all file transformations performed by Filo. This is **non-negotiable** in real forensic investigations and court proceedings, where you must prove exactly what happened to evidence files.

### Why It Matters

**Legal Requirements:**
- Court evidence requires **documented chain-of-custody**
- Every transformation must be traceable with cryptographic proof
- Expert witnesses must explain **exactly** how files were processed

**Forensic Integrity:**
- Prove files weren't tampered with during analysis  
- Track multi-step processing (repair → carve → analyze)
- Demonstrate reproducible methodology for peer review

**Incident Response:**
- Reconstruct investigation timeline from hash records
- Verify which files came from which sources
- Audit all transformations for compliance

## What Gets Tracked

### Tracked Operations

1. **Repair (`filo repair`)** - Original → Repaired
2. **Carve (`filo carve`)** - Container → Extracted Files
3. **Extract** - Archive → Member Files
4. **Export** - Source → Export Format (JSON/SARIF)
5. **Teach** - Sample → ML Model Update
6. **Analyze** - File → Analysis Report

### Recorded Information

For each transformation, Filo records:
- **Original SHA-256 hash** - Source file cryptographic identifier
- **Result SHA-256 hash** - Transformed file cryptographic identifier  
- **Operation type** - What was done (repair, carve, etc.)
- **Timestamp** - ISO 8601 UTC timestamp of operation
- **File paths** - Original and result file locations (optional)
- **Metadata** - Operation-specific details:
  - Repair: format, strategy used, changes made
  - Carve: offset, size, detected format, confidence
  - Extract: archive path, member name
  - Export: export format, options

## Usage

### Basic Usage

Lineage tracking is **automatic** for supported operations. No configuration needed:

```bash
# Repair a file - lineage automatically tracked
filo repair broken.png --format png --output fixed.png

# Carve files - tracks container → extracted lineage  
filo carve disk.img --output carved_files/

# Query lineage for a file
filo lineage $(sha256sum fixed.png | cut -d' ' -f1)
```

### Query Lineage Chain

```bash
# Get SHA-256 hash of file
FILE_HASH=$(sha256sum fixed.png | cut -d' ' -f1)

# Show chain-of-custody report (text format)
filo lineage $FILE_HASH

# Export as JSON for programmatic use
filo lineage $FILE_HASH --format json

# Save report to file
filo lineage $FILE_HASH --output chain-of-custody.txt
```

### View Lineage History

```bash
# Show recent operations (all types)
filo lineage-history

# Filter by operation type
filo lineage-history --operation repair
filo lineage-history --operation carve

# Show more records
filo lineage-history --limit 50
```

### Lineage Statistics

```bash
# View database statistics
filo lineage-stats
```

## Chain-of-Custody Reports

### Text Report Format

```
======================================================================
FORENSIC CHAIN-OF-CUSTODY REPORT
======================================================================

Generated: 2026-01-05 02:15:30 UTC
Query Hash: 1c40568e6f44aab70d9d9849b2464231e0de366539cdd225901d4d34e8f90374
Root Hash:  97c83e799e16441806414a9ca5ae465fc6ebea4b81237171d7c8e8409bea8271
Chain Length: 3 transformations

======================================================================
LINEAGE CHAIN
======================================================================

BACKWARD CHAIN (Origins):
----------------------------------------------------------------------

1. REPAIR
   Timestamp:     2026-01-05T02:07:40.051481Z
   Original Hash: 97c83e799e16441806414a9ca5ae465fc6ebea4b81237171d7c8e8409bea8271
   Result Hash:   4fac499216e2bd1dd811e335b6aebd060d477fdd4a512270741385e72cd6d246
   Original Path: /evidence/corrupt_image.png
   Result Path:   /evidence/repaired_image.png
   Metadata:      {"format": "png", "strategy": "add_header"}

======================================================================
CURRENT FILE: 1c40568e6f44aab70d9d9849b2464231e0de366539cdd225901d4d34e8f90374
======================================================================

FORWARD CHAIN (Derived Files):
----------------------------------------------------------------------

1. EXPORT
   Timestamp:     2026-01-05T02:07:40.053201Z
   Original Hash: 1c40568e6f44aab70d9d9849b2464231e0de366539cdd225901d4d34e8f90374  
   Result Hash:   a7f3c4d8e9b2f1a6c5d8e7b4a3f2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4
   Metadata:      {"format": "json"}

======================================================================
END OF CHAIN-OF-CUSTODY REPORT
======================================================================
```

### JSON Export Format

```json
{
  "lineage_export": {
    "version": "1.0",
    "export_timestamp": "2026-01-05T02:15:30.123456Z",
    "query_hash": "1c40568e...",
    "chain": {
      "root_hash": "97c83e7...",
      "query_hash": "1c40568e...",
      "ancestors": [
        {
          "original_hash": "97c83e7...",
          "result_hash": "4fac4992...",
          "operation": "repair",
          "timestamp": "2026-01-05T02:07:40.051481Z",
          "original_path": "/evidence/corrupt_image.png",
          "result_path": "/evidence/repaired_image.png",
          "metadata": {
            "format": "png",
            "strategy": "add_header",
            "changes": ["Added PNG signature", "Reconstructed IHDR"]
          }
        }
      ],
      "descendants": [
        {
          "original_hash": "1c40568e...",
          "result_hash": "a7f3c4d8...",
          "operation": "export",
          "timestamp": "2026-01-05T02:07:40.053201Z",
          "metadata": {
            "format": "json"
          }
        }
      ],
      "chain_length": 3
    }
  }
}
```

## Integration Examples

### Court Evidence Documentation

```bash
#!/bin/bash
# Generate chain-of-custody for court submission

EVIDENCE_FILE="seized_harddrive.img"
HASH=$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)

# Create comprehensive report
filo lineage $HASH --output "Evidence_${HASH:0:8}_Chain_of_Custody.txt"

# Also create JSON for technical review
filo lineage $HASH --format json --output "Evidence_${HASH:0:8}_Lineage.json"

echo "Chain-of-custody documentation generated:"
echo "  - Text report for court submission"
echo "  - JSON export for technical verification"
```

### Automated Processing with Lineage

```python
from filo.lineage import LineageTracker, OperationType
from filo.repair import RepairEngine
from pathlib import Path

# Initialize with lineage tracking
tracker = LineageTracker()
repair_engine = RepairEngine(lineage_tracker=tracker)

# Process evidence file
original_file = Path("evidence/corrupt_document.pdf")
original_data = original_file.read_bytes()

# Repair with automatic lineage recording
repaired_data, report = repair_engine.repair(
    data=original_data,
    format_name="pdf",
    strategy="auto",
    original_path=str(original_file)
)

# Save repaired file
repaired_file = Path("evidence/repaired_document.pdf")
repaired_file.write_bytes(repaired_data)

# Query lineage
import hashlib
original_hash = hashlib.sha256(original_data).hexdigest()
chain = tracker.get_full_chain(original_hash)

print(f"Transformation recorded:")
print(f"  Root: {chain['root_hash']}")
print(f"  Descendants: {len(chain['descendants'])}")
```

### Batch Processing with Lineage

```python
from filo.carver import CarverEngine  
from filo.lineage import LineageTracker

tracker = LineageTracker()
carver = CarverEngine(lineage_tracker=tracker)

# Carve all files from disk image
disk_image = Path("disk.img").read_bytes()
carved_files = carver.carve(disk_image)

# Each carved file automatically has lineage recorded
for carved in carved_files:
    print(f"Carved: {carved.format} at offset {carved.offset}")
    
# Query lineage for any carved file
import hashlib
carved_hash = hashlib.sha256(carved_files[0].data).hexdigest()
lineage = tracker.get_ancestors(carved_hash)

print(f"This file was carved from:")
for record in lineage:
    print(f"  {record.operation}: {record.original_hash[:16]}...")
```

## API Reference

### LineageTracker Class

```python
from filo.lineage import LineageTracker, OperationType

# Initialize tracker
tracker = LineageTracker()  # Default: ~/.filo/lineage.db
tracker = LineageTracker(Path("/custom/path/lineage.db"))  # Custom location

# Record transformation
lineage = tracker.record(
    original_data=original_bytes,
    result_data=result_bytes,
    operation=OperationType.REPAIR,
    original_path="/path/to/original.png",  # Optional
    result_path="/path/to/repaired.png",    # Optional
    format="png",                            # Custom metadata
    strategy="add_header"                    # Custom metadata
)

# Record from files (convenience method)
lineage = tracker.record_from_files(
    original_path=Path("original.png"),
    result_path=Path("repaired.png"),
    operation=OperationType.REPAIR,
    format="png"
)

# Query forward lineage (descendants)
descendants = tracker.get_descendants(file_hash)

# Query backward lineage (ancestors)
ancestors = tracker.get_ancestors(file_hash)

# Get complete chain
chain = tracker.get_full_chain(file_hash)

# Filter by operation
repairs = tracker.get_by_operation(OperationType.REPAIR)
carves = tracker.get_by_operation(OperationType.CARVE)

# Export for court
json_export = tracker.export_chain_json(file_hash)
text_report = tracker.export_chain_report(file_hash)

# Statistics
stats = tracker.get_stats()
```

### FileLineage Class

```python
from filo.lineage import FileLineage, OperationType

# Create lineage record
lineage = FileLineage(
    original_hash="abc123...",
    result_hash="def456...",
    operation=OperationType.REPAIR,
    timestamp="2026-01-05T02:07:40.051481Z",
    original_path="/path/to/original",
    result_path="/path/to/result",
    metadata={"format": "png", "strategy": "add_header"}
)

# Convert to/from dict
data = lineage.to_dict()
reconstructed = FileLineage.from_dict(data)
```

## Best Practices

### 1. Always Enable Lineage Tracking

```python
# GOOD: Enable lineage tracking for investigations
tracker = LineageTracker()
repair_engine = RepairEngine(lineage_tracker=tracker)

# BAD: No lineage tracking - unusable in court
repair_engine = RepairEngine()
```

### 2. Store Lineage Database Securely

```bash
# Store lineage database with evidence
EVIDENCE_DIR="/secure/case_2026_001"
mkdir -p "$EVIDENCE_DIR"

# Use case-specific lineage database
export FILO_LINEAGE_DB="$EVIDENCE_DIR/lineage.db"

# Process evidence
filo repair evidence.bin --format png --output repaired.png

# Backup lineage database with evidence
cp "$EVIDENCE_DIR/lineage.db" "$EVIDENCE_DIR/lineage.db.backup"
```

### 3. Generate Reports Immediately

```bash
# Generate chain-of-custody BEFORE analysis
FILE_HASH=$(sha256sum evidence.bin | cut -d' ' -f1)
filo lineage $FILE_HASH --output "initial_state_${FILE_HASH:0:8}.txt"

# Process file
filo repair evidence.bin --format pdf --output repaired.pdf

# Generate final chain-of-custody
REPAIRED_HASH=$(sha256sum repaired.pdf | cut -d' ' -f1)
filo lineage $REPAIRED_HASH --output "final_state_${REPAIRED_HASH:0:8}.txt"
```

### 4. Document Complex Chains

```python
# For multi-step processing, document each step
tracker = LineageTracker()

# Step 1: Repair
repaired, _ = repair_engine.repair(data, "png", original_path="corrupt.png")
repaired_hash = hashlib.sha256(repaired).hexdigest()

# Document step 1
step1_report = tracker.export_chain_report(repaired_hash)
Path("step1_repair.txt").write_text(step1_report)

# Step 2: Carve
carved_files = carver.carve(repaired)

# Document step 2
for i, carved in enumerate(carved_files):
    carved_hash = hashlib.sha256(carved.data).hexdigest()
    step2_report = tracker.export_chain_report(carved_hash)
    Path(f"step2_carve_{i}.txt").write_text(step2_report)
```

### 5. Validate Lineage Integrity

```python
# Verify lineage chain integrity
def validate_chain(tracker, file_hash):
    """Validate that lineage chain is complete and consistent."""
    chain = tracker.get_full_chain(file_hash)
    
    # Check for broken chains
    if not chain['ancestors'] and not chain['descendants']:
        print(f"Warning: Isolated file with no lineage")
        return False
    
    # Verify hash consistency
    for ancestor in chain['ancestors']:
        # In a valid chain, one record's result_hash should match next's original_hash
        descendants = tracker.get_descendants(ancestor['result_hash'])
        if not descendants:
            print(f"Warning: Broken chain at {ancestor['result_hash'][:16]}...")
            return False
    
    return True
```

## Court Presentation

### Sample Court Testimony Script

**Q: How do you know this file is the repaired version of the original evidence?**

A: I can demonstrate through cryptographic chain-of-custody. The original file has SHA-256 hash `97c83e7...` as documented in the evidence log. After repair using Filo's PNG header reconstruction strategy, the result has hash `4fac499...`. This transformation is recorded in the lineage database with timestamp 2026-01-05 02:07:40 UTC, operation type "repair", and metadata showing the exact strategy used. I can provide the complete chain-of-custody report showing every transformation.

**Q: Could this file have been modified without detection?**

A: No. SHA-256 is a cryptographic hash function - even a single bit change produces a completely different hash. The lineage database records the hash before and after each operation. Any tampering would be immediately evident because the hashes wouldn't match the recorded values.

**Q: Can you prove what tools and versions were used?**

A: Yes. The lineage metadata includes the operation type (repair, carve, etc.) and operation-specific details like the repair strategy name. The database schema is versioned and the export format includes version numbers for reproducibility.

### Evidence Package Checklist

For court submission, provide:

- [ ] **Original Evidence Hash**: SHA-256 of original seized file
- [ ] **Chain-of-Custody Report**: Text format for judges/jury
- [ ] **Lineage JSON Export**: Technical verification for expert witnesses  
- [ ] **Tool Version**: `filo --version` output
- [ ] **Methodology Document**: Steps taken during analysis
- [ ] **Lineage Database**: Full SQLite database (optional, for verification)

## Limitations

### Not Tracked

- **In-place operations**: Some operations modify files without creating lineage
- **Manual modifications**: Edits outside Filo are not tracked
- **System crashes**: Incomplete operations may not have lineage records

### Storage Considerations

- Each lineage record: ~500 bytes
- 10,000 operations: ~5 MB database
- Database grows with number of transformations, not file size

### Performance

- Lineage recording adds <1ms per operation
- Hash computation is I/O bound (file read time)
- Database queries are indexed and fast (<10ms for most queries)

## Troubleshooting

### Database Location

```bash
# Default location
~/.filo/lineage.db

# Check where lineage is stored
filo lineage-stats

# Custom location via environment variable
export FILO_LINEAGE_DB="/path/to/custom.db"
```

### Missing Lineage Records

```bash
# If lineage commands show no records:

# 1. Verify database exists
ls -lh ~/.filo/lineage.db

# 2. Check statistics
filo lineage-stats

# 3. Ensure lineage tracking was enabled
# (Some older operations may not have tracking)

# 4. Verify hash is correct
sha256sum file.bin
```

### Export/Import Lineage Database

```bash
# Backup lineage database
cp ~/.filo/lineage.db /backup/lineage_$(date +%Y%m%d).db

# Import/merge lineage databases
sqlite3 ~/.filo/lineage.db ".dump" | sqlite3 /new/lineage.db
```

## See Also

- [Advanced Repair](ADVANCED_REPAIR.md) - Repair strategies that generate lineage
- [File Carving](../examples/carving_demo.py) - Carving with lineage tracking
- [Batch Processing](../examples/features_demo.py) - Batch operations with lineage
