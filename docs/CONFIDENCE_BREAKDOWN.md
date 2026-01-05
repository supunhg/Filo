# Confidence Decomposition & Explanation

## Overview

Filo now provides detailed confidence breakdown to make detection decisions auditable and transparent. This feature shows exactly how each analyzer contributes to the final confidence score, making it suitable for forensic analysis where courts and analysts require explainable results.

## Usage

Use the `--explain` flag with the `analyze` command:

```bash
filo analyze file.docx --explain
```

## Output Format

The confidence breakdown shows:

1. **Primary format** with total confidence percentage
2. **Individual contributions** from each detection module:
   - Signature matching
   - Structural analysis
   - Container analysis (for ZIP-based formats)
   - ML similarity
3. **Positive contributions** (+X%) showing evidence that supports the format
4. **Negative contributions** (-X%) showing penalties for missing/conflicting traits

### Example: DOCX Detection

```
Primary: DOCX (100.0%)
  +28.5%  ZIP header (DOCX is ZIP-based) at offset 0
  +80.0%  Contains word/document.xml
  +72.0%  Contains [Content_Types].xml
```

This shows:
- 28.5% confidence from ZIP signature match
- 80.0% from finding the DOCX-specific document.xml file
- 72.0% from finding the mandatory Content_Types.xml file

### Example: With Penalties

```
Primary: PNG (75.0%)
  +47.5%  PNG signature at offset 0
  +47.5%  IHDR chunk at offset 8
  +32.0%  Valid header size (8 bytes)
  -12.0%  Missing IEND footer chunk
```

This shows:
- Strong signature matches (+47.5% each)
- Valid header structure (+32.0%)
- Penalty for missing expected footer (-12.0%)

## Confidence Sources

### Signature Matching
- **Weight**: 0.6 (60% of signature confidence)
- **Description**: Byte pattern matches at specific offsets
- **Example**: "PNG signature at offset 0"

### Structural Analysis
- **Weight**: 0.4 (40% of structure confidence)
- **Description**: Format-specific structure validation
- **Example**: "Valid header size (8 bytes)"

### Container Analysis
- **Weight**: 0.8 (80% of container confidence)
- **Description**: ZIP-based format detection (DOCX, XLSX, PPTX, JAR, APK)
- **Example**: "Contains word/document.xml"

### ML Similarity
- **Weight**: 0.2 (20% of ML confidence)
- **Description**: Machine learning pattern matching
- **Example**: "Learned pattern match"

## Penalties

Penalties are shown with negative values and occur when:

1. **Missing mandatory fields**
   - Expected chunks/structures not found
   - Example: "-9% Missing core properties"

2. **Conflicting format traits**
   - File too small for expected header
   - Example: "-40% File too small for expected header"

3. **Structure violations**
   - Invalid chunk sequences
   - Corrupted markers

## Technical Details

### Contribution Calculation

Each analyzer returns individual `ConfidenceContribution` objects:

```python
ConfidenceContribution(
    source="container",           # Type of evidence
    value=0.50,                   # Raw contribution value
    description="Contains word/document.xml",  # Human-readable
    is_penalty=False              # True for negative contributions
)
```

The final confidence is calculated by:

1. Collecting all contributions for each format
2. Applying module weights (signature: 0.6, structure: 0.4, container: 0.8, ml: 0.2)
3. Summing weighted contributions
4. Clamping to [0.0, 1.0] range

### JSON Output

Use `--json` flag to get machine-readable breakdown:

```bash
filo analyze file.docx --json
```

The `evidence_chain` includes `contributions` arrays:

```json
{
  "module": "zip_container_analysis",
  "format": "docx",
  "confidence": 0.95,
  "contributions": [
    {
      "source": "container",
      "value": 0.50,
      "description": "Contains word/document.xml",
      "is_penalty": false
    },
    {
      "source": "container",
      "value": 0.45,
      "description": "Contains [Content_Types].xml",
      "is_penalty": false
    }
  ]
}
```

## Use Cases

### Forensic Analysis
```bash
# Analyze recovered file with full explanation
filo analyze recovered_doc.dat --explain

# Review each evidence item to determine authenticity
# Court-admissible transparency
```

### Debugging Detection
```bash
# Understand why detection failed/succeeded
filo analyze mystery_file.bin --explain --all-evidence

# See which signatures matched and which didn't
```

### Confidence Tuning
```bash
# Compare contributions across similar files
filo batch samples/ --explain > results.txt

# Identify which patterns need adjustment
```

### Teaching Mode
```bash
# See what patterns the ML detector learned
filo teach sample.xyz --format custom
filo analyze sample.xyz --explain

# Verify ML contributions
```

## Command Options

| Flag | Description |
|------|-------------|
| `--explain` | Show detailed confidence breakdown |
| `--all-evidence` | Show all detection evidence (not just top 3) |
| `--json` | Output as JSON with contributions |
| `--no-ml` | Disable ML to see only signature/structure contributions |

## Combining Flags

```bash
# Full transparency: all evidence with explanations
filo analyze file.bin --explain --all-evidence

# JSON with breakdown for automation
filo analyze file.bin --json --explain

# Pure signature/structure analysis
filo analyze file.bin --explain --no-ml
```

## Interpretation Guide

### High Confidence (>80%)
- Multiple strong contributions from different sources
- Container analysis confirms format (for ZIP-based)
- Example: DOCX with proper structure

### Medium Confidence (50-80%)
- Partial signature matches
- Some structure validation
- May have minor penalties
- Example: Corrupted file with valid header

### Low Confidence (25-50%)
- Weak signature matches or fallback patterns
- ML-based detection only
- Significant penalties
- Example: Highly corrupted or fragment

### Very Low (<25%)
- No signatures matched
- ML hints only
- Format unknown or severely damaged

## Best Practices

1. **Always use `--explain` for forensic work** - Courts require transparency
2. **Combine with `--all-evidence`** - See full detection chain
3. **Use `--no-ml` for reproducibility** - ML can vary between systems
4. **Export to JSON** - Archive complete analysis results
5. **Review penalties carefully** - They indicate potential corruption

## FAQ

**Q: Why do contributions sum to more than 100%?**  
A: Each module contributes independently. The final confidence is clamped to 100%. Seeing >100% total means very strong detection from multiple sources.

**Q: Can I trust low-confidence detections?**  
A: Depends on context. 25-50% often means file fragment or heavy corruption. Use `--explain` to see if the evidence makes sense.

**Q: Why are there no penalties shown?**  
A: Penalties only appear when we detect format-specific issues (missing chunks, invalid structure). Clean files have only positive contributions.

**Q: What's the difference between signature and container?**  
A: Signatures are byte patterns at fixed offsets. Container analysis opens ZIP files and checks internal structure. Container is much more reliable for DOCX/XLSX/etc.

## Examples

### Standard Detection
```bash
$ filo analyze document.docx --explain

Primary: DOCX (95.0%)
  +28.5%  ZIP header (DOCX is ZIP-based) at offset 0
  +76.0%  Contains word/document.xml
  +68.4%  Contains [Content_Types].xml
```

### Corrupted File
```bash
$ filo analyze broken.pdf --explain

Primary: PDF (62.0%)
  +47.5%  PDF signature at offset 0
  +25.6%  Valid header size
  -11.1%  Missing EOF marker
```

### Fragment
```bash
$ filo analyze fragment.bin --explain

Primary: JPEG (28.0%)
  +19.0%  JFIF marker (fallback) at offset 12
  + 9.0%  ML Similarity match
```

## See Also

- [QUICKSTART.md](../QUICKSTART.md) - Basic usage
- [README.md](../README.md) - Feature overview
- [examples/features_demo.py](../examples/features_demo.py) - Python API examples
