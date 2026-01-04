import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import print as rprint

from filo import __version__
from filo.analyzer import Analyzer
from filo.formats import FormatDatabase
from filo.repair import RepairEngine
from filo.carver import CarverEngine
from filo.batch import BatchProcessor, BatchConfig
from filo.export import JSONExporter, SARIFExporter, export_to_file
from filo.container import ContainerDetector
from filo.profiler import Profiler

console = Console()


def _print_hex_dump(data: bytes, width: int = 16) -> None:
    """Print hex dump of binary data."""
    for i in range(0, min(len(data), 256), width):
        # Offset
        offset = f"{i:08x}"
        
        # Hex bytes
        hex_part = " ".join(f"{b:02x}" for b in data[i:i+width])
        hex_part = hex_part.ljust(width * 3)
        
        # ASCII representation
        ascii_part = "".join(
            chr(b) if 32 <= b < 127 else "."
            for b in data[i:i+width]
        )
        
        console.print(f"  {offset}  {hex_part}  {ascii_part}")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@click.group()
@click.version_option(version=__version__, prog_name="filo")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def main(verbose: bool) -> None:
    """
    Filo - Forensic Intelligence & Ligation Orchestrator
    
    Battle-tested file forensics platform for security professionals.
    """
    setup_logging(verbose)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
@click.option("--deep", is_flag=True, help="Deep analysis (slower, more thorough)")
@click.option("--no-ml", is_flag=True, help="Disable ML-based detection")
def analyze(file_path: str, output_json: bool, deep: bool, no_ml: bool) -> None:
    """
    Analyze a file to detect its format.
    
    FILE_PATH: Path to file to analyze
    """
    try:
        analyzer = Analyzer(use_ml=not no_ml)
        result = analyzer.analyze_file(file_path)
        
        if output_json:
            # JSON output
            output = {
                "file": str(file_path),
                "format": result.primary_format,
                "confidence": result.confidence,
                "alternatives": [
                    {"format": fmt, "confidence": conf}
                    for fmt, conf in result.alternative_formats
                ],
                "file_size": result.file_size,
                "entropy": result.entropy,
                "checksum": result.checksum_sha256,
                "evidence": result.evidence_chain,
            }
            console.print_json(json.dumps(output, indent=2))
        else:
            # Rich formatted output
            console.print(Panel.fit(
                f"[bold cyan]File Analysis:[/bold cyan] {file_path}",
                border_style="cyan"
            ))
            
            # Main result
            confidence_color = "green" if result.confidence > 0.8 else "yellow" if result.confidence > 0.5 else "red"
            console.print(f"\n[bold]Detected Format:[/bold] [{confidence_color}]{result.primary_format}[/{confidence_color}]")
            console.print(f"[bold]Confidence:[/bold] [{confidence_color}]{result.confidence:.1%}[/{confidence_color}]")
            
            # Alternatives
            if result.alternative_formats:
                console.print("\n[bold]Alternative Possibilities:[/bold]")
                for fmt, conf in result.alternative_formats[:3]:
                    console.print(f"  • {fmt}: {conf:.1%}")
            
            # File info
            console.print(f"\n[bold]File Size:[/bold] {result.file_size:,} bytes")
            if result.entropy is not None:
                console.print(f"[bold]Entropy:[/bold] {result.entropy:.2f} bits/byte")
            console.print(f"[bold]SHA256:[/bold] {result.checksum_sha256}")
            
            # Evidence
            if result.evidence_chain:
                console.print("\n[bold]Detection Evidence:[/bold]")
                for evidence in result.evidence_chain:
                    module = evidence.get("module", "unknown")
                    conf = evidence.get("confidence", 0)
                    evid_list = evidence.get("evidence", [])
                    
                    console.print(f"\n  [cyan]{module}[/cyan] (confidence: {conf:.1%})")
                    for e in evid_list:
                        console.print(f"    • {e}")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--format", "format_name", required=True, help="Correct format")
def teach(file_path: str, format_name: str) -> None:
    """
    Teach Filo the correct format for a file (ML learning).
    
    FILE_PATH: Path to file to learn from
    """
    try:
        analyzer = Analyzer(use_ml=True)
        
        with open(file_path, "rb") as f:
            data = f.read()
        
        analyzer.teach(data, format_name)
        
        console.print(f"[green]✓ Learned from {file_path} as {format_name}[/green]")
        from pathlib import Path
        model_path = Path(__file__).parent.parent / "models" / "learned_patterns.pkl"
        console.print(f"[dim]Model saved to {model_path}[/dim]")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--format", "format_name", required=True, help="Target format")
@click.option("-o", "--output", "output_path", type=click.Path(), help="Output file path")
@click.option("-s", "--strategy", default="auto", help="Repair strategy (auto, or specific)")
@click.option("--no-backup", is_flag=True, help="Don't create backup file")
@click.option("--dry-run", is_flag=True, help="Simulate repair without writing")
def repair(
    file_path: str,
    format_name: str,
    output_path: Optional[str],
    strategy: str,
    no_backup: bool,
    dry_run: bool,
) -> None:
    """
    Repair a corrupted file.
    
    FILE_PATH: Path to corrupted file
    """
    try:
        engine = RepairEngine()
        
        # Read file
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Repair
        repaired_data, report = engine.repair(data, format_name, strategy)
        
        # Display results
        console.print(Panel.fit(
            f"[bold cyan]File Repair:[/bold cyan] {file_path}",
            border_style="cyan"
        ))
        
        status_color = "green" if report.success else "red"
        status_text = "SUCCESS" if report.success else "FAILED"
        console.print(f"\n[{status_color}][bold]Status:[/bold] {status_text}[/{status_color}]")
        console.print(f"[bold]Strategy Used:[/bold] {report.strategy_used}")
        console.print(f"[bold]Original Size:[/bold] {report.original_size:,} bytes")
        console.print(f"[bold]Repaired Size:[/bold] {report.repaired_size:,} bytes")
        
        if report.changes_made:
            console.print("\n[bold]Changes Made:[/bold]")
            for change in report.changes_made:
                console.print(f"  • {change}")
        
        if report.warnings:
            console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in report.warnings:
                console.print(f"  ⚠ {warning}")
        
        # Write output
        if report.success and not dry_run:
            if output_path is None:
                output_path = file_path
            
            out_path = Path(output_path)
            
            # Backup
            if not no_backup and out_path == Path(file_path):
                backup_path = out_path.with_suffix(out_path.suffix + ".bak")
                backup_path.write_bytes(data)
                console.print(f"\n[dim]Backup created: {backup_path}[/dim]")
            
            # Write repaired file
            out_path.write_bytes(repaired_data)
            console.print(f"[green]✓ Repaired file written to: {out_path}[/green]")
        elif dry_run:
            console.print("\n[dim]Dry run - no files written[/dim]")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)


@main.group()
def formats() -> None:
    """Manage format database."""
    pass


@formats.command("list")
@click.option("-c", "--category", help="Filter by category")
def formats_list(category: Optional[str]) -> None:
    """List all available formats."""
    db = FormatDatabase()
    
    if category:
        specs = db.get_formats_by_category(category)
    else:
        specs = [db.get_format(name) for name in db.list_formats()]
    
    if not specs:
        console.print("[yellow]No formats found[/yellow]")
        return
    
    # Create table
    table = Table(title="Available Formats")
    table.add_column("Format", style="cyan", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Extensions", style="green")
    table.add_column("Signatures", justify="right", style="blue")
    
    for spec in specs:
        if spec:
            table.add_row(
                spec.format,
                spec.category,
                ", ".join(spec.extensions[:3]),
                str(len(spec.signatures)),
            )
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(specs)} formats[/dim]")


@formats.command("show")
@click.argument("format_name")
def formats_show(format_name: str) -> None:
    """Show detailed information about a format."""
    db = FormatDatabase()
    spec = db.get_format(format_name)
    
    if not spec:
        console.print(f"[red]Format not found:[/red] {format_name}")
        sys.exit(1)
    
    console.print(Panel.fit(
        f"[bold cyan]Format Specification:[/bold cyan] {spec.format}",
        border_style="cyan"
    ))
    
    console.print(f"\n[bold]Version:[/bold] {spec.version}")
    console.print(f"[bold]Category:[/bold] {spec.category}")
    console.print(f"[bold]MIME Types:[/bold] {', '.join(spec.mime)}")
    console.print(f"[bold]Extensions:[/bold] {', '.join(spec.extensions)}")
    
    if spec.description:
        console.print(f"\n[bold]Description:[/bold]\n{spec.description}")
    
    # Signatures
    console.print(f"\n[bold]Signatures ({len(spec.signatures)}):[/bold]")
    for sig in spec.signatures:
        console.print(f"  • Offset {sig.offset}: {sig.hex} - {sig.description}")
    
    # Footers
    if spec.footers:
        console.print(f"\n[bold]Footers ({len(spec.footers)}):[/bold]")
        for footer in spec.footers:
            console.print(f"  • {footer.hex} - {footer.description}")
    
    # Templates
    if spec.templates:
        console.print(f"\n[bold]Templates ({len(spec.templates)}):[/bold]")
        for name in spec.templates:
            console.print(f"  • {name}")
    
    # Repair strategies
    if spec.repair_strategies:
        console.print(f"\n[bold]Repair Strategies ({len(spec.repair_strategies)}):[/bold]")
        for strategy in sorted(spec.repair_strategies, key=lambda s: s.priority):
            console.print(f"  {strategy.priority}. {strategy.name}")


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("-f", "--formats", help="Comma-separated list of formats to carve")
@click.option("-o", "--output-dir", default="carved", help="Output directory")
@click.option("--min-size", type=int, default=512, help="Minimum file size in bytes")
@click.option("--max-size", type=int, help="Maximum file size in bytes")
def carve(file_path: str, formats: Optional[str], output_dir: str, min_size: int, max_size: Optional[int]) -> None:
    """
    Carve embedded files from disk images or binary blobs.
    
    FILE_PATH: Path to disk image or binary file to carve from
    """
    from pathlib import Path
    
    source_path = Path(file_path)
    output_path = Path(output_dir)
    
    console.print(f"[cyan]Carving files from:[/cyan] {source_path}")
    console.print(f"[dim]Output directory: {output_path}[/dim]")
    console.print(f"[dim]Min size: {min_size} bytes, Max size: {max_size or 'unlimited'}[/dim]\n")
    
    try:
        carver = CarverEngine()
        carved_files = carver.carve_file(source_path, min_size=min_size, max_size=max_size)
        
        if not carved_files:
            console.print("[yellow]No files carved[/yellow]")
            return
        
        output_path.mkdir(parents=True, exist_ok=True)
        
        table = Table(title=f"Carved {len(carved_files)} Files")
        table.add_column("Offset", style="cyan")
        table.add_column("Size", style="green")
        table.add_column("Format", style="yellow")
        table.add_column("Confidence", style="magenta")
        table.add_column("Output File", style="blue")
        
        for i, carved in enumerate(carved_files):
            out_name = f"{source_path.stem}_carved_{i:04d}_{carved.format}.bin"
            out_file = output_path / out_name
            
            carved.save(out_file)
            
            table.add_row(
                f"0x{carved.offset:08x}",
                f"{carved.size:,} bytes",
                carved.format.upper(),
                f"{carved.confidence:.1%}",
                out_name
            )
        
        console.print(table)
        console.print(f"\n[green]✓[/green] Saved {len(carved_files)} files to {output_path}")
        
    except Exception as e:
        console.print(f"[red]Error during carving: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--recursive/--no-recursive", default=True, help="Recursively process subdirectories")
@click.option("--workers", "-w", default=4, type=int, help="Number of parallel workers")
@click.option("--max-size", default=100, type=int, help="Max file size in MB")
@click.option("--export", type=click.Choice(["json", "sarif"]), help="Export results")
@click.option("--output", "-o", type=click.Path(), help="Output file for export")
def batch(directory: str, recursive: bool, workers: int, max_size: int, export: Optional[str], output: Optional[str]) -> None:
    """
    Batch analyze all files in a directory.
    
    Examples:
        filo batch ./samples
        filo batch --workers=8 --export=json --output=results.json ./data
    """
    try:
        from pathlib import Path
        
        config = BatchConfig(
            max_workers=workers,
            max_file_size=max_size * 1024 * 1024,
            recursive=recursive,
            progress_callback=None
        )
        
        processor = BatchProcessor(config)
        
        console.print(f"[bold]Batch Processing:[/bold] {directory}\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing files...", total=None)
            
            result = processor.process_directory(Path(directory))
            progress.update(task, completed=result.total_files, total=result.total_files)
        
        # Show summary
        console.print(f"\n[bold]Results Summary:[/bold]")
        console.print(f"Total files: {result.total_files}")
        console.print(f"[green]Analyzed: {result.analyzed_files}[/green]")
        console.print(f"[red]Failed: {result.failed_files}[/red]")
        console.print(f"[yellow]Skipped: {result.skipped_files}[/yellow]")
        console.print(f"Duration: {result.duration:.2f}s ({result.files_per_second:.1f} files/sec)")
        
        # Show format breakdown
        if result.results:
            format_counts = {}
            for path, res in result.results:
                fmt = res.format_name
                format_counts[fmt] = format_counts.get(fmt, 0) + 1
            
            table = Table(title="Format Distribution", show_header=True)
            table.add_column("Format", style="cyan")
            table.add_column("Count", justify="right", style="green")
            table.add_column("Percentage", justify="right")
            
            for fmt, count in sorted(format_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                pct = count / result.analyzed_files * 100
                table.add_row(fmt, str(count), f"{pct:.1f}%")
            
            console.print(table)
        
        # Export if requested
        if export and result.results:
            if export == "json":
                exported = JSONExporter.export_batch(result.results, pretty=True)
            elif export == "sarif":
                exported = SARIFExporter.export_batch(result.results, pretty=True)
            
            if output:
                export_to_file(exported, Path(output), overwrite=True)
                console.print(f"\n[green]✓[/green] Exported to {output}")
            else:
                console.print("\n" + exported)
        
    except Exception as e:
        console.print(f"[red]Error during batch processing: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--profile/--no-profile", default=False, help="Enable performance profiling")
@click.option("--show-stats", is_flag=True, help="Show detailed profiling statistics")
def profile(file_path: str, profile: bool, show_stats: bool) -> None:
    """
    Profile performance of file analysis.
    
    Examples:
        filo profile large_file.bin
        filo profile --show-stats suspicious.dat
    """
    try:
        profiler = Profiler(enabled=True)
        profiler.start()
        
        # Run analysis
        analyzer = Analyzer(use_ml=False)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        with profiler.time_operation("analyze"):
            result = analyzer.analyze(data)
        
        report = profiler.stop()
        
        # Show results
        console.print(f"\n[bold]Performance Profile:[/bold] {file_path}\n")
        console.print(f"Total Duration: [cyan]{report.total_duration:.4f}s[/cyan]")
        
        if report.timings:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Operation")
            table.add_column("Time (s)", justify="right")
            table.add_column("Calls", justify="right")
            table.add_column("Avg (s)", justify="right")
            
            for timing in report.get_sorted_timings()[:10]:
                table.add_row(
                    timing.name,
                    f"{timing.duration:.4f}",
                    str(timing.calls),
                    f"{timing.avg_duration:.6f}"
                )
            
            console.print(table)
        
        if show_stats and report.profile_data:
            console.print("\n[bold]Detailed Statistics:[/bold]")
            console.print(report.profile_data)
        
    except Exception as e:
        console.print(f"[red]Error during profiling: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
