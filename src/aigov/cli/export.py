from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from aigov.core.exporter import records_from_scan_json, to_csv, to_flat_json
from aigov.core.reporter import write_output

app = typer.Typer(help="Export scan results for GRC platform integration.")
console = Console()

_VALID_FORMATS = {"csv", "json", "sarif"}


def export_command(
    input_file: str = typer.Argument(
        ...,
        help="Scan results JSON file (produced by: aigov scan --output json --out-file results.json).",
    ),
    fmt: str = typer.Option(
        "csv",
        "--format",
        "-f",
        help="Export format: csv (default), json, or sarif.",
    ),
    out_file: Optional[str] = typer.Option(
        None,
        "--out-file",
        "-o",
        help="Write output to this file instead of stdout.",
    ),
) -> None:
    """Export scan results to CSV or flat JSON for GRC platform import.

    \b
    Supported targets:
      Excel, CISO Assistant, ServiceNow, or any GRC tool that accepts CSV.

    \b
    Typical workflow:
      aigov scan . --classify --output json --out-file results.json
      aigov export results.json --format csv --out-file inventory.csv
    """
    if fmt not in _VALID_FORMATS:
        console.print(
            f"[red]Error:[/red] unknown format '{fmt}'. "
            f"Choose from: {', '.join(sorted(_VALID_FORMATS))}."
        )
        raise typer.Exit(code=1)

    file_path = Path(input_file)
    if not file_path.exists():
        console.print(f"[red]Error:[/red] file not found: {input_file}")
        raise typer.Exit(code=1)

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Error reading {input_file}:[/red] {exc}")
        raise typer.Exit(code=1)

    records = records_from_scan_json(data)

    if not records:
        console.print("[yellow]No records found in the input file.[/yellow]")
        raise typer.Exit(code=0)

    if fmt == "csv":
        content = to_csv(records)
    elif fmt == "sarif":
        from aigov.core.sarif import records_to_sarif
        content = records_to_sarif(records)
    else:
        content = to_flat_json(records)

    if out_file:
        write_output(content, out_file)
        console.print(f"[green]Exported {len(records)} record(s) to {out_file}[/green]")
    else:
        write_output(content, None)


app.command("export")(export_command)
