"""`aigov classify` command — classify AI systems against governance frameworks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


def classify_command(
    paths: Optional[list[str]] = typer.Argument(
        default=None,
        help="Paths to scan and classify, or a single JSON file from a previous scan.",
    ),
    output: str = typer.Option(
        "table", "--output", "-f",
        help="Output format: table (default), json, markdown.",
    ),
    out_file: Optional[str] = typer.Option(
        None, "--out-file", "-o",
        help="Write output to this file instead of stdout.",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated framework names (default: eu_ai_act).",
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names when scanning paths (default: all).",
    ),
    rules: Optional[str] = typer.Option(
        None, "--rules",
        help="Custom rules file path (default: .aigov-rules.yaml in cwd).",
    ),
) -> None:
    """Classify AI systems against governance frameworks.

    Accepts either a JSON file produced by a previous scan
    (aigov classify results.json) or one or more paths to scan first
    (aigov classify ./src).
    """
    from aigov.core.engine import ScanEngine, ScanResult, classify_results
    from aigov.core.models import AISystemRecord
    from aigov.core.reporter import (
        print_table,
        print_risk_summary,
        to_json,
        to_markdown,
        write_output,
    )

    targets = paths or ["."]
    fw_list = [f.strip() for f in frameworks.split(",")]
    rules_path = Path(rules) if rules else None

    result: ScanResult
    if len(targets) == 1 and targets[0].lower().endswith(".json") and Path(targets[0]).is_file():
        json_path = Path(targets[0])
        console.print(f"[bold]Loading scan results from[/bold] {json_path} ...")
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Error reading {json_path}:[/red] {exc}")
            raise typer.Exit(code=1)

        findings = raw.get("findings", [])
        records = []
        for item in findings:
            try:
                records.append(AISystemRecord.from_dict(item))
            except (KeyError, ValueError) as exc:
                console.print(f"[yellow]Warning:[/yellow] skipping malformed finding: {exc}")

        summary = raw.get("summary", {})
        result = ScanResult(
            records=records,
            scanners_run=summary.get("scanners_run", []),
            scanned_paths=summary.get("scanned_paths", [json_path.name]),
            duration_seconds=summary.get("duration_seconds", 0.0),
        )
        result._compute_summaries()
    else:
        enabled = [s.strip() for s in scanners.split(",")] if scanners else None
        try:
            engine = ScanEngine(paths=targets, enabled_scanners=enabled)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(code=1)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            def on_progress(scanner_name: str, state: str) -> None:
                if state == "start":
                    progress.update(task, description=f"Running [cyan]{scanner_name}[/cyan]...")

            result = engine.run(progress_callback=on_progress)

    try:
        result = classify_results(result, fw_list, rules_path=rules_path)
    except ValueError as exc:
        console.print(f"[red]Classification error:[/red] {exc}")
        raise typer.Exit(code=1)

    if output == "json":
        content = to_json(result)
        if out_file:
            write_output(content, out_file)
            console.print(f"[green]JSON report written to {out_file}[/green]")
        else:
            write_output(content, None)

    elif output == "markdown":
        content = to_markdown(result)
        if out_file:
            write_output(content, out_file)
            console.print(f"[green]Markdown report written to {out_file}[/green]")
        else:
            write_output(content, None)

    else:
        print_table(result, console=console)
        if out_file:
            write_output(to_json(result), out_file)
            console.print(f"[green]JSON report also written to {out_file}[/green]")

    print_risk_summary(result, console=console)
