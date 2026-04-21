from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

app = typer.Typer(help="AI Governance-as-Code CLI — discover, classify, and govern AI systems.")
console = Console()

_VERSION = "aigov 0.1.0"


def version_callback(value: bool) -> None:
    if value:
        console.print(_VERSION)
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


@app.command()
def scan(
    paths: Optional[list[str]] = typer.Argument(
        default=None, help="Paths to scan (defaults to current directory)."
    ),
    output: str = typer.Option(
        "table", "--output", "-f",
        help="Output format: table (default), json, markdown.",
    ),
    out_file: Optional[str] = typer.Option(
        None, "--out-file", "-o",
        help="Write output to this file instead of stdout.",
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names to run (default: all).",
    ),
    do_classify: bool = typer.Option(
        False, "--classify",
        help="Classify results against governance frameworks after scanning.",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated framework names to use for classification (default: eu_ai_act).",
    ),
) -> None:
    """Discover AI systems in the specified paths."""
    from aigov.core.engine import ScanEngine, classify_results
    from aigov.core.reporter import print_table, print_risk_summary, to_json, to_markdown, write_output

    targets = paths or ["."]
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

    if do_classify:
        fw_list = [f.strip() for f in frameworks.split(",")]
        try:
            result = classify_results(result, fw_list)
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
        # Default: rich table to terminal.
        print_table(result, console=console)
        if out_file:
            write_output(to_json(result), out_file)
            console.print(f"[green]JSON report also written to {out_file}[/green]")

    if do_classify:
        print_risk_summary(result, console=console)


@app.command()
def classify(
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
) -> None:
    """Classify AI systems against governance frameworks.

    Accepts either a JSON file produced by a previous scan
    (aigov classify results.json) or one or more paths to scan first
    (aigov classify ./src).
    """
    from aigov.core.engine import ScanEngine, ScanResult, classify_results
    from aigov.core.models import AISystemRecord
    from aigov.core.reporter import print_table, print_risk_summary, to_json, to_markdown, write_output

    targets = paths or ["."]
    fw_list = [f.strip() for f in frameworks.split(",")]

    # Detect whether the sole argument is an existing JSON scan file.
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
        # Scan first, then classify.
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

    # Classify.
    try:
        result = classify_results(result, fw_list)
    except ValueError as exc:
        console.print(f"[red]Classification error:[/red] {exc}")
        raise typer.Exit(code=1)

    # Output.
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


@app.command()
def docs(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path for generated docs."),
) -> None:
    """Generate governance documentation for discovered AI systems."""
    dest = output or "aigov-report.md"
    console.print(f"[bold green]Generating docs[/bold green] -> {dest} ...")
