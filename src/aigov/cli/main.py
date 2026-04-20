from __future__ import annotations

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
) -> None:
    """Discover AI systems in the specified paths."""
    from aigov.core.engine import ScanEngine
    from aigov.core.reporter import print_table, to_json, to_markdown, write_output

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


@app.command()
def classify(
    paths: Optional[list[str]] = typer.Argument(default=None, help="Paths to classify."),
) -> None:
    """Classify discovered AI systems against governance frameworks."""
    targets = paths or ["."]
    console.print(f"[bold yellow]Classifying[/bold yellow] {', '.join(targets)} ...")


@app.command()
def docs(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path for generated docs."),
) -> None:
    """Generate governance documentation for discovered AI systems."""
    dest = output or "aigov-report.md"
    console.print(f"[bold green]Generating docs[/bold green] -> {dest} ...")
