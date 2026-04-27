"""`aigov docs` command — generate EU AI Act compliance documentation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


def docs_command(
    paths: Optional[list[str]] = typer.Argument(
        default=None,
        help="Classified JSON file from a previous scan, or paths to scan and classify first.",
    ),
    out_dir: str = typer.Option(
        "compliance-docs", "--out-dir", "-o",
        help="Output directory for generated compliance documents (default: compliance-docs).",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated framework names for classification (default: eu_ai_act).",
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names when scanning paths (default: all).",
    ),
) -> None:
    """Generate EU AI Act compliance documentation for classified AI systems.

    Accepts a classified JSON file (aigov docs results.json) or paths to
    scan and classify first (aigov docs ./src).
    """
    from aigov.core.docs_generator import DocsGenerator
    from aigov.core.engine import ScanEngine, ScanResult, classify_results
    from aigov.core.models import AISystemRecord, RiskLevel

    targets = paths or ["."]
    fw_list = [f.strip() for f in frameworks.split(",")]

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

        needs_classification = any(
            r.risk_classification in (None, RiskLevel.UNKNOWN) for r in result.records
        )
        if needs_classification:
            try:
                result = classify_results(result, fw_list)
            except ValueError as exc:
                console.print(f"[red]Classification error:[/red] {exc}")
                raise typer.Exit(code=1)
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
            result = classify_results(result, fw_list)
        except ValueError as exc:
            console.print(f"[red]Classification error:[/red] {exc}")
            raise typer.Exit(code=1)

    generator = DocsGenerator()
    created = generator.generate(result.records, out_dir)
    console.print(f"\n[bold green]Compliance documents written to[/bold green] {out_dir}/")
    for path in created:
        console.print(f"  [dim]{path}[/dim]")
