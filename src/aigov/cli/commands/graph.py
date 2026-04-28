"""`aigov graph` command — generate an evidence-based AI System Graph."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()

_VALID_OUTPUTS = {"html", "json"}


def graph_command(
    paths: Optional[list[str]] = typer.Argument(
        default=None,
        help="Paths to scan (defaults to '.'). Ignored when --from-file is set.",
    ),
    from_file: Optional[str] = typer.Option(
        None, "--from-file",
        help="Generate the graph from an existing scan-result JSON file.",
    ),
    output: str = typer.Option(
        "html", "--output", "-f",
        help="Output format: html (default) or json.",
    ),
    out_file: Optional[str] = typer.Option(
        None, "--out-file", "-o",
        help=(
            "Output path. Defaults to 'aigov-graph.html' or 'aigov-graph.json' "
            "based on --output."
        ),
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names (default: all). Ignored with --from-file.",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated framework names for classification (default: eu_ai_act).",
    ),
) -> None:
    """Build an interactive graph of discovered AI systems and their relationships.

    The graph treats each AI system as a node, and connects them with
    evidence-backed edges (shared config files, same provider in same dir,
    MCP servers alongside services, same Python package, same Terraform
    module, …). Output is a self-contained HTML file (open by double-click)
    or a JSON document.
    """
    if output not in _VALID_OUTPUTS:
        console.print(
            f"[red]Error:[/red] unknown --output {output!r}. "
            f"Choose from: {', '.join(sorted(_VALID_OUTPUTS))}."
        )
        raise typer.Exit(code=1)

    from aigov.core.engine import ScanEngine, ScanResult, classify_results
    from aigov.core.graph import build_graph, to_html, to_json
    from aigov.core.models import AISystemRecord
    from aigov.core.risk import apply_risk

    targets = paths or ["."]

    if from_file:
        json_path = Path(from_file)
        if not json_path.exists():
            console.print(f"[red]Error:[/red] file not found: {from_file}")
            raise typer.Exit(code=1)
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Error reading {json_path}:[/red] {exc}")
            raise typer.Exit(code=1)

        records: list[AISystemRecord] = []
        for finding in raw.get("findings", []):
            try:
                records.append(AISystemRecord.from_dict(finding))
            except (KeyError, ValueError) as exc:
                console.print(f"[yellow]Warning:[/yellow] skipping malformed finding: {exc}")
        scanned_paths = list(raw.get("summary", {}).get("scanned_paths") or [str(json_path)])
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

            def on_progress(name: str, state: str) -> None:
                if state == "start":
                    progress.update(task, description=f"Running [cyan]{name}[/cyan]...")

            scan_result = engine.run(progress_callback=on_progress)

        fw_list = [f.strip() for f in frameworks.split(",")]
        try:
            scan_result = classify_results(scan_result, fw_list)
        except ValueError as exc:
            console.print(f"[red]Classification error:[/red] {exc}")
            raise typer.Exit(code=1)

        scored = apply_risk(scan_result.records, list(scan_result.scanned_paths) or targets)
        records = scored
        scanned_paths = list(scan_result.scanned_paths) or targets

    graph = build_graph(records, scanned_paths)

    dest = out_file or _default_out_file(output)
    if output == "json":
        Path(dest).write_text(to_json(graph), encoding="utf-8")
    else:
        Path(dest).write_text(to_html(graph), encoding="utf-8")

    console.print(
        f"[bold green]Graph written to[/bold green] {dest}  "
        f"[dim]({len(graph.nodes)} node(s), {len(graph.edges)} edge(s))[/dim]"
    )


def _default_out_file(output: str) -> str:
    return "aigov-graph.html" if output == "html" else "aigov-graph.json"
