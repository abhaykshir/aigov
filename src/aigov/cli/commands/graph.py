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
    from aigov.core.graph import build_graph, compute_insights, to_html
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
    insights = compute_insights(graph)

    dest = out_file or _default_out_file(output)
    if output == "json":
        # Merge insights into the JSON envelope so downstream tools get the
        # same view the HTML renderer does.
        payload = graph.to_dict()
        payload["insights"] = insights.to_dict()
        Path(dest).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        Path(dest).write_text(to_html(graph, insights=insights), encoding="utf-8")

    console.print(
        f"[bold green]Graph written to[/bold green] {dest}  "
        f"[dim]({len(graph.nodes)} node(s), {len(graph.edges)} edge(s))[/dim]"
    )
    _print_insights_summary(insights, graph)


def _print_insights_summary(insights, graph) -> None:
    """One-line digest after the graph is written, e.g.:

    ``Graph: 7 nodes, 9 edges, 2 clusters. Highest blast radius: foo.py (critical, 4 connections)``
    """
    parts = [
        f"Graph: {insights.total_nodes} node{_s(insights.total_nodes)}",
        f"{insights.total_edges} edge{_s(insights.total_edges)}",
        f"{len(insights.risk_clusters)} cluster{_s(len(insights.risk_clusters))}",
    ]
    line = ", ".join(parts) + "."

    worst_id = insights.highest_blast_radius_node
    if worst_id and worst_id in insights.node_insights:
        ins = insights.node_insights[worst_id]
        node = next((n for n in graph.nodes if n.id == worst_id), None)
        label = node.label if node else worst_id
        line += (
            f" Highest blast radius: {label} "
            f"({ins.blast_radius}, {ins.degree} connection{_s(ins.degree)})."
        )

    if insights.isolated_nodes:
        n = len(insights.isolated_nodes)
        line += f" {n} isolated system{_s(n)} — review for shadow AI."

    console.print(line)


def _s(n: int) -> str:
    return "" if n == 1 else "s"


def _default_out_file(output: str) -> str:
    return "aigov-graph.html" if output == "html" else "aigov-graph.json"
