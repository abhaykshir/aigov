"""`aigov scan` command — discover AI systems in the given paths."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

console = Console()


def scan_command(
    paths: Optional[list[str]] = typer.Argument(
        default=None, help="Paths to scan (defaults to current directory)."
    ),
    output: str = typer.Option(
        "table", "--output", "-f",
        help="Output format: table (default), json, markdown, csv, sarif.",
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
    do_gaps: bool = typer.Option(
        False, "--gaps",
        help="Run compliance gap analysis after classification (implies --classify).",
    ),
    do_docs: bool = typer.Option(
        False, "--docs",
        help="Generate EU AI Act compliance documents after classification (implies --classify).",
    ),
    docs_dir: str = typer.Option(
        "compliance-docs", "--docs-dir",
        help="Output directory for generated compliance documents (default: compliance-docs).",
    ),
    rules: Optional[str] = typer.Option(
        None, "--rules",
        help="Custom rules file path (default: .aigov-rules.yaml in cwd).",
    ),
    local_config: bool = typer.Option(
        False, "--local-config",
        help=(
            "Also scan OS-level MCP client configs (Claude Desktop, Cursor, "
            "Windsurf, VS Code personal configs). Off by default — only the "
            "given paths are scanned."
        ),
    ),
    strict: bool = typer.Option(
        False, "--strict",
        help=(
            "Exit with code 1 if any scanner raises an error. Default behavior "
            "logs scanner failures as warnings and continues."
        ),
    ),
    with_risk: bool = typer.Option(
        False, "--with-risk",
        help=(
            "Run context-aware risk scoring after classification. Adds a "
            "0–100 score, a categorical level, and explicit drivers based on "
            "deployment context (environment, exposure, data sensitivity, "
            "interaction type). Implies --classify."
        ),
    ),
) -> None:
    """Discover AI systems in the specified paths."""
    from aigov.core.engine import ScanEngine, classify_results
    from aigov.core.reporter import (
        print_table,
        print_risk_summary,
        to_json,
        to_markdown,
        write_output,
    )

    if do_gaps or do_docs or with_risk:
        do_classify = True

    targets = paths or ["."]
    enabled = [s.strip() for s in scanners.split(",")] if scanners else None

    try:
        engine = ScanEngine(paths=targets, enabled_scanners=enabled, local_config=local_config)
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

    if strict and result.scanner_errors:
        console.print(
            f"[red]Strict mode:[/red] {len(result.scanner_errors)} scanner(s) failed."
        )
        for err in result.scanner_errors:
            console.print(f"  [red]{err}[/red]")
        raise typer.Exit(code=1)

    if do_classify:
        fw_list = [f.strip() for f in frameworks.split(",")]
        rules_path = Path(rules) if rules else None
        try:
            result = classify_results(result, fw_list, rules_path=rules_path)
        except ValueError as exc:
            console.print(f"[red]Classification error:[/red] {exc}")
            raise typer.Exit(code=1)

    if with_risk:
        from aigov.core.risk import apply_risk
        scored = apply_risk(result.records, list(result.scanned_paths) or targets)
        import dataclasses as _dc
        result = _dc.replace(result, records=scored)
        result._compute_summaries()

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

    elif output == "csv":
        from aigov.core.exporter import to_csv
        content = to_csv(result.records)
        if out_file:
            write_output(content, out_file)
            console.print(f"[green]CSV report written to {out_file}[/green]")
        else:
            write_output(content, None)

    elif output == "sarif":
        from aigov.core.sarif import to_sarif
        content = to_sarif(result)
        if out_file:
            write_output(content, out_file)
            console.print(f"[green]SARIF report written to {out_file}[/green]")
        else:
            write_output(content, None)

    else:
        print_table(result, console=console)
        if out_file:
            write_output(to_json(result), out_file)
            console.print(f"[green]JSON report also written to {out_file}[/green]")

    if do_classify:
        print_risk_summary(result, console=console)

    if do_gaps:
        from aigov.core.gaps import GapAnalyzer
        from aigov.core.reporter import gap_report_to_markdown, print_gap_report
        analyzer = GapAnalyzer()
        gap_report = analyzer.analyze(result.records)
        if output == "markdown":
            gap_md = gap_report_to_markdown(gap_report)
            if out_file:
                existing = Path(out_file).read_text(encoding="utf-8") if Path(out_file).exists() else ""
                write_output(existing + "\n---\n\n" + gap_md, out_file)
                console.print(f"[green]Gap report appended to {out_file}[/green]")
            else:
                write_output(gap_md, None)
        else:
            print_gap_report(gap_report, console=console)

    if do_docs:
        from aigov.core.docs_generator import DocsGenerator
        generator = DocsGenerator()
        created = generator.generate(result.records, docs_dir)
        console.print(f"\n[bold green]Compliance documents written to[/bold green] {docs_dir}/")
        for path in created:
            console.print(f"  [dim]{path}[/dim]")
