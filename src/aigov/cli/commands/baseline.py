"""`aigov baseline` commands — save and diff against a scan baseline."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aigov.core.baseline import DriftReport, compare_to_baseline, save_baseline
from aigov.core.models import RiskLevel

app = typer.Typer(help="Manage scan baselines and detect drift in AI system inventories.")
console = Console()

_RISK_COLORS = {
    RiskLevel.PROHIBITED:   "bold red",
    RiskLevel.HIGH_RISK:    "dark_orange",
    RiskLevel.LIMITED_RISK: "yellow",
    RiskLevel.MINIMAL_RISK: "green",
    RiskLevel.NEEDS_REVIEW: "cyan",
    RiskLevel.UNKNOWN:      "dim",
}

_CRITICAL_LEVELS = {RiskLevel.PROHIBITED, RiskLevel.HIGH_RISK}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run_scan_and_classify(
    paths: list[str],
    frameworks: str,
    scanners: Optional[str],
) -> "ScanResult":  # noqa: F821
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from aigov.core.engine import ScanEngine, classify_results

    enabled = [s.strip() for s in scanners.split(",")] if scanners else None
    try:
        engine = ScanEngine(paths=paths, enabled_scanners=enabled)
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

        result = engine.run(progress_callback=on_progress)

    fw_list = [f.strip() for f in frameworks.split(",")]
    try:
        result = classify_results(result, fw_list)
    except ValueError as exc:
        console.print(f"[red]Classification error:[/red] {exc}")
        raise typer.Exit(code=1)

    return result


def _load_result_from_file(json_path: Path) -> "ScanResult":  # noqa: F821
    from aigov.core.engine import ScanResult
    from aigov.core.models import AISystemRecord

    try:
        raw = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Error reading {json_path}:[/red] {exc}")
        raise typer.Exit(code=1)

    records = []
    for item in raw.get("findings", []):
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
    return result


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------

@app.command("save")
def save(
    paths: Optional[list[str]] = typer.Argument(
        default=None,
        help="Paths to scan (defaults to '.'). Ignored when --from-file is set.",
    ),
    from_file: Optional[str] = typer.Option(
        None, "--from-file",
        help="Save an existing scan JSON as the baseline instead of running a new scan.",
    ),
    baseline: str = typer.Option(
        ".aigov-baseline.json", "--baseline",
        help="Baseline file path (default: .aigov-baseline.json).",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated classification frameworks (default: eu_ai_act).",
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names to run (default: all).",
    ),
) -> None:
    """Scan, classify, and save the result as the current baseline.

    Use this after an AI system has been reviewed and approved. Future
    `aigov baseline diff` runs will compare against this snapshot.
    """
    if from_file:
        result = _load_result_from_file(Path(from_file))
        console.print(f"[bold]Loaded {result.total_found} system(s) from[/bold] {from_file}")
    else:
        targets = paths or ["."]
        result = _run_scan_and_classify(targets, frameworks, scanners)
        console.print(f"[bold]Scanned:[/bold] {result.total_found} system(s) found")

    dest = save_baseline(result, path=baseline)
    console.print(
        f"[bold green]Baseline saved to[/bold green] {dest}  "
        f"[dim]({result.total_found} system(s))[/dim]"
    )


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

@app.command("diff")
def diff(
    paths: Optional[list[str]] = typer.Argument(
        default=None,
        help="Paths to scan (defaults to '.').",
    ),
    output: str = typer.Option(
        "table", "--output", "-f",
        help="Output format: table (default) or json.",
    ),
    baseline: str = typer.Option(
        ".aigov-baseline.json", "--baseline",
        help="Baseline file to compare against (default: .aigov-baseline.json).",
    ),
    frameworks: str = typer.Option(
        "eu_ai_act", "--frameworks",
        help="Comma-separated classification frameworks (default: eu_ai_act).",
    ),
    scanners: Optional[str] = typer.Option(
        None, "--scanners",
        help="Comma-separated scanner names to run (default: all).",
    ),
    fail_on_drift: bool = typer.Option(
        False, "--fail-on-drift",
        help="Exit 1 if any new HIGH_RISK or PROHIBITED systems are detected.",
    ),
) -> None:
    """Compare a fresh scan against the saved baseline to detect AI system drift.

    Useful in CI/CD: add --fail-on-drift to block pipelines when new
    high-risk or prohibited AI systems appear in a commit.
    """
    targets = paths or ["."]
    current = _run_scan_and_classify(targets, frameworks, scanners)
    report = compare_to_baseline(current, baseline_path=baseline)

    if output == "json":
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        sys.stdout.write("\n")
    else:
        _print_drift_report(report)

    if fail_on_drift:
        critical_new = [
            r for r in report.new_systems
            if r.risk_classification in _CRITICAL_LEVELS
        ]
        if critical_new:
            console.print(
                f"\n[bold red]--fail-on-drift: {len(critical_new)} new HIGH_RISK or "
                f"PROHIBITED system(s) detected.[/bold red]"
            )
            raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Rich output for drift report
# ---------------------------------------------------------------------------

def _print_drift_report(report: DriftReport) -> None:
    baseline_str = (
        report.baseline_date.strftime("%Y-%m-%d %H:%M UTC")
        if report.baseline_date else "no baseline — all systems treated as new"
    )
    console.print(f"\n[bold]Baseline date:[/bold] {baseline_str}")

    if not report.has_drift:
        console.print(
            f"\n[bold green]No drift detected.[/bold green]  "
            f"[dim]{report.unchanged_count} system(s) unchanged.[/dim]"
        )
        return

    if report.new_systems:
        table = Table(title=f"New Systems ({len(report.new_systems)})", show_lines=False)
        table.add_column("Name", style="bold cyan", min_width=20)
        table.add_column("Provider", style="green", min_width=12)
        table.add_column("Type", style="magenta", min_width=12)
        table.add_column("Risk", min_width=14)
        table.add_column("Location", style="dim", min_width=28)
        for rec in report.new_systems:
            risk = rec.risk_classification
            color = _RISK_COLORS.get(risk, "dim") if risk else "dim"
            label = risk.value.upper().replace("_", " ") if risk else "UNKNOWN"
            row_color = "bold red" if risk in _CRITICAL_LEVELS else "yellow"
            loc = rec.source_location
            if len(loc) > 50:
                loc = "..." + loc[-47:]
            table.add_row(
                f"[{row_color}]{rec.name}[/{row_color}]",
                rec.provider,
                rec.system_type.value,
                f"[{color}]{label}[/{color}]",
                loc,
            )
        console.print()
        console.print(table)

    if report.removed_systems:
        table = Table(title=f"Removed Systems ({len(report.removed_systems)})", show_lines=False)
        table.add_column("Name", style="bold", min_width=20)
        table.add_column("Provider", min_width=12)
        table.add_column("Location", style="dim", min_width=28)
        for rec in report.removed_systems:
            table.add_row(rec.name, rec.provider, rec.source_location)
        console.print()
        console.print(table)

    if report.changed_classification:
        table = Table(
            title=f"Changed Classification ({len(report.changed_classification)})",
            show_lines=False,
        )
        table.add_column("Name", style="bold cyan", min_width=20)
        table.add_column("Was", min_width=14)
        table.add_column("Now", min_width=14)
        table.add_column("Location", style="dim", min_width=28)
        for old, new in report.changed_classification:
            old_risk = old.risk_classification
            new_risk = new.risk_classification
            old_color = _RISK_COLORS.get(old_risk, "dim") if old_risk else "dim"
            new_color = _RISK_COLORS.get(new_risk, "dim") if new_risk else "dim"
            old_label = old_risk.value.upper().replace("_", " ") if old_risk else "UNKNOWN"
            new_label = new_risk.value.upper().replace("_", " ") if new_risk else "UNKNOWN"
            table.add_row(
                new.name,
                f"[{old_color}]{old_label}[/{old_color}]",
                f"[{new_color}]{new_label}[/{new_color}]",
                new.source_location,
            )
        console.print()
        console.print(table)

    parts: list[str] = []
    if report.new_systems:
        critical = sum(1 for r in report.new_systems if r.risk_classification in _CRITICAL_LEVELS)
        color = "bold red" if critical else "yellow"
        parts.append(f"[{color}]{len(report.new_systems)} new[/{color}]")
    if report.removed_systems:
        parts.append(f"[dim]{len(report.removed_systems)} removed[/dim]")
    if report.changed_classification:
        parts.append(f"[cyan]{len(report.changed_classification)} reclassified[/cyan]")
    if report.unchanged_count:
        parts.append(f"[green]{report.unchanged_count} unchanged[/green]")
    console.print("\n" + "  ·  ".join(parts))
