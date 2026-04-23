from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from rich.console import Console
from rich.table import Table

from aigov.core.engine import ScanResult
from aigov.core.models import AISystemRecord, RiskLevel

if TYPE_CHECKING:
    from aigov.core.gaps import GapReport


# ---------------------------------------------------------------------------
# Risk-level display helpers
# ---------------------------------------------------------------------------

_RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.PROHIBITED:    "bold red",
    RiskLevel.HIGH_RISK:     "dark_orange",
    RiskLevel.LIMITED_RISK:  "yellow",
    RiskLevel.MINIMAL_RISK:  "green",
    RiskLevel.NEEDS_REVIEW:  "cyan",
    RiskLevel.UNKNOWN:       "dim",
}

_RISK_ORDER = [
    RiskLevel.PROHIBITED,
    RiskLevel.HIGH_RISK,
    RiskLevel.LIMITED_RISK,
    RiskLevel.MINIMAL_RISK,
    RiskLevel.NEEDS_REVIEW,
]


def _risk_cell(level: RiskLevel | None) -> str:
    if level is None or level == RiskLevel.UNKNOWN:
        return ""
    color = _RISK_COLORS.get(level, "dim")
    label = level.value.upper().replace("_", " ")
    return f"[{color}]{label}[/{color}]"


def _has_classifications(result: ScanResult) -> bool:
    return any(
        r.risk_classification and r.risk_classification not in (RiskLevel.UNKNOWN, None)
        for r in result.records
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pct(n: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{n * 100 // total}%"


def _sorted_breakdown(d: dict[str, int]) -> list[tuple[str, int]]:
    return sorted(d.items(), key=lambda kv: -kv[1])


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def to_json(result: ScanResult, *, indent: int = 2) -> str:
    payload = {
        "aigov_version": "0.2.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_found": result.total_found,
            "duration_seconds": round(result.duration_seconds, 3),
            "scanners_run": result.scanners_run,
            "scanned_paths": result.scanned_paths,
            "by_type": dict(_sorted_breakdown(result.by_type)),
            "by_provider": dict(_sorted_breakdown(result.by_provider)),
            "by_jurisdiction": dict(_sorted_breakdown(result.by_jurisdiction)),
        },
        "warnings": result.warnings,
        # classification_rationale is included via to_dict() → each finding
        "findings": [r.to_dict() for r in result.records],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown reporter
# ---------------------------------------------------------------------------

def to_markdown(result: ScanResult) -> str:
    buf = StringIO()
    w = buf.write

    w("# aigov Scan Report\n\n")
    w(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n")
    w(f"Scanned paths: {', '.join(f'`{p}`' for p in result.scanned_paths)}  \n")
    w(f"Duration: {result.duration_seconds:.2f}s  \n")
    w(f"Scanners run: {', '.join(f'`{s}`' for s in result.scanners_run)}\n\n")

    w("## Summary\n\n")
    w(f"**Total AI systems found: {result.total_found}**\n\n")

    if result.by_type:
        w("### By Type\n\n")
        w("| Type | Count |\n|------|-------|\n")
        for t, n in _sorted_breakdown(result.by_type):
            w(f"| {t} | {n} |\n")
        w("\n")

    if result.by_provider:
        w("### By Provider\n\n")
        w("| Provider | Count |\n|----------|-------|\n")
        for p, n in _sorted_breakdown(result.by_provider):
            w(f"| {p} | {n} |\n")
        w("\n")

    if result.by_jurisdiction:
        w("### By Jurisdiction\n\n")
        w("| Jurisdiction | Count |\n|-------------|-------|\n")
        for j, n in _sorted_breakdown(result.by_jurisdiction):
            w(f"| {j} | {n} |\n")
        w("\n")

    # Risk classification section (only when records have been classified)
    if _has_classifications(result):
        w("## Risk Classification (EU AI Act)\n\n")

        counts: dict[RiskLevel, int] = {lvl: 0 for lvl in _RISK_ORDER}
        high_risk_cats: dict[str, int] = {}

        for rec in result.records:
            lvl = rec.risk_classification or RiskLevel.UNKNOWN
            if lvl in counts:
                counts[lvl] = counts[lvl] + 1
            if lvl == RiskLevel.HIGH_RISK:
                cat = rec.tags.get("eu_ai_act_category") or "Unknown"
                high_risk_cats[cat] = high_risk_cats.get(cat, 0) + 1

        w("| Risk Level | Count | Notes |\n|------------|-------|-------|\n")
        for lvl in _RISK_ORDER:
            n = counts.get(lvl, 0)
            notes = ""
            if lvl == RiskLevel.HIGH_RISK and high_risk_cats:
                notes = "; ".join(
                    f"{cat} ({c})" for cat, c in sorted(high_risk_cats.items())
                )
            w(f"| {lvl.value.upper().replace('_', ' ')} | {n} | {notes} |\n")
        w("\n")

    if result.warnings:
        w("## Warnings\n\n")
        for warning in result.warnings:
            w(f"- {warning}\n")
        w("\n")

    w("## Findings\n\n")
    if not result.records:
        w("_No AI systems detected._\n")
    else:
        classified = _has_classifications(result)
        header = "| # | Name | Type | Provider | Jurisdiction | Confidence | Location |"
        sep    = "|---|------|------|----------|--------------|------------|----------|"
        if classified:
            header += " Risk | Category |"
            sep    += " ---- | -------- |"
        w(header + "\n")
        w(sep + "\n")

        for i, rec in enumerate(result.records, start=1):
            jur = rec.tags.get("origin_jurisdiction", "XX")
            loc = rec.source_location
            if len(loc) > 60:
                loc = "..." + loc[-57:]
            row = (
                f"| {i} | {rec.name} | {rec.system_type.value} | {rec.provider} "
                f"| {jur} | {rec.confidence:.0%} | `{loc}` |"
            )
            if classified:
                lvl = rec.risk_classification
                lvl_str = lvl.value.upper().replace("_", " ") if lvl else ""
                cat_str = rec.tags.get("eu_ai_act_category", "")
                row += f" {lvl_str} | {cat_str} |"
            w(row + "\n")

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Rich table reporter (terminal)
# ---------------------------------------------------------------------------

def print_table(result: ScanResult, console: Console | None = None) -> None:
    if console is None:
        console = Console()

    if not result.records:
        console.print("[yellow]No AI systems detected.[/yellow]")
        return

    classified = _has_classifications(result)

    table = Table(
        title=f"AI Systems Found ({result.total_found})",
        show_lines=False,
        highlight=True,
    )
    table.add_column("#", style="dim", width=4, no_wrap=True)
    table.add_column("Name", style="bold cyan", min_width=16)
    table.add_column("Type", style="magenta", min_width=12)
    table.add_column("Provider", style="green", min_width=14)
    table.add_column("Jurisdiction", style="yellow", width=12, no_wrap=True)
    table.add_column("Confidence", width=11, no_wrap=True)
    table.add_column("Location", style="dim", min_width=24)
    if classified:
        table.add_column("Risk", min_width=14, no_wrap=True)
        table.add_column("Category", style="dim", min_width=20)

    for i, rec in enumerate(result.records, start=1):
        jur = rec.tags.get("origin_jurisdiction", "XX")
        confidence_bar = _confidence_bar(rec.confidence)
        loc = rec.source_location
        if len(loc) > 55:
            loc = "..." + loc[-52:]

        row: list[str] = [
            str(i),
            rec.name,
            rec.system_type.value,
            rec.provider,
            jur,
            confidence_bar,
            loc,
        ]
        if classified:
            row.append(_risk_cell(rec.risk_classification))
            row.append(rec.tags.get("eu_ai_act_category", ""))

        table.add_row(*row)

    console.print(table)
    _print_summary_line(result, console)


def print_risk_summary(result: ScanResult, console: Console | None = None) -> None:
    """Print a risk-level breakdown table for classified results."""
    if console is None:
        console = Console()

    if not _has_classifications(result):
        return

    counts: dict[RiskLevel, int] = {lvl: 0 for lvl in _RISK_ORDER}
    high_risk_cats: dict[str, int] = {}

    for rec in result.records:
        lvl = rec.risk_classification or RiskLevel.UNKNOWN
        if lvl in counts:
            counts[lvl] += 1
        if lvl == RiskLevel.HIGH_RISK:
            cat = rec.tags.get("eu_ai_act_category") or "Unknown"
            high_risk_cats[cat] = high_risk_cats.get(cat, 0) + 1

    table = Table(
        title="EU AI Act Risk Summary",
        show_lines=False,
        highlight=False,
    )
    table.add_column("Risk Level", style="bold", min_width=16)
    table.add_column("Count", width=7, justify="right")
    table.add_column("Notes", style="dim", min_width=32)

    for lvl in _RISK_ORDER:
        n = counts.get(lvl, 0)
        color = _RISK_COLORS.get(lvl, "dim")
        label = f"[{color}]{lvl.value.upper().replace('_', ' ')}[/{color}]"
        notes = ""
        if lvl == RiskLevel.HIGH_RISK and high_risk_cats:
            notes = "; ".join(
                f"{cat} ({c})" for cat, c in sorted(high_risk_cats.items())
            )
        table.add_row(label, str(n) if n > 0 else "-", notes)

    console.print()
    console.print(table)


def _confidence_bar(confidence: float) -> str:
    filled = round(confidence * 5)
    bar = "#" * filled + "." * (5 - filled)
    pct = f"{confidence:.0%}"
    if confidence >= 0.9:
        return f"[green]{bar}[/green] {pct}"
    if confidence >= 0.7:
        return f"[yellow]{bar}[/yellow] {pct}"
    return f"[red]{bar}[/red] {pct}"


def _print_summary_line(result: ScanResult, console: Console) -> None:
    parts: list[str] = []
    type_labels = {
        "api_service": "API services",
        "model": "models",
        "mcp_server": "MCP servers",
        "agent": "agents",
        "embedding": "embeddings",
        "rag_pipeline": "RAG pipelines",
        "fine_tune": "fine-tunes",
        "other": "other",
    }
    for key, label in type_labels.items():
        n = result.by_type.get(key, 0)
        if n:
            parts.append(f"{n} {label}")

    provider_count = len(result.by_provider)
    providers_str = f"{provider_count} provider{'s' if provider_count != 1 else ''}"

    breakdown = ", ".join(parts) if parts else "none"
    console.print(
        f"\n[bold]Found {result.total_found} AI system{'s' if result.total_found != 1 else ''} "
        f"({breakdown}) across {providers_str}[/bold]"
    )
    if result.warnings:
        console.print(f"[yellow]{len(result.warnings)} warning(s) — run with --output json for details[/yellow]")


# ---------------------------------------------------------------------------
# Gap report — Rich terminal output
# ---------------------------------------------------------------------------

_GAP_STATUS_COLORS = {
    "missing": "bold red",
    "partial": "yellow",
    "unknown": "dim cyan",
}

_PRIORITY_COLORS = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "green",
}


def print_gap_report(gap_report: GapReport, console: Console | None = None) -> None:
    from aigov.core.gaps import _PRIORITY_ORDER

    if console is None:
        console = Console()

    summary = gap_report.overall_summary
    days = summary.get("days_until_deadline", 0)
    deadline_str = gap_report.deadline.strftime("%B %-d, %Y") if sys.platform != "win32" else gap_report.deadline.strftime("%B %d, %Y").replace(" 0", " ")
    deadline_color = "bold red" if days < 60 else ("dark_orange" if days < 120 else "yellow")

    console.print()
    console.rule("[bold]EU AI Act Compliance Gap Analysis[/bold]")
    console.print(
        f"\n  Deadline: [{deadline_color}]{deadline_str}[/{deadline_color}] — "
        f"[{deadline_color}]{days} days remaining[/{deadline_color}]"
    )
    console.print(
        f"  Systems analysed: [bold]{summary['total_systems']}[/bold]  |  "
        f"Total gaps: [bold]{summary['total_gaps']}[/bold]  |  "
        f"Estimated effort: [bold]{summary['estimated_effort_min_hours']}–"
        f"{summary['estimated_effort_max_hours']} hours[/bold]\n"
    )

    # Sort systems: critical first, then by name
    ordered = sorted(
        gap_report.systems,
        key=lambda s: (_PRIORITY_ORDER.get(s.priority, 99), s.record.name),
    )

    for analysis in ordered:
        rec = analysis.record
        pcolor = _PRIORITY_COLORS.get(analysis.priority, "dim")
        risk_label = (rec.risk_classification.value.upper().replace("_", " ") if rec.risk_classification else "UNKNOWN")
        console.print(
            f"[bold]{rec.name}[/bold]  "
            f"[{pcolor}]{analysis.priority.upper()}[/{pcolor}]  "
            f"[dim]({risk_label}  |  est. {analysis.estimated_effort_hours}h)[/dim]"
        )

        if not analysis.gaps:
            console.print("  [green]No compliance gaps identified.[/green]\n")
            continue

        table = Table(show_header=True, show_lines=False, box=None, pad_edge=False, padding=(0, 1))
        table.add_column("Requirement", style="bold", min_width=32)
        table.add_column("Article", style="dim", width=12, no_wrap=True)
        table.add_column("Status", width=10, no_wrap=True)
        table.add_column("Description", min_width=40)

        for gap in analysis.gaps:
            sc = _GAP_STATUS_COLORS.get(gap.status, "dim")
            table.add_row(
                gap.requirement_name,
                gap.article_reference,
                f"[{sc}]{gap.status}[/{sc}]",
                gap.description[:80] + ("…" if len(gap.description) > 80 else ""),
            )

        console.print(table)
        console.print()

    # Priority-ordered action list
    console.rule("[bold]Action List (priority order)[/bold]")
    seen: set[str] = set()
    action_num = 1
    for analysis in ordered:
        if not analysis.gaps:
            continue
        pcolor = _PRIORITY_COLORS.get(analysis.priority, "dim")
        for gap in analysis.gaps:
            key = f"{gap.article_reference}:{gap.requirement_name}"
            if key in seen:
                continue
            seen.add(key)
            console.print(
                f"\n  [{action_num}] [{pcolor}]{gap.requirement_name}[/{pcolor}] "
                f"[dim]({gap.article_reference})[/dim]"
            )
            for step in gap.remediation_steps:
                console.print(f"      • {step}")
            action_num += 1

    console.print()


# ---------------------------------------------------------------------------
# Gap report — Markdown output
# ---------------------------------------------------------------------------

def gap_report_to_markdown(gap_report: GapReport) -> str:
    from aigov.core.gaps import _PRIORITY_ORDER

    buf = StringIO()
    w = buf.write
    summary = gap_report.overall_summary

    w("# EU AI Act Compliance Gap Report\n\n")
    w(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n")
    w(f"Deadline: **{gap_report.deadline.isoformat()}** ({summary['days_until_deadline']} days remaining)  \n\n")

    w("## Overall Summary\n\n")
    w(f"| Metric | Value |\n|--------|-------|\n")
    w(f"| Total systems analysed | {summary['total_systems']} |\n")
    w(f"| Total compliance gaps | {summary['total_gaps']} |\n")
    w(f"| Estimated effort | {summary['estimated_effort_min_hours']}–{summary['estimated_effort_max_hours']} hours |\n")
    w(f"| Days until deadline | {summary['days_until_deadline']} |\n\n")

    if summary.get("systems_by_risk"):
        w("### Systems by Risk Level\n\n")
        w("| Risk Level | Count |\n|------------|-------|\n")
        for lvl, count in sorted(summary["systems_by_risk"].items()):
            w(f"| {lvl.upper().replace('_', ' ')} | {count} |\n")
        w("\n")

    ordered = sorted(
        gap_report.systems,
        key=lambda s: (_PRIORITY_ORDER.get(s.priority, 99), s.record.name),
    )

    w("## Per-System Gap Analysis\n\n")
    for analysis in ordered:
        rec = analysis.record
        risk_label = (rec.risk_classification.value.upper().replace("_", " ") if rec.risk_classification else "UNKNOWN")
        w(f"### {rec.name}\n\n")
        w(f"- **Risk level:** {risk_label}  \n")
        w(f"- **Priority:** {analysis.priority.upper()}  \n")
        w(f"- **Estimated effort:** {analysis.estimated_effort_hours} hours  \n")
        w(f"- **Location:** `{rec.source_location}`  \n\n")

        if not analysis.gaps:
            w("_No compliance gaps identified._\n\n")
            continue

        w("| Requirement | Article | Status | Description |\n")
        w("|-------------|---------|--------|-------------|\n")
        for gap in analysis.gaps:
            desc = gap.description.replace("|", "\\|")[:100] + ("…" if len(gap.description) > 100 else "")
            w(f"| {gap.requirement_name} | {gap.article_reference} | {gap.status} | {desc} |\n")
        w("\n")

    w("## Remediation Action List\n\n")
    seen: set[str] = set()
    action_num = 1
    for analysis in ordered:
        if not analysis.gaps:
            continue
        for gap in analysis.gaps:
            key = f"{gap.article_reference}:{gap.requirement_name}"
            if key in seen:
                continue
            seen.add(key)
            w(f"### {action_num}. {gap.requirement_name} ({gap.article_reference})\n\n")
            w(f"**Priority:** {analysis.priority.upper()}  \n")
            w(f"**Status:** {gap.status}  \n\n")
            for step in gap.remediation_steps:
                w(f"- {step}\n")
            w("\n")
            action_num += 1

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def write_output(content: str, out_file: str | None) -> None:
    if out_file:
        Path(out_file).write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
