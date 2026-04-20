from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import TextIO

from rich.console import Console
from rich.table import Table

from aigov.core.engine import ScanResult
from aigov.core.models import AISystemRecord


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

def _record_to_json(rec: AISystemRecord) -> dict:
    return rec.to_dict()


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    payload = {
        "aigov_version": "0.1.0",
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
        "findings": [_record_to_json(r) for r in result.records],
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

    if result.warnings:
        w("## Warnings\n\n")
        for warning in result.warnings:
            w(f"- {warning}\n")
        w("\n")

    w("## Findings\n\n")
    if not result.records:
        w("_No AI systems detected._\n")
    else:
        w("| # | Name | Type | Provider | Jurisdiction | Confidence | Location |\n")
        w("|---|------|------|----------|--------------|------------|----------|\n")
        for i, rec in enumerate(result.records, start=1):
            jur = rec.tags.get("origin_jurisdiction", "XX")
            loc = rec.source_location
            # Truncate long paths for readability
            if len(loc) > 60:
                loc = "..." + loc[-57:]
            w(
                f"| {i} | {rec.name} | {rec.system_type.value} | {rec.provider} "
                f"| {jur} | {rec.confidence:.0%} | `{loc}` |\n"
            )

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

    for i, rec in enumerate(result.records, start=1):
        jur = rec.tags.get("origin_jurisdiction", "XX")
        confidence_bar = _confidence_bar(rec.confidence)
        loc = rec.source_location
        if len(loc) > 55:
            loc = "..." + loc[-52:]
        table.add_row(
            str(i),
            rec.name,
            rec.system_type.value,
            rec.provider,
            jur,
            confidence_bar,
            loc,
        )

    console.print(table)
    _print_summary_line(result, console)


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
# Write helpers
# ---------------------------------------------------------------------------

def write_output(content: str, out_file: str | None) -> None:
    if out_file:
        Path(out_file).write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
