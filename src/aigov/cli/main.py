"""aigov Typer app entrypoint.

This module wires the top-level command tree together. Each command's logic
lives in its own module under :mod:`aigov.cli.commands`. Keep this file
small — adding a new command means importing it here, not implementing it
inline.
"""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from aigov.cli.commands.baseline import app as _baseline_app
from aigov.cli.commands.classify import classify_command
from aigov.cli.commands.docs import docs_command
from aigov.cli.commands.export_cmd import export_command
from aigov.cli.commands.gaps import gaps_command
from aigov.cli.commands.hooks import app as _hooks_app
from aigov.cli.commands.scan import scan_command

app = typer.Typer(help="AI Governance-as-Code CLI — discover, classify, and govern AI systems.")
console = Console()

_VERSION = "aigov 0.2.1"

# Top-level commands.
app.command("scan")(scan_command)
app.command("classify")(classify_command)
app.command("gaps")(gaps_command)
app.command("docs")(docs_command)
app.command("export")(export_command)

# Command groups.
app.add_typer(_hooks_app, name="hooks")
app.add_typer(_baseline_app, name="baseline")


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
