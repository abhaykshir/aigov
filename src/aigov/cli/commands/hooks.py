from __future__ import annotations

import shutil
import stat
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(help="Manage aigov git hooks.")
console = Console()

_HOOK_MARKER = "# aigov-hook-managed"
_BACKUP_SUFFIX = ".aigov-backup"

# ---------------------------------------------------------------------------
# Hook script template
# The literal string AIGOV_BACKUP_PLACEHOLDER is replaced with the actual
# backup path (or "") by _build_hook_script().
# ---------------------------------------------------------------------------

_HOOK_TEMPLATE = """\
#!/usr/bin/env python3
# aigov-hook-managed — do not remove this line
# Installed by `aigov hooks install`. Edit .aigov-allowlist.yaml to manage exceptions.
_AIGOV_BACKUP_HOOK = AIGOV_BACKUP_PLACEHOLDER

from __future__ import annotations
import fnmatch
import json
import os
import subprocess
import sys
from pathlib import Path

_RELEVANT_SUFFIXES = frozenset({".py", ".yaml", ".yml", ".tf", ".json", ".env"})


def _get_staged_files() -> list[str]:
    try:
        r = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True, text=True, check=False,
        )
        return [f.strip() for f in r.stdout.splitlines() if f.strip()]
    except OSError:
        return []


def _is_relevant(filepath: str) -> bool:
    p = Path(filepath)
    if p.name.startswith("Dockerfile"):
        return True
    if p.name == ".env" or p.name.endswith(".mcp.json"):
        return True
    return p.suffix.lower() in _RELEVANT_SUFFIXES


def _load_allowlist() -> tuple[set[str], list[str]]:
    allowed_ids: set[str] = set()
    allowed_patterns: list[str] = []
    path = Path(".aigov-allowlist.yaml")
    if not path.exists():
        return allowed_ids, allowed_patterns
    try:
        import yaml  # noqa: PLC0415
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in data.get("approved") or []:
            if isinstance(entry, dict):
                if "id" in entry:
                    allowed_ids.add(str(entry["id"]))
                if "name_pattern" in entry:
                    allowed_patterns.append(str(entry["name_pattern"]))
    except Exception:  # noqa: BLE001
        pass
    return allowed_ids, allowed_patterns


def _is_allowlisted(finding: dict, allowed_ids: set[str], allowed_patterns: list[str]) -> bool:
    if finding.get("id", "") in allowed_ids:
        return True
    name = finding.get("name", "")
    return any(fnmatch.fnmatch(name, p) for p in allowed_patterns)


def _block_on_high_risk() -> bool:
    config = Path(".aigov.yaml")
    if not config.exists():
        return False
    try:
        import yaml  # noqa: PLC0415
        cfg = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
        return bool(cfg.get("hooks", {}).get("block_on_high_risk", False))
    except Exception:  # noqa: BLE001
        return False


def main() -> None:
    staged = _get_staged_files()
    if not any(_is_relevant(f) for f in staged):
        sys.exit(0)

    try:
        proc = subprocess.run(
            ["aigov", "scan", ".", "--classify", "--output", "json"],
            capture_output=True, text=True, check=False,
        )
        data = json.loads(proc.stdout)
    except (OSError, json.JSONDecodeError):
        # aigov unavailable — warn but do not block commit
        print("[aigov] Warning: could not run aigov, skipping AI governance check",
              file=sys.stderr)
        sys.exit(0)

    findings = data.get("findings", [])
    staged_set = set(staged)

    # Filter to findings whose source_location overlaps with staged file paths.
    # Only names/locations are inspected — file contents are never read or logged.
    relevant = [
        f for f in findings
        if any(sf in f.get("source_location", "") for sf in staged_set)
    ]

    allowed_ids, allowed_patterns = _load_allowlist()

    prohibited = [
        f for f in relevant
        if f.get("risk_classification") == "prohibited"
        and not _is_allowlisted(f, allowed_ids, allowed_patterns)
    ]
    high_risk = [
        f for f in relevant
        if f.get("risk_classification") == "high_risk"
        and not _is_allowlisted(f, allowed_ids, allowed_patterns)
    ]

    if prohibited:
        print("\\n[aigov] COMMIT BLOCKED — PROHIBITED AI systems detected:", file=sys.stderr)
        for f in prohibited:
            # Log name and location only — never file contents per SECURITY.md
            print(f"  BLOCKED: {f.get('name')} in {f.get('source_location')}", file=sys.stderr)
            print(f"           {f.get('description', '')}", file=sys.stderr)
        print("\\nEU AI Act Article 5 prohibits these practices. Remove before committing.",
              file=sys.stderr)
        sys.exit(1)

    if high_risk:
        print("\\n[aigov] WARNING — HIGH RISK AI systems in staged files:", file=sys.stderr)
        for f in high_risk:
            print(f"  WARNING: {f.get('name')} in {f.get('source_location')}", file=sys.stderr)
        print("\\nTo approve: add to .aigov-allowlist.yaml with a documented reason.",
              file=sys.stderr)
        if _block_on_high_risk():
            print("[aigov] Commit blocked: hooks.block_on_high_risk=true in .aigov.yaml",
                  file=sys.stderr)
            sys.exit(1)

    # Chain to original pre-commit hook if one was backed up during install
    if _AIGOV_BACKUP_HOOK:
        if os.path.isfile(_AIGOV_BACKUP_HOOK) and os.access(_AIGOV_BACKUP_HOOK, os.X_OK):
            result = subprocess.run([_AIGOV_BACKUP_HOOK] + sys.argv[1:])
            if result.returncode != 0:
                sys.exit(result.returncode)

    sys.exit(0)


if __name__ == "__main__":
    main()
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_hook_script(backup_path: Optional[Path] = None) -> str:
    backup_val = repr(str(backup_path)) if backup_path else '""'
    return _HOOK_TEMPLATE.replace("AIGOV_BACKUP_PLACEHOLDER", backup_val)


def _find_git_hooks_dir(cwd: Optional[Path] = None) -> Path:
    """Walk up from *cwd* to find .git/hooks/. Raises ValueError if not in a git repo."""
    start = cwd or Path.cwd()
    for parent in [start, *start.parents]:
        git_dir = parent / ".git"
        if git_dir.is_dir():
            hooks_dir = git_dir / "hooks"
            hooks_dir.mkdir(exist_ok=True)
            return hooks_dir
    raise ValueError(f"Not inside a git repository: {start}")


def _make_executable(path: Path) -> None:
    current = path.stat().st_mode
    path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _install_hook(hooks_dir: Path) -> str:
    """Install the pre-commit hook into *hooks_dir*. Returns a status string."""
    hook_path = hooks_dir / "pre-commit"
    backup_path = hooks_dir / f"pre-commit{_BACKUP_SUFFIX}"

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8", errors="replace")
        if _HOOK_MARKER in existing:
            # Already an aigov hook — overwrite with the latest version, preserve backup path
            hook_path.write_text(_build_hook_script(
                backup_path if backup_path.exists() else None
            ), encoding="utf-8")
            _make_executable(hook_path)
            return "updated"
        else:
            # Back up the existing hook and chain to it
            shutil.copy2(hook_path, backup_path)
            hook_path.write_text(_build_hook_script(backup_path), encoding="utf-8")
            _make_executable(hook_path)
            return "installed (backed up existing hook)"
    else:
        hook_path.write_text(_build_hook_script(), encoding="utf-8")
        _make_executable(hook_path)
        return "installed"


def _uninstall_hook(hooks_dir: Path) -> str:
    """Remove the aigov pre-commit hook from *hooks_dir*. Returns a status string."""
    hook_path = hooks_dir / "pre-commit"
    backup_path = hooks_dir / f"pre-commit{_BACKUP_SUFFIX}"

    if not hook_path.exists():
        return "not installed"

    existing = hook_path.read_text(encoding="utf-8", errors="replace")
    if _HOOK_MARKER not in existing:
        return "not an aigov hook — not removed"

    if backup_path.exists():
        shutil.copy2(backup_path, hook_path)
        _make_executable(hook_path)
        backup_path.unlink()
        return "removed (original hook restored)"
    else:
        hook_path.unlink()
        return "removed"


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@app.command()
def install() -> None:
    """Install the aigov pre-commit hook in the current git repository."""
    try:
        hooks_dir = _find_git_hooks_dir()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    status = _install_hook(hooks_dir)
    hook_path = hooks_dir / "pre-commit"
    console.print(f"[green]aigov pre-commit hook {status}.[/green]")
    console.print(f"  Location: [dim]{hook_path}[/dim]")
    console.print(
        "AI systems will be checked on every commit. "
        "Prohibited systems block commits; high-risk systems warn.\n"
        "Manage exceptions in [bold].aigov-allowlist.yaml[/bold]."
    )


@app.command()
def uninstall() -> None:
    """Remove the aigov pre-commit hook from the current git repository."""
    try:
        hooks_dir = _find_git_hooks_dir()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    status = _uninstall_hook(hooks_dir)
    console.print(f"[green]aigov pre-commit hook:[/green] {status}")
