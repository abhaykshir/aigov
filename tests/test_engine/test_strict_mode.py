"""Tests for ScanResult.scanner_errors and the --strict CLI flag."""
from __future__ import annotations

from typer.testing import CliRunner

from aigov.cli.main import app
from aigov.core.engine import ScanEngine, ScanResult
from aigov.core.models import AISystemRecord
from aigov.scanners.base import BaseScanner


class _BoomScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "code.python_imports"  # masquerade as a real scanner name

    @property
    def description(self) -> str:
        return "Always raises"

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        raise RuntimeError("boom — simulated scanner failure")


def test_scanner_error_is_recorded_in_scan_result(tmp_path):
    """A failing scanner adds entries to both warnings and scanner_errors."""
    engine = ScanEngine(paths=[str(tmp_path)], enabled_scanners=["code.python_imports"])
    # Replace the registered scanner instance with one that throws.
    engine._scanners = [_BoomScanner()]
    result = engine.run()
    assert isinstance(result, ScanResult)
    assert any("boom" in w for w in result.warnings)
    assert any("boom" in e for e in result.scanner_errors)


def test_scan_result_scanner_errors_empty_on_success(tmp_path):
    (tmp_path / "x.py").write_text("print('hi')\n", encoding="utf-8")
    result = ScanEngine(paths=[str(tmp_path)]).run()
    assert result.scanner_errors == []


def test_strict_flag_exits_nonzero_when_scanner_fails(tmp_path, monkeypatch):
    """`aigov scan --strict` must exit code 1 if any scanner raised an error."""
    from aigov.cli import main as cli_main

    original_init = ScanEngine.__init__

    def patched_init(self, paths, enabled_scanners=None, local_config=False):
        original_init(self, paths, enabled_scanners=enabled_scanners, local_config=local_config)
        self._scanners = [_BoomScanner()]

    monkeypatch.setattr(cli_main.ScanEngine if hasattr(cli_main, "ScanEngine") else ScanEngine, "__init__", patched_init)
    monkeypatch.setattr("aigov.core.engine.ScanEngine.__init__", patched_init)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--strict"])
    assert result.exit_code == 1, f"stdout={result.stdout!r} exc={result.exception!r}"
    assert "Strict mode" in result.stdout or "boom" in result.stdout


def test_default_swallows_scanner_failure(tmp_path, monkeypatch):
    """Without --strict, scanner failures are warnings and the CLI returns 0."""
    from aigov.core.engine import ScanEngine as _SE

    original_init = _SE.__init__

    def patched_init(self, paths, enabled_scanners=None, local_config=False):
        original_init(self, paths, enabled_scanners=enabled_scanners, local_config=local_config)
        self._scanners = [_BoomScanner()]

    monkeypatch.setattr("aigov.core.engine.ScanEngine.__init__", patched_init)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, f"stdout={result.stdout!r} exc={result.exception!r}"
