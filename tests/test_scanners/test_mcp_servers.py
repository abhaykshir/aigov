from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aigov.core.models import AISystemType, DeploymentType
from aigov.scanners.config.mcp_servers import McpServersScanner

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
CLAUDE_DESKTOP_FIXTURE = FIXTURE_DIR / "fake_claude_desktop_config.json"
MCP_JSON_FIXTURE = FIXTURE_DIR / "fake_mcp.json"

# Env-var values that appear in the fixture files and must NEVER leak into records.
_SECRET_VALUES = [
    "FAKE_TOKEN_NEVER_REAL",
    "FAKE_BRAVE_KEY_NEVER_REAL",
]


def _scan_from_fixture(tmp_path: Path, fixture_src: Path, filename: str) -> list:
    """Copy a fixture into a neutral tmp dir and scan it directly."""
    dest = tmp_path / filename
    shutil.copy(fixture_src, dest)
    return McpServersScanner().scan([str(dest)])


def _scan_desktop_fixture(tmp_path: Path) -> list:
    return _scan_from_fixture(tmp_path, CLAUDE_DESKTOP_FIXTURE, "claude_desktop_config.json")


def _scan_mcp_json_fixture(tmp_path: Path) -> list:
    return _scan_from_fixture(tmp_path, MCP_JSON_FIXTURE, "mcp.json")


def _all_string_values(rec) -> list[str]:
    def _walk(obj, out: list[str]) -> None:
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v, out)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v, out)
    out: list[str] = []
    _walk(rec.to_dict(), out)
    return out


# ---------------------------------------------------------------------------
# Scanner metadata
# ---------------------------------------------------------------------------

def test_scanner_name():
    assert McpServersScanner().name == "config.mcp_servers"


def test_scanner_does_not_require_credentials():
    assert McpServersScanner().requires_credentials is False


# ---------------------------------------------------------------------------
# Discovery — claude_desktop_config.json via direct file path
# ---------------------------------------------------------------------------

def test_desktop_finds_two_servers(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    names = {r.name for r in recs}
    assert "filesystem" in names
    assert "github" in names


def test_desktop_system_type_is_mcp_server(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    assert all(r.system_type == AISystemType.MCP_SERVER for r in recs)


def test_desktop_deployment_type_is_local(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    assert all(r.deployment_type == DeploymentType.LOCAL for r in recs)


# ---------------------------------------------------------------------------
# Transport detection
# ---------------------------------------------------------------------------

def test_filesystem_transport_is_stdio(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    fs = next(r for r in recs if r.name == "filesystem")
    assert fs.tags["transport"] == "stdio"


def test_brave_search_transport_is_sse(tmp_path):
    recs = _scan_mcp_json_fixture(tmp_path)
    brave = next(r for r in recs if r.name == "brave-search")
    assert brave.tags["transport"] == "sse"


# ---------------------------------------------------------------------------
# Env var exposure surface
# ---------------------------------------------------------------------------

def test_github_records_env_var_count(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    github = next(r for r in recs if r.name == "github")
    assert github.tags["env_vars_passed"] == "2"


def test_filesystem_has_no_env_vars(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    fs = next(r for r in recs if r.name == "filesystem")
    assert fs.tags["env_vars_passed"] == "0"


def test_env_var_names_are_recorded(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    github = next(r for r in recs if r.name == "github")
    names = github.tags.get("env_var_names", "")
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in names
    assert "GITHUB_REPO" in names


# ---------------------------------------------------------------------------
# CRITICAL: env-var values must never appear in any record field
# ---------------------------------------------------------------------------

def test_no_secret_values_in_desktop_records(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    for rec in recs:
        strings = _all_string_values(rec)
        for secret in _SECRET_VALUES:
            for s in strings:
                assert secret not in s, (
                    f"Secret value leaked into record field for {rec.name!r}"
                )


def test_no_secret_values_in_mcp_json_records(tmp_path):
    recs = _scan_mcp_json_fixture(tmp_path)
    for rec in recs:
        strings = _all_string_values(rec)
        for secret in _SECRET_VALUES:
            for s in strings:
                assert secret not in s, (
                    f"Secret value leaked into record field for {rec.name!r}"
                )


def test_no_secret_values_in_json_serialisation(tmp_path):
    recs = _scan_desktop_fixture(tmp_path) + _scan_mcp_json_fixture(tmp_path)
    blob = json.dumps([r.to_dict() for r in recs])
    for secret in _SECRET_VALUES:
        assert secret not in blob, f"Secret value found in JSON output"


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

def test_direct_file_scan_uses_project_file_confidence(tmp_path):
    # Scanning a file directly by path → "project_file" source at 0.85
    recs = _scan_mcp_json_fixture(tmp_path)
    assert all(r.confidence == 0.85 for r in recs)


def test_source_client_tag_set_for_project_file(tmp_path):
    recs = _scan_mcp_json_fixture(tmp_path)
    assert all(r.tags["source_client"] == "project_file" for r in recs)


def test_source_client_tag_for_desktop_config(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    assert all(r.tags["source_client"] == "claude_desktop" for r in recs)


# ---------------------------------------------------------------------------
# Walking a directory finds .mcp.json
# ---------------------------------------------------------------------------

def test_directory_walk_finds_mcp_json(tmp_path):
    dest = tmp_path / ".mcp.json"
    shutil.copy(MCP_JSON_FIXTURE, dest)
    recs = McpServersScanner().scan([str(tmp_path)])
    names = {r.name for r in recs}
    assert "brave-search" in names


def test_directory_walk_finds_mcp_config_json(tmp_path):
    dest = tmp_path / "mcp_config.json"
    shutil.copy(MCP_JSON_FIXTURE, dest)
    recs = McpServersScanner().scan([str(tmp_path)])
    names = {r.name for r in recs}
    assert "brave-search" in names


# ---------------------------------------------------------------------------
# Claude Code settings.json in .claude/
# ---------------------------------------------------------------------------

def test_finds_claude_code_settings(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "mcpServers": {
            "my-tool": {
                "command": "node",
                "args": ["server.js"]
            }
        }
    }
    (claude_dir / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    recs = McpServersScanner().scan([str(tmp_path)])
    names = {r.name for r in recs}
    assert "my-tool" in names


def test_claude_code_settings_confidence(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {"mcpServers": {"dev-server": {"command": "python", "args": ["srv.py"]}}}
    (claude_dir / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    recs = McpServersScanner().scan([str(tmp_path)])
    dev = next(r for r in recs if r.name == "dev-server")
    assert dev.confidence == 0.95
    assert dev.tags["source_client"] == "claude_code"


# ---------------------------------------------------------------------------
# Tools list
# ---------------------------------------------------------------------------

def test_declared_tools_captured(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    fs = next(r for r in recs if r.name == "filesystem")
    tools = fs.tags.get("declared_tools", "")
    assert "read_file" in tools
    assert "write_file" in tools


# ---------------------------------------------------------------------------
# Origin jurisdiction
# ---------------------------------------------------------------------------

def test_all_records_have_origin_jurisdiction(tmp_path):
    recs = _scan_desktop_fixture(tmp_path) + _scan_mcp_json_fixture(tmp_path)
    for rec in recs:
        assert "origin_jurisdiction" in rec.tags, f"{rec.name} missing origin_jurisdiction"


def test_github_server_jurisdiction_us(tmp_path):
    recs = _scan_desktop_fixture(tmp_path)
    github = next(r for r in recs if r.name == "github")
    assert github.tags["origin_jurisdiction"] == "US"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_invalid_json_skipped(tmp_path):
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not valid json", encoding="utf-8")
    recs = McpServersScanner().scan([str(tmp_path)])
    assert recs == []


def test_missing_mcp_servers_key_skipped(tmp_path):
    f = tmp_path / "mcp.json"
    f.write_text('{"someOtherKey": {}}', encoding="utf-8")
    recs = McpServersScanner().scan([str(tmp_path)])
    assert recs == []


def test_nonexistent_client_config_silently_ignored():
    # Scanning a path that has no client configs should not raise.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        recs = McpServersScanner().scan([td])
    assert isinstance(recs, list)


# ---------------------------------------------------------------------------
# Deduplication — same file not processed twice
# ---------------------------------------------------------------------------

def test_no_duplicate_records_for_same_file(tmp_path):
    dest = tmp_path / ".mcp.json"
    shutil.copy(MCP_JSON_FIXTURE, dest)
    # Scan the same path twice.
    recs = McpServersScanner().scan([str(tmp_path), str(tmp_path)])
    brave_recs = [r for r in recs if r.name == "brave-search"]
    assert len(brave_recs) == 1, f"Expected 1 record, got {len(brave_recs)}"


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def test_to_dict_json_safe(tmp_path):
    recs = _scan_desktop_fixture(tmp_path) + _scan_mcp_json_fixture(tmp_path)
    for rec in recs:
        json.dumps(rec.to_dict())  # must not raise


# ---------------------------------------------------------------------------
# --local-config scope: OS-level configs are ignored by default
# ---------------------------------------------------------------------------

def test_default_does_not_scan_os_client_configs(tmp_path, monkeypatch):
    """Without local_config, the scanner must not pull in OS-level client configs.

    We point APPDATA / HOME at an empty tmp dir to make sure that even if a
    real Claude Desktop / Cursor config exists on the host, the scanner ignores
    it — and that scanning an empty project tree returns zero records.
    """
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("APPDATA", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    project = tmp_path / "proj"
    project.mkdir()

    recs = McpServersScanner().scan([str(project)])
    assert recs == []


def test_local_config_flag_scans_os_client_configs(tmp_path, monkeypatch):
    """With local_config=True, an OS-level Claude Desktop config is detected."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("APPDATA", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    # Plant a fake client config in the location the scanner expects.
    import sys
    if sys.platform == "win32":
        target = fake_home / "Claude" / "claude_desktop_config.json"
    else:
        target = fake_home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(CLAUDE_DESKTOP_FIXTURE, target)

    project = tmp_path / "proj"
    project.mkdir()

    # Default mode — must NOT find the OS-level config.
    default_recs = McpServersScanner().scan([str(project)])
    assert default_recs == []

    # Opt-in mode — must find the OS-level config.
    local_recs = McpServersScanner(local_config=True).scan([str(project)])
    names = {r.name for r in local_recs}
    assert "filesystem" in names or "github" in names


def test_local_config_flag_does_not_break_project_file_scan(tmp_path, monkeypatch):
    """Project-level files inside the scanned dir continue to work in either mode."""
    fake_home = tmp_path / "fake_home"
    fake_home.mkdir()
    monkeypatch.setenv("APPDATA", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))

    project = tmp_path / "proj"
    project.mkdir()
    shutil.copy(MCP_JSON_FIXTURE, project / ".mcp.json")

    for scanner in (McpServersScanner(), McpServersScanner(local_config=True)):
        recs = scanner.scan([str(project)])
        names = {r.name for r in recs}
        assert "brave-search" in names
