from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Known client config locations
# ---------------------------------------------------------------------------

def _appdata() -> Path:
    return Path(os.environ.get("APPDATA", "~")).expanduser()


def _home() -> Path:
    return Path("~").expanduser()


@dataclass(frozen=True)
class _ClientConfig:
    client_id: str          # used in source_client tag
    path: Path
    json_mcp_key: str | None = None   # dot-path to mcpServers dict, None = root


def _client_configs() -> list[_ClientConfig]:
    is_windows = sys.platform == "win32"
    configs: list[_ClientConfig] = []

    if is_windows:
        configs += [
            _ClientConfig(
                "claude_desktop",
                _appdata() / "Claude" / "claude_desktop_config.json",
            ),
            _ClientConfig(
                "cursor",
                _appdata() / "Cursor" / "User" / "globalStorage" / "cursor.mcp" / "mcp.json",
            ),
            _ClientConfig(
                "windsurf",
                _appdata() / "Windsurf" / "mcp_config.json",
            ),
        ]
    else:
        configs += [
            _ClientConfig(
                "claude_desktop",
                _home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            ),
            _ClientConfig(
                "cursor",
                _home() / ".cursor" / "mcp.json",
            ),
            _ClientConfig(
                "windsurf",
                _home() / ".codeium" / "windsurf" / "mcp_config.json",
            ),
        ]

    return configs


# ---------------------------------------------------------------------------
# MCP transport detection
# ---------------------------------------------------------------------------

def _detect_transport(server_cfg: dict[str, Any]) -> str:
    """Infer transport type from server config fields."""
    if "url" in server_cfg:
        url: str = server_cfg["url"]
        if "sse" in url.lower() or server_cfg.get("transport") == "sse":
            return "sse"
        return "streamable-http"
    transport = server_cfg.get("transport", "")
    if transport:
        return str(transport)
    if "command" in server_cfg:
        return "stdio"
    return "unknown"


# ---------------------------------------------------------------------------
# Jurisdiction hints from package / command names
# ---------------------------------------------------------------------------

_PACKAGE_JURISDICTION: dict[str, str] = {
    # Known US providers
    "@anthropic": "US",
    "@openai": "US",
    "@google": "US",
    "anthropic": "US",
    "openai": "US",
    "google": "US",
    "aws": "US",
    "azure": "US",
    "@aws": "US",
    "@azure": "US",
    "@microsoft": "US",
    "github": "US",
    "stripe": "US",
    "browserbase": "US",
    "firecrawl": "US",
    "replicate": "US",
    # Known CN providers
    "deepseek": "CN",
    "qianfan": "CN",
    "dashscope": "CN",
    "zhipuai": "CN",
    "volcengine": "CN",
    "minimaxi": "CN",
    "moonshot": "CN",
    "sensenova": "CN",
}


def _infer_jurisdiction(server_name: str, command: str, args: list[str]) -> str:
    haystack = " ".join([server_name.lower(), command.lower()] + [a.lower() for a in args])
    for fragment, code in _PACKAGE_JURISDICTION.items():
        if fragment in haystack:
            return code
    return "XX"


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def _extract_mcp_servers(data: dict[str, Any]) -> dict[str, Any]:
    """Return the mcpServers dict from a config, wherever it lives."""
    if "mcpServers" in data:
        val = data["mcpServers"]
        if isinstance(val, dict):
            return val
    # VS Code stores MCP config under various key paths; do a shallow search.
    for key, val in data.items():
        if "mcp" in key.lower() and isinstance(val, dict) and "mcpServers" in val:
            servers = val["mcpServers"]
            if isinstance(servers, dict):
                return servers
    return {}


def _env_var_names(env_dict: Any) -> list[str]:
    """Return just the names of environment variables — never values."""
    if not isinstance(env_dict, dict):
        return []
    return sorted(env_dict.keys())


def _record_id(source_location: str, server_name: str) -> str:
    raw = f"{source_location}:{server_name}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def _build_record(
    server_name: str,
    server_cfg: dict[str, Any],
    source_location: str,
    source_client: str,
    confidence: float,
    timestamp: datetime,
) -> AISystemRecord:
    command: str = server_cfg.get("command", "")
    args: list[str] = server_cfg.get("args", [])
    url: str = server_cfg.get("url", "")
    transport = _detect_transport(server_cfg)

    # Environment variable names only — values are never recorded (SECURITY.md).
    env_names = _env_var_names(server_cfg.get("env", {}))

    tools: list[str] = []
    if isinstance(server_cfg.get("tools"), list):
        tools = [str(t) for t in server_cfg["tools"]]

    transport_hint = command or url or "unknown"
    jurisdiction = _infer_jurisdiction(server_name, transport_hint, args)

    tags: dict[str, str] = {
        "transport": transport,
        "env_vars_passed": str(len(env_names)),
        "env_var_names": ",".join(env_names),
        "source_client": source_client,
        "origin_jurisdiction": jurisdiction,
    }
    if tools:
        tags["declared_tools"] = ",".join(tools)

    description_parts = [f"MCP server '{server_name}'"]
    if command:
        description_parts.append(f"command: {command}")
    if url:
        description_parts.append(f"url: {url}")
    description_parts.append(f"transport: {transport}")

    return AISystemRecord(
        id=_record_id(source_location, server_name),
        name=server_name,
        description=", ".join(description_parts),
        source_scanner="config.mcp_servers",
        source_location=source_location,
        discovery_timestamp=timestamp,
        confidence=confidence,
        system_type=AISystemType.MCP_SERVER,
        provider=server_name,
        deployment_type=DeploymentType.LOCAL,
        tags=tags,
    )


def _parse_config_file(
    path: Path,
    source_client: str,
    confidence: float,
    timestamp: datetime,
) -> list[AISystemRecord]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        console.print(f"[yellow]Warning:[/yellow] invalid JSON in {path} ({exc})")
        return []

    if not isinstance(data, dict):
        return []

    servers = _extract_mcp_servers(data)
    if not servers:
        return []

    records: list[AISystemRecord] = []
    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        records.append(
            _build_record(
                server_name=server_name,
                server_cfg=server_cfg,
                source_location=str(path),
                source_client=source_client,
                confidence=confidence,
                timestamp=timestamp,
            )
        )
    return records


# ---------------------------------------------------------------------------
# Filename → source_client inference
# ---------------------------------------------------------------------------

_FILENAME_CLIENT: dict[str, str] = {
    "claude_desktop_config.json": "claude_desktop",
    "settings.json": "claude_code",      # .claude/settings.json
    "mcp.json": "project_file",
    ".mcp.json": "project_file",
    "mcp_config.json": "project_file",
}

# Cursor's global storage file is also called mcp.json — check parent path fragment.
def _source_client_from_name(filename: str) -> str:
    return _FILENAME_CLIENT.get(filename.lower(), "project_file")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class McpServersScanner(BaseScanner):
    """Discovers MCP server configurations.

    By default only the paths passed to ``scan()`` are inspected — project files
    like ``.mcp.json`` and ``.claude/settings.json`` inside those directories.
    Pass ``local_config=True`` (the ``--local-config`` CLI flag) to also walk
    OS-level config locations such as Claude Desktop, Cursor, and Windsurf user
    configs.  Those locations are off by default because they describe the
    operator's personal environment, not the project being scanned.
    """

    def __init__(self, local_config: bool = False) -> None:
        self._local_config = local_config

    @property
    def name(self) -> str:
        return "config.mcp_servers"

    @property
    def description(self) -> str:
        return "Discovers MCP server configurations from project files (and OS-level configs with --local-config)"

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        timestamp = datetime.now(timezone.utc)
        records: list[AISystemRecord] = []
        seen_locations: set[str] = set()

        # Resolve the paths the user passed so we never accidentally reach into
        # an OS-level client config that happens to share a parent with one of
        # them (e.g. a $HOME-level scan).  Only honour these when --local-config
        # is off.
        scoped_roots: list[Path] = []
        for p in paths:
            try:
                scoped_roots.append(Path(p).resolve())
            except OSError:
                continue

        client_paths: set[str] = set()
        for client in _client_configs():
            try:
                client_paths.add(str(client.path.resolve()))
            except OSError:
                # Path can't be resolved on this platform — still skip it by
                # name comparison via the unresolved string.
                client_paths.add(str(client.path))

        def _ingest(path: Path, client_id: str, confidence: float) -> None:
            try:
                loc = str(path.resolve())
            except OSError:
                loc = str(path)
            if loc in seen_locations:
                return
            # Skip known OS-level client configs unless explicitly opted-in.
            if not self._local_config and loc in client_paths:
                return
            seen_locations.add(loc)
            records.extend(_parse_config_file(path, client_id, confidence, timestamp))

        # 1. Known client config files (OS-specific, not path-relative) — only
        #    when --local-config is set.
        if self._local_config:
            for client in _client_configs():
                _ingest(client.path, client.client_id, 0.95)

        # 2. Explicitly-passed files — parse any JSON file directly.
        #    Confidence follows client identity: known clients = 0.95, generic project files = 0.85.
        _KNOWN_CLIENT_IDS = frozenset({"claude_desktop", "claude_code", "cursor", "windsurf", "vscode"})
        for root_str in paths:
            root = Path(root_str)
            if root.is_file() and root.suffix.lower() == ".json":
                client_id = _source_client_from_name(root.name)
                confidence = 0.95 if client_id in _KNOWN_CLIENT_IDS else 0.85
                _ingest(root, client_id, confidence)

        # 3. Well-known relative config paths inside scanned directories.
        _PROJECT_MCP_NAMES = frozenset({"mcp.json", ".mcp.json", "mcp_config.json"})

        for root_str in paths:
            root = Path(root_str)
            if not root.is_dir():
                continue

            # Claude Code
            for rel in [".claude/settings.json", ".mcp.json"]:
                _ingest(root / rel, "claude_code", 0.95)

            # VS Code
            for vscode_settings in root.rglob(".vscode/settings.json"):
                _ingest(vscode_settings, "vscode", 0.95)

            # Generic project MCP files found by walking the tree
            for candidate in root.rglob("*"):
                if candidate.is_file() and candidate.name in _PROJECT_MCP_NAMES:
                    _ingest(candidate, "project_file", 0.85)

        return records
