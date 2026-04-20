from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from rich.console import Console

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

console = Console(stderr=True)

_MAX_FILE_BYTES = 1_048_576  # 1 MB

_SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", "__pycache__", ".git", ".tox", "site-packages",
})

# Exact directory-name components to skip (whole component, not substring).
# Prevents false positives from test fixtures and documentation samples.
_SKIP_PATH_COMPONENTS = frozenset({
    "test", "tests", "__tests__",
    "fixture", "fixtures",
    "mock", "mocks", "__mocks__",
    "example", "examples",
    "spec", "specs",
    "docs", "documentation",
})

_SCANNABLE_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".yaml", ".yml", ".json", ".toml",
    ".env", ".sh", ".bash", ".cfg", ".ini", ".conf",
})

# Filenames with no extension that are also scannable.
_SCANNABLE_NAMES = re.compile(r"^(docker-compose[^/\\]*|\.env(\.[^/\\]+)?)$", re.IGNORECASE)


class _PatternDef(NamedTuple):
    label: str          # human-readable key type
    provider: str
    jurisdiction: str
    pattern: re.Pattern[str]
    confidence: float
    context_pattern: re.Pattern[str] | None  # if set, line must also match this


# Redact everything after the first 4 characters, keeping the prefix readable.
def _redact(value: str) -> str:
    return value[:4] + "****"


def _make_record(
    file_path: str,
    lineno: int,
    defn: _PatternDef,
    key_preview: str,
    timestamp: datetime,
) -> AISystemRecord:
    record_id = hashlib.sha1(f"{file_path}:{lineno}:{defn.label}".encode()).hexdigest()[:16]
    return AISystemRecord(
        id=record_id,
        name=f"{defn.label} detected",
        description=f"{defn.label} found in source file — value redacted per security policy",
        source_scanner="code.api_keys",
        source_location=f"{file_path}:{lineno}",
        discovery_timestamp=timestamp,
        confidence=defn.confidence,
        system_type=AISystemType.API_SERVICE,
        provider=defn.provider,
        deployment_type=DeploymentType.CLOUD_API,
        tags={
            "key_type": defn.label,
            "key_preview": key_preview,
            "origin_jurisdiction": defn.jurisdiction,
        },
    )


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_PATTERNS: list[_PatternDef] = [
    # OpenAI project key (more specific — check before generic sk-)
    _PatternDef(
        label="OpenAI API Key (project)",
        provider="OpenAI",
        jurisdiction="US",
        pattern=_compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # OpenAI legacy key
    _PatternDef(
        label="OpenAI API Key",
        provider="OpenAI",
        jurisdiction="US",
        pattern=_compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # Anthropic
    _PatternDef(
        label="Anthropic API Key",
        provider="Anthropic",
        jurisdiction="US",
        pattern=_compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # Google AI (AIza...)
    _PatternDef(
        label="Google AI API Key",
        provider="Google",
        jurisdiction="US",
        pattern=_compile(r"\bAIza[A-Za-z0-9_\-]{35}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # HuggingFace
    _PatternDef(
        label="HuggingFace API Token",
        provider="HuggingFace",
        jurisdiction="US",
        pattern=_compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # Cohere
    _PatternDef(
        label="Cohere API Key",
        provider="Cohere",
        jurisdiction="CA",
        pattern=_compile(r"\bco-[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # Replicate
    _PatternDef(
        label="Replicate API Token",
        provider="Replicate",
        jurisdiction="US",
        pattern=_compile(r"\br8_[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # Azure OpenAI endpoint URL
    _PatternDef(
        label="Azure OpenAI Endpoint",
        provider="Azure",
        jurisdiction="US",
        pattern=_compile(r"https?://[a-zA-Z0-9_\-]+\.openai\.azure\.com\b"),
        confidence=0.95,
        context_pattern=None,
    ),
    # AWS access key — only when bedrock/sagemaker appears nearby (same line)
    _PatternDef(
        label="AWS Access Key ID (AI context)",
        provider="AWS",
        jurisdiction="US",
        pattern=_compile(r"\bAKIA[A-Z0-9]{16}\b"),
        confidence=0.7,
        context_pattern=_compile(r"bedrock|sagemaker", re.IGNORECASE),
    ),
    # DeepSeek — generic sk- near deepseek reference (same line)
    _PatternDef(
        label="DeepSeek API Key",
        provider="DeepSeek",
        jurisdiction="CN",
        pattern=_compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        confidence=0.7,
        context_pattern=_compile(r"deepseek", re.IGNORECASE),
    ),
]


def _is_scannable(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    if suffix in _SCANNABLE_SUFFIXES:
        return True
    if _SCANNABLE_NAMES.match(name):
        return True
    return False


def _should_skip(path: Path) -> bool:
    parts_lower = [p.lower() for p in path.parts]
    if any(part in _SKIP_DIRS for part in parts_lower):
        return True
    if any(part in _SKIP_PATH_COMPONENTS for part in parts_lower):
        return True
    return False


def _scan_file(
    file_path: Path,
    timestamp: datetime,
    seen: set[tuple[str, str]],
) -> list[AISystemRecord]:
    try:
        if file_path.stat().st_size > _MAX_FILE_BYTES:
            return []
        raw = file_path.read_bytes()
        # Bail out on binary files: look for null bytes in the first 8 KB.
        if b"\x00" in raw[:8192]:
            return []
        text = raw.decode("utf-8", errors="replace")
    except OSError as exc:
        console.print(f"[yellow]Warning:[/yellow] skipping {file_path} (read error: {exc.strerror})")
        return []

    records: list[AISystemRecord] = []
    lines = text.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for defn in _PATTERNS:
            if defn.context_pattern and not defn.context_pattern.search(line):
                continue

            for match in defn.pattern.finditer(line):
                raw_value = match.group(0)
                key_preview = _redact(raw_value)

                dedup_key = (str(file_path), defn.label)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                records.append(_make_record(str(file_path), lineno, defn, key_preview, timestamp))

    return records


class ApiKeysScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "code.api_keys"

    @property
    def description(self) -> str:
        return "Detects AI service API keys and credentials in source code and config files"

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        timestamp = datetime.now(timezone.utc)
        records: list[AISystemRecord] = []
        seen: set[tuple[str, str]] = set()

        for root_path in paths:
            root = Path(root_path)
            candidates: list[Path] = []

            if root.is_file():
                candidates = [root]
            elif root.is_dir():
                candidates = list(root.rglob("*"))

            for path in candidates:
                if not path.is_file():
                    continue
                if _should_skip(path):
                    continue
                if not _is_scannable(path):
                    continue
                records.extend(_scan_file(path, timestamp, seen))

        return records
