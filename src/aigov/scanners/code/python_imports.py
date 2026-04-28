from __future__ import annotations

import ast
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from rich.console import Console

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

console = Console(stderr=True)

_SKIP_DIRS = frozenset({
    ".venv", "venv", "node_modules", "__pycache__", ".git", ".tox", "site-packages",
})

# Exact directory-name components to skip (whole component, not substring).
# Mirrors api_keys.py — prevents false positives from test fixtures and samples.
_SKIP_PATH_COMPONENTS = frozenset({
    "test", "tests", "__tests__",
    "fixture", "fixtures",
    "mock", "mocks", "__mocks__",
    "example", "examples",
    "spec", "specs",
    "docs", "documentation",
    "test_data",
})


class _LibraryDef(NamedTuple):
    provider: str
    system_type: AISystemType
    deployment_type: DeploymentType
    tags: dict[str, str]


def _t(jurisdiction: str) -> dict[str, str]:
    return {"origin_jurisdiction": jurisdiction}


# Maps top-level import root → library definition.
# boto3 is handled separately (needs heuristic for bedrock/sagemaker).
_LIBRARY_MAP: dict[str, _LibraryDef] = {
    # US cloud APIs
    "openai": _LibraryDef("OpenAI", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "anthropic": _LibraryDef("Anthropic", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "google": _LibraryDef("Google", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "vertexai": _LibraryDef("Google", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "azure": _LibraryDef("Azure", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    # Non-US Western cloud APIs
    "cohere": _LibraryDef("Cohere", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CA")),
    "mistralai": _LibraryDef("Mistral", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("FR")),
    # US local / self-hosted model libraries
    "transformers": _LibraryDef("HuggingFace", AISystemType.MODEL, DeploymentType.SELF_HOSTED, _t("US")),
    "torch": _LibraryDef("PyTorch", AISystemType.MODEL, DeploymentType.SELF_HOSTED, _t("US")),
    "tensorflow": _LibraryDef("TensorFlow", AISystemType.MODEL, DeploymentType.SELF_HOSTED, _t("US")),
    # US agent / orchestration frameworks
    "langchain": _LibraryDef("LangChain", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "langchain_core": _LibraryDef("LangChain", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "langchain_community": _LibraryDef("LangChain", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "langchain_openai": _LibraryDef("LangChain", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "llama_index": _LibraryDef("LlamaIndex", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "crewai": _LibraryDef("CrewAI", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    "autogen": _LibraryDef("AutoGen", AISystemType.AGENT, DeploymentType.LOCAL, _t("US")),
    # Chinese AI providers (CN)
    "dashscope": _LibraryDef("Alibaba (Qwen/Tongyi)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "modelscope": _LibraryDef("Alibaba (Qwen/Tongyi)", AISystemType.MODEL, DeploymentType.SELF_HOSTED, _t("CN")),
    "zhipuai": _LibraryDef("Zhipu AI (GLM/ChatGLM)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "qianfan": _LibraryDef("Baidu (ERNIE/Wenxin)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "erniebot": _LibraryDef("Baidu (ERNIE/Wenxin)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "volcengine": _LibraryDef("ByteDance (Doubao/Skylark)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "ark": _LibraryDef("ByteDance (Doubao/Skylark)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "minimaxi": _LibraryDef("MiniMax", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "moonshot": _LibraryDef("Moonshot AI (Kimi)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "kimi": _LibraryDef("Moonshot AI (Kimi)", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "deepseek": _LibraryDef("DeepSeek", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
    "sensenova": _LibraryDef("SenseTime", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("CN")),
}

# Sub-module prefixes that narrow a top-level match (checked before the generic root).
_PREFIX_OVERRIDES: dict[str, _LibraryDef] = {
    "google.generativeai": _LibraryDef("Google", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "azure.ai": _LibraryDef("Azure", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
    "azure.cognitiveservices": _LibraryDef("Azure", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US")),
}

# Boto3 keywords that indicate AI/ML usage.
_BOTO3_AI_KEYWORDS = frozenset({"bedrock", "sagemaker"})


def _should_skip(path: Path, scan_root: Path | None = None) -> bool:
    """Decide whether *path* should be excluded from scanning.

    The skip list (``test``, ``examples``, ``mocks`` …) prevents noise from
    sample / fixture code inside a real project — but it also prevents users
    from pointing aigov *at* an examples directory and getting any output.
    To support both, we only apply the skip list to path components **below**
    ``scan_root``: anything in the scan-root prefix itself is the user's
    deliberate target and exempt.
    """
    parts_lower = _components_below_root(path, scan_root)
    if any(part in _SKIP_DIRS for part in parts_lower):
        return True
    if any(part in _SKIP_PATH_COMPONENTS for part in parts_lower):
        return True
    return False


def _components_below_root(path: Path, scan_root: Path | None) -> list[str]:
    """Return *path*'s components below the scan root, lowercased.

    Falls back to every component of *path* when ``scan_root`` is None or
    when *path* is not a descendant of it — preserving the original
    scan-everything behaviour for callers that don't pass a root.
    """
    parts_lower = [p.lower() for p in path.parts]
    if scan_root is None:
        return parts_lower
    try:
        rel = path.resolve().relative_to(scan_root.resolve())
    except (OSError, ValueError):
        return parts_lower
    return [p.lower() for p in rel.parts]


def _import_root(name: str) -> str:
    return name.split(".")[0]


def _resolve_library(module_name: str) -> _LibraryDef | None:
    for prefix, defn in _PREFIX_OVERRIDES.items():
        if module_name == prefix or module_name.startswith(prefix + "."):
            return defn
    root = _import_root(module_name)
    return _LIBRARY_MAP.get(root)


def _record_id(file_path: str, lineno: int, provider: str) -> str:
    raw = f"{file_path}:{lineno}:{provider}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def _extract_names(tree: ast.AST) -> tuple[list[str], list[str]]:
    """Return (func_names, class_names) extracted from AST definition nodes.

    Only reads identifier names from def/async def/class declarations —
    never accesses bodies, arguments, default values, decorators, or docstrings.
    Dunder names (__init__ etc.) are omitted to reduce noise.
    Names are returned in source order, deduplicated.
    """
    candidates: list[tuple[int, str, str]] = []  # (lineno, kind, name)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            candidates.append((getattr(node, "lineno", 0), "class", node.name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name
            if not (name.startswith("__") and name.endswith("__")):
                candidates.append((getattr(node, "lineno", 0), "func", name))

    candidates.sort(key=lambda t: t[0])

    func_names: list[str] = []
    class_names: list[str] = []
    seen_funcs: set[str] = set()
    seen_classes: set[str] = set()
    for _, kind, name in candidates:
        if kind == "class" and name not in seen_classes:
            seen_classes.add(name)
            class_names.append(name)
        elif kind == "func" and name not in seen_funcs:
            seen_funcs.add(name)
            func_names.append(name)

    return func_names, class_names


def _make_description(module_name: str, func_names: list[str], class_names: list[str]) -> str:
    parts = [f"imports: {module_name}"]
    if class_names:
        parts.append(f"classes: {', '.join(class_names)}")
    if func_names:
        parts.append(f"functions: {', '.join(func_names)}")
    return "; ".join(parts)


def _make_record(
    file_path: str,
    lineno: int,
    module_name: str,
    lib: _LibraryDef,
    timestamp: datetime,
    func_names: list[str],
    class_names: list[str],
) -> AISystemRecord:
    source_location = f"{file_path}:{lineno}"
    return AISystemRecord(
        id=_record_id(file_path, lineno, lib.provider),
        name=f"{lib.provider} via {module_name}",
        description=_make_description(module_name, func_names, class_names),
        source_scanner="code.python_imports",
        source_location=source_location,
        discovery_timestamp=timestamp,
        confidence=0.85,
        system_type=lib.system_type,
        provider=lib.provider,
        deployment_type=lib.deployment_type,
        tags=dict(lib.tags),
    )


def _scan_file(
    file_path: Path,
    timestamp: datetime,
    seen: set[tuple[str, str]],
) -> list[AISystemRecord]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as exc:
        console.print(f"[yellow]Warning:[/yellow] skipping {file_path} (syntax error: {exc.msg})")
        return []
    except OSError as exc:
        console.print(f"[yellow]Warning:[/yellow] skipping {file_path} (read error: {exc.strerror})")
        return []

    # Extract definition names once per file; all records from this file share them.
    func_names, class_names = _extract_names(tree)

    records: list[AISystemRecord] = []
    boto3_seen_at: int | None = None
    boto3_ai_found = False

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules: list[tuple[str, int]] = []

            if isinstance(node, ast.Import):
                modules = [(alias.name, node.lineno) for alias in node.names]
            else:
                if node.module:
                    modules = [(node.module, node.lineno)]

            for module_name, lineno in modules:
                root = _import_root(module_name)

                if root == "boto3":
                    boto3_seen_at = lineno
                    continue

                lib = _resolve_library(module_name)
                if lib is None:
                    continue

                dedup_key = (str(file_path), lib.provider)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                records.append(
                    _make_record(str(file_path), lineno, module_name, lib, timestamp, func_names, class_names)
                )

        # Detect boto3 AI usage via string literals: e.g. client("bedrock-runtime")
        elif boto3_seen_at is not None and isinstance(node, ast.Constant) and isinstance(node.value, str):
            val_lower = node.value.lower()
            if any(kw in val_lower for kw in _BOTO3_AI_KEYWORDS):
                boto3_ai_found = True

    if boto3_seen_at is not None and boto3_ai_found:
        lib = _LibraryDef("AWS", AISystemType.API_SERVICE, DeploymentType.CLOUD_API, _t("US"))
        dedup_key = (str(file_path), lib.provider)
        if dedup_key not in seen:
            seen.add(dedup_key)
            records.append(
                _make_record(str(file_path), boto3_seen_at, "boto3", lib, timestamp, func_names, class_names)
            )

    return records


class PythonImportsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "code.python_imports"

    @property
    def description(self) -> str:
        return "Detects AI/ML libraries and API usage in Python source files"

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        timestamp = datetime.now(timezone.utc)
        records: list[AISystemRecord] = []
        seen: set[tuple[str, str]] = set()

        for root_path in paths:
            root = Path(root_path)
            if root.is_file() and root.suffix == ".py":
                # A direct file argument is exempt — the user pointed at it.
                records.extend(_scan_file(root, timestamp, seen))
            elif root.is_dir():
                for py_file in root.rglob("*.py"):
                    if not _should_skip(py_file, scan_root=root):
                        records.extend(_scan_file(py_file, timestamp, seen))

        return records
