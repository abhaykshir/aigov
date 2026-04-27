"""Context enrichment for risk scoring.

For each AISystemRecord, ``enrich()`` infers four context signals from the
surrounding repository:

* ``environment`` — production / staging / development / test / unknown
* ``exposure`` — public_api / internal_service / batch_offline / unknown
* ``data_sensitivity`` — list of categories (pii, financial, auth, health)
* ``interaction_type`` — user_facing_realtime / batch_offline / internal_tooling / unknown

SECURITY (per SECURITY.md): file contents are read solely to test for the
presence of fixed patterns. The text never leaves this module — only the
boolean / categorical results do.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from aigov.core.models import AISystemRecord

# How many bytes to read from any one file. Risk patterns are short and live
# near the top of source files, so a small cap keeps memory bounded on large
# generated files (notebooks, vendored bundles, etc.) without losing signal.
_MAX_BYTES_SOURCE = 200_000
_MAX_BYTES_SIBLING = 20_000

# File extensions we'll text-scan for patterns. Other types (binaries,
# images) are skipped entirely.
_TEXT_SUFFIXES = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".env",
    ".yaml", ".yml", ".json", ".tf", ".toml", ".ini", ".cfg",
    ".dockerfile", ".sh",
})

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------

# Each environment maps to the path tokens that imply it. Order in the value
# list does not matter; precedence between environments is enforced below.
_ENV_TOKENS: dict[str, list[str]] = {
    "production": ["production", "prod"],
    "staging": ["staging", "stage"],
    "test": ["test", "tests"],
    "development": ["development", "dev"],
}

# Precedence when multiple environments match. Production wins because we
# want to err on the side of treating ambiguous code as the higher-stakes
# environment for risk purposes.
_ENV_PRECEDENCE: tuple[str, ...] = ("production", "staging", "test", "development")

_DOTENV_RE = re.compile(
    r"\.env\.(production|prod|staging|stage|development|dev|test)\b",
    re.IGNORECASE,
)

_CI_ENV_VARS = ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "JENKINS_HOME", "GITLAB_CI")


def _word_match(token: str, text: str) -> bool:
    """Match *token* as a word, treating both non-word characters AND underscores
    as boundaries.

    Python's ``\\b`` keeps ``_`` on the word side, so ``\\bpayment\\b`` would not
    match ``charge_payment`` — but in practice variable and function names like
    ``charge_payment`` and ``fetch_patient`` are exactly the signal we want.
    The custom boundary uses look-arounds against ``[A-Za-z0-9]`` so that any
    other character (``_``, ``-``, ``/``, ``.``, end-of-string) counts as a
    boundary.
    """
    pattern = rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def _detect_environment(parts: list[str]) -> str:
    haystack = " ".join(parts)

    # Explicit .env.<env> filenames are the strongest signal — short-circuit.
    m = _DOTENV_RE.search(haystack)
    if m:
        suffix = m.group(1).lower()
        for env_name, tokens in _ENV_TOKENS.items():
            if suffix in tokens:
                return env_name

    # Token presence in any haystack fragment (paths, source content).
    found: set[str] = set()
    for env_name, tokens in _ENV_TOKENS.items():
        for tok in tokens:
            if _word_match(tok, haystack):
                found.add(env_name)
                break

    # CI runners imply we're in a test/build context unless something stronger
    # already fired (e.g. a Terraform file under prod/).
    if any(os.environ.get(v) for v in _CI_ENV_VARS) and not found:
        return "test"

    for env_name in _ENV_PRECEDENCE:
        if env_name in found:
            return env_name
    return "unknown"


# ---------------------------------------------------------------------------
# Exposure detection
# ---------------------------------------------------------------------------

_FRAMEWORK_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "fastapi": [
        re.compile(r"\bfrom\s+fastapi\b", re.IGNORECASE),
        re.compile(r"\bimport\s+fastapi\b", re.IGNORECASE),
        re.compile(r"@\w+\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
        re.compile(r"\bAPIRouter\b"),
    ],
    "flask": [
        re.compile(r"\bfrom\s+flask\b", re.IGNORECASE),
        re.compile(r"@\w+\.route\s*\(", re.IGNORECASE),
    ],
    "express": [
        re.compile(r"require\(\s*['\"]express['\"]\s*\)"),
        re.compile(r"\brouter\.(get|post|put|delete|patch)\s*\(", re.IGNORECASE),
    ],
    "django": [
        re.compile(r"\bfrom\s+django\b", re.IGNORECASE),
        re.compile(r"\burlpatterns\b"),
    ],
}

_OPENAPI_HINT_RE = re.compile(r"\b(openapi\.json|swagger\.json|swagger\.yaml)\b", re.IGNORECASE)
_API_PATH_RE = re.compile(r"[/\\]api[/\\]", re.IGNORECASE)
_INTERNAL_PATH_RE = re.compile(r"\b(internal|private|rpc)\b", re.IGNORECASE)
_BATCH_PATH_RE = re.compile(
    r"\b(batch|cron|worker|etl|scheduled|airflow|nightly|pipeline)\b",
    re.IGNORECASE,
)


def _has_framework(text: str) -> bool:
    return any(pat.search(text) for pats in _FRAMEWORK_PATTERNS.values() for pat in pats)


def _detect_exposure(parts: list[str]) -> str:
    haystack = " ".join(parts)

    framework_present = _has_framework(haystack)
    if framework_present:
        if _INTERNAL_PATH_RE.search(haystack):
            return "internal_service"
        return "public_api"

    if _OPENAPI_HINT_RE.search(haystack) or _API_PATH_RE.search(haystack):
        return "public_api"

    if _BATCH_PATH_RE.search(haystack):
        return "batch_offline"

    return "unknown"


# ---------------------------------------------------------------------------
# Data sensitivity detection
# ---------------------------------------------------------------------------

_DATA_KEYWORDS: dict[str, list[str]] = {
    "pii": ["email", "ssn", "social_security", "user_data"],
    "financial": [
        "payment", "credit_card", "card_number", "financial",
        "salary", "bank_account",
    ],
    "auth": ["password", "auth_token"],
    "health": ["patient", "medical", "diagnosis"],
}


def _detect_data_sensitivity(parts: list[str]) -> list[str]:
    """Return the categories whose keywords appear anywhere in *parts*.

    The match is whole-word, case-insensitive. Categories are returned in a
    deterministic order to keep risk drivers stable across runs.
    """
    haystack = " ".join(parts)
    matched: list[str] = []
    for category in ("pii", "financial", "health", "auth"):
        for kw in _DATA_KEYWORDS[category]:
            if _word_match(kw, haystack):
                matched.append(category)
                break
    return matched


# ---------------------------------------------------------------------------
# Interaction type
# ---------------------------------------------------------------------------

_REALTIME_RE = re.compile(
    r"(@\w+\.(get|post|put|delete|patch|route)\s*\(|"
    r"\bdef\s+(get|post|put|delete|patch)\s*\(|"
    r"\brequest\.(form|json|args|files)\b|"
    r"\bchat(_|\.|bot|gpt)|"
    r"\bwebsocket\b)",
    re.IGNORECASE,
)

_BATCH_INTERACTION_RE = re.compile(
    r"(@(scheduled|cron|periodic_task)\b|"
    r"\bairflow\b|"
    r"\bdef\s+process_batch\b|"
    r"\bbatch_size\b|"
    r"\bcron\b)",
    re.IGNORECASE,
)

_INTERNAL_TOOL_RE = re.compile(
    r"(\bargparse\.ArgumentParser\b|"
    r"\bif\s+__name__\s*==\s*['\"]__main__['\"]|"
    r"\bclick\.command\b)",
    re.IGNORECASE,
)


def _detect_interaction_type(parts: list[str]) -> str:
    haystack = " ".join(parts)
    if _REALTIME_RE.search(haystack):
        return "user_facing_realtime"
    if _BATCH_INTERACTION_RE.search(haystack) or _BATCH_PATH_RE.search(haystack):
        return "batch_offline"
    if _INTERNAL_TOOL_RE.search(haystack):
        return "internal_tooling"
    return "unknown"


# ---------------------------------------------------------------------------
# File access helpers
# ---------------------------------------------------------------------------

def _strip_line_suffix(loc: str) -> str:
    return re.sub(r"[:#]L?\d+$", "", loc)


def _record_file(record: AISystemRecord) -> Path | None:
    """Return the source file backing a record, or None for synthetic locations."""
    loc = _strip_line_suffix(record.source_location)
    # Cloud / opaque identifiers — no readable file.
    if loc.startswith("arn:") or loc.startswith("http://") or loc.startswith("https://"):
        return None
    try:
        p = Path(loc)
    except (OSError, ValueError):
        return None
    if p.exists() and p.is_file():
        return p
    return None


def _read_text(path: Path, max_bytes: int) -> str:
    """Read up to *max_bytes* of text. Errors yield an empty string — never raise."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except OSError:
        return ""


def _resolved_roots(scan_paths: list[str]) -> list[Path]:
    roots: list[Path] = []
    for raw in scan_paths:
        try:
            p = Path(raw)
            if p.exists():
                roots.append(p.resolve())
        except (OSError, ValueError):
            continue
    return roots


def _relativize(path_str: str, roots: list[Path]) -> str:
    """Return *path_str* relative to the first parent root, else unchanged.

    Without this, the haystack would include absolute paths whose parent
    directories often contain unrelated tokens (e.g. pytest's
    ``test_<name>0/`` per-test tmp dir, or ``/usr/src/...``). Stripping the
    scan-root prefix scopes detection to the project layout the user
    actually pointed us at.
    """
    if not roots:
        return path_str
    try:
        p = Path(path_str)
    except (OSError, ValueError):
        return path_str
    try:
        resolved = p.resolve() if p.exists() else p
    except OSError:
        resolved = p
    for root in roots:
        try:
            return str(resolved.relative_to(root))
        except ValueError:
            continue
    return path_str


def _gather_haystack(record: AISystemRecord, scan_paths: list[str]) -> list[str]:
    """Return the text fragments the detectors will search.

    Includes the record's own metadata and (when the record has a real source
    file) that file plus textual siblings in its directory. Path strings are
    relativized against the scan roots so the surrounding filesystem doesn't
    leak unrelated tokens into environment detection. Content is held only
    inside this function and the detectors that consume its return value —
    never persisted.
    """
    roots = _resolved_roots(scan_paths)

    # Only include fields that actually carry deployment-context signal:
    # the file path (relativized) plus the human-readable name/description.
    # ``source_scanner`` and tag values describe *what kind* of finding this
    # is, not *where* it runs, and would leak unrelated tokens — e.g. a
    # scanner literally named "test.scanner" should not imply test env.
    parts: list[str] = [
        _relativize(record.source_location, roots),
        record.name,
        record.description,
    ]

    file_path = _record_file(record)
    if file_path is None:
        return parts

    parts.append(_relativize(str(file_path), roots))
    parts.append(_read_text(file_path, _MAX_BYTES_SOURCE))

    try:
        siblings = list(file_path.parent.iterdir())
    except OSError:
        return parts

    for sibling in siblings:
        if not sibling.is_file() or sibling == file_path:
            continue
        parts.append(_relativize(str(sibling), roots))
        if sibling.suffix.lower() in _TEXT_SUFFIXES:
            parts.append(_read_text(sibling, _MAX_BYTES_SIBLING))

    return parts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def enrich(record: AISystemRecord, scan_paths: list[str]) -> dict:
    """Return a context dict for *record*.

    Keys:
        environment        str  — production / staging / development / test / unknown
        exposure           str  — public_api / internal_service / batch_offline / unknown
        data_sensitivity   list — categories: pii / financial / auth / health
        interaction_type   str  — user_facing_realtime / batch_offline / internal_tooling / unknown
    """
    parts = _gather_haystack(record, scan_paths)
    return {
        "environment": _detect_environment(parts),
        "exposure": _detect_exposure(parts),
        "data_sensitivity": _detect_data_sensitivity(parts),
        "interaction_type": _detect_interaction_type(parts),
    }
