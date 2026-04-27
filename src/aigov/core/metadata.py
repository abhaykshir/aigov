"""Shared tool metadata builder.

Every aigov output that needs to embed "who produced this and when" — JSON
scan reports, SARIF, baseline snapshots — should call :func:`build_metadata`
instead of assembling its own dict. Keeps the tool name, version, and
timestamp shape consistent across formats and ensures a version bump only
needs to land in :mod:`aigov.version`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from aigov.version import __version__

_TOOL_NAME = "aigov"


def build_metadata(generated_at: datetime | None = None) -> dict[str, Any]:
    """Return the canonical metadata block.

    Parameters
    ----------
    generated_at:
        Optional override for the timestamp. Defaults to ``now`` in UTC.
        Tests pass a fixed value to make output deterministic.
    """
    moment = generated_at or datetime.now(timezone.utc)
    return {
        "tool_name": _TOOL_NAME,
        "version": __version__,
        "generated_at": moment.isoformat(),
    }


def tool_name() -> str:
    return _TOOL_NAME


def tool_version() -> str:
    return __version__
