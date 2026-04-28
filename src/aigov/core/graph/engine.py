"""Graph engine — convert a record list into a complete :class:`AISystemGraph`."""
from __future__ import annotations

from typing import Iterable

from aigov.core.graph.relationships import detect_relationships
from aigov.core.graph.schema import AISystemGraph, GraphNode
from aigov.core.metadata import build_metadata
from aigov.core.models import AISystemRecord


def build_graph(
    records: list[AISystemRecord],
    scan_paths: list[str],
) -> AISystemGraph:
    """Return a graph whose nodes mirror *records* and edges come from the
    relationship detectors.

    The graph carries its own metadata (tool name, version, generated_at,
    scan_paths) so renderers — and any downstream consumer — don't need to
    receive that context separately.
    """
    nodes = [_record_to_node(r) for r in records]
    edges = detect_relationships(records)

    base_meta = build_metadata()
    metadata = {
        **base_meta,
        "scan_paths": list(scan_paths),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    return AISystemGraph(nodes=nodes, edges=edges, metadata=metadata)


def _record_to_node(record: AISystemRecord) -> GraphNode:
    return GraphNode(
        id=record.id,
        label=record.name,
        system_type=record.system_type.value,
        provider=record.provider,
        source_location=record.source_location,
        origin_jurisdiction=(record.tags or {}).get("origin_jurisdiction", ""),
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        # Pass through context-related tags only; never carry credential
        # previews or raw env-var values into the graph payload.
        tags=_safe_tags(record),
    )


# Tags that may carry redacted credential material — never into the graph.
_SENSITIVE_TAGS = frozenset({"key_preview", "key_type"})


def _safe_tags(record: AISystemRecord) -> dict[str, str]:
    return {k: v for k, v in (record.tags or {}).items() if k not in _SENSITIVE_TAGS}
