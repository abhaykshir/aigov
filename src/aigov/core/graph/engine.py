"""Graph engine — convert a record list into a complete :class:`AISystemGraph`."""
from __future__ import annotations

from typing import Iterable

from aigov.core.graph.relationships import detect_relationships
from aigov.core.graph.schema import AISystemGraph, GraphNode
from aigov.core.metadata import build_metadata
from aigov.core.models import AISystemRecord


# Records from these scanners are *not* AI systems in their own right — they
# describe the credentials AI systems share. We strip them out of the node
# list so the graph stays a clean inventory of services, then pass them
# through to the relationship detector as evidence: an API key found in a
# directory tells us that the AI services in that directory share a config.
_EVIDENCE_ONLY_SCANNERS = frozenset({"code.api_keys"})


def build_graph(
    records: list[AISystemRecord],
    scan_paths: list[str],
) -> AISystemGraph:
    """Return a graph whose nodes mirror *records* and edges come from the
    relationship detectors.

    Records produced by ``code.api_keys`` are excluded from the node list
    (they're shared resources, not AI systems) and instead handed to the
    relationship detector as evidence-only inputs that strengthen
    ``shared_config`` edges between the AI services that live in the same
    directory.

    The graph carries its own metadata (tool name, version, generated_at,
    scan_paths) so renderers — and any downstream consumer — don't need to
    receive that context separately.
    """
    node_records, evidence_records = _split(records)
    nodes = [_record_to_node(r) for r in node_records]
    edges = detect_relationships(node_records, evidence_records=evidence_records)

    base_meta = build_metadata()
    metadata = {
        **base_meta,
        "scan_paths": list(scan_paths),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    return AISystemGraph(nodes=nodes, edges=edges, metadata=metadata)


def _split(
    records: list[AISystemRecord],
) -> tuple[list[AISystemRecord], list[AISystemRecord]]:
    """Return ``(node_records, evidence_records)`` partitioned by scanner."""
    node_records: list[AISystemRecord] = []
    evidence_records: list[AISystemRecord] = []
    for record in records:
        if record.source_scanner in _EVIDENCE_ONLY_SCANNERS:
            evidence_records.append(record)
        else:
            node_records.append(record)
    return node_records, evidence_records


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
