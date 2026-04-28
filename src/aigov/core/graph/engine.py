"""Graph engine — convert a record list into a complete :class:`AISystemGraph`."""
from __future__ import annotations

from typing import Iterable, Optional

from aigov.core.graph.relationships import detect_relationships
from aigov.core.graph.schema import AISystemGraph, GraphEdge, GraphNode
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
    min_risk_score: Optional[int] = None,
) -> AISystemGraph:
    """Return a graph whose nodes mirror *records* and edges come from the
    relationship detectors.

    Records produced by ``code.api_keys`` are excluded from the node list
    (they're shared resources, not AI systems) and instead handed to the
    relationship detector as evidence-only inputs that strengthen
    ``shared_config`` edges between the AI services that live in the same
    directory.

    When *min_risk_score* is set, nodes whose ``risk_score`` is below the
    threshold are dropped. Unscored nodes (``risk_score is None``) are kept
    only when they have an edge to a surviving scored node — they may be
    important connections (e.g. an unscored MCP server linking two critical
    services). Edges are kept only when both endpoints survive.

    The graph carries its own metadata (tool name, version, generated_at,
    scan_paths) so renderers — and any downstream consumer — don't need to
    receive that context separately.
    """
    node_records, evidence_records = _split(records)
    nodes = [_record_to_node(r) for r in node_records]
    edges = detect_relationships(node_records, evidence_records=evidence_records)

    if min_risk_score is not None:
        nodes, edges = _filter_by_risk(nodes, edges, min_risk_score)

    base_meta = build_metadata()
    metadata = {
        **base_meta,
        "scan_paths": list(scan_paths),
        "node_count": len(nodes),
        "edge_count": len(edges),
    }
    if min_risk_score is not None:
        metadata["min_risk_score"] = min_risk_score
    return AISystemGraph(nodes=nodes, edges=edges, metadata=metadata)


def _filter_by_risk(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    threshold: int,
) -> tuple[list[GraphNode], list[GraphEdge]]:
    """Drop low-risk nodes; keep unscored nodes only if linked to a survivor.

    A node survives the filter if its ``risk_score`` is >= *threshold*.
    Unscored nodes (``risk_score is None``) get a second chance: they survive
    if at least one edge connects them to a node that survived on its own.
    Edges are then filtered to those whose endpoints both survive.
    """
    scored_survivors = {n.id for n in nodes if n.risk_score is not None and n.risk_score >= threshold}
    unscored = {n.id for n in nodes if n.risk_score is None}

    rescued: set[str] = set()
    for edge in edges:
        if edge.source_id in scored_survivors and edge.target_id in unscored:
            rescued.add(edge.target_id)
        elif edge.target_id in scored_survivors and edge.source_id in unscored:
            rescued.add(edge.source_id)

    surviving_ids = scored_survivors | rescued
    surviving_nodes = [n for n in nodes if n.id in surviving_ids]
    surviving_edges = [
        e for e in edges
        if e.source_id in surviving_ids and e.target_id in surviving_ids
    ]
    return surviving_nodes, surviving_edges


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
