"""Graph-level analytics — turns an :class:`AISystemGraph` into reviewable
insight: who's connected to whom, who has critical blast radius, which
systems are isolated (potential shadow AI), and which clusters of systems
share infrastructure.

This module is pure: same graph in → same insights out. No file I/O, no
network. The CLI, the JSON exporter, and the HTML renderer all consume
``compute_insights(graph)`` rather than re-deriving these numbers.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from aigov.core.graph.schema import AISystemGraph, GraphEdge, GraphNode


# Risk-level cutoffs — must stay in sync with aigov.core.risk.scoring._LEVEL_BANDS.
# Pinned here as constants so the test suite catches an accidental drift.
_HIGH_RISK_SCORE = 60
_CRITICAL_SCORE = 80


# ---------------------------------------------------------------------------
# Per-node insight
# ---------------------------------------------------------------------------

@dataclass
class NodeInsight:
    node_id: str
    label: str
    degree: int
    high_risk_neighbors: int   # neighbours with risk_score >= 60
    critical_neighbors: int    # neighbours with risk_score >= 80
    blast_radius: str          # "critical" | "high" | "medium" | "low"
    is_isolated: bool          # degree == 0 → potential shadow AI

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "degree": self.degree,
            "high_risk_neighbors": self.high_risk_neighbors,
            "critical_neighbors": self.critical_neighbors,
            "blast_radius": self.blast_radius,
            "is_isolated": self.is_isolated,
        }


# ---------------------------------------------------------------------------
# Graph-level insights
# ---------------------------------------------------------------------------

@dataclass
class GraphInsights:
    node_insights: dict[str, NodeInsight] = field(default_factory=dict)
    total_nodes: int = 0
    total_edges: int = 0
    most_connected_node: Optional[str] = None       # node id of highest-degree node
    highest_blast_radius_node: Optional[str] = None  # node id of worst blast radius
    isolated_nodes: list[str] = field(default_factory=list)  # ids — shadow AI candidates
    risk_clusters: list[list[str]] = field(default_factory=list)  # connected components, each a list of ids
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "most_connected_node": self.most_connected_node,
            "highest_blast_radius_node": self.highest_blast_radius_node,
            "isolated_nodes": list(self.isolated_nodes),
            "risk_clusters": [list(c) for c in self.risk_clusters],
            "summary": self.summary,
            "node_insights": {nid: ins.to_dict() for nid, ins in self.node_insights.items()},
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def compute_insights(graph: AISystemGraph) -> GraphInsights:
    """Return a fully-populated :class:`GraphInsights` for *graph*."""
    by_id: dict[str, GraphNode] = {n.id: n for n in graph.nodes}
    adjacency: dict[str, list[str]] = _adjacency(graph.nodes, graph.edges)

    node_insights: dict[str, NodeInsight] = {}
    for node in graph.nodes:
        node_insights[node.id] = _node_insight(node, adjacency[node.id], by_id)

    insights = GraphInsights(
        node_insights=node_insights,
        total_nodes=len(graph.nodes),
        total_edges=len(graph.edges),
    )
    insights.isolated_nodes = sorted(
        nid for nid, ins in node_insights.items() if ins.is_isolated
    )
    insights.risk_clusters = _connected_components(graph.nodes, adjacency)
    insights.most_connected_node = _max_by(
        node_insights, key=lambda i: i.degree
    )
    insights.highest_blast_radius_node = _max_by(
        node_insights, key=lambda i: (_BLAST_RANK[i.blast_radius], i.degree)
    )
    insights.summary = _summary_text(insights, by_id)
    return insights


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Higher rank == worse. Used to pick the "worst" blast radius node.
_BLAST_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _adjacency(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
) -> dict[str, list[str]]:
    """Return id → list of neighbour ids. Treats edges as undirected."""
    adj: dict[str, list[str]] = {n.id: [] for n in nodes}
    node_ids = set(adj)
    for edge in edges:
        if edge.source_id not in node_ids or edge.target_id not in node_ids:
            # Edge references an unknown node — skip rather than KeyError.
            # Realistically only happens when callers hand-build a graph.
            continue
        adj[edge.source_id].append(edge.target_id)
        adj[edge.target_id].append(edge.source_id)
    return adj


def _node_insight(
    node: GraphNode,
    neighbour_ids: list[str],
    by_id: dict[str, GraphNode],
) -> NodeInsight:
    high = sum(
        1 for nid in neighbour_ids
        if (by_id[nid].risk_score or 0) >= _HIGH_RISK_SCORE
    )
    crit = sum(
        1 for nid in neighbour_ids
        if (by_id[nid].risk_score or 0) >= _CRITICAL_SCORE
    )
    return NodeInsight(
        node_id=node.id,
        label=node.label,
        degree=len(neighbour_ids),
        high_risk_neighbors=high,
        critical_neighbors=crit,
        blast_radius=_blast_radius(len(neighbour_ids), high),
        is_isolated=(len(neighbour_ids) == 0),
    )


def _blast_radius(degree: int, high_risk_neighbors: int) -> str:
    """Classify how much damage a compromise of this node could spread.

    Two axes count: raw connection count and *how risky* those connections
    are. A node wired to four minimal-risk systems is louder than one wired
    to two high-risk ones, but both deserve attention — so the rule fires on
    *either* axis.
    """
    if high_risk_neighbors >= 2 or degree >= 4:
        return "critical"
    if high_risk_neighbors >= 1 or degree >= 3:
        return "high"
    if degree >= 2:
        return "medium"
    return "low"


def _connected_components(
    nodes: list[GraphNode],
    adjacency: dict[str, list[str]],
) -> list[list[str]]:
    """Return clusters of node ids — each cluster is one connected component.

    Output order is deterministic: clusters are sorted by descending size,
    ties broken by the lexicographically-smallest node id in each cluster.
    Within each cluster, ids are sorted.
    """
    visited: set[str] = set()
    clusters: list[list[str]] = []
    for node in nodes:
        if node.id in visited:
            continue
        # BFS — small graphs in practice; iteration depth is fine.
        component: list[str] = []
        queue: deque[str] = deque([node.id])
        visited.add(node.id)
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbour in adjacency.get(current, []):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)
        clusters.append(sorted(component))
    clusters.sort(key=lambda c: (-len(c), c[0] if c else ""))
    return clusters


def _max_by(
    node_insights: dict[str, NodeInsight],
    key,
) -> Optional[str]:
    """Return the node id whose insight scores highest under *key*. None when empty."""
    if not node_insights:
        return None
    # Tie-break by node_id so the result is deterministic.
    best_id = max(
        node_insights.keys(),
        key=lambda nid: (key(node_insights[nid]), -ord(nid[0]) if nid else 0),
    )
    # If even the "best" has zero degree, the graph has no connections —
    # most_connected_node still resolves to *some* id, which keeps the field
    # type stable. The summary text guards against the degenerate case.
    return best_id


def _summary_text(
    insights: GraphInsights,
    by_id: dict[str, GraphNode],
) -> str:
    """Compose the one-line human summary embedded in JSON / printed by the CLI."""
    n_critical = sum(
        1 for ins in insights.node_insights.values()
        if ins.blast_radius == "critical"
    )
    n_high = sum(
        1 for ins in insights.node_insights.values()
        if ins.blast_radius == "high"
    )
    parts = [
        f"{insights.total_nodes} AI system{_s(insights.total_nodes)} "
        f"in {len(insights.risk_clusters)} cluster{_s(len(insights.risk_clusters))}."
    ]
    if n_critical:
        parts.append(
            f"{n_critical} node{_s(n_critical)} "
            f"{'has' if n_critical == 1 else 'have'} critical blast radius."
        )
    elif n_high:
        parts.append(
            f"{n_high} node{_s(n_high)} "
            f"{'has' if n_high == 1 else 'have'} high blast radius."
        )
    else:
        parts.append("No nodes with critical or high blast radius.")
    parts.append(
        f"{len(insights.isolated_nodes)} isolated system"
        f"{_s(len(insights.isolated_nodes))}."
    )
    return " ".join(parts)


def _s(n: int) -> str:
    return "" if n == 1 else "s"
