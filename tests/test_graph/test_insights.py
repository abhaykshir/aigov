"""Tests for aigov.core.graph.insights.compute_insights()."""
from __future__ import annotations

import pytest

from aigov.core.graph.insights import GraphInsights, NodeInsight, compute_insights
from aigov.core.graph.schema import AISystemGraph, GraphEdge, GraphNode


# ---------------------------------------------------------------------------
# Tiny builders so each test stays focused on what it's asserting
# ---------------------------------------------------------------------------

def _node(node_id: str, *, score: int | None = None, level: str | None = None) -> GraphNode:
    return GraphNode(
        id=node_id,
        label=node_id,
        system_type="api_service",
        provider="OpenAI",
        source_location=f"src/{node_id}.py",
        risk_score=score,
        risk_level=level,
    )


def _edge(a: str, b: str, *, conf: float = 0.7) -> GraphEdge:
    return GraphEdge(
        source_id=a,
        target_id=b,
        relationship="same_module",
        confidence=conf,
        evidence=[f"{a} ↔ {b}"],
    )


def _graph(nodes, edges) -> AISystemGraph:
    return AISystemGraph(nodes=nodes, edges=edges, metadata={})


# ---------------------------------------------------------------------------
# Degree
# ---------------------------------------------------------------------------

class TestDegree:
    def test_node_with_one_edge_has_degree_one(self):
        g = _graph([_node("a"), _node("b")], [_edge("a", "b")])
        ins = compute_insights(g)
        assert ins.node_insights["a"].degree == 1
        assert ins.node_insights["b"].degree == 1

    def test_central_node_collects_degree_from_every_neighbour(self):
        nodes = [_node(x) for x in ("hub", "a", "b", "c")]
        edges = [_edge("hub", x) for x in ("a", "b", "c")]
        g = _graph(nodes, edges)
        ins = compute_insights(g)
        assert ins.node_insights["hub"].degree == 3
        for x in ("a", "b", "c"):
            assert ins.node_insights[x].degree == 1

    def test_isolated_node_has_degree_zero(self):
        g = _graph([_node("solo")], [])
        ins = compute_insights(g)
        assert ins.node_insights["solo"].degree == 0


# ---------------------------------------------------------------------------
# High-risk / critical neighbour counts
# ---------------------------------------------------------------------------

class TestRiskNeighbors:
    def test_high_risk_neighbour_threshold_is_60(self):
        # 60 counts as high-risk; 59 does not.
        g = _graph(
            [_node("a"), _node("at60", score=60), _node("at59", score=59)],
            [_edge("a", "at60"), _edge("a", "at59")],
        )
        ins = compute_insights(g)
        assert ins.node_insights["a"].high_risk_neighbors == 1

    def test_critical_neighbour_threshold_is_80(self):
        g = _graph(
            [_node("a"), _node("at80", score=80), _node("at79", score=79)],
            [_edge("a", "at80"), _edge("a", "at79")],
        )
        ins = compute_insights(g)
        # Both are >= 60 so high_risk_neighbors == 2; only one is >= 80.
        assert ins.node_insights["a"].high_risk_neighbors == 2
        assert ins.node_insights["a"].critical_neighbors == 1

    def test_unscored_neighbour_is_not_high_risk(self):
        g = _graph(
            [_node("a"), _node("unscored", score=None)],
            [_edge("a", "unscored")],
        )
        ins = compute_insights(g)
        assert ins.node_insights["a"].high_risk_neighbors == 0
        assert ins.node_insights["a"].critical_neighbors == 0


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------

class TestBlastRadius:
    def test_low_when_isolated(self):
        g = _graph([_node("solo")], [])
        assert compute_insights(g).node_insights["solo"].blast_radius == "low"

    def test_low_when_single_minor_neighbour(self):
        g = _graph(
            [_node("a"), _node("b", score=20)],
            [_edge("a", "b")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "low"

    def test_medium_at_two_minor_neighbours(self):
        g = _graph(
            [_node("a"), _node("b", score=10), _node("c", score=10)],
            [_edge("a", "b"), _edge("a", "c")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "medium"

    def test_high_when_one_high_risk_neighbour(self):
        g = _graph(
            [_node("a"), _node("hr", score=70)],
            [_edge("a", "hr")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "high"

    def test_high_at_three_neighbours_even_if_low_risk(self):
        g = _graph(
            [_node("a")] + [_node(x, score=10) for x in ("b", "c", "d")],
            [_edge("a", x) for x in ("b", "c", "d")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "high"

    def test_critical_when_two_high_risk_neighbours(self):
        g = _graph(
            [_node("a"), _node("h1", score=70), _node("h2", score=80)],
            [_edge("a", "h1"), _edge("a", "h2")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "critical"

    def test_critical_at_four_neighbours_regardless_of_risk(self):
        g = _graph(
            [_node("a")] + [_node(x, score=10) for x in ("b", "c", "d", "e")],
            [_edge("a", x) for x in ("b", "c", "d", "e")],
        )
        assert compute_insights(g).node_insights["a"].blast_radius == "critical"


# ---------------------------------------------------------------------------
# Isolated-node detection
# ---------------------------------------------------------------------------

class TestIsolated:
    def test_isolated_listed_when_degree_zero(self):
        g = _graph([_node("a"), _node("b"), _node("solo")], [_edge("a", "b")])
        ins = compute_insights(g)
        assert ins.isolated_nodes == ["solo"]
        assert ins.node_insights["solo"].is_isolated is True
        assert ins.node_insights["a"].is_isolated is False

    def test_no_isolated_when_every_node_has_an_edge(self):
        nodes = [_node(x) for x in ("a", "b", "c")]
        edges = [_edge("a", "b"), _edge("b", "c")]
        ins = compute_insights(_graph(nodes, edges))
        assert ins.isolated_nodes == []

    def test_all_isolated_when_no_edges(self):
        g = _graph([_node("a"), _node("b"), _node("c")], [])
        ins = compute_insights(g)
        assert ins.isolated_nodes == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# Cluster (connected-component) detection
# ---------------------------------------------------------------------------

class TestClusters:
    def test_single_connected_graph_produces_one_cluster(self):
        nodes = [_node(x) for x in ("a", "b", "c")]
        edges = [_edge("a", "b"), _edge("b", "c")]
        ins = compute_insights(_graph(nodes, edges))
        assert len(ins.risk_clusters) == 1
        assert sorted(ins.risk_clusters[0]) == ["a", "b", "c"]

    def test_two_separate_groups_yield_two_clusters(self):
        nodes = [_node(x) for x in ("a", "b", "c", "d")]
        edges = [_edge("a", "b"), _edge("c", "d")]
        ins = compute_insights(_graph(nodes, edges))
        assert len(ins.risk_clusters) == 2
        # Clusters are sorted by descending size, ties broken by smallest id.
        assert {tuple(sorted(c)) for c in ins.risk_clusters} == {("a", "b"), ("c", "d")}

    def test_isolated_node_is_its_own_cluster(self):
        g = _graph([_node("a"), _node("b"), _node("solo")], [_edge("a", "b")])
        ins = compute_insights(g)
        assert len(ins.risk_clusters) == 2
        clusters = sorted(ins.risk_clusters, key=lambda c: -len(c))
        assert clusters[0] == ["a", "b"]
        assert clusters[1] == ["solo"]

    def test_clusters_sorted_largest_first(self):
        nodes = [_node(x) for x in ("a", "b", "c", "d", "e", "f")]
        edges = [_edge("a", "b"), _edge("b", "c"), _edge("c", "d"), _edge("e", "f")]
        ins = compute_insights(_graph(nodes, edges))
        assert len(ins.risk_clusters[0]) == 4
        assert len(ins.risk_clusters[1]) == 2


# ---------------------------------------------------------------------------
# Most connected + highest-blast-radius selection
# ---------------------------------------------------------------------------

class TestPickedNodes:
    def test_most_connected_picks_highest_degree(self):
        nodes = [_node(x) for x in ("hub", "a", "b", "c")]
        edges = [_edge("hub", x) for x in ("a", "b", "c")]
        ins = compute_insights(_graph(nodes, edges))
        assert ins.most_connected_node == "hub"

    def test_highest_blast_radius_picks_critical_over_high(self):
        # Build two distinct hubs: ``crit`` connects to two high-risk
        # neighbours (critical blast radius); ``hi`` connects to one
        # high-risk neighbour (high blast radius).
        nodes = [
            _node("crit"),
            _node("crit_n1", score=80),
            _node("crit_n2", score=70),
            _node("hi"),
            _node("hi_n", score=70),
        ]
        edges = [
            _edge("crit", "crit_n1"),
            _edge("crit", "crit_n2"),
            _edge("hi", "hi_n"),
        ]
        ins = compute_insights(_graph(nodes, edges))
        assert ins.node_insights["crit"].blast_radius == "critical"
        assert ins.node_insights["hi"].blast_radius == "high"
        assert ins.highest_blast_radius_node == "crit"


# ---------------------------------------------------------------------------
# Summary string
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_is_populated_for_a_normal_graph(self):
        nodes = [_node(x) for x in ("a", "b", "c")]
        edges = [_edge("a", "b")]
        ins = compute_insights(_graph(nodes, edges))
        assert ins.summary
        assert "3 AI systems" in ins.summary
        assert "isolated" in ins.summary

    def test_summary_mentions_critical_count_when_present(self):
        # 4-neighbour star → blast radius critical for the hub.
        nodes = [_node("hub")] + [_node(x, score=20) for x in ("a", "b", "c", "d")]
        edges = [_edge("hub", x) for x in ("a", "b", "c", "d")]
        ins = compute_insights(_graph(nodes, edges))
        assert "critical" in ins.summary.lower()


# ---------------------------------------------------------------------------
# Zero-edge / empty graph
# ---------------------------------------------------------------------------

class TestEmptyAndZeroEdge:
    def test_zero_edges_means_every_node_isolated(self):
        nodes = [_node(x) for x in ("a", "b", "c")]
        ins = compute_insights(_graph(nodes, []))
        assert ins.total_edges == 0
        assert ins.isolated_nodes == ["a", "b", "c"]
        assert all(ins.node_insights[x].degree == 0 for x in ("a", "b", "c"))
        assert all(ins.node_insights[x].blast_radius == "low" for x in ("a", "b", "c"))

    def test_empty_graph_has_no_nodes_no_clusters(self):
        ins = compute_insights(_graph([], []))
        assert ins.total_nodes == 0
        assert ins.total_edges == 0
        assert ins.isolated_nodes == []
        assert ins.risk_clusters == []
        assert ins.most_connected_node is None
        assert ins.highest_blast_radius_node is None


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def test_to_dict_contains_every_documented_field():
    ins = compute_insights(_graph([_node("a")], []))
    d = ins.to_dict()
    for key in (
        "total_nodes", "total_edges", "most_connected_node",
        "highest_blast_radius_node", "isolated_nodes", "risk_clusters",
        "summary", "node_insights",
    ):
        assert key in d, f"missing key: {key}"


def test_node_insight_to_dict_contains_every_documented_field():
    ins = compute_insights(_graph([_node("a"), _node("b")], [_edge("a", "b")]))
    nd = ins.node_insights["a"].to_dict()
    for key in (
        "node_id", "label", "degree",
        "high_risk_neighbors", "critical_neighbors",
        "blast_radius", "is_isolated",
    ):
        assert key in nd, f"missing key: {key}"
