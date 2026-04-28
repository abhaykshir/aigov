"""Tests for the graph schema dataclasses."""
from __future__ import annotations

import pytest

from aigov.core.graph.schema import AISystemGraph, GraphEdge, GraphNode


# ---------------------------------------------------------------------------
# Node construction + serialization
# ---------------------------------------------------------------------------

class TestGraphNode:
    def test_minimal_node_serializes(self):
        n = GraphNode(
            id="a",
            label="Service A",
            system_type="api_service",
            provider="OpenAI",
            source_location="src/a.py",
        )
        d = n.to_dict()
        assert d["id"] == "a"
        assert d["label"] == "Service A"
        # Optional risk fields are omitted when unset.
        assert "risk_score" not in d
        assert "risk_level" not in d

    def test_round_trip_preserves_all_fields(self):
        n = GraphNode(
            id="a",
            label="Service A",
            system_type="api_service",
            provider="OpenAI",
            source_location="src/a.py:7",
            origin_jurisdiction="US",
            risk_score=85,
            risk_level="critical",
            tags={"eu_ai_act_category": "Employment"},
        )
        round_tripped = GraphNode.from_dict(n.to_dict())
        assert round_tripped == n


# ---------------------------------------------------------------------------
# Edge construction + canonical ordering
# ---------------------------------------------------------------------------

class TestGraphEdge:
    def test_edge_canonicalises_node_order(self):
        # source > target lexically — should swap.
        e = GraphEdge("zzz", "aaa", "shared_config", 0.9, "evidence")
        assert e.source_id == "aaa"
        assert e.target_id == "zzz"

    def test_self_loop_rejected(self):
        with pytest.raises(ValueError, match="cannot connect a node to itself"):
            GraphEdge("a", "a", "shared_config", 0.9, "x")

    def test_invalid_confidence_rejected(self):
        with pytest.raises(ValueError):
            GraphEdge("a", "b", "shared_config", 1.5, "x")
        with pytest.raises(ValueError):
            GraphEdge("a", "b", "shared_config", -0.1, "x")

    def test_empty_node_id_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            GraphEdge("", "b", "shared_config", 0.5, "x")

    def test_key_dedups_irrespective_of_order(self):
        a = GraphEdge("a", "b", "shared_config", 0.9, "evidence one")
        b = GraphEdge("b", "a", "shared_config", 0.5, "evidence two")
        assert a.key == b.key

    def test_round_trip(self):
        e = GraphEdge("a", "b", "mcp_connection", 0.8, "evidence")
        round_tripped = GraphEdge.from_dict(e.to_dict())
        assert round_tripped == e


# ---------------------------------------------------------------------------
# Graph round-trip
# ---------------------------------------------------------------------------

class TestAISystemGraph:
    def test_empty_graph_round_trips(self):
        g = AISystemGraph()
        round_tripped = AISystemGraph.from_dict(g.to_dict())
        assert round_tripped.nodes == []
        assert round_tripped.edges == []
        assert round_tripped.metadata == {}

    def test_full_graph_round_trips(self):
        node_a = GraphNode(id="a", label="A", system_type="api_service", provider="OpenAI", source_location="src/a.py")
        node_b = GraphNode(id="b", label="B", system_type="api_service", provider="OpenAI", source_location="src/b.py", risk_score=50, risk_level="medium")
        edge = GraphEdge("a", "b", "shared_provider_key", 0.85, "Both use OpenAI")

        graph = AISystemGraph(nodes=[node_a, node_b], edges=[edge], metadata={"version": "0.4.0"})
        round_tripped = AISystemGraph.from_dict(graph.to_dict())

        assert len(round_tripped.nodes) == 2
        assert {n.id for n in round_tripped.nodes} == {"a", "b"}
        assert len(round_tripped.edges) == 1
        assert round_tripped.edges[0].relationship == "shared_provider_key"
        assert round_tripped.metadata["version"] == "0.4.0"
