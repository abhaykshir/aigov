"""Tests for the --min-risk-score filter on build_graph and the graph CLI."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from aigov.cli.main import app
from aigov.core.graph import build_graph
from aigov.core.graph.engine import _filter_by_risk
from aigov.core.graph.schema import GraphEdge, GraphNode
from aigov.core.models import AISystemRecord, AISystemType, DeploymentType, RiskLevel


_T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _record(
    rid: str,
    *,
    risk_score: int | None,
    source_location: str,
    provider: str = "OpenAI",
    system_type: AISystemType = AISystemType.API_SERVICE,
    source_scanner: str = "code.python_imports",
) -> AISystemRecord:
    return AISystemRecord(
        id=rid,
        name=f"system-{rid}",
        description="",
        source_scanner=source_scanner,
        source_location=source_location,
        discovery_timestamp=_T,
        confidence=0.9,
        system_type=system_type,
        provider=provider,
        deployment_type=DeploymentType.CLOUD_API,
        risk_classification=RiskLevel.MINIMAL_RISK,
        risk_score=risk_score,
        risk_level="critical" if (risk_score or 0) >= 80 else "low",
    )


def _node(nid: str, *, risk_score: int | None) -> GraphNode:
    return GraphNode(
        id=nid,
        label=nid,
        system_type="api_service",
        provider="OpenAI",
        source_location=f"{nid}.py",
        risk_score=risk_score,
    )


def _edge(a: str, b: str) -> GraphEdge:
    return GraphEdge(
        source_id=a,
        target_id=b,
        relationship="shared_provider_key",
        confidence=0.85,
        evidence=["test edge"],
    )


# ---------------------------------------------------------------------------
# _filter_by_risk — pure unit
# ---------------------------------------------------------------------------

class TestFilterByRisk:
    def test_drops_nodes_below_threshold(self):
        nodes = [_node("a", risk_score=90), _node("b", risk_score=20)]
        surviving_nodes, surviving_edges = _filter_by_risk(nodes, [], 60)
        assert {n.id for n in surviving_nodes} == {"a"}
        assert surviving_edges == []

    def test_drops_edges_with_excluded_endpoint(self):
        nodes = [_node("a", risk_score=90), _node("b", risk_score=20)]
        edges = [_edge("a", "b")]
        _, surviving_edges = _filter_by_risk(nodes, edges, 60)
        assert surviving_edges == []

    def test_keeps_unscored_node_when_linked_to_survivor(self):
        nodes = [
            _node("critical", risk_score=95),
            _node("mcp", risk_score=None),
        ]
        edges = [_edge("critical", "mcp")]
        surviving_nodes, surviving_edges = _filter_by_risk(nodes, edges, 60)
        assert {n.id for n in surviving_nodes} == {"critical", "mcp"}
        assert len(surviving_edges) == 1

    def test_drops_unscored_node_with_no_surviving_neighbour(self):
        nodes = [
            _node("low", risk_score=20),
            _node("mcp", risk_score=None),
        ]
        edges = [_edge("low", "mcp")]
        surviving_nodes, surviving_edges = _filter_by_risk(nodes, edges, 60)
        assert surviving_nodes == []
        assert surviving_edges == []

    def test_drops_isolated_unscored_node(self):
        nodes = [_node("orphan", risk_score=None)]
        surviving_nodes, _ = _filter_by_risk(nodes, [], 60)
        assert surviving_nodes == []

    def test_threshold_is_inclusive(self):
        nodes = [_node("at", risk_score=60)]
        surviving_nodes, _ = _filter_by_risk(nodes, [], 60)
        assert {n.id for n in surviving_nodes} == {"at"}


# ---------------------------------------------------------------------------
# build_graph integration with min_risk_score
# ---------------------------------------------------------------------------

class TestBuildGraphMinRiskScore:
    def test_default_includes_everything(self):
        records = [
            _record("a", risk_score=90, source_location="src/a.py:1"),
            _record("b", risk_score=20, source_location="src/b.py:1"),
        ]
        graph = build_graph(records, ["src"])
        assert {n.id for n in graph.nodes} == {"a", "b"}
        assert "min_risk_score" not in graph.metadata

    def test_min_risk_score_zero_includes_everything(self):
        records = [
            _record("a", risk_score=90, source_location="src/a.py:1"),
            _record("b", risk_score=20, source_location="src/b.py:1"),
        ]
        graph = build_graph(records, ["src"], min_risk_score=0)
        assert {n.id for n in graph.nodes} == {"a", "b"}
        assert graph.metadata.get("min_risk_score") == 0

    def test_filter_excludes_low_scoring_nodes(self):
        records = [
            _record("crit", risk_score=95, source_location="src/a.py:1"),
            _record("low", risk_score=20, source_location="src/b.py:1"),
            _record("med", risk_score=55, source_location="src/c.py:1"),
        ]
        graph = build_graph(records, ["src"], min_risk_score=60)
        assert {n.id for n in graph.nodes} == {"crit"}
        assert graph.metadata["node_count"] == 1
        assert graph.metadata["min_risk_score"] == 60

    def test_filter_drops_edges_to_excluded_nodes(self):
        # Two openai records in the same dir would normally pull in a
        # shared_provider_key edge. Filtering should drop both endpoints'
        # edge once one is excluded.
        records = [
            _record("crit", risk_score=95, source_location="proj/crit/x.py:1"),
            _record("low", risk_score=20, source_location="proj/crit/y.py:1"),
        ]
        graph = build_graph(records, ["proj"], min_risk_score=60)
        assert {n.id for n in graph.nodes} == {"crit"}
        assert graph.edges == []

    def test_unscored_node_kept_when_linked_to_high_risk_node(self):
        # Two python records share a directory and provider → produces a
        # shared_provider_key edge. Drop the score on one and keep the other
        # above threshold. The unscored one must survive.
        records = [
            _record("crit", risk_score=95, source_location="proj/crit/x.py:1"),
            _record("unscored", risk_score=None, source_location="proj/crit/y.py:1"),
        ]
        graph = build_graph(records, ["proj"], min_risk_score=60)
        ids = {n.id for n in graph.nodes}
        assert "crit" in ids
        assert "unscored" in ids
        assert len(graph.edges) >= 1


# ---------------------------------------------------------------------------
# CLI integration — --min-risk-score wiring + zero-node messaging
# ---------------------------------------------------------------------------

class TestGraphCommandMinRiskScore:
    def test_zero_nodes_prints_message_and_no_file(self, tmp_path, monkeypatch):
        out_file = tmp_path / "graph.html"
        monkeypatch.chdir(tmp_path)

        # Force an empty repo so the scan returns nothing AI-related but the
        # command still has somewhere to point. Even with records, threshold
        # 100 above any plausible score would empty the graph.
        target = tmp_path / "empty_proj"
        target.mkdir()
        (target / "noop.py").write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["graph", str(target), "--min-risk-score", "100", "--out-file", str(out_file)],
        )
        assert result.exit_code == 0, result.output
        assert "No AI systems found with risk score >= 100" in result.output
        assert "Try a lower threshold" in result.output
        assert not out_file.exists(), "should not write a file when graph is empty"

    def test_filter_passes_through_to_engine(self, tmp_path, monkeypatch):
        # Spy on build_graph at its source module — the CLI imports it lazily
        # from aigov.core.graph inside the command body, so the rebinding has
        # to land on the package attribute the CLI's `from ... import` resolves.
        out_file = tmp_path / "graph.html"
        monkeypatch.chdir(tmp_path)
        target = tmp_path / "proj"
        target.mkdir()
        (target / "x.py").write_text("import openai\n")

        captured: dict = {}
        real_build = build_graph

        def spy(records, scan_paths, min_risk_score=None):
            captured["min_risk_score"] = min_risk_score
            return real_build(records, scan_paths, min_risk_score=min_risk_score)

        runner = CliRunner()
        with patch("aigov.core.graph.build_graph", side_effect=spy):
            result = runner.invoke(
                app,
                ["graph", str(target), "--min-risk-score", "70", "--out-file", str(out_file)],
            )
        assert result.exit_code == 0, result.output
        assert captured.get("min_risk_score") == 70
