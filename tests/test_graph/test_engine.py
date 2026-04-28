"""End-to-end tests: run aigov on the sample_graph_project fixture and
verify the resulting graph."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from aigov.core.engine import ScanEngine, classify_results
from aigov.core.graph import build_graph
from aigov.core.risk import apply_risk

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_graph_project"


@pytest.fixture(autouse=True)
def _clear_ci_env(monkeypatch):
    # The risk engine bumps environment to "test" when CI vars are set;
    # tests assert exact node states, so neutralise them.
    for var in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "JENKINS_HOME", "GITLAB_CI"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def graph(tmp_path_factory):
    """Run the full pipeline against the sample_graph_project fixture.

    The python_imports / api_keys scanners deliberately skip path components
    named ``test``, ``tests``, ``fixture``, ``fixtures`` — so we can't scan
    ``tests/fixtures/sample_graph_project`` directly. Copy the fixture into a
    clean tmp-tree first.
    """
    scope_root = tmp_path_factory.mktemp("graph_scope")
    project = scope_root / "project"
    shutil.copytree(FIXTURE, project)

    paths = [str(project)]
    engine = ScanEngine(paths=paths)
    result = engine.run()
    classified = classify_results(result, ["eu_ai_act"])
    scored = apply_risk(classified.records, paths)
    return build_graph(scored, paths)


# ---------------------------------------------------------------------------
# Graph shape
# ---------------------------------------------------------------------------

def test_graph_has_at_least_one_node(graph):
    assert len(graph.nodes) > 0


def test_metadata_carries_tool_version(graph):
    assert graph.metadata.get("version")
    assert graph.metadata.get("tool_name") == "aigov"
    assert graph.metadata.get("scan_paths")


def test_node_count_matches_metadata(graph):
    assert graph.metadata["node_count"] == len(graph.nodes)


def test_edge_count_matches_metadata(graph):
    assert graph.metadata["edge_count"] == len(graph.edges)


# ---------------------------------------------------------------------------
# Expected relationships fire on the fixture
# ---------------------------------------------------------------------------

def _edges(graph, relationship: str):
    return [e for e in graph.edges if e.relationship == relationship]


def _nodes_in(graph, dir_fragment: str):
    return [n for n in graph.nodes if dir_fragment in n.source_location.replace("\\", "/")]


def test_hiring_directory_yields_provider_edge(graph):
    """resume_screener.py + candidate_ranker.py both import openai → at least
    one shared_provider_key edge must connect them."""
    hiring = _nodes_in(graph, "hiring/")
    assert len(hiring) >= 2, "expected at least two hiring/* records"
    edges = _edges(graph, "shared_provider_key")
    pair = {n.id for n in hiring}
    assert any({e.source_id, e.target_id} == pair or pair.issubset({e.source_id, e.target_id})
               for e in edges) or any(e.source_id in pair and e.target_id in pair for e in edges)


def _evidence_contains(edge, fragment: str) -> bool:
    """Substring-search every sentence in an edge's evidence list."""
    return any(fragment in s for s in edge.evidence)


def test_hiring_python_files_get_same_python_package_evidence(graph):
    """The hiring/ pair collapses to ``shared_provider_key`` (winning conf 0.85),
    but the merged evidence list must still contain the same_python_package
    sentence (the prior ``import_chain`` reason, renamed in v0.5.1)."""
    package_evidence = [
        e for e in graph.edges
        if any("package" in s for s in e.evidence)
        and any("hiring/" in s for s in e.evidence)
    ]
    assert package_evidence, (
        "expected hiring/ Python files to contribute a same_python_package "
        f"evidence sentence; got: {[(e.relationship, e.evidence) for e in graph.edges]}"
    )


def test_analytics_directory_yields_provider_edge(graph):
    edges = _edges(graph, "shared_provider_key")
    assert any(_evidence_contains(e, "analytics") for e in edges), edges


def test_terraform_resources_share_module(graph):
    edges = _edges(graph, "shared_terraform_module")
    assert edges, "expected sagemaker resources in ml_pipeline.tf to be linked"
    assert all(e.confidence >= 0.85 for e in edges)


def test_mcp_connection_links_chatbot_to_mcp(graph):
    edges = _edges(graph, "mcp_connection")
    assert edges, "expected support/.mcp.json to connect to support/chatbot.py"
    for edge in edges:
        # Evidence must name the MCP server.
        assert _evidence_contains(edge, "MCP server")


def test_no_edges_between_unrelated_directories(graph):
    """A hiring/* node and an analytics/* node should not share a
    shared_provider_key edge — the directories differ."""
    hiring = {n.id for n in _nodes_in(graph, "hiring/")}
    analytics = {n.id for n in _nodes_in(graph, "analytics/")}
    if not (hiring and analytics):
        pytest.skip("fixture didn't produce both hiring and analytics nodes")
    for e in _edges(graph, "shared_provider_key"):
        assert not (e.source_id in hiring and e.target_id in analytics), (
            f"unexpected cross-directory edge: {e.evidence}"
        )
        assert not (e.source_id in analytics and e.target_id in hiring), (
            f"unexpected cross-directory edge: {e.evidence}"
        )


# ---------------------------------------------------------------------------
# Risk fields propagate to nodes
# ---------------------------------------------------------------------------

def test_classified_nodes_carry_risk_score(graph):
    scored = [n for n in graph.nodes if n.risk_score is not None]
    assert scored, "expected at least one risk-scored node"


def test_no_credential_tags_in_graph(graph):
    """The graph engine must strip credential-adjacent tags (key_preview, key_type)."""
    for node in graph.nodes:
        assert "key_preview" not in node.tags
        assert "key_type" not in node.tags


def test_api_key_findings_are_not_nodes(graph):
    """code.api_keys records describe shared credentials, not AI systems —
    they must not appear as nodes."""
    for node in graph.nodes:
        loc = node.source_location.replace("\\", "/")
        # Strip the trailing :NN line suffix so we look at the file path.
        path = loc.split(":")[0] if ":" in loc and not loc.startswith("arn:") else loc
        leaf = path.rsplit("/", 1)[-1]
        assert not leaf.startswith(".env"), (
            f".env credential record leaked into nodes: {node.label} @ {node.source_location}"
        )


def test_api_key_evidence_strengthens_hiring_shared_config(graph):
    """The hiring/ subdir ships an .env with an OpenAI API key plus two .py
    files. After collapse the surviving relationship for that pair is
    ``shared_provider_key`` (0.85), but the merged evidence list must still
    contain the api-key sentence (0.8) as one of its entries."""
    by_id = {n.id: n for n in graph.nodes}
    candidates = [
        e for e in graph.edges
        if any("API key" in s for s in e.evidence)
    ]
    assert candidates, (
        "no edges carry api-key evidence at all; "
        f"got: {[(e.relationship, e.evidence) for e in graph.edges]}"
    )

    def _dir_contains(edge, fragment: str) -> bool:
        a = by_id.get(edge.source_id)
        b = by_id.get(edge.target_id)
        if not (a and b):
            return False
        a_loc = a.source_location.replace("\\", "/").lower()
        b_loc = b.source_location.replace("\\", "/").lower()
        return f"/{fragment}/" in a_loc and f"/{fragment}/" in b_loc

    assert any(_dir_contains(e, "hiring") for e in candidates), (
        "expected an api-key evidence sentence between two hiring/ records; "
        f"got: {[(by_id[e.source_id].label, by_id[e.target_id].label) for e in candidates]}"
    )


# ---------------------------------------------------------------------------
# Graph round-trips through to_dict / from_dict
# ---------------------------------------------------------------------------

def test_graph_round_trips_through_dict(graph):
    from aigov.core.graph.schema import AISystemGraph
    round_tripped = AISystemGraph.from_dict(graph.to_dict())
    assert len(round_tripped.nodes) == len(graph.nodes)
    assert len(round_tripped.edges) == len(graph.edges)
    assert round_tripped.metadata == graph.metadata
