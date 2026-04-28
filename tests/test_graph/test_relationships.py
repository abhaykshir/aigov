"""Tests for the relationship detectors in aigov.core.graph.relationships."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aigov.core.graph.relationships import detect_relationships
from aigov.core.models import AISystemRecord, AISystemType, DeploymentType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _record(
    rid: str,
    *,
    name: str = "thing",
    provider: str = "OpenAI",
    system_type: AISystemType = AISystemType.API_SERVICE,
    source_location: str = "src/x.py:1",
) -> AISystemRecord:
    return AISystemRecord(
        id=rid,
        name=name,
        description="",
        source_scanner="test.scanner",
        source_location=source_location,
        discovery_timestamp=_T,
        confidence=0.9,
        system_type=system_type,
        provider=provider,
        deployment_type=DeploymentType.CLOUD_API,
    )


def _by_relationship(edges, relationship: str):
    return [e for e in edges if e.relationship == relationship]


def _ids(edges):
    return {(e.source_id, e.target_id) for e in edges}


# ---------------------------------------------------------------------------
# shared_config
# ---------------------------------------------------------------------------

class TestSharedConfig:
    def test_two_findings_in_same_env_file(self):
        a = _record("a", name="OpenAI key", source_location="hiring/.env:3")
        b = _record("b", name="Anthropic key", source_location="hiring/.env:5")
        edges = _by_relationship(detect_relationships([a, b]), "shared_config")
        assert len(edges) == 1
        assert edges[0].confidence == 0.9
        assert "hiring/.env" in edges[0].evidence

    def test_two_mcp_findings_in_same_mcp_json(self):
        a = _record("a", name="db", source_location="proj/.mcp.json")
        b = _record("b", name="slack", source_location="proj/.mcp.json")
        edges = _by_relationship(detect_relationships([a, b]), "shared_config")
        assert len(edges) == 1

    def test_records_in_different_env_files_do_not_share_config(self):
        a = _record("a", source_location="hiring/.env:3")
        b = _record("b", source_location="analytics/.env:3")
        edges = _by_relationship(detect_relationships([a, b]), "shared_config")
        assert edges == []

    def test_non_config_files_never_get_shared_config_edge(self):
        a = _record("a", source_location="src/a.py:1")
        b = _record("b", source_location="src/a.py:2")
        edges = _by_relationship(detect_relationships([a, b]), "shared_config")
        assert edges == []

    def test_api_key_evidence_creates_shared_config_between_co_located_services(self):
        """An api_keys evidence record at hiring/.env ties together every AI
        service in hiring/. Confirms the v0.5 evidence-based path."""
        api_key_evidence = _record(
            "ev",
            name="OpenAI API Key detected",
            provider="OpenAI",
            source_location="hiring/.env:3",
        )
        screener = _record("a", source_location="hiring/screener.py:1")
        ranker = _record("b", source_location="hiring/ranker.py:1")
        edges = detect_relationships(
            [screener, ranker], evidence_records=[api_key_evidence]
        )
        shared = [e for e in edges if e.relationship == "shared_config"]
        assert len(shared) == 1
        assert shared[0].confidence == 0.9
        assert "OpenAI" in shared[0].evidence
        assert ".env" in shared[0].evidence

    def test_api_key_evidence_does_not_link_services_in_different_dirs(self):
        api_key_evidence = _record(
            "ev",
            name="key",
            provider="OpenAI",
            source_location="hiring/.env:1",
        )
        screener = _record("a", source_location="hiring/screener.py:1")
        scorer = _record("b", source_location="analytics/scorer.py:1")
        edges = detect_relationships(
            [screener, scorer], evidence_records=[api_key_evidence]
        )
        shared = [e for e in edges if e.relationship == "shared_config"]
        assert shared == []

    def test_evidence_records_default_empty(self):
        """The new keyword arg is optional — single-arg calls still work."""
        a = _record("a", source_location="x/.mcp.json")
        b = _record("b", source_location="x/.mcp.json")
        edges = detect_relationships([a, b])
        assert any(e.relationship == "shared_config" for e in edges)


# ---------------------------------------------------------------------------
# shared_provider_key
# ---------------------------------------------------------------------------

class TestSharedProviderKey:
    def test_same_provider_same_directory(self):
        a = _record("a", provider="OpenAI", source_location="hiring/screener.py:1")
        b = _record("b", provider="OpenAI", source_location="hiring/ranker.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "shared_provider_key")
        assert len(edges) == 1
        assert edges[0].confidence == 0.85
        assert "OpenAI" in edges[0].evidence

    def test_same_provider_different_directories_does_not_match(self):
        a = _record("a", provider="OpenAI", source_location="hiring/screener.py:1")
        b = _record("b", provider="OpenAI", source_location="analytics/scorer.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "shared_provider_key")
        assert edges == []

    def test_different_providers_never_match(self):
        a = _record("a", provider="OpenAI", source_location="hiring/x.py:1")
        b = _record("b", provider="Anthropic", source_location="hiring/y.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "shared_provider_key")
        assert edges == []

    def test_unknown_provider_does_not_seed_edges(self):
        a = _record("a", provider="unknown", source_location="hiring/x.py:1")
        b = _record("b", provider="unknown", source_location="hiring/y.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "shared_provider_key")
        assert edges == []


# ---------------------------------------------------------------------------
# mcp_connection
# ---------------------------------------------------------------------------

class TestMcpConnection:
    def test_mcp_alongside_api_service(self):
        mcp = _record("mcp", system_type=AISystemType.MCP_SERVER,
                     name="vector-db", source_location="support/.mcp.json")
        api = _record("api", system_type=AISystemType.API_SERVICE,
                     provider="Anthropic", source_location="support/chatbot.py:1")
        edges = _by_relationship(detect_relationships([mcp, api]), "mcp_connection")
        assert len(edges) == 1
        assert edges[0].confidence == 0.8
        assert "vector-db" in edges[0].evidence

    def test_mcp_in_unrelated_project_does_not_match(self):
        mcp = _record("mcp", system_type=AISystemType.MCP_SERVER,
                     source_location="totally/different/.mcp.json")
        api = _record("api", system_type=AISystemType.API_SERVICE,
                     source_location="hiring/screener.py:1")
        edges = _by_relationship(detect_relationships([mcp, api]), "mcp_connection")
        assert edges == []

    def test_two_mcps_dont_get_mcp_connection(self):
        a = _record("a", system_type=AISystemType.MCP_SERVER, source_location="proj/.mcp.json")
        b = _record("b", system_type=AISystemType.MCP_SERVER, source_location="proj/.mcp.json")
        edges = _by_relationship(detect_relationships([a, b]), "mcp_connection")
        assert edges == []

    def test_mcp_one_level_above_api_matches(self):
        """MCP at project root + API in immediate subdir → match."""
        mcp = _record("mcp", system_type=AISystemType.MCP_SERVER,
                     source_location="proj/.mcp.json")
        api = _record("api", system_type=AISystemType.API_SERVICE,
                     source_location="proj/app/main.py:1")
        edges = _by_relationship(detect_relationships([mcp, api]), "mcp_connection")
        assert len(edges) == 1

    def test_mcp_two_levels_above_api_does_not_match(self):
        """MCP at project root + API two directories deeper → no edge.

        This is the tangle-prevention rule: an MCP config at the repo root
        must not connect to every API service in every nested subdirectory.
        """
        mcp = _record("mcp", system_type=AISystemType.MCP_SERVER,
                     source_location="proj/.mcp.json")
        deep_api = _record("api", system_type=AISystemType.API_SERVICE,
                          source_location="proj/app/sub/handler.py:1")
        edges = _by_relationship(detect_relationships([mcp, deep_api]), "mcp_connection")
        assert edges == []

    def test_mcp_in_sibling_directory_does_not_match(self):
        """MCP in support/, API in hiring/ → no edge (siblings, not lineage)."""
        mcp = _record("mcp", system_type=AISystemType.MCP_SERVER,
                     source_location="proj/support/.mcp.json")
        api = _record("api", system_type=AISystemType.API_SERVICE,
                     source_location="proj/hiring/screener.py:1")
        edges = _by_relationship(detect_relationships([mcp, api]), "mcp_connection")
        assert edges == []


# ---------------------------------------------------------------------------
# same_module
# ---------------------------------------------------------------------------

class TestSameModule:
    def test_same_directory_yields_edge(self):
        a = _record("a", source_location="hiring/x.py:1")
        b = _record("b", source_location="hiring/y.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "same_module")
        assert len(edges) == 1
        assert edges[0].confidence == 0.5

    def test_different_directories_skip(self):
        a = _record("a", source_location="hiring/x.py:1")
        b = _record("b", source_location="support/y.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "same_module")
        assert edges == []


# ---------------------------------------------------------------------------
# import_chain
# ---------------------------------------------------------------------------

class TestImportChain:
    def test_two_python_files_in_same_package(self):
        a = _record("a", name="A", source_location="hiring/screener.py:1")
        b = _record("b", name="B", source_location="hiring/ranker.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "import_chain")
        assert len(edges) == 1
        assert edges[0].confidence == 0.7
        assert "hiring/" in edges[0].evidence

    def test_only_python_files_qualify(self):
        a = _record("a", source_location="hiring/x.tf:1")
        b = _record("b", source_location="hiring/y.tf:1")
        edges = _by_relationship(detect_relationships([a, b]), "import_chain")
        assert edges == []


# ---------------------------------------------------------------------------
# shared_terraform_module
# ---------------------------------------------------------------------------

class TestSharedTerraformModule:
    def test_two_resources_in_same_tf_file(self):
        a = _record("a", source_location="infra/ml.tf:5")
        b = _record("b", source_location="infra/ml.tf:20")
        edges = _by_relationship(detect_relationships([a, b]), "shared_terraform_module")
        assert len(edges) == 1
        assert edges[0].confidence == 0.9

    def test_two_tf_files_in_same_module_directory(self):
        a = _record("a", source_location="infra/ml/a.tf:5")
        b = _record("b", source_location="infra/ml/b.tf:5")
        edges = _by_relationship(detect_relationships([a, b]), "shared_terraform_module")
        assert len(edges) == 1
        assert edges[0].confidence == 0.85
        assert "infra/ml/" in edges[0].evidence

    def test_resources_in_different_modules_do_not_match(self):
        a = _record("a", source_location="infra/ml/a.tf:5")
        b = _record("b", source_location="infra/ingest/b.tf:5")
        edges = _by_relationship(detect_relationships([a, b]), "shared_terraform_module")
        assert edges == []

    def test_python_files_never_get_tf_edge(self):
        a = _record("a", source_location="src/a.py:1")
        b = _record("b", source_location="src/b.py:1")
        edges = _by_relationship(detect_relationships([a, b]), "shared_terraform_module")
        assert edges == []


# ---------------------------------------------------------------------------
# Cross-cutting: deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_relationship_emitted_only_once(self):
        a = _record("a", source_location="hiring/x.py:1")
        b = _record("b", source_location="hiring/y.py:1")
        edges = detect_relationships([a, b])
        # Sanity check we get at least one edge per relationship type that
        # applies; key uniqueness covered next.
        keys = [e.key for e in edges]
        assert len(keys) == len(set(keys))

    def test_evidence_strings_are_populated(self):
        a = _record("a", source_location="hiring/.env:1")
        b = _record("b", source_location="hiring/.env:2")
        for edge in detect_relationships([a, b]):
            assert edge.evidence
            assert len(edge.evidence) > 5

    def test_unrelated_records_produce_no_edges(self):
        a = _record("a", provider="OpenAI", source_location="hiring/screener.py:1")
        b = _record(
            "b",
            provider="Anthropic",
            system_type=AISystemType.MCP_SERVER,
            source_location="totally/different/.mcp.json",
        )
        edges = detect_relationships([a, b])
        # Different providers, different dirs, MCP not in same project as API:
        # nothing should fire.
        assert edges == []
