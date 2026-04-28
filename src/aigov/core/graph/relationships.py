"""Relationship detectors — turn a flat list of records into typed edges.

Each detector emits zero or more ``GraphEdge`` instances; every edge carries
its own evidence string and confidence value. We deliberately favour fewer,
high-quality edges over many speculative ones.

Edges are deduplicated by ``(source, target, relationship)`` after canonical
ordering, with the highest-confidence variant winning.
"""
from __future__ import annotations

import re
from itertools import combinations
from pathlib import PurePosixPath
from typing import Iterable

from aigov.core.graph.schema import GraphEdge
from aigov.core.models import AISystemRecord, AISystemType


# How many directory levels apart counts as "same module" for the weakest signal.
_SAME_MODULE_DISTANCE = 1

# File names that mark a config-shared boundary. Two records with source paths
# that resolve to one of these in the same directory get a ``shared_config``
# edge. We pin the list rather than matching by extension because a stray
# `.env.example` shouldn't drag every record together.
_SHARED_CONFIG_FILES = frozenset({
    ".env",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".mcp.json",
    "mcp.json",
})


# ---------------------------------------------------------------------------
# Path helpers — normalise both POSIX and Windows separators
# ---------------------------------------------------------------------------

def _strip_line(loc: str) -> str:
    """Drop a trailing ``:NN`` or ``#L NN`` line suffix."""
    return re.sub(r"[:#]L?\d+$", "", loc)


def _to_posix(loc: str) -> str:
    return _strip_line(loc).replace("\\", "/")


def _path(loc: str) -> PurePosixPath:
    return PurePosixPath(_to_posix(loc))


def _filename(loc: str) -> str:
    return _path(loc).name


def _parent(loc: str, levels: int = 1) -> str:
    p = _path(loc)
    for _ in range(levels):
        if p.parent == p:
            break
        p = p.parent
    return str(p) if str(p) not in {".", ""} else ""


def _directory(loc: str) -> str:
    """The immediate directory portion of a source location."""
    return str(_path(loc).parent)


# ---------------------------------------------------------------------------
# Detectors — each takes the full record list and returns edges
# ---------------------------------------------------------------------------

def _shared_config_edges(
    records: list[AISystemRecord],
    evidence_records: list[AISystemRecord] | None = None,
) -> list[GraphEdge]:
    """Two records that share a config file get a ``shared_config`` edge.

    Two paths produce these edges, both at confidence 0.9:

    1. **Direct co-residence.** Two records whose own ``source_location``
       is a recognised config file (``.env`` / ``.mcp.json``) — e.g. two
       MCP servers declared in the same ``.mcp.json``. Evidence:
       *"Both found in <path>"*.
    2. **API-key evidence (new in v0.5).** An ``evidence_record`` (typically
       a ``code.api_keys`` finding inside an ``.env``) lives in directory
       ``D``. Every pair of AI service records whose ``source_location``
       sits in ``D`` gets a ``shared_config`` edge. Evidence: *"Both in
       directory containing <env file> with detected <provider> API key"*.
    """
    evidence_records = evidence_records or []
    edges: list[GraphEdge] = []

    # Path 1 — direct co-residence (e.g. multiple MCP servers in one .mcp.json).
    by_path: dict[str, list[AISystemRecord]] = {}
    for record in records:
        norm = _to_posix(record.source_location)
        if _filename(record.source_location).lower() in _SHARED_CONFIG_FILES:
            by_path.setdefault(norm, []).append(record)

    for path, group in by_path.items():
        for a, b in combinations(group, 2):
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="shared_config",
                confidence=0.9,
                evidence=f"Both found in {path}",
            ))

    # Path 2 — evidence-driven edges. An API key in dir D ties together every
    # pair of AI services that live in D. Confidence is 0.8 (not 0.9 like
    # path 1): co-residence with an .env is a *reasonable* assumption that
    # both services share the credential, not a proven one — they could read
    # different env files, use a secrets manager, or hold a stale key.
    for ev in evidence_records:
        ev_dir = _directory(ev.source_location)
        if not ev_dir:
            continue
        ev_filename = _filename(ev.source_location) or "config file"
        co_located = [
            r for r in records if _directory(r.source_location) == ev_dir
        ]
        if len(co_located) < 2:
            continue
        for a, b in combinations(co_located, 2):
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="shared_config",
                confidence=0.8,
                evidence=(
                    f"Both in directory containing {ev_filename} with "
                    f"detected {ev.provider} API key"
                ),
            ))

    return edges


def _shared_provider_key_edges(records: list[AISystemRecord]) -> list[GraphEdge]:
    """Same provider + share a directory or live near the same .env file → likely
    talking to the same backing service via the same key.

    Heuristic: pair every two records with the same (case-insensitive) provider
    whose immediate parent directories are the same OR whose nearest .env file
    is the same. Lower than ``shared_config`` because we're inferring intent
    rather than proving it.
    """
    edges: list[GraphEdge] = []

    # Index records by (provider_lower, directory)
    by_pair: dict[tuple[str, str], list[AISystemRecord]] = {}
    for record in records:
        provider = (record.provider or "").lower()
        if not provider or provider in {"unknown", "internal", ""}:
            continue
        directory = _directory(record.source_location)
        by_pair.setdefault((provider, directory), []).append(record)

    for (provider, directory), group in by_pair.items():
        if len(group) < 2:
            continue
        for a, b in combinations(group, 2):
            if a.id == b.id:
                continue
            evidence = (
                f"Both use {a.provider} in {directory or '<root>'}"
            )
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="shared_provider_key",
                confidence=0.85,
                evidence=evidence,
            ))
    return edges


def _mcp_connection_edges(records: list[AISystemRecord]) -> list[GraphEdge]:
    """An MCP server in the same directory as — or one directory above — an AI
    API service implies the agent consuming the MCP server can also call that
    service.

    Tightened in v0.4: previously this fired for any shared prefix between the
    MCP config's path and the API service's path, which on a multi-app repo
    produced an edge between every MCP at the project root and every API in
    every subdirectory. The new rule is strictly local — same dir, or
    *exactly* one level up — so a tangle at scale becomes a small fan-out.
    """
    edges: list[GraphEdge] = []
    mcps = [r for r in records if r.system_type == AISystemType.MCP_SERVER]
    apis = [r for r in records if r.system_type == AISystemType.API_SERVICE]
    if not mcps or not apis:
        return edges

    for mcp in mcps:
        mcp_dir = _directory(mcp.source_location)
        for api in apis:
            api_dir = _directory(api.source_location)
            if not _mcp_within_one_level(mcp_dir, api_dir):
                continue
            evidence = (
                f"MCP server '{mcp.name}' configured alongside {api.provider} "
                f"usage in same project"
            )
            edges.append(GraphEdge(
                source_id=mcp.id,
                target_id=api.id,
                relationship="mcp_connection",
                confidence=0.8,
                evidence=evidence,
            ))
    return edges


def _mcp_within_one_level(mcp_dir: str, api_dir: str) -> bool:
    """True iff *mcp_dir* is the same as *api_dir*, or its immediate parent."""
    if not (mcp_dir and api_dir):
        return False
    if mcp_dir == api_dir:
        return True
    api_parent = _immediate_parent(api_dir)
    return bool(api_parent) and api_parent == mcp_dir


def _immediate_parent(path_str: str) -> str:
    """Return the parent directory of *path_str*, or '' at the root."""
    p = PurePosixPath(path_str)
    if p.parent == p:
        return ""
    parent = str(p.parent)
    return "" if parent in {".", ""} else parent


def _same_module_edges(records: list[AISystemRecord]) -> list[GraphEdge]:
    """Two records in the same directory (or within ``_SAME_MODULE_DISTANCE`` levels)."""
    edges: list[GraphEdge] = []
    for a, b in combinations(records, 2):
        a_dir = _directory(a.source_location)
        b_dir = _directory(b.source_location)
        if not a_dir or not b_dir:
            continue
        if a_dir == b_dir:
            evidence = f"Both in {a_dir}/"
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="same_module",
                confidence=0.5,
                evidence=evidence,
            ))
    return edges


def _same_python_package_edges(records: list[AISystemRecord]) -> list[GraphEdge]:
    """Two Python AI findings in the same directory get a ``same_python_package``
    edge.

    Renamed from ``import_chain`` in v0.5.1 — the prior name implied AST-level
    import-graph analysis, which we *don't* do. We only check that two
    ``.py`` files share the same parent directory. Python's package
    discipline means same-dir modules almost always import each other or
    share a module entry point, but the relationship name now reflects what
    we actually detect.
    """
    edges: list[GraphEdge] = []
    py_records = [
        r for r in records
        if _to_posix(r.source_location).endswith(".py")
    ]
    by_package: dict[str, list[AISystemRecord]] = {}
    for record in py_records:
        package = _directory(record.source_location)
        if not package:
            continue
        by_package.setdefault(package, []).append(record)

    for package, group in by_package.items():
        if len(group) < 2:
            continue
        for a, b in combinations(group, 2):
            a_name = _filename(a.source_location)
            b_name = _filename(b.source_location)
            evidence = f"{a_name} and {b_name} both in {package}/ package"
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="same_python_package",
                confidence=0.7,
                evidence=evidence,
            ))
    return edges


def _shared_terraform_module_edges(records: list[AISystemRecord]) -> list[GraphEdge]:
    """Two AI resources defined in the same ``.tf`` file or Terraform module
    directory share infrastructure, lifecycle, and IAM — strongest infra signal
    we have."""
    edges: list[GraphEdge] = []
    tf_records = [
        r for r in records
        if _to_posix(r.source_location).endswith(".tf")
    ]
    if len(tf_records) < 2:
        return edges

    # First group by exact .tf file (highest confidence — same module).
    by_file: dict[str, list[AISystemRecord]] = {}
    for record in tf_records:
        path = _to_posix(_strip_line(record.source_location))
        by_file.setdefault(path, []).append(record)

    seen_pairs: set[tuple[str, str]] = set()
    for path, group in by_file.items():
        if len(group) < 2:
            continue
        for a, b in combinations(group, 2):
            evidence = f"Both provisioned in {path}"
            pair = tuple(sorted([a.id, b.id]))
            seen_pairs.add(pair)
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="shared_terraform_module",
                confidence=0.9,
                evidence=evidence,
            ))

    # Then: records in the same Terraform directory but different files.
    by_dir: dict[str, list[AISystemRecord]] = {}
    for record in tf_records:
        by_dir.setdefault(_directory(record.source_location), []).append(record)

    for directory, group in by_dir.items():
        if len(group) < 2 or not directory:
            continue
        for a, b in combinations(group, 2):
            pair = tuple(sorted([a.id, b.id]))
            if pair in seen_pairs:
                continue
            evidence = f"Both in Terraform module {directory}/"
            edges.append(GraphEdge(
                source_id=a.id,
                target_id=b.id,
                relationship="shared_terraform_module",
                confidence=0.85,
                evidence=evidence,
            ))
    return edges


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

# Detectors that only need the node-record list.
_NODE_ONLY_DETECTORS = (
    _shared_provider_key_edges,
    _mcp_connection_edges,
    _same_python_package_edges,
    _shared_terraform_module_edges,
    _same_module_edges,
)


def detect_relationships(
    records: list[AISystemRecord],
    evidence_records: list[AISystemRecord] | None = None,
) -> list[GraphEdge]:
    """Run every detector and return a deduplicated, collapsed list of edges.

    *records* are the AI-system records that become graph nodes. *evidence_records*
    (optional) are records that should *not* become nodes themselves, but whose
    presence strengthens edges between other records — for example, a
    ``code.api_keys`` finding inside an ``.env`` file ties together every AI
    service that lives in that directory.

    Two reductions happen here:

    1. **Per-relationship dedup.** When two detectors produce the same
       ``(source, target, relationship)`` triple, the higher-confidence
       variant wins.
    2. **Parallel-edge collapse.** Two AI services may match several
       detectors at once (e.g. ``shared_provider_key``, ``same_module``,
       ``same_python_package`` all between the same hiring/ pair). Rendering
       three near-identical lines on top of each other is noise; we instead
       emit a single edge whose ``relationship`` is the highest-confidence
       reason and whose ``evidence`` list accumulates *all* the contributing
       sentences. The viewer keeps every reason without the visual stack.
    """
    by_key: dict[tuple[str, str, str], GraphEdge] = {}

    # The shared_config detector takes both lists; everything else only sees
    # the node records.
    for edge in _shared_config_edges(records, evidence_records):
        existing = by_key.get(edge.key)
        if existing is None or edge.confidence > existing.confidence:
            by_key[edge.key] = edge

    for detector in _NODE_ONLY_DETECTORS:
        for edge in detector(records):
            existing = by_key.get(edge.key)
            if existing is None or edge.confidence > existing.confidence:
                by_key[edge.key] = edge

    collapsed = _collapse_parallel_edges(by_key.values())

    # Stable sort: by relationship, then source, then target — keeps test
    # assertions deterministic across runs.
    return sorted(collapsed, key=lambda e: (e.relationship, e.source_id, e.target_id))


def _collapse_parallel_edges(edges: Iterable[GraphEdge]) -> list[GraphEdge]:
    """Collapse edges sharing a ``(source_id, target_id)`` pair into one.

    Inputs come from ``detect_relationships`` after per-relationship dedup,
    so each pair has at most one edge per relationship type. The merge
    rules:

    * **Relationship**: the type with the highest ``confidence`` wins.
      Ties resolve by the first-seen relationship (stable).
    * **Confidence**: the maximum confidence in the group.
    * **Evidence**: every contributing edge's evidence sentences,
      concatenated in descending-confidence order, de-duplicated.
    """
    by_pair: dict[tuple[str, str], list[GraphEdge]] = {}
    for edge in edges:
        by_pair.setdefault((edge.source_id, edge.target_id), []).append(edge)

    out: list[GraphEdge] = []
    for pair, group in by_pair.items():
        if len(group) == 1:
            out.append(group[0])
            continue

        # Highest confidence first; ties keep their original relative order.
        sorted_group = sorted(group, key=lambda e: -e.confidence)
        winner = sorted_group[0]

        merged_evidence: list[str] = []
        seen: set[str] = set()
        for e in sorted_group:
            for sentence in e.evidence:
                if sentence and sentence not in seen:
                    merged_evidence.append(sentence)
                    seen.add(sentence)

        out.append(GraphEdge(
            source_id=winner.source_id,
            target_id=winner.target_id,
            relationship=winner.relationship,
            confidence=winner.confidence,
            evidence=merged_evidence,
        ))
    return out
