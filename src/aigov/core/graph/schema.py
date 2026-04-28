"""Graph schema — :class:`GraphNode`, :class:`GraphEdge`, :class:`AISystemGraph`.

These dataclasses are the single source of truth for graph shape. Every
renderer (D3 HTML, plain JSON) consumes ``AISystemGraph.to_dict()``; never
reach into the field layout of a record directly inside a renderer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class GraphNode:
    """One AI system. Sized + coloured by risk in the renderer."""
    id: str
    label: str
    system_type: str
    provider: str
    source_location: str
    origin_jurisdiction: str = ""
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "label": self.label,
            "system_type": self.system_type,
            "provider": self.provider,
            "source_location": self.source_location,
            "origin_jurisdiction": self.origin_jurisdiction,
            "tags": dict(self.tags),
        }
        if self.risk_score is not None:
            out["risk_score"] = self.risk_score
        if self.risk_level is not None:
            out["risk_level"] = self.risk_level
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphNode":
        return cls(
            id=data["id"],
            label=data["label"],
            system_type=data["system_type"],
            provider=data["provider"],
            source_location=data["source_location"],
            origin_jurisdiction=data.get("origin_jurisdiction", ""),
            risk_score=data.get("risk_score"),
            risk_level=data.get("risk_level"),
            tags=dict(data.get("tags") or {}),
        )


@dataclass
class GraphEdge:
    """One relationship between two nodes.

    Edges are intentionally undirected for our six relationship types — the
    ``source_id``/``target_id`` order is canonicalised (lex-sorted) at
    construction so dedup is a simple tuple compare.

    ``evidence`` is a list of human-readable sentences. Each detector
    contributes one entry; when parallel edges between the same pair are
    collapsed (see :func:`detect_relationships`), the surviving edge accumulates
    every contributing evidence sentence so a reviewer sees *all* the reasons
    the systems are linked.

    For ergonomics the constructor accepts a single ``str`` and wraps it,
    since most call-sites only have one sentence to add.
    """
    source_id: str
    target_id: str
    relationship: str
    confidence: float
    evidence: list[str]

    def __post_init__(self) -> None:
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(
                f"GraphEdge.confidence must be 0.0..1.0, got {self.confidence!r}"
            )
        if not (self.source_id and self.target_id):
            raise ValueError("GraphEdge requires non-empty source_id and target_id")
        if self.source_id == self.target_id:
            raise ValueError("GraphEdge cannot connect a node to itself")
        # Canonicalise so dedup compares ordered tuples.
        if self.source_id > self.target_id:
            self.source_id, self.target_id = self.target_id, self.source_id
        # Normalise evidence: accept a string for ergonomics, store a list.
        if isinstance(self.evidence, str):
            self.evidence = [self.evidence] if self.evidence else []
        elif self.evidence is None:
            self.evidence = []
        else:
            self.evidence = [str(e) for e in self.evidence if e]

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity for dedup: same nodes + same relationship → same edge."""
        return (self.source_id, self.target_id, self.relationship)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphEdge":
        raw = data.get("evidence")
        if raw is None:
            evidence: list[str] = []
        elif isinstance(raw, str):
            evidence = [raw] if raw else []
        else:
            evidence = [str(e) for e in raw if e]
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relationship=data["relationship"],
            confidence=float(data["confidence"]),
            evidence=evidence,
        )


@dataclass
class AISystemGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": dict(self.metadata),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AISystemGraph":
        return cls(
            nodes=[GraphNode.from_dict(n) for n in data.get("nodes") or []],
            edges=[GraphEdge.from_dict(e) for e in data.get("edges") or []],
            metadata=dict(data.get("metadata") or {}),
        )
