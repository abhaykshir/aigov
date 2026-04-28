"""AI System Graph — evidence-based relationship modelling.

The graph subsystem turns a flat list of :class:`AISystemRecord` instances
into a typed graph: each record becomes a node, and relationship detectors
produce edges with a relationship type, a confidence score, and a short
evidence sentence explaining why the edge exists. Renderers (HTML, JSON)
consume the graph; they do not re-derive relationships.

SECURITY: graph output never carries credential values, file contents, or
raw env-var values — only file paths and metadata. The same SECURITY.md
posture as the rest of aigov.
"""
from __future__ import annotations

from aigov.core.graph.engine import build_graph
from aigov.core.graph.relationships import detect_relationships
from aigov.core.graph.renderer import to_html, to_json
from aigov.core.graph.schema import AISystemGraph, GraphEdge, GraphNode

__all__ = [
    "AISystemGraph",
    "GraphEdge",
    "GraphNode",
    "build_graph",
    "detect_relationships",
    "to_html",
    "to_json",
]
