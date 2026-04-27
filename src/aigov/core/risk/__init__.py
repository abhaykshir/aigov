"""Context-aware risk scoring for AISystemRecord.

The risk subsystem produces an explainable, deterministic score that augments
the EU AI Act risk classification with deployment-context signals (environment,
exposure, data sensitivity, interaction type).

SECURITY: context enrichment may read source files for pattern matching, but
file contents are never logged, persisted, or returned. Only the *presence* of
patterns becomes part of the output.
"""
from __future__ import annotations

from aigov.core.risk.context import enrich
from aigov.core.risk.engine import apply_risk
from aigov.core.risk.scoring import RiskResult, compute_risk

__all__ = ["apply_risk", "compute_risk", "enrich", "RiskResult"]
