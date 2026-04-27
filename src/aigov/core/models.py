from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class AISystemType(str, Enum):
    MODEL = "model"
    AGENT = "agent"
    API_SERVICE = "api_service"
    EMBEDDING = "embedding"
    FINE_TUNE = "fine_tune"
    RAG_PIPELINE = "rag_pipeline"
    MCP_SERVER = "mcp_server"
    BROWSER_EXTENSION = "browser_extension"
    COPILOT = "copilot"
    OTHER = "other"


class DeploymentType(str, Enum):
    CLOUD_API = "cloud_api"
    SELF_HOSTED = "self_hosted"
    SAAS = "saas"
    LOCAL = "local"
    EMBEDDED = "embedded"


class RiskLevel(str, Enum):
    PROHIBITED = "prohibited"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"
    NEEDS_REVIEW = "needs_review"
    UNKNOWN = "unknown"


@dataclass
class AISystemRecord:
    id: str
    name: str
    description: str
    source_scanner: str
    source_location: str
    discovery_timestamp: datetime
    confidence: float
    system_type: AISystemType
    provider: str
    deployment_type: DeploymentType
    data_categories: list[str] = field(default_factory=list)
    model_identifier: Optional[str] = None
    risk_classification: Optional[RiskLevel] = RiskLevel.UNKNOWN
    classification_rationale: Optional[str] = None
    tags: dict[str, str] = field(default_factory=dict)

    # Risk-engine output. These are populated by aigov.core.risk.engine.apply_risk
    # and are first-class so consumers (JSON, SARIF, CSV, table) don't have to
    # reach into ``tags`` and stringify-then-parse to read them.
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_drivers: Optional[list[str]] = None
    risk_confidence: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError(
                f"AISystemRecord.confidence must be between 0.0 and 1.0 inclusive, "
                f"got {self.confidence!r}"
            )
        if not (isinstance(self.provider, str) and self.provider.strip()):
            raise ValueError("AISystemRecord.provider must be a non-empty string")
        if not (isinstance(self.source_location, str) and self.source_location.strip()):
            raise ValueError("AISystemRecord.source_location must be a non-empty string")
        if not (isinstance(self.source_scanner, str) and self.source_scanner.strip()):
            raise ValueError("AISystemRecord.source_scanner must be a non-empty string")
        if self.risk_score is not None:
            if not isinstance(self.risk_score, int) or not (0 <= self.risk_score <= 100):
                raise ValueError(
                    f"AISystemRecord.risk_score must be an int 0..100, got {self.risk_score!r}"
                )
        if self.risk_confidence is not None:
            if not isinstance(self.risk_confidence, (int, float)) or not (
                0.0 <= float(self.risk_confidence) <= 1.0
            ):
                raise ValueError(
                    "AISystemRecord.risk_confidence must be between 0.0 and 1.0 inclusive, "
                    f"got {self.risk_confidence!r}"
                )

    @classmethod
    def from_dict(cls, data: dict) -> "AISystemRecord":
        from datetime import datetime
        rl_raw = data.get("risk_classification")
        risk_score_raw = data.get("risk_score")
        risk_drivers_raw = data.get("risk_drivers")
        risk_confidence_raw = data.get("risk_confidence")
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            source_scanner=data["source_scanner"],
            source_location=data["source_location"],
            discovery_timestamp=datetime.fromisoformat(data["discovery_timestamp"]),
            confidence=float(data["confidence"]),
            system_type=AISystemType(data["system_type"]),
            provider=data["provider"],
            deployment_type=DeploymentType(data["deployment_type"]),
            data_categories=list(data.get("data_categories") or []),
            model_identifier=data.get("model_identifier"),
            risk_classification=RiskLevel(rl_raw) if rl_raw else RiskLevel.UNKNOWN,
            classification_rationale=data.get("classification_rationale"),
            tags=dict(data.get("tags") or {}),
            risk_score=int(risk_score_raw) if risk_score_raw is not None else None,
            risk_level=data.get("risk_level"),
            risk_drivers=list(risk_drivers_raw) if risk_drivers_raw is not None else None,
            risk_confidence=float(risk_confidence_raw) if risk_confidence_raw is not None else None,
        )

    def to_dict(self) -> dict:
        out: dict = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "source_scanner": self.source_scanner,
            "source_location": self.source_location,
            "discovery_timestamp": self.discovery_timestamp.isoformat(),
            "confidence": self.confidence,
            "system_type": self.system_type.value,
            "provider": self.provider,
            "model_identifier": self.model_identifier,
            "deployment_type": self.deployment_type.value,
            "data_categories": list(self.data_categories),
            "risk_classification": self.risk_classification.value if self.risk_classification else None,
            "classification_rationale": self.classification_rationale,
            "tags": dict(self.tags),
        }
        # Only emit risk_* keys when populated, so unscored records don't carry
        # null clutter in their JSON.
        if self.risk_score is not None:
            out["risk_score"] = self.risk_score
        if self.risk_level is not None:
            out["risk_level"] = self.risk_level
        if self.risk_drivers is not None:
            out["risk_drivers"] = list(self.risk_drivers)
        if self.risk_confidence is not None:
            out["risk_confidence"] = self.risk_confidence
        return out
