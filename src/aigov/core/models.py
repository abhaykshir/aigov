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

    def to_dict(self) -> dict:
        return {
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
