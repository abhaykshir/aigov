from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from aigov.core.models import AISystemRecord, AISystemType, DeploymentType
from aigov.scanners.base import BaseScanner

# ---------------------------------------------------------------------------
# Resource type → (provider, system_type, jurisdiction) mappings
# ---------------------------------------------------------------------------

# Each entry: (prefix_or_exact, provider_label, system_type, jurisdiction)
_RESOURCE_RULES: list[tuple[str, str, AISystemType, str]] = [
    # AWS
    ("aws_sagemaker_endpoint",      "AWS", AISystemType.API_SERVICE, "US"),
    ("aws_sagemaker_model",         "AWS", AISystemType.MODEL,       "US"),
    ("aws_sagemaker_training_job",  "AWS", AISystemType.MODEL,       "US"),
    ("aws_sagemaker_",              "AWS", AISystemType.MODEL,       "US"),
    ("aws_bedrock_agent",           "AWS", AISystemType.AGENT,       "US"),
    ("aws_bedrock_",                "AWS", AISystemType.MODEL,       "US"),
    ("aws_comprehend_",             "AWS", AISystemType.MODEL,       "US"),
    ("aws_lex_",                    "AWS", AISystemType.AGENT,       "US"),
    ("aws_rekognition_",            "AWS", AISystemType.MODEL,       "US"),
    # Azure
    ("azurerm_cognitive_account",       "Azure", AISystemType.API_SERVICE, "EU"),
    ("azurerm_machine_learning_",       "Azure", AISystemType.MODEL,       "EU"),
    ("azurerm_ai_",                     "Azure", AISystemType.API_SERVICE, "EU"),
    # GCP
    ("google_vertex_ai_",    "GCP", AISystemType.API_SERVICE, "US"),
    ("google_ml_engine_",    "GCP", AISystemType.MODEL,       "US"),
    ("google_dialogflow_",   "GCP", AISystemType.AGENT,       "US"),
]

# ---------------------------------------------------------------------------
# HCL parsing — regex over raw text, no HCL library required
# ---------------------------------------------------------------------------

# Matches:  resource "TYPE" "NAME" {
_RESOURCE_RE = re.compile(
    r'^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _record_id(location: str, resource_type: str, resource_name: str) -> str:
    raw = f"infra.terraform|{location}|{resource_type}|{resource_name}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]


def _classify_resource(resource_type: str) -> tuple[str, AISystemType, str] | None:
    """Return (provider, system_type, jurisdiction) or None if not an AI resource."""
    rt = resource_type.lower()
    for prefix, provider, system_type, jurisdiction in _RESOURCE_RULES:
        if rt == prefix or rt.startswith(prefix):
            return provider, system_type, jurisdiction
    return None


def _scan_tf_file(path: Path) -> list[AISystemRecord]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    records: list[AISystemRecord] = []
    location = str(path)

    for match in _RESOURCE_RE.finditer(text):
        resource_type = match.group(1)
        resource_name = match.group(2)

        result = _classify_resource(resource_type)
        if result is None:
            continue

        provider, system_type, jurisdiction = result
        records.append(AISystemRecord(
            id=_record_id(location, resource_type, resource_name),
            name=resource_name,
            description=f"Terraform resource {resource_type!r} named {resource_name!r}",
            source_scanner="infra.terraform",
            source_location=location,
            discovery_timestamp=_now(),
            confidence=0.95,
            system_type=system_type,
            provider=provider,
            deployment_type=DeploymentType.CLOUD_API,
            tags={
                "origin_jurisdiction": jurisdiction,
                "terraform_resource_type": resource_type,
                "terraform_resource_name": resource_name,
            },
        ))

    return records


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TerraformScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "infra.terraform"

    @property
    def description(self) -> str:
        return (
            "Scans Terraform .tf files for AI/ML cloud resources across "
            "AWS (SageMaker, Bedrock), Azure (Cognitive Services), and GCP (Vertex AI)"
        )

    def scan(self, paths: list[str]) -> list[AISystemRecord]:
        records: list[AISystemRecord] = []
        for root_path in paths:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [
                    d for d in dirnames
                    if not d.startswith(".") and d not in {"__pycache__", ".venv", "venv", ".terraform"}
                ]
                for filename in filenames:
                    if filename.endswith(".tf"):
                        records.extend(_scan_tf_file(Path(dirpath) / filename))
        return records
