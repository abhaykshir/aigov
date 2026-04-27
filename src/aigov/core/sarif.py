from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aigov.core.engine import ScanResult
    from aigov.core.models import AISystemRecord

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_TOOL_NAME = "aigov"
_TOOL_VERSION = "0.4.0"
_INFORMATION_URI = "https://github.com/abhaykshir/aigov"

_RULES: list[dict] = [
    {
        "id": "ai-governance/prohibited",
        "name": "ProhibitedAIPractice",
        "shortDescription": {"text": "EU AI Act Article 5 — Prohibited AI Practice"},
        "fullDescription": {
            "text": (
                "This AI system falls under Article 5 of the EU AI Act, which prohibits "
                "AI practices that pose an unacceptable risk to fundamental rights. "
                "Prohibited practices include social scoring by public authorities, "
                "real-time remote biometric identification in public spaces by law "
                "enforcement (with narrow exceptions), AI that manipulates persons "
                "through subliminal techniques or exploits vulnerabilities, and "
                "emotion recognition in workplaces and educational institutions. "
                "These systems must be immediately taken out of service."
            )
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://artificialintelligenceact.eu/article/5/",
    },
    {
        "id": "ai-governance/high-risk",
        "name": "HighRiskAISystem",
        "shortDescription": {"text": "EU AI Act Annex III — High-Risk AI System"},
        "fullDescription": {
            "text": (
                "This AI system is classified as high-risk under EU AI Act Annex III. "
                "High-risk AI systems must comply with strict mandatory requirements "
                "before being placed on the market or put into service, including: "
                "risk management systems, data governance, technical documentation, "
                "record-keeping, transparency and provision of information to users, "
                "human oversight, accuracy and robustness requirements, and "
                "conformity assessment with registration in the EU database. "
                "Categories include biometric systems, critical infrastructure, "
                "education, employment, essential services, law enforcement, "
                "migration and border control, and administration of justice."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://artificialintelligenceact.eu/annex/3/",
    },
    {
        "id": "ai-governance/limited-risk",
        "name": "LimitedRiskAISystem",
        "shortDescription": {"text": "EU AI Act Article 50 — Transparency Obligations"},
        "fullDescription": {
            "text": (
                "This AI system has limited risk under the EU AI Act and is subject to "
                "transparency obligations under Article 50. Providers and deployers must "
                "ensure that users are informed when they are interacting with an AI "
                "system, unless this is obvious from context. This applies to chatbots, "
                "emotion recognition systems, biometric categorisation systems, systems "
                "that generate or manipulate images, audio or video (deepfakes), and "
                "AI-generated or manipulated content. Required disclosures must be "
                "provided in a clear and distinguishable manner."
            )
        },
        "defaultConfiguration": {"level": "note"},
        "helpUri": "https://artificialintelligenceact.eu/article/50/",
    },
    {
        "id": "ai-governance/minimal-risk",
        "name": "MinimalRiskAISystem",
        "shortDescription": {"text": "EU AI Act — Minimal Risk AI System"},
        "fullDescription": {
            "text": (
                "This AI system presents minimal or no risk under the EU AI Act. "
                "The vast majority of AI systems currently used in the EU fall into "
                "this category. No mandatory legal requirements apply, although "
                "providers are encouraged to voluntarily apply codes of conduct and "
                "follow best practices for responsible AI development, including the "
                "requirements applicable to high-risk AI systems."
            )
        },
        "defaultConfiguration": {"level": "none"},
        "helpUri": "https://artificialintelligenceact.eu/",
    },
    {
        "id": "ai-governance/needs-review",
        "name": "AISystemRequiringReview",
        "shortDescription": {"text": "AI System Requiring Human Classification Review"},
        "fullDescription": {
            "text": (
                "This AI system requires human classification review. It has been "
                "flagged by automated scanning or custom governance rules but its "
                "risk classification under the EU AI Act or your organisation's "
                "internal AI governance policy could not be determined automatically. "
                "A qualified person should assess this system against applicable "
                "regulatory requirements and document the classification decision."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://artificialintelligenceact.eu/",
    },
]

_RULE_ID_INDEX: dict[str, int] = {rule["id"]: i for i, rule in enumerate(_RULES)}

_RISK_TO_RULE_ID: dict[str, str] = {
    "prohibited":   "ai-governance/prohibited",
    "high_risk":    "ai-governance/high-risk",
    "limited_risk": "ai-governance/limited-risk",
    "minimal_risk": "ai-governance/minimal-risk",
    "needs_review": "ai-governance/needs-review",
    "unknown":      "ai-governance/needs-review",
}

_RISK_TO_LEVEL: dict[str, str] = {
    "prohibited":   "error",
    "high_risk":    "warning",
    "limited_risk": "note",
    "minimal_risk": "none",
    "needs_review": "warning",
    "unknown":      "none",
}

# Matches "path/to/file.ext:42" — the numeric suffix is the line number.
_FILE_LINE_RE = re.compile(r"^(.+):(\d+)$")


def _parse_location(source_location: str) -> dict:
    """Return a SARIF location object for *source_location*."""
    if source_location.startswith("arn:") or "://" in source_location:
        return {"logicalLocations": [{"name": source_location}]}

    m = _FILE_LINE_RE.match(source_location)
    if m:
        uri = m.group(1).replace("\\", "/")
        line = int(m.group(2))
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }
        }

    uri = source_location.replace("\\", "/")
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def _record_to_sarif_result(record: AISystemRecord) -> dict:
    from aigov.core.models import RiskLevel

    risk = record.risk_classification or RiskLevel.UNKNOWN
    risk_val = risk.value
    rule_id = _RISK_TO_RULE_ID.get(risk_val, "ai-governance/needs-review")
    level = _RISK_TO_LEVEL.get(risk_val, "none")
    rule_index = _RULE_ID_INDEX.get(rule_id, 4)

    risk_label = risk_val.upper().replace("_", " ")
    rationale = record.classification_rationale or "No classification rationale available."
    message_text = f"{record.name} ({record.provider}) classified as {risk_label}. {rationale}"

    # Properties bag — only safe, non-sensitive fields (no API key values or raw tag blobs).
    properties: dict = {
        "provider": record.provider,
        "system_type": record.system_type.value,
        "origin_jurisdiction": record.tags.get("origin_jurisdiction", ""),
        "confidence": record.confidence,
    }
    eu_cat = record.tags.get("eu_ai_act_category", "")
    if eu_cat:
        properties["eu_ai_act_category"] = eu_cat

    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message_text},
        "locations": [_parse_location(record.source_location)],
        "properties": properties,
    }


def _build_sarif_document(records: list[AISystemRecord]) -> dict:
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _INFORMATION_URI,
                        "rules": _RULES,
                    }
                },
                "results": [_record_to_sarif_result(rec) for rec in records],
            }
        ],
    }


def to_sarif(result: ScanResult, *, indent: int = 2) -> str:
    """Render *result* as a SARIF 2.1.0 JSON string."""
    return json.dumps(_build_sarif_document(result.records), indent=indent, ensure_ascii=False)


def records_to_sarif(records: list[AISystemRecord], *, indent: int = 2) -> str:
    """Render *records* as a SARIF 2.1.0 JSON string."""
    return json.dumps(_build_sarif_document(records), indent=indent, ensure_ascii=False)
