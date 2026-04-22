from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from aigov.core.models import AISystemRecord, RiskLevel

_EU_AI_ACT_DEADLINE = date(2026, 8, 2)

_PRIORITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class ComplianceGap:
    requirement_name: str
    article_reference: str
    status: str  # "missing" | "partial" | "unknown"
    description: str
    remediation_steps: list[str] = field(default_factory=list)


@dataclass
class SystemGapAnalysis:
    record: AISystemRecord
    gaps: list[ComplianceGap]
    estimated_effort_hours: int
    priority: str  # "critical" | "high" | "medium" | "low"


@dataclass
class GapReport:
    systems: list[SystemGapAnalysis]
    overall_summary: dict
    deadline: date


# ---------------------------------------------------------------------------
# Gap factories — fresh instances per call to avoid shared mutable state
# ---------------------------------------------------------------------------

def _high_risk_gaps() -> list[ComplianceGap]:
    return [
        ComplianceGap(
            requirement_name="Risk management system",
            article_reference="Article 9",
            status="missing",
            description=(
                "A risk management system must be established, implemented, documented, "
                "and maintained throughout the AI system lifecycle."
            ),
            remediation_steps=[
                "Identify and analyse known and reasonably foreseeable risks",
                "Estimate and evaluate risks that may emerge during intended use",
                "Adopt suitable risk mitigation measures before deployment",
                "Maintain and update the risk management system regularly",
            ],
        ),
        ComplianceGap(
            requirement_name="Data governance practices",
            article_reference="Article 10",
            status="missing",
            description=(
                "Training, validation, and testing datasets must meet quality criteria "
                "including relevance, representativeness, and freedom from errors."
            ),
            remediation_steps=[
                "Document data collection and preparation methodology",
                "Assess datasets for biases and take corrective action",
                "Implement data governance and data management practices",
                "Ensure personal data handling complies with GDPR",
            ],
        ),
        ComplianceGap(
            requirement_name="Technical documentation",
            article_reference="Article 11",
            status="missing",
            description=(
                "Technical documentation must be drawn up before the AI system is placed "
                "on the market and kept up-to-date (Annex IV requirements)."
            ),
            remediation_steps=[
                "Prepare technical documentation per Annex IV",
                "Include system description, design specs, and capabilities",
                "Document validation and testing procedures",
                "Keep documentation current with every system change",
            ],
        ),
        ComplianceGap(
            requirement_name="Record-keeping and logging",
            article_reference="Article 12",
            status="unknown",
            description=(
                "High-risk AI systems must have automatic logging capabilities enabling "
                "traceability of operations throughout the system's lifetime."
            ),
            remediation_steps=[
                "Verify existing logging covers all required operational events",
                "Implement automatic logging of operation periods and inputs",
                "Ensure logs capture outputs relevant to risk monitoring",
                "Establish log retention policy and access controls",
            ],
        ),
        ComplianceGap(
            requirement_name="Transparency to users",
            article_reference="Article 13",
            status="missing",
            description=(
                "High-risk AI systems must be designed to enable deployers to interpret "
                "system output and use it appropriately, with clear instructions for use."
            ),
            remediation_steps=[
                "Create instructions for use in plain language",
                "Document system capabilities and limitations",
                "Describe accuracy levels and known performance issues",
                "Specify human oversight measures required of deployers",
            ],
        ),
        ComplianceGap(
            requirement_name="Human oversight mechanism",
            article_reference="Article 14",
            status="missing",
            description=(
                "High-risk AI systems must enable effective oversight by natural persons "
                "during the period of use, including the ability to intervene or stop."
            ),
            remediation_steps=[
                "Implement override and intervention controls for operators",
                "Design UI so operators can understand and interpret outputs",
                "Create stop/pause functionality for immediate cessation",
                "Document the human oversight role and responsibilities",
            ],
        ),
        ComplianceGap(
            requirement_name="Accuracy, robustness, and cybersecurity",
            article_reference="Article 15",
            status="unknown",
            description=(
                "High-risk AI systems must achieve appropriate levels of accuracy, "
                "robustness, and cybersecurity throughout their lifecycle."
            ),
            remediation_steps=[
                "Establish accuracy metrics and acceptable performance thresholds",
                "Test system robustness against adversarial and out-of-distribution inputs",
                "Conduct a cybersecurity assessment and implement protections",
                "Define procedures for handling errors and unexpected outputs",
            ],
        ),
        ComplianceGap(
            requirement_name="Conformity assessment",
            article_reference="Article 43",
            status="missing",
            description=(
                "High-risk AI systems must undergo a conformity assessment procedure "
                "before being placed on the EU market."
            ),
            remediation_steps=[
                "Determine applicable conformity assessment route (self-assessment or notified body)",
                "Complete conformity assessment against Annex III requirements",
                "Compile and sign EU declaration of conformity",
                "Affix CE marking where applicable",
            ],
        ),
        ComplianceGap(
            requirement_name="EU database registration",
            article_reference="Article 49",
            status="missing",
            description=(
                "Providers of high-risk AI systems must register the system in the EU-wide "
                "AI database before placing it on the market (Annex VIII information required)."
            ),
            remediation_steps=[
                "Create an account in the EU AI Act compliance database",
                "Register all required system information per Annex VIII",
                "Assign a unique identifier to the AI system",
                "Keep registration information current with system changes",
            ],
        ),
    ]


def _limited_risk_gaps() -> list[ComplianceGap]:
    return [
        ComplianceGap(
            requirement_name="AI interaction disclosure",
            article_reference="Article 50",
            status="unknown",
            description=(
                "Providers of AI systems that interact with natural persons must ensure "
                "those persons are informed they are interacting with an AI system, "
                "unless this is obvious from context."
            ),
            remediation_steps=[
                "Audit all user-facing interfaces for AI interaction disclosure",
                "Add clear disclosure messaging at the start of AI interactions",
                "Document disclosure mechanism in technical documentation",
            ],
        ),
        ComplianceGap(
            requirement_name="Synthetic content labeling",
            article_reference="Article 50",
            status="unknown",
            description=(
                "AI-generated or AI-manipulated content (including deepfakes and synthetic "
                "audio/video/text) must be labeled as artificially generated or manipulated."
            ),
            remediation_steps=[
                "Identify all outputs that constitute synthetic or AI-generated content",
                "Implement machine-readable and human-readable content labeling",
                "Verify labeling persists through content distribution channels",
            ],
        ),
    ]


def _prohibited_gap() -> ComplianceGap:
    return ComplianceGap(
        requirement_name="Immediate cessation required",
        article_reference="Article 5",
        status="missing",
        description=(
            "This AI system falls under a prohibited practice under Article 5 of the EU AI Act. "
            "Deployment, continued development, or placing on the market must cease immediately."
        ),
        remediation_steps=[
            "Immediately suspend all deployment and operation of this AI system",
            "Notify relevant internal stakeholders and legal counsel",
            "Confirm classification with qualified EU AI Act legal advice",
            "Document the cessation decision and retain all related records",
        ],
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class GapAnalyzer:
    def analyze(self, records: list[AISystemRecord]) -> GapReport:
        systems: list[SystemGapAnalysis] = []
        risk_counts: dict[str, int] = {}

        for record in records:
            analysis = self._analyze_record(record)
            systems.append(analysis)
            risk_key = (record.risk_classification or RiskLevel.UNKNOWN).value
            risk_counts[risk_key] = risk_counts.get(risk_key, 0) + 1

        total_gaps = sum(len(s.gaps) for s in systems)

        n_high = risk_counts.get(RiskLevel.HIGH_RISK.value, 0)
        n_limited = risk_counts.get(RiskLevel.LIMITED_RISK.value, 0)
        effort_min = n_high * 120 + n_limited * 8
        effort_max = n_high * 160 + n_limited * 16

        today = date.today()
        days_until_deadline = (_EU_AI_ACT_DEADLINE - today).days

        overall_summary: dict = {
            "total_systems": len(records),
            "systems_by_risk": risk_counts,
            "total_gaps": total_gaps,
            "estimated_effort_min_hours": effort_min,
            "estimated_effort_max_hours": effort_max,
            "days_until_deadline": days_until_deadline,
            "deadline": _EU_AI_ACT_DEADLINE.isoformat(),
        }

        return GapReport(systems=systems, overall_summary=overall_summary, deadline=_EU_AI_ACT_DEADLINE)

    def _analyze_record(self, record: AISystemRecord) -> SystemGapAnalysis:
        risk = record.risk_classification or RiskLevel.UNKNOWN

        if risk == RiskLevel.PROHIBITED:
            return SystemGapAnalysis(
                record=record,
                gaps=[_prohibited_gap()],
                estimated_effort_hours=0,
                priority="critical",
            )
        if risk == RiskLevel.HIGH_RISK:
            return SystemGapAnalysis(
                record=record,
                gaps=_high_risk_gaps(),
                estimated_effort_hours=120,
                priority="critical",
            )
        if risk == RiskLevel.LIMITED_RISK:
            return SystemGapAnalysis(
                record=record,
                gaps=_limited_risk_gaps(),
                estimated_effort_hours=8,
                priority="medium",
            )
        return SystemGapAnalysis(
            record=record,
            gaps=[],
            estimated_effort_hours=0,
            priority="low",
        )
