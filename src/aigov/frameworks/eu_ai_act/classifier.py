from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from aigov.core.models import AISystemRecord, RiskLevel

_YAML_DIR = Path(__file__).parent

# Disclaimer marker added to every classified record so consumers know the
# output is a machine signal, not legal advice.
_CLASSIFICATION_TYPE_TAG = "automated_signal"


def _load_yaml(filename: str) -> dict:
    with (_YAML_DIR / filename).open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _normalize(text: str) -> str:
    """Lowercase and replace path/name separators with spaces for substring matching."""
    return re.sub(r"[_\-/\\\.]+", " ", text).lower()


@dataclass
class _RuleMatch:
    rule_id: str
    rule_name: str
    total_hits: int
    library_or_cloud_hit: bool
    details: list[str]


def _keyword_hits(keywords: list[str], text: str) -> list[str]:
    # text is pre-normalized; apply the same normalization to each keyword
    # so that e.g. "real-time facial recognition" matches "real time facial recognition"
    return [kw for kw in keywords if _normalize(kw) in text]


def _pattern_hits(patterns: list[str], text: str) -> list[str]:
    text_lower = text.lower()
    matched = []
    for pattern in patterns:
        try:
            if re.search(pattern.lower(), text_lower):
                matched.append(pattern)
        except re.error:
            if pattern.lower() in text_lower:
                matched.append(pattern)
    return matched


def _service_hits(services: list[str], provider: str) -> list[str]:
    provider_lower = provider.lower()
    return [svc for svc in services if svc.lower() in provider_lower]


def _evaluate_rule(
    rule: dict,
    searchable: str,
    lib_text: str,
    provider: str,
    prohibited_mode: bool,
) -> Optional[_RuleMatch]:
    signals = rule.get("signals") or {}
    keywords = signals.get("keywords") or []
    library_patterns = signals.get("library_patterns") or []
    cloud_services = signals.get("cloud_services") or []

    matched_kw = _keyword_hits(keywords, searchable)
    matched_lib = _pattern_hits(library_patterns, lib_text)
    matched_svc = _service_hits(cloud_services, provider)

    kw_count = len(matched_kw)
    lib_count = len(matched_lib)
    svc_count = len(matched_svc)
    total = kw_count + lib_count + svc_count
    lib_or_cloud = (lib_count + svc_count) > 0

    if prohibited_mode:
        # For absolute prohibitions, a library/cloud signal alone is insufficient —
        # at least one keyword is required to establish context before classifying
        # as PROHIBITED, preventing a bare library match from over-escalating risk.
        matched = (kw_count >= 2) or (kw_count >= 1 and lib_or_cloud)
    else:
        # Require at least 2 total signal hits (any combination of keyword +
        # library + cloud).  A lone library hit without any keyword corroboration
        # is too noisy given how broadly general-purpose APIs like OpenAI are used.
        matched = total >= 2

    if not matched:
        return None

    details: list[str] = []
    if matched_kw:
        kw_preview = ", ".join(repr(k) for k in matched_kw[:3])
        extra = f" (+{len(matched_kw) - 3} more)" if len(matched_kw) > 3 else ""
        details.append(f"keyword signals: {kw_preview}{extra}")
    if matched_lib:
        details.append(f"library match: {', '.join(matched_lib[:2])}")
    if matched_svc:
        details.append(f"cloud service: {', '.join(matched_svc[:2])}")

    return _RuleMatch(
        rule_id=rule.get("id", "unknown"),
        rule_name=rule.get("name", "unknown"),
        total_hits=total,
        library_or_cloud_hit=lib_or_cloud,
        details=details,
    )


def _best_match(
    rules: list[dict],
    searchable: str,
    lib_text: str,
    provider: str,
    prohibited_mode: bool = False,
) -> Optional[_RuleMatch]:
    best: Optional[_RuleMatch] = None
    for rule in rules:
        m = _evaluate_rule(rule, searchable, lib_text, provider, prohibited_mode)
        if m is None:
            continue
        if best is None or m.total_hits > best.total_hits:
            best = m
    return best


def _confidence(match: _RuleMatch) -> str:
    if match.library_or_cloud_hit or match.total_hits >= 5:
        return "high"
    if match.total_hits >= 3:
        return "medium"
    return "low"


def _rationale(level: str, category: Optional[str], match: _RuleMatch) -> str:
    cat_part = f" under {category}" if category else ""
    evidence = "; ".join(match.details)
    return (
        f"Classified as {level}{cat_part} "
        f"(rule: '{match.rule_name}'). "
        f"Evidence — {evidence}."
    )


class EUAIActClassifier:
    """Classifies AISystemRecord instances under the EU AI Act risk framework.

    Always returns a new AISystemRecord — input records are never mutated.
    """

    def __init__(self) -> None:
        prohibited_data = _load_yaml("prohibited.yaml")
        annex_iii_data = _load_yaml("annex_iii.yaml")
        transparency_data = _load_yaml("transparency.yaml")

        self._prohibited: list[dict] = prohibited_data.get("practices", [])
        self._annex_iii: list[dict] = annex_iii_data.get("categories", [])
        self._transparency: list[dict] = transparency_data.get("obligations", [])

    def classify(self, record: AISystemRecord) -> AISystemRecord:
        """Return a new record with risk_classification, rationale, and tags populated.

        The input record is never mutated.
        """
        searchable = _normalize(
            " ".join([record.name or "", record.description or "", record.source_location or ""])
        )
        lib_text = _normalize(" ".join([record.name or "", record.provider or ""]))
        provider = (record.provider or "").lower()

        # 1. Prohibited practices (Article 5) — highest priority
        prohibited_rules = {r.get("id"): r for r in self._prohibited}
        match = _best_match(self._prohibited, searchable, lib_text, provider, prohibited_mode=True)
        if match:
            rule = prohibited_rules.get(match.rule_id, {})
            new_tags = {
                **record.tags,
                "confidence_adjustment": _confidence(match),
                "eu_ai_act_category": match.rule_name,
                "eu_ai_act_article": rule.get("article_reference", "Article 5"),
                "classification_type": _CLASSIFICATION_TYPE_TAG,
            }
            return dataclasses.replace(
                record,
                risk_classification=RiskLevel.PROHIBITED,
                classification_rationale=_rationale("PROHIBITED", None, match),
                tags=new_tags,
            )

        # 2. High-risk systems (Annex III)
        annex_rules = {r.get("id"): r for r in self._annex_iii}
        match = _best_match(self._annex_iii, searchable, lib_text, provider)
        if match:
            rule = annex_rules.get(match.rule_id, {})
            cat_num = match.rule_id.replace("annex_iii_", "")
            category = f"Annex III category {cat_num} ({match.rule_name})"
            new_tags = {
                **record.tags,
                "confidence_adjustment": _confidence(match),
                "eu_ai_act_category": match.rule_name,
                "eu_ai_act_article": rule.get("article_reference", "Annex III"),
                "classification_type": _CLASSIFICATION_TYPE_TAG,
            }
            return dataclasses.replace(
                record,
                risk_classification=RiskLevel.HIGH_RISK,
                classification_rationale=_rationale("HIGH_RISK", category, match),
                tags=new_tags,
            )

        # 3. Limited-risk systems (Article 50 transparency obligations)
        transparency_rules = {r.get("id"): r for r in self._transparency}
        match = _best_match(self._transparency, searchable, lib_text, provider)
        if match:
            rule = transparency_rules.get(match.rule_id, {})
            category = f"Article 50 transparency ({match.rule_name})"
            new_tags = {
                **record.tags,
                "confidence_adjustment": _confidence(match),
                "eu_ai_act_category": match.rule_name,
                "eu_ai_act_article": rule.get("article_reference", "Article 50"),
                "classification_type": _CLASSIFICATION_TYPE_TAG,
            }
            return dataclasses.replace(
                record,
                risk_classification=RiskLevel.LIMITED_RISK,
                classification_rationale=_rationale("LIMITED_RISK", category, match),
                tags=new_tags,
            )

        # 4. Default — no signals detected
        new_tags = {
            **record.tags,
            "confidence_adjustment": "high",
            "eu_ai_act_category": "",
            "eu_ai_act_article": "",
            "classification_type": _CLASSIFICATION_TYPE_TAG,
        }
        return dataclasses.replace(
            record,
            risk_classification=RiskLevel.MINIMAL_RISK,
            classification_rationale=(
                "No EU AI Act risk signals detected in name, description, source location, "
                "or provider. Classified as MINIMAL_RISK by default."
            ),
            tags=new_tags,
        )
