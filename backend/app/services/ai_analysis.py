from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.prompts import build_analyst_messages
from app.ai.providers import (
    AIProvider,
    AIProviderError,
    DisabledProvider,
    get_ai_provider,
)
from app.core.config import settings
from app.models.threat import Threat
from app.models.threat_analysis import ThreatAnalysis
from app.schemas.ai_analysis import AnalystOutput


def _fallback_output(threat: Threat) -> AnalystOutput:
    return AnalystOutput(
        summary=(
            f"Deterministic rule {threat.rule_id} produced a "
            f"{threat.severity} threat with risk score {threat.risk_score}/100."
        ),
        observed_evidence=[
            f"Detection rule: {threat.rule_id}",
            f"Risk score: {threat.risk_score}/100",
            f"Severity: {threat.severity}",
            f"Supporting events: {len(threat.event_ids)}",
        ],
        interpretation=(
            "AI-assisted interpretation is unavailable. Review the deterministic "
            "evidence and rule documentation before taking action."
        ),
        investigation_steps=[
            "Review the supporting normalized events.",
            "Validate whether the source and activity are expected.",
            "Compare the behavior with nearby events in the same time window.",
        ],
        caveats=[
            "This fallback contains no model-generated conclusions.",
            "A detection indicates suspicious behavior, not confirmed compromise.",
        ],
        confidence="low",
    )


def _persist_analysis(
    db: Session,
    threat: Threat,
    output: AnalystOutput,
    *,
    status: str,
    provider: str,
    model: str,
) -> ThreatAnalysis:
    analysis = ThreatAnalysis(
        threat_id=threat.id,
        status=status,
        provider=provider,
        model=model,
        template_version=settings.ai_prompt_template_version,
        summary=output.summary,
        observed_evidence=output.observed_evidence,
        interpretation=output.interpretation,
        investigation_steps=output.investigation_steps,
        caveats=output.caveats,
        confidence=output.confidence,
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    return analysis


def analyze_threat(
    db: Session,
    threat: Threat,
    provider: AIProvider | None = None,
) -> ThreatAnalysis:
    try:
        selected_provider = provider or get_ai_provider()
    except AIProviderError:
        selected_provider = DisabledProvider()

    messages = build_analyst_messages(threat)

    try:
        response = selected_provider.generate(messages)
        output = AnalystOutput.model_validate_json(response.content)
        return _persist_analysis(
            db,
            threat,
            output,
            status="success",
            provider=response.provider,
            model=response.model,
        )
    except (AIProviderError, ValidationError, ValueError, TypeError):
        fallback = _fallback_output(threat)
        provider_name = getattr(selected_provider, "name", "unknown")
        provider_model = getattr(selected_provider, "model", "unknown")
        return _persist_analysis(
            db,
            threat,
            fallback,
            status="fallback",
            provider=provider_name,
            model=provider_model,
        )


def get_threat_or_none(db: Session, threat_id: int) -> Threat | None:
    return db.scalar(select(Threat).where(Threat.id == threat_id))
