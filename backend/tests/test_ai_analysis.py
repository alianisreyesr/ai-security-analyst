import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.providers import AIProviderError, ProviderResponse
from app.models.threat import Threat
from app.models.threat_analysis import ThreatAnalysis
from app.services.ai_analysis import analyze_threat


class ValidFakeProvider:
    name = "fake"
    model = "fake-model-v1"

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        assert messages[0]["role"] == "system"
        return ProviderResponse(
            provider=self.name,
            model=self.model,
            content=json.dumps(
                {
                    "summary": "Repeated authentication failures were detected.",
                    "observed_evidence": [
                        "Six failed authentication events support this finding."
                    ],
                    "interpretation": (
                        "The pattern is consistent with credential guessing and "
                        "should be reviewed."
                    ),
                    "investigation_steps": [
                        "Review authentication events from the source."
                    ],
                    "caveats": [
                        "This detection does not prove account compromise."
                    ],
                    "confidence": "high",
                }
            ),
        )


class InvalidExtraFieldProvider:
    name = "fake-invalid"
    model = "fake-model-v1"

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        del messages
        return ProviderResponse(
            provider=self.name,
            model=self.model,
            content=json.dumps(
                {
                    "summary": "Attempt to override deterministic score.",
                    "observed_evidence": ["Synthetic evidence."],
                    "interpretation": "Synthetic interpretation.",
                    "investigation_steps": ["Review evidence."],
                    "caveats": ["Synthetic caveat."],
                    "confidence": "high",
                    "risk_score": 0,
                }
            ),
        )


class FailingProvider:
    name = "failing"
    model = "failing-model"

    def generate(self, messages: list[dict[str, str]]) -> ProviderResponse:
        del messages
        raise AIProviderError("synthetic provider outage")


def _create_threat(db: Session) -> Threat:
    threat = Threat(
        fingerprint="a" * 64,
        rule_id="auth.brute_force",
        title="Repeated authentication failures",
        source_ip="203.0.113.42",
        risk_score=72,
        severity="high",
        first_seen=datetime(2026, 9, 21, 20, 0, tzinfo=UTC),
        last_seen=datetime(2026, 9, 21, 20, 4, tzinfo=UTC),
        event_ids=[1, 2, 3, 4, 5, 6],
        evidence={
            "failed_attempts": 6,
            "unique_usernames": 2,
            "usernames": ["admin", "root"],
        },
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat


def test_valid_ai_output_is_persisted(db_session: Session) -> None:
    threat = _create_threat(db_session)

    analysis = analyze_threat(
        db_session,
        threat,
        provider=ValidFakeProvider(),
    )

    assert analysis.status == "success"
    assert analysis.provider == "fake"
    assert analysis.model == "fake-model-v1"
    assert analysis.confidence == "high"
    assert analysis.threat_id == threat.id


def test_extra_model_fields_trigger_fallback(db_session: Session) -> None:
    threat = _create_threat(db_session)

    analysis = analyze_threat(
        db_session,
        threat,
        provider=InvalidExtraFieldProvider(),
    )

    assert analysis.status == "fallback"
    assert "72/100" in analysis.summary

    stored_threat = db_session.scalar(select(Threat).where(Threat.id == threat.id))
    assert stored_threat is not None
    assert stored_threat.risk_score == 72


def test_provider_failure_preserves_deterministic_analysis(db_session: Session) -> None:
    threat = _create_threat(db_session)

    analysis = analyze_threat(
        db_session,
        threat,
        provider=FailingProvider(),
    )

    assert analysis.status == "fallback"
    assert analysis.provider == "failing"
    assert analysis.model == "failing-model"
    assert analysis.confidence == "low"


def test_analysis_records_are_auditable(db_session: Session) -> None:
    threat = _create_threat(db_session)

    analyze_threat(db_session, threat, provider=ValidFakeProvider())

    stored = db_session.scalar(
        select(ThreatAnalysis).where(ThreatAnalysis.threat_id == threat.id)
    )
    assert stored is not None
    assert stored.template_version
    assert stored.provider == "fake"
    assert stored.status == "success"
