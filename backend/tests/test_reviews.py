from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.threat import Threat


def _create_threat(db: Session) -> Threat:
    threat = Threat(
        fingerprint="9" * 64,
        rule_id="auth.brute_force",
        title="Synthetic threat",
        source_ip="8.8.8.8",
        risk_score=72,
        severity="high",
        first_seen=datetime(2026, 9, 21, 20, 0, tzinfo=UTC),
        last_seen=datetime(2026, 9, 21, 20, 4, tzinfo=UTC),
        event_ids=[1, 2, 3],
        evidence={"failed_attempts": 6, "synthetic": True},
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat


def test_review_is_audited_without_mutating_original_threat(
    client: TestClient,
    db_session: Session,
) -> None:
    threat = _create_threat(db_session)
    original_evidence = dict(threat.evidence)
    original_score = threat.risk_score

    response = client.post(
        f"/api/v1/threats/{threat.id}/reviews",
        json={
            "disposition": "likely_false_positive",
            "rationale": "Synthetic allowlisted maintenance scanner.",
            "reviewer": "test-analyst",
        },
    )

    assert response.status_code == 201
    db_session.refresh(threat)
    assert threat.evidence == original_evidence
    assert threat.risk_score == original_score

    history = client.get(f"/api/v1/threats/{threat.id}/reviews")
    assert history.status_code == 200
    items = history.json()["items"]
    assert len(items) == 1
    assert items[0]["disposition"] == "likely_false_positive"
    assert items[0]["reviewer"] == "test-analyst"


def test_review_unknown_threat_returns_404(client: TestClient) -> None:
    response = client.post(
        "/api/v1/threats/999999/reviews",
        json={
            "disposition": "needs_review",
            "rationale": "Synthetic review.",
            "reviewer": "test-analyst",
        },
    )

    assert response.status_code == 404
