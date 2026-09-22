from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.threat import Threat


def test_threat_analysis_endpoint_falls_back_when_ai_disabled(
    client: TestClient,
    db_session: Session,
) -> None:
    threat = Threat(
        fingerprint="d" * 64,
        rule_id="network.port_scan",
        title="Multi-port probing detected",
        source_ip="198.51.100.7",
        risk_score=70,
        severity="high",
        first_seen=datetime(2026, 9, 21, 20, 0, tzinfo=UTC),
        last_seen=datetime(2026, 9, 21, 20, 3, tzinfo=UTC),
        event_ids=[10, 11, 12],
        evidence={"unique_destination_ports": 12},
    )
    db_session.add(threat)
    db_session.commit()
    db_session.refresh(threat)

    response = client.post(f"/api/v1/threats/{threat.id}/analysis")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "fallback"
    assert payload["provider"] == "disabled"
    assert payload["output"]["confidence"] == "low"
    assert "70/100" in payload["output"]["summary"]


def test_threat_analysis_endpoint_returns_404_for_unknown_threat(
    client: TestClient,
) -> None:
    response = client.post("/api/v1/threats/999999/analysis")

    assert response.status_code == 404
