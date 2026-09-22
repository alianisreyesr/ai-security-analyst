from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.models.threat import Threat


def _add_event(
    db: Session,
    *,
    timestamp: datetime,
    source_ip: str,
    destination_port: int,
    event_type: str = "firewall_deny",
    source: str = "firewall",
) -> SecurityEvent:
    event = SecurityEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip="10.0.0.5",
        source_port=50000,
        destination_port=destination_port,
        protocol="TCP",
        event_type=event_type,
        username=None,
        source=source,
        raw_payload={"synthetic": True},
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _add_threat(
    db: Session,
    *,
    fingerprint: str,
    rule_id: str,
    source_ip: str,
    score: int,
    severity: str,
    event_ids: list[int],
    first_seen: datetime,
    last_seen: datetime,
) -> Threat:
    threat = Threat(
        fingerprint=fingerprint,
        rule_id=rule_id,
        title="Synthetic threat",
        source_ip=source_ip,
        risk_score=score,
        severity=severity,
        first_seen=first_seen,
        last_seen=last_seen,
        event_ids=event_ids,
        evidence={"synthetic": True},
    )
    db.add(threat)
    db.commit()
    db.refresh(threat)
    return threat


def test_threat_timeline_is_chronological(
    client: TestClient,
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    later = _add_event(
        db_session,
        timestamp=start + timedelta(minutes=2),
        source_ip="8.8.8.8",
        destination_port=443,
    )
    earlier = _add_event(
        db_session,
        timestamp=start,
        source_ip="8.8.8.8",
        destination_port=22,
    )
    threat = _add_threat(
        db_session,
        fingerprint="e" * 64,
        rule_id="network.port_scan",
        source_ip="8.8.8.8",
        score=70,
        severity="high",
        event_ids=[later.id, earlier.id],
        first_seen=start,
        last_seen=start + timedelta(minutes=2),
    )

    response = client.get(f"/api/v1/threats/{threat.id}/timeline")

    assert response.status_code == 200
    events = response.json()["events"]
    assert [event["id"] for event in events] == [earlier.id, later.id]
    assert events[0]["timestamp"].endswith("+00:00")


def test_threat_list_filters_and_includes_mitre(
    client: TestClient,
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    _add_threat(
        db_session,
        fingerprint="f" * 64,
        rule_id="network.port_scan",
        source_ip="8.8.8.8",
        score=70,
        severity="high",
        event_ids=[],
        first_seen=start,
        last_seen=start,
    )
    _add_threat(
        db_session,
        fingerprint="1" * 64,
        rule_id="auth.brute_force",
        source_ip="1.1.1.1",
        score=85,
        severity="critical",
        event_ids=[],
        first_seen=start,
        last_seen=start,
    )

    response = client.get(
        "/api/v1/threats",
        params={"severity": "high", "source_ip": "8.8.8.8", "limit": 1},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert len(payload["items"]) == 1
    assert payload["items"][0]["rule_id"] == "network.port_scan"
    assert payload["items"][0]["mitre"][0]["technique_id"] == "T1046"


def test_threat_search_and_pagination(
    client: TestClient,
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    for index in range(3):
        _add_threat(
            db_session,
            fingerprint=str(index + 2) * 64,
            rule_id="auth.brute_force",
            source_ip=f"8.8.8.{index + 1}",
            score=65 + index,
            severity="high",
            event_ids=[],
            first_seen=start + timedelta(minutes=index),
            last_seen=start + timedelta(minutes=index),
        )

    response = client.get(
        "/api/v1/threats",
        params={"q": "brute_force", "limit": 2, "offset": 1},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert len(payload["items"]) == 2
    assert payload["offset"] == 1


def test_source_statistics(
    client: TestClient,
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    for index in range(2):
        _add_threat(
            db_session,
            fingerprint=str(index + 7) * 64,
            rule_id="auth.brute_force",
            source_ip="8.8.8.8",
            score=60 + index,
            severity="high",
            event_ids=[],
            first_seen=start,
            last_seen=start + timedelta(minutes=index),
        )

    response = client.get("/api/v1/threats/sources/statistics")

    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["source_ip"] == "8.8.8.8"
    assert item["threat_count"] == 2
    assert item["max_risk_score"] == 61
