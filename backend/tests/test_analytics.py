from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analytics.baseline import compute_baseline, score_anomaly
from app.models.analytics_snapshot import AnalyticsSnapshot
from app.models.threat import Threat
from app.services.analytics import rebuild_threat_snapshots


def _threat(
    fingerprint: str,
    *,
    source_ip: str,
    last_seen: datetime,
    score: int = 70,
    severity: str = "high",
    rule_id: str = "network.port_scan",
) -> Threat:
    return Threat(
        fingerprint=fingerprint,
        rule_id=rule_id,
        title="Synthetic threat",
        source_ip=source_ip,
        risk_score=score,
        severity=severity,
        first_seen=last_seen - timedelta(minutes=1),
        last_seen=last_seen,
        event_ids=[],
        evidence={"synthetic": True},
    )


def test_baseline_cold_start_is_safe() -> None:
    baseline = compute_baseline([1.0, 2.0])

    assert baseline.status == "cold_start"
    result = score_anomaly(10.0, baseline)
    assert result.anomaly_score == 0
    assert result.anomalous is False
    assert "Insufficient historical samples" in result.explanation


def test_interpretable_anomaly_score() -> None:
    baseline = compute_baseline([1.0, 1.0, 1.0, 1.0, 1.0])

    assert baseline.status == "ready"
    result = score_anomaly(5.0, baseline)

    assert result.z_score == 3.0
    assert result.anomaly_score == 60
    assert result.anomalous is True
    assert "historical mean" in result.explanation


def test_rebuild_creates_continuous_snapshots_and_is_idempotent(
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)
    db_session.add_all(
        [
            _threat("a" * 64, source_ip="8.8.8.8", last_seen=start + timedelta(minutes=10)),
            _threat(
                "b" * 64,
                source_ip="1.1.1.1",
                last_seen=start + timedelta(hours=2, minutes=5),
                score=85,
                severity="critical",
                rule_id="auth.brute_force",
            ),
        ]
    )
    db_session.commit()

    first = rebuild_threat_snapshots(
        db_session,
        start=start,
        end=start + timedelta(hours=3),
        granularity="hour",
    )
    second = rebuild_threat_snapshots(
        db_session,
        start=start,
        end=start + timedelta(hours=3),
        granularity="hour",
    )

    assert [item.total_threats for item in first] == [1, 0, 1]
    assert [item.total_threats for item in second] == [1, 0, 1]
    count = db_session.scalar(select(func.count()).select_from(AnalyticsSnapshot))
    assert count == 3


def test_rebuild_api_rejects_unbounded_range(client: TestClient) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    response = client.post(
        "/api/v1/analytics/rebuild",
        json={
            "granularity": "day",
            "start": start.isoformat(),
            "end": (start + timedelta(days=91)).isoformat(),
        },
    )

    assert response.status_code == 422
    assert "maximum" in response.json()["detail"]


def test_source_anomaly_endpoint_uses_historical_baseline(
    client: TestClient,
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 10, 0, tzinfo=UTC)
    for index in range(6):
        current_count = 5 if index == 5 else 1
        db_session.add(
            AnalyticsSnapshot(
                bucket_key=f"hour:{index}",
                granularity="hour",
                bucket_start=start + timedelta(hours=index),
                total_threats=current_count,
                severity_counts={"high": current_count},
                rule_counts={"network.port_scan": current_count},
                source_counts={"8.8.8.8": current_count},
            )
        )
    db_session.commit()

    response = client.get(
        "/api/v1/analytics/sources/8.8.8.8/anomaly",
        params={"granularity": "hour", "lookback": 5},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["baseline"]["status"] == "ready"
    assert payload["current_value"] == 5.0
    assert payload["anomaly_score"] == 60
    assert payload["anomalous"] is True


def test_anomaly_threshold_is_configurable() -> None:
    baseline = compute_baseline([1.0, 1.0, 1.0, 1.0, 1.0])

    result = score_anomaly(5.0, baseline, threshold=80)

    assert result.anomaly_score == 60
    assert result.threshold == 80
    assert result.anomalous is False
