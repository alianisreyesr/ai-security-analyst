from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.security_case import SecurityCase
from app.models.threat import Threat
from app.services.correlation import correlate_threats


def _threat(
    threat_id: int,
    fingerprint: str,
    *,
    source_ip: str,
    first_seen: datetime,
    rule_id: str,
    event_ids: list[int],
) -> Threat:
    return Threat(
        id=threat_id,
        fingerprint=fingerprint,
        rule_id=rule_id,
        title="Synthetic threat",
        source_ip=source_ip,
        risk_score=70,
        severity="high",
        first_seen=first_seen,
        last_seen=first_seen + timedelta(minutes=1),
        event_ids=event_ids,
        evidence={"synthetic": True},
    )


def test_correlation_handles_out_of_order_threats_and_preserves_evidence(
    db_session: Session,
) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    earlier = _threat(
        1,
        "a" * 64,
        source_ip="8.8.8.8",
        first_seen=start,
        rule_id="network.port_scan",
        event_ids=[1, 2],
    )
    later = _threat(
        2,
        "b" * 64,
        source_ip="8.8.8.8",
        first_seen=start + timedelta(minutes=10),
        rule_id="auth.brute_force",
        event_ids=[2, 3, 4],
    )
    db_session.add_all([earlier, later])
    db_session.commit()

    cases = correlate_threats(db_session, [later, earlier])

    assert len(cases) == 1
    case = cases[0]
    assert case.threat_ids == [1, 2]
    assert case.event_ids == [1, 2, 3, 4]
    assert case.evidence["distinct_rule_ids"] == [
        "auth.brute_force",
        "network.port_scan",
    ]


def test_correlation_is_idempotent(db_session: Session) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    threats = [
        _threat(
            10,
            "c" * 64,
            source_ip="1.1.1.1",
            first_seen=start,
            rule_id="network.port_scan",
            event_ids=[10],
        ),
        _threat(
            11,
            "d" * 64,
            source_ip="1.1.1.1",
            first_seen=start + timedelta(minutes=5),
            rule_id="auth.brute_force",
            event_ids=[11],
        ),
    ]
    db_session.add_all(threats)
    db_session.commit()

    first = correlate_threats(db_session, threats)
    second = correlate_threats(db_session, threats)

    assert first[0].id == second[0].id
    count = db_session.scalar(select(func.count()).select_from(SecurityCase))
    assert count == 1
