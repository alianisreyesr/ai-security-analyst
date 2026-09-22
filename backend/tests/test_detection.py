from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.detection.engine import run_detection
from app.detection.risk import severity_from_score
from app.detection.rules import detect_port_scan, detect_request_burst
from app.models.security_event import SecurityEvent


def _event(
    event_id: int,
    timestamp: datetime,
    *,
    source_ip: str,
    event_type: str,
    source: str,
    username: str | None = None,
    destination_port: int | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip="10.0.0.5",
        source_port=50000 + event_id,
        destination_port=destination_port,
        protocol="TCP",
        event_type=event_type,
        username=username,
        source=source,
        raw_payload={"synthetic": True},
    )


def test_brute_force_detection() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 20),
            source_ip="203.0.113.42",
            event_type="authentication_failure",
            source="linux_ssh",
            username="admin",
            destination_port=22,
        )
        for index in range(1, 7)
    ]

    findings = run_detection(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "auth.brute_force"
    assert finding.evidence["failed_attempts"] == 6
    assert finding.score >= 60


def test_success_after_failures_increases_risk() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    failures = [
        _event(
            index,
            start + timedelta(seconds=index * 20),
            source_ip="203.0.113.42",
            event_type="authentication_failure",
            source="linux_ssh",
            username="admin",
            destination_port=22,
        )
        for index in range(1, 7)
    ]
    success = _event(
        99,
        start + timedelta(minutes=3),
        source_ip="203.0.113.42",
        event_type="authentication_success",
        source="linux_ssh",
        username="admin",
        destination_port=22,
    )

    findings = run_detection([*failures, success])

    assert len(findings) == 1
    assert findings[0].rule_id == "auth.brute_force_success"
    assert findings[0].score >= 75
    assert findings[0].evidence["follow_up_successes"] == 1


def test_port_scan_detection() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 5),
            source_ip="198.51.100.7",
            event_type="firewall_deny",
            source="firewall",
            destination_port=20 + index,
        )
        for index in range(1, 12)
    ]

    findings = run_detection(events)

    assert any(finding.rule_id == "network.port_scan" for finding in findings)


def test_request_burst_detection() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(milliseconds=index * 500),
            source_ip="198.51.100.9",
            event_type="http_request",
            source="web_access",
        )
        for index in range(1, 51)
    ]

    findings = run_detection(events)

    assert any(finding.rule_id == "web.request_burst" for finding in findings)


def test_severity_boundaries() -> None:
    assert severity_from_score(0) == "low"
    assert severity_from_score(30) == "medium"
    assert severity_from_score(60) == "high"
    assert severity_from_score(80) == "critical"
    assert severity_from_score(120) == "critical"


def test_rule_failure_does_not_interrupt_other_rules() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 20),
            source_ip="203.0.113.42",
            event_type="authentication_failure",
            source="linux_ssh",
            username="admin",
            destination_port=22,
        )
        for index in range(1, 7)
    ]

    def broken_rule(_: list[SecurityEvent]) -> list:
        raise RuntimeError("synthetic rule failure")

    findings = run_detection(events, rules=(broken_rule,))

    assert findings == []


def test_port_scan_can_exclude_known_source() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 5),
            source_ip="198.51.100.7",
            event_type="firewall_deny",
            source="firewall",
            destination_port=20 + index,
        )
        for index in range(1, 12)
    ]

    findings = detect_port_scan(events, excluded_source_ips={"198.51.100.7"})

    assert findings == []


def test_request_burst_can_exclude_known_source() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(milliseconds=index * 500),
            source_ip="198.51.100.9",
            event_type="http_request",
            source="web_access",
        )
        for index in range(1, 51)
    ]

    findings = detect_request_burst(events, excluded_source_ips={"198.51.100.9"})

    assert findings == []


def test_brute_force_threshold_is_configurable(monkeypatch) -> None:
    monkeypatch.setattr(settings, "brute_force_failure_threshold", 3)
    monkeypatch.setattr(settings, "brute_force_window_seconds", 120)
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 10),
            source_ip="203.0.113.55",
            event_type="authentication_failure",
            source="linux_ssh",
            username="admin",
            destination_port=22,
        )
        for index in range(1, 4)
    ]

    findings = run_detection(events)

    assert any(finding.rule_id == "auth.brute_force" for finding in findings)


def test_port_scan_threshold_is_configurable(monkeypatch) -> None:
    monkeypatch.setattr(settings, "port_scan_unique_ports_threshold", 3)
    monkeypatch.setattr(settings, "port_scan_window_seconds", 120)
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index * 5),
            source_ip="198.51.100.30",
            event_type="firewall_deny",
            source="firewall",
            destination_port=100 + index,
        )
        for index in range(1, 4)
    ]

    findings = detect_port_scan(events)

    assert len(findings) == 1
    assert findings[0].evidence["threshold"] == 3


def test_request_burst_threshold_is_configurable(monkeypatch) -> None:
    monkeypatch.setattr(settings, "request_burst_threshold", 3)
    monkeypatch.setattr(settings, "request_burst_window_seconds", 30)
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        _event(
            index,
            start + timedelta(seconds=index),
            source_ip="198.51.100.31",
            event_type="http_request",
            source="web_access",
        )
        for index in range(1, 4)
    ]

    findings = detect_request_burst(events)

    assert len(findings) == 1
    assert findings[0].evidence["threshold"] == 3


def test_below_default_thresholds_do_not_alert() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    auth_events = [
        _event(
            index,
            start + timedelta(seconds=index * 10),
            source_ip="203.0.113.80",
            event_type="authentication_failure",
            source="linux_ssh",
            username="admin",
            destination_port=22,
        )
        for index in range(1, settings.brute_force_failure_threshold)
    ]

    findings = run_detection(auth_events)

    assert findings == []
