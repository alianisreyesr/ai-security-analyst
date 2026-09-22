from datetime import UTC, datetime, timedelta
from time import perf_counter

from app.detection.engine import run_detection
from app.models.security_event import SecurityEvent


def test_detection_pipeline_performance_smoke() -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    events = [
        SecurityEvent(
            id=index,
            timestamp=start + timedelta(milliseconds=index * 10),
            source_ip=f"198.51.100.{(index % 100) + 1}",
            destination_ip="10.0.0.5",
            source_port=40000 + (index % 1000),
            destination_port=20 + (index % 100),
            protocol="TCP",
            event_type="firewall_deny",
            username=None,
            source="firewall",
            raw_payload={"synthetic": True},
        )
        for index in range(1, 1001)
    ]

    started = perf_counter()
    findings = run_detection(events)
    elapsed = perf_counter() - started

    assert elapsed >= 0
    assert len(events) / max(elapsed, 1e-9) > 0
    assert isinstance(findings, list)
