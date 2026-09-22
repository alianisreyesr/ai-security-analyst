import json
from datetime import UTC, datetime, timedelta
from time import perf_counter

from app.detection.engine import run_detection
from app.models.security_event import SecurityEvent


def build_events(count: int = 10_000) -> list[SecurityEvent]:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
    return [
        SecurityEvent(
            id=index,
            timestamp=start + timedelta(milliseconds=index * 5),
            source_ip=f"198.51.100.{(index % 200) + 1}",
            destination_ip="10.0.0.5",
            source_port=40000 + (index % 1000),
            destination_port=20 + (index % 200),
            protocol="TCP",
            event_type="firewall_deny",
            username=None,
            source="firewall",
            raw_payload={"synthetic": True},
        )
        for index in range(1, count + 1)
    ]


def main() -> None:
    events = build_events()
    started = perf_counter()
    findings = run_detection(events)
    elapsed = perf_counter() - started

    result = {
        "events": len(events),
        "duration_seconds": round(elapsed, 6),
        "events_per_second": round(len(events) / max(elapsed, 1e-9), 2),
        "findings": len(findings),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
