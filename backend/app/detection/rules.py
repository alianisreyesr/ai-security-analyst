from collections import defaultdict
from datetime import UTC, datetime, timedelta

from app.detection.types import DetectionFinding
from app.models.security_event import SecurityEvent


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _best_window(
    events: list[SecurityEvent],
    window: timedelta,
) -> list[SecurityEvent]:
    ordered = sorted(events, key=lambda event: _naive_utc(event.timestamp))
    best: list[SecurityEvent] = []
    left = 0

    for right, event in enumerate(ordered):
        right_time = _naive_utc(event.timestamp)
        while right_time - _naive_utc(ordered[left].timestamp) > window:
            left += 1
        current = ordered[left : right + 1]
        if len(current) > len(best):
            best = current

    return best


def detect_brute_force(events: list[SecurityEvent]) -> list[DetectionFinding]:
    failures_by_source: dict[str, list[SecurityEvent]] = defaultdict(list)
    successes_by_source: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if not event.source_ip:
            continue
        if event.event_type == "authentication_failure":
            failures_by_source[event.source_ip].append(event)
        elif event.event_type == "authentication_success":
            successes_by_source[event.source_ip].append(event)

    findings: list[DetectionFinding] = []

    for source_ip, failures in failures_by_source.items():
        cluster = _best_window(failures, timedelta(minutes=5))
        if len(cluster) < 5:
            continue

        usernames = sorted({event.username for event in cluster if event.username})
        score = min(85, 30 + len(cluster) * 5 + len(usernames) * 2)
        first_seen = min(event.timestamp for event in cluster)
        last_seen = max(event.timestamp for event in cluster)
        title = "Repeated authentication failures"
        rule_id = "auth.brute_force"
        evidence = {
            "failed_attempts": len(cluster),
            "unique_usernames": len(usernames),
            "usernames": usernames[:20],
            "window_minutes": 5,
        }
        event_ids = [event.id for event in cluster if event.id is not None]

        follow_up_successes = [
            event
            for event in successes_by_source.get(source_ip, [])
            if _naive_utc(last_seen)
            <= _naive_utc(event.timestamp)
            <= _naive_utc(last_seen) + timedelta(minutes=5)
        ]
        if follow_up_successes:
            score = min(100, score + 15)
            title = "Successful login after repeated authentication failures"
            rule_id = "auth.brute_force_success"
            evidence["follow_up_successes"] = len(follow_up_successes)
            event_ids.extend(
                event.id for event in follow_up_successes if event.id is not None
            )
            last_seen = max(
                [last_seen, *(event.timestamp for event in follow_up_successes)]
            )

        findings.append(
            DetectionFinding(
                rule_id=rule_id,
                title=title,
                source_ip=source_ip,
                score=score,
                first_seen=first_seen,
                last_seen=last_seen,
                event_ids=sorted(set(event_ids)),
                evidence=evidence,
            )
        )

    return findings


def detect_port_scan(events: list[SecurityEvent]) -> list[DetectionFinding]:
    firewall_by_source: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if (
            event.source_ip
            and event.destination_port is not None
            and event.source == "firewall"
        ):
            firewall_by_source[event.source_ip].append(event)

    findings: list[DetectionFinding] = []

    for source_ip, source_events in firewall_by_source.items():
        cluster = _best_window(source_events, timedelta(minutes=5))
        ports = sorted(
            {
                event.destination_port
                for event in cluster
                if event.destination_port is not None
            }
        )
        if len(ports) < 10:
            continue

        score = min(90, 60 + (len(ports) - 10) * 2)
        findings.append(
            DetectionFinding(
                rule_id="network.port_scan",
                title="Multi-port probing detected",
                source_ip=source_ip,
                score=score,
                first_seen=min(event.timestamp for event in cluster),
                last_seen=max(event.timestamp for event in cluster),
                event_ids=[event.id for event in cluster if event.id is not None],
                evidence={
                    "unique_destination_ports": len(ports),
                    "destination_ports": ports[:50],
                    "window_minutes": 5,
                },
            )
        )

    return findings


def detect_request_burst(events: list[SecurityEvent]) -> list[DetectionFinding]:
    web_by_source: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.source_ip and event.event_type == "http_request":
            web_by_source[event.source_ip].append(event)

    findings: list[DetectionFinding] = []

    for source_ip, source_events in web_by_source.items():
        cluster = _best_window(source_events, timedelta(minutes=1))
        if len(cluster) < 50:
            continue

        score = min(85, 50 + (len(cluster) - 50))
        findings.append(
            DetectionFinding(
                rule_id="web.request_burst",
                title="High-rate web request burst",
                source_ip=source_ip,
                score=score,
                first_seen=min(event.timestamp for event in cluster),
                last_seen=max(event.timestamp for event in cluster),
                event_ids=[event.id for event in cluster if event.id is not None],
                evidence={
                    "request_count": len(cluster),
                    "window_minutes": 1,
                },
            )
        )

    return findings
