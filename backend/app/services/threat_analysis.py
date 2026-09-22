import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import run_detection
from app.detection.risk import severity_from_score
from app.detection.types import DetectionFinding
from app.models.security_event import SecurityEvent
from app.models.threat import Threat


def finding_fingerprint(finding: DetectionFinding) -> str:
    raw = "|".join(
        [
            finding.rule_id,
            finding.source_ip or "",
            finding.first_seen.isoformat(),
            finding.last_seen.isoformat(),
            ",".join(str(event_id) for event_id in sorted(finding.event_ids)),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def persist_findings(
    db: Session,
    findings: list[DetectionFinding],
) -> list[Threat]:
    threats: list[Threat] = []

    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        existing = db.scalar(select(Threat).where(Threat.fingerprint == fingerprint))
        if existing is not None:
            threats.append(existing)
            continue

        threat = Threat(
            fingerprint=fingerprint,
            rule_id=finding.rule_id,
            title=finding.title,
            source_ip=finding.source_ip,
            risk_score=finding.score,
            severity=severity_from_score(finding.score),
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            event_ids=finding.event_ids,
            evidence=finding.evidence,
        )
        db.add(threat)
        threats.append(threat)

    db.commit()
    for threat in threats:
        db.refresh(threat)

    return threats


def analyze_latest_events(db: Session, limit: int = 5000) -> list[Threat]:
    events = list(
        db.scalars(
            select(SecurityEvent)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(limit)
        )
    )
    findings = run_detection(events)
    return persist_findings(db, findings)
