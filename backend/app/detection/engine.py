import logging
from collections.abc import Callable

from app.detection.rules import (
    detect_brute_force,
    detect_port_scan,
    detect_request_burst,
)
from app.detection.types import DetectionFinding
from app.models.security_event import SecurityEvent

logger = logging.getLogger(__name__)

DetectionRule = Callable[[list[SecurityEvent]], list[DetectionFinding]]

DEFAULT_RULES: tuple[DetectionRule, ...] = (
    detect_brute_force,
    detect_port_scan,
    detect_request_burst,
)


def run_detection(
    events: list[SecurityEvent],
    rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
) -> list[DetectionFinding]:
    findings: list[DetectionFinding] = []
    for rule in rules:
        try:
            findings.extend(rule(events))
        except Exception:
            logger.exception(
                "Detection rule failed without interrupting remaining rules.",
                extra={"rule": getattr(rule, "__name__", repr(rule))},
            )
    return findings
