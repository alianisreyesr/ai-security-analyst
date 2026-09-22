import re
from datetime import UTC, datetime
from ipaddress import ip_address

from app.ingestion.parsers.base import LogParser
from app.schemas.security_event import SecurityEventCreate

_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
)
_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)


class SSHAuthParser(LogParser):
    def __init__(self, year: int | None = None) -> None:
        self.year = year or datetime.now(UTC).year

    def _timestamp(self, line: str) -> datetime | None:
        match = _SYSLOG_RE.match(line)
        if match is None:
            return None
        value = (
            f"{self.year} {match.group('month')} {match.group('day')} "
            f"{match.group('time')}"
        )
        return datetime.strptime(value, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)

    def parse_line(self, line: str) -> SecurityEventCreate | None:
        timestamp = self._timestamp(line)
        if timestamp is None:
            return None

        failed = _FAILED_RE.search(line)
        if failed is not None:
            try:
                source_ip = ip_address(failed.group("ip"))
            except ValueError:
                return None

            return SecurityEventCreate(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_port=22,
                protocol="TCP",
                event_type="authentication_failure",
                username=failed.group("username"),
                source="linux_ssh",
                raw_payload={"message": line},
            )

        accepted = _ACCEPTED_RE.search(line)
        if accepted is not None:
            try:
                source_ip = ip_address(accepted.group("ip"))
            except ValueError:
                return None

            return SecurityEventCreate(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_port=22,
                protocol="TCP",
                event_type="authentication_success",
                username=accepted.group("username"),
                source="linux_ssh",
                raw_payload={"message": line},
            )

        return None
