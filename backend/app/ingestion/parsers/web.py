import re
from datetime import datetime

from app.ingestion.parsers.base import LogParser
from app.schemas.security_event import SecurityEventCreate

_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<version>HTTP/\d(?:\.\d)?)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


class WebAccessParser(LogParser):
    def parse_line(self, line: str) -> SecurityEventCreate | None:
        match = _ACCESS_RE.match(line)
        if match is None:
            return None

        timestamp = datetime.strptime(
            match.group("time"),
            "%d/%b/%Y:%H:%M:%S %z",
        )

        return SecurityEventCreate(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            protocol="HTTP",
            event_type="http_request",
            source="web_access",
            raw_payload={
                "method": match.group("method"),
                "path": match.group("path"),
                "status": int(match.group("status")),
                "message": line,
            },
        )
