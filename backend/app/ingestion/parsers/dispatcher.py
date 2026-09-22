from collections.abc import Iterable

from app.ingestion.parsers.base import LogParser
from app.ingestion.parsers.firewall import FirewallParser
from app.ingestion.parsers.ssh import SSHAuthParser
from app.ingestion.parsers.web import WebAccessParser
from app.schemas.security_event import SecurityEventCreate

PARSERS: tuple[LogParser, ...] = (
    SSHAuthParser(),
    WebAccessParser(),
    FirewallParser(),
)


def parse_log_line(
    line: str,
    parsers: Iterable[LogParser] = PARSERS,
) -> SecurityEventCreate | None:
    for parser in parsers:
        event = parser.parse_line(line)
        if event is not None:
            return event
    return None
