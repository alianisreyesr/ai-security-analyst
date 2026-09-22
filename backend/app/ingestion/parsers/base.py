from abc import ABC, abstractmethod

from app.schemas.security_event import SecurityEventCreate


class LogParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> SecurityEventCreate | None:
        """Parse one log line into a normalized security event."""
