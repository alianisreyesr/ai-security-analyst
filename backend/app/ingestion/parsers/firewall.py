import shlex
from datetime import datetime

from app.ingestion.parsers.base import LogParser
from app.schemas.security_event import SecurityEventCreate


class FirewallParser(LogParser):
    def parse_line(self, line: str) -> SecurityEventCreate | None:
        values: dict[str, str] = {}
        try:
            tokens = shlex.split(line)
        except ValueError:
            return None

        for token in tokens:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            values[key.upper()] = value

        required = {"TIMESTAMP", "SRC", "DST"}
        if not required.issubset(values):
            return None

        try:
            timestamp = datetime.fromisoformat(values["TIMESTAMP"].replace("Z", "+00:00"))
            source_port = int(values["SPT"]) if values.get("SPT") else None
            destination_port = int(values["DPT"]) if values.get("DPT") else None
        except ValueError:
            return None

        action = values.get("ACTION", "OBSERVED").lower()

        return SecurityEventCreate(
            timestamp=timestamp,
            source_ip=values["SRC"],
            destination_ip=values["DST"],
            source_port=source_port,
            destination_port=destination_port,
            protocol=values.get("PROTO"),
            event_type=f"firewall_{action}",
            source="firewall",
            raw_payload={"message": line, "action": action},
        )
