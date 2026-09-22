import csv
import io
import json
from typing import Any

from pydantic import ValidationError

from app.core.config import settings
from app.ingestion.parsers.dispatcher import parse_log_line
from app.schemas.security_event import SecurityEventCreate

class BatchParseError(ValueError):
    pass


def _validate_items(items: list[dict[str, Any]]) -> tuple[list[SecurityEventCreate], list[str]]:
    events: list[SecurityEventCreate] = []
    errors: list[str] = []

    for index, item in enumerate(items[: settings.max_batch_rows], start=1):
        try:
            events.append(SecurityEventCreate.model_validate(item))
        except ValidationError as exc:
            errors.append(f"row {index}: {exc.errors()[0]['msg']}")

    if len(items) > settings.max_batch_rows:
        errors.append(f"batch exceeds maximum of {settings.max_batch_rows} rows")

    return events, errors


def parse_batch(format_name: str, content: str) -> tuple[list[SecurityEventCreate], list[str]]:
    normalized_format = format_name.lower().strip()

    if normalized_format == "json":
        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise BatchParseError("invalid JSON content") from exc

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise BatchParseError("JSON batch must be an object or array of objects")
        return _validate_items(payload)

    if normalized_format == "csv":
        reader = csv.DictReader(io.StringIO(content))
        if reader.fieldnames is None:
            raise BatchParseError("CSV header is required")
        return _validate_items([dict(row) for row in reader])

    if normalized_format in {"log", "txt"}:
        events: list[SecurityEventCreate] = []
        errors: list[str] = []
        for index, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            if len(events) >= settings.max_batch_rows:
                errors.append(f"batch exceeds maximum of {settings.max_batch_rows} parsed rows")
                break
            event = parse_log_line(line)
            if event is None:
                errors.append(f"line {index}: unsupported or malformed log line")
            else:
                events.append(event)
        return events, errors

    raise BatchParseError(f"unsupported batch format: {format_name}")
