from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


VALID_EVENT = {
    "timestamp": "2026-09-21T20:32:14Z",
    "source_ip": "45.83.10.22",
    "destination_ip": "10.0.0.5",
    "source_port": 54321,
    "destination_port": 22,
    "protocol": "TCP",
    "event_type": "authentication_failure",
    "username": "admin",
    "source": "linux_ssh",
    "raw_payload": {"message": "synthetic failed authentication sample"},
}


def test_create_event(client: TestClient, db_session: Session) -> None:
    response = client.post("/api/v1/events", json=VALID_EVENT)

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "accepted"
    assert payload["normalized"] is True
    assert isinstance(payload["id"], int)

    stored = db_session.scalar(select(SecurityEvent).where(SecurityEvent.id == payload["id"]))
    assert stored is not None
    assert stored.source_ip == "45.83.10.22"
    assert stored.event_type == "authentication_failure"


def test_rejects_invalid_port(client: TestClient) -> None:
    invalid_event = {**VALID_EVENT, "destination_port": 70000}

    response = client.post("/api/v1/events", json=invalid_event)

    assert response.status_code == 422


def test_rejects_unknown_fields(client: TestClient) -> None:
    invalid_event = {**VALID_EVENT, "unexpected": "value"}

    response = client.post("/api/v1/events", json=invalid_event)

    assert response.status_code == 422
