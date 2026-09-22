# ruff: noqa: I001

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


def test_list_events_is_paginated_and_filterable(
    client: TestClient,
    db_session: Session,
) -> None:
    first = SecurityEvent(
        timestamp="2026-09-21T20:32:14+00:00",
        source_ip="203.0.113.10",
        destination_ip="10.0.0.5",
        source_port=50000,
        destination_port=22,
        protocol="TCP",
        event_type="authentication_failure",
        username="admin",
        source="linux_ssh",
        raw_payload={"synthetic": True},
    )
    second = SecurityEvent(
        timestamp="2026-09-21T20:33:14+00:00",
        source_ip="203.0.113.20",
        destination_ip="10.0.0.5",
        source_port=50001,
        destination_port=443,
        protocol="TCP",
        event_type="firewall_deny",
        username=None,
        source="firewall",
        raw_payload={"synthetic": True},
    )
    db_session.add_all([first, second])
    db_session.commit()

    response = client.get(
        "/api/v1/events",
        params={"event_type": "authentication_failure", "limit": 10},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["source_ip"] == "203.0.113.10"
    assert payload["items"][0]["event_type"] == "authentication_failure"
