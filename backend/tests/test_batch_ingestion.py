import json

from fastapi.testclient import TestClient

from app.core.config import settings


def test_json_batch_ingestion(client: TestClient) -> None:
    content = json.dumps(
        [
            {
                "timestamp": "2026-09-21T20:32:14Z",
                "source_ip": "203.0.113.42",
                "destination_ip": "10.0.0.5",
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "authentication_failure",
                "username": "admin",
                "source": "linux_ssh",
            }
        ]
    )

    response = client.post(
        "/api/v1/ingest/batch",
        json={"format": "json", "content": content},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["rejected"] == 0
    assert len(payload["event_ids"]) == 1


def test_text_batch_reports_unsupported_lines(client: TestClient) -> None:
    content = "\n".join(
        [
            (
                "Sep 21 20:32:14 host sshd[123]: Failed password for admin "
                "from 203.0.113.42 port 54400 ssh2"
            ),
            "this is not a supported log line",
        ]
    )

    response = client.post(
        "/api/v1/ingest/batch",
        json={"format": "log", "content": content},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["rejected"] == 1


def test_invalid_json_batch_returns_422(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingest/batch",
        json={"format": "json", "content": "{bad-json"},
    )

    assert response.status_code == 422


def test_batch_content_limit_is_configurable(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "max_batch_content_chars", 10)

    response = client.post(
        "/api/v1/ingest/batch",
        json={"format": "txt", "content": "x" * 11},
    )

    assert response.status_code == 413
