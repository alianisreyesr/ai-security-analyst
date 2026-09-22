from fastapi.testclient import TestClient
import pytest

from app.core.config import settings
from app.security.auth import validate_security_configuration


EVENT = {
    "timestamp": "2026-09-21T20:32:14Z",
    "source_ip": "203.0.113.42",
    "destination_ip": "10.0.0.5",
    "destination_port": 22,
    "protocol": "TCP",
    "event_type": "authentication_failure",
    "username": "admin",
    "source": "linux_ssh",
}


def test_security_headers_and_request_id(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-request-id"]


def test_authentication_rejects_missing_and_invalid_key(client: TestClient) -> None:
    old_enabled = settings.auth_enabled
    old_analyst = settings.analyst_api_key
    old_admin = settings.admin_api_key
    try:
        settings.auth_enabled = True
        settings.analyst_api_key = "synthetic-analyst-key"
        settings.admin_api_key = "synthetic-admin-key"

        missing = client.post("/api/v1/events", json=EVENT)
        invalid = client.post(
            "/api/v1/events",
            json=EVENT,
            headers={"X-API-Key": "wrong-key"},
        )

        assert missing.status_code == 401
        assert invalid.status_code == 401
    finally:
        settings.auth_enabled = old_enabled
        settings.analyst_api_key = old_analyst
        settings.admin_api_key = old_admin


def test_analyst_can_ingest_but_cannot_run_admin_operation(
    client: TestClient,
) -> None:
    old_enabled = settings.auth_enabled
    old_analyst = settings.analyst_api_key
    old_admin = settings.admin_api_key
    try:
        settings.auth_enabled = True
        settings.analyst_api_key = "synthetic-analyst-key"
        settings.admin_api_key = "synthetic-admin-key"
        headers = {"X-API-Key": settings.analyst_api_key}

        ingest = client.post("/api/v1/events", json=EVENT, headers=headers)
        rebuild = client.post(
            "/api/v1/analytics/rebuild",
            headers=headers,
            json={
                "granularity": "hour",
                "start": "2026-09-21T20:00:00Z",
                "end": "2026-09-21T21:00:00Z",
            },
        )

        assert ingest.status_code == 201
        assert rebuild.status_code == 403
    finally:
        settings.auth_enabled = old_enabled
        settings.analyst_api_key = old_analyst
        settings.admin_api_key = old_admin


def test_admin_can_run_admin_operation(client: TestClient) -> None:
    old_enabled = settings.auth_enabled
    old_analyst = settings.analyst_api_key
    old_admin = settings.admin_api_key
    try:
        settings.auth_enabled = True
        settings.analyst_api_key = "synthetic-analyst-key"
        settings.admin_api_key = "synthetic-admin-key"

        response = client.post(
            "/api/v1/analytics/rebuild",
            headers={"X-API-Key": settings.admin_api_key},
            json={
                "granularity": "hour",
                "start": "2026-09-21T20:00:00Z",
                "end": "2026-09-21T21:00:00Z",
            },
        )

        assert response.status_code == 200
    finally:
        settings.auth_enabled = old_enabled
        settings.analyst_api_key = old_analyst
        settings.admin_api_key = old_admin


def test_request_size_limit(client: TestClient) -> None:
    old_limit = settings.max_request_bytes
    try:
        settings.max_request_bytes = 10
        response = client.post("/api/v1/events", json=EVENT)
        assert response.status_code == 413
    finally:
        settings.max_request_bytes = old_limit


def test_rate_limit(client: TestClient) -> None:
    old_enabled = settings.rate_limit_enabled
    old_limit = settings.rate_limit_requests_per_minute
    try:
        settings.rate_limit_enabled = True
        settings.rate_limit_requests_per_minute = 1

        first = client.post("/api/v1/events", json=EVENT)
        second = client.post("/api/v1/events", json=EVENT)

        assert first.status_code == 201
        assert second.status_code == 429
        assert second.headers["retry-after"] == "60"
    finally:
        settings.rate_limit_enabled = old_enabled
        settings.rate_limit_requests_per_minute = old_limit


def test_production_requires_authentication() -> None:
    old_env = settings.app_env
    old_enabled = settings.auth_enabled
    try:
        settings.app_env = "production"
        settings.auth_enabled = False

        with pytest.raises(RuntimeError, match="Authentication must be enabled"):
            validate_security_configuration()
    finally:
        settings.app_env = old_env
        settings.auth_enabled = old_enabled
