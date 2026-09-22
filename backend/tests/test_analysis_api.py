from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def test_analysis_persists_brute_force_threat(client: TestClient) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)

    for index in range(6):
        payload = {
            "timestamp": (start + timedelta(seconds=index * 20)).isoformat(),
            "source_ip": "203.0.113.42",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "protocol": "TCP",
            "event_type": "authentication_failure",
            "username": "admin",
            "source": "linux_ssh",
        }
        response = client.post("/api/v1/events", json=payload)
        assert response.status_code == 201

    response = client.post("/api/v1/analysis/run", json={"limit": 100})

    assert response.status_code == 200
    threats = response.json()["threats"]
    assert len(threats) == 1
    assert threats[0]["rule_id"] == "auth.brute_force"
    assert threats[0]["risk_score"] >= 60


def test_analysis_is_idempotent_for_same_evidence(client: TestClient) -> None:
    start = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)

    for index in range(5):
        response = client.post(
            "/api/v1/events",
            json={
                "timestamp": (start + timedelta(seconds=index * 15)).isoformat(),
                "source_ip": "198.51.100.20",
                "destination_ip": "10.0.0.5",
                "destination_port": 22,
                "protocol": "TCP",
                "event_type": "authentication_failure",
                "username": "root",
                "source": "linux_ssh",
            },
        )
        assert response.status_code == 201

    first = client.post("/api/v1/analysis/run", json={"limit": 100})
    second = client.post("/api/v1/analysis/run", json={"limit": 100})

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["threats"][0]["id"] == second.json()["threats"][0]["id"]
