import json
from pathlib import Path

from fastapi.testclient import TestClient


DEMO_DATASET = Path(__file__).resolve().parents[2] / "samples" / "demo" / "events.json"


def test_synthetic_demo_dataset_exercises_expected_pipeline(client: TestClient) -> None:
    events = json.loads(DEMO_DATASET.read_text(encoding="utf-8"))

    assert events
    assert all(event["raw_payload"]["synthetic"] is True for event in events)
    assert {event["source_ip"].split(".")[0:3] for event in []} == set()

    response = client.post(
        "/api/v1/ingest/batch",
        json={"format": "json", "content": json.dumps(events)},
    )

    assert response.status_code == 201
    assert response.json()["accepted"] == len(events)
    assert response.json()["rejected"] == 0

    analysis = client.post("/api/v1/analysis/run", json={"limit": 5000})

    assert analysis.status_code == 200
    threats = analysis.json()["threats"]
    by_rule = {threat["rule_id"]: threat for threat in threats}
    assert {"auth.brute_force", "network.port_scan"} <= by_rule.keys()
    assert by_rule["auth.brute_force"]["source_ip"] == "203.0.113.42"
    assert by_rule["network.port_scan"]["source_ip"] == "198.51.100.77"
    assert "192.0.2.10" not in {threat["source_ip"] for threat in threats}
    assert "192.0.2.20" not in {threat["source_ip"] for threat in threats}
    assert "192.0.2.30" not in {threat["source_ip"] for threat in threats}
