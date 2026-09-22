#!/usr/bin/env python3
"""Load the public synthetic demo dataset and verify its expected detections."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXPECTED_RULES = {"auth.brute_force", "network.port_scan"}
DEFAULT_DATASET = Path(__file__).resolve().parents[1] / "samples" / "demo" / "events.json"


def post_json(base_url: str, path: str, payload: dict[str, Any], api_key: str) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{path} returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach {base_url}: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default=os.getenv("ASA_BASE_URL", "http://localhost:8000"),
        help="API base URL (default: %(default)s or ASA_BASE_URL)",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to the synthetic JSON dataset",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("ASA_API_KEY", ""),
        help="Optional API key (or set ASA_API_KEY)",
    )
    args = parser.parse_args()

    events = json.loads(args.dataset.read_text(encoding="utf-8"))
    if not isinstance(events, list) or not events:
        raise RuntimeError("Demo dataset must be a non-empty JSON array.")

    ingestion = post_json(
        args.base_url,
        "/api/v1/ingest/batch",
        {"format": "json", "content": json.dumps(events)},
        args.api_key,
    )
    if ingestion.get("accepted") != len(events) or ingestion.get("rejected") != 0:
        raise RuntimeError(f"Demo ingestion did not fully succeed: {ingestion}")

    analysis = post_json(
        args.base_url,
        "/api/v1/analysis/run",
        {"limit": 5000},
        args.api_key,
    )
    threats = analysis.get("threats", [])
    detected_rules = {item.get("rule_id") for item in threats}
    missing = EXPECTED_RULES - detected_rules
    if missing:
        raise RuntimeError(f"Expected detections were not produced: {sorted(missing)}")

    print(f"Accepted {ingestion['accepted']} synthetic events.")
    print(f"Verified detections: {', '.join(sorted(EXPECTED_RULES))}.")
    print("Demo data uses only RFC 5737 documentation source ranges.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Demo seed failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
