# Synthetic demo

The repository includes a deterministic, public demo dataset at
`samples/demo/events.json`. Every record is generated for this project and marks
`raw_payload.synthetic` as `true`.

Source addresses use the RFC 5737 documentation ranges:

- `192.0.2.0/24` for normal activity
- `203.0.113.0/24` for repeated authentication failures
- `198.51.100.0/24` for multi-port probing

The destination `10.0.0.5` is an invented private lab host. The dataset contains
no production telemetry, credentials, private services, or external API dependency.

## Scenarios and expected results

| Scenario | Events | Expected result |
|---|---:|---|
| Normal authentication, web request, and firewall traffic | 3 | Stored as events; no threat |
| Repeated SSH authentication failures from `203.0.113.42` | 6 | `auth.brute_force` |
| Firewall probes across 12 ports from `198.51.100.77` | 12 | `network.port_scan` |

The expected threat scores are at least 60 and therefore fall in the **High**
severity band. Exact evidence remains visible in the threat timeline.

## Run the complete demo

Start the stack:

```bash
cp .env.example .env
docker compose up --build
```

In another terminal, run:

```bash
python scripts/seed_demo.py
```

The command imports all 21 events, runs deterministic analysis, verifies both
expected rule IDs, and exits nonzero if ingestion or detection is incomplete.

Optional settings:

```bash
ASA_BASE_URL=http://localhost:8000 ASA_API_KEY=local-key python scripts/seed_demo.py
```

You can also open `http://localhost:8080` and select **Load demo + analyze**.
The browser demo uses the same scenarios and documentation-only source ranges.

## Reproducibility

CI loads the canonical dataset through the batch-ingestion API and asserts that
normal sources remain unflagged while both malicious scenarios produce their
documented detections. The demo uses the built-in deterministic fallback for AI
summaries, so no private model provider is required.
