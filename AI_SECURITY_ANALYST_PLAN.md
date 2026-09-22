# AI Security Analyst — Project Scope & Roadmap

> **Status:** Planning / v0.1 Foundation  
> **Goal:** Build a portfolio-grade security analysis platform that ingests security logs, normalizes events, detects suspicious behavior, calculates risk, and produces analyst-friendly explanations.

## Product vision

AI Security Analyst combines deterministic security detection with AI-assisted explanation. Detection and scoring remain explainable and auditable; AI is used to summarize evidence, add context, and help an analyst investigate.

## Architecture

```mermaid
flowchart LR
    A["Log Sources<br/>Linux • Apache/Nginx • Firewall • CSV/JSON"] --> B["FastAPI Ingestion API"]
    B --> C["Normalization Layer"]
    C --> D["Detection Engine"]
    D --> E["Risk Scoring"]
    E --> F["AI Analyst"]
    C --> G[("PostgreSQL")]
    D --> G
    E --> G
    F --> G
    G --> H["React Security Dashboard"]

    classDef sources fill:#0f172a,stroke:#38bdf8,color:#f8fafc,stroke-width:2px;
    classDef backend fill:#172554,stroke:#60a5fa,color:#eff6ff,stroke-width:2px;
    classDef detection fill:#3f1d0b,stroke:#fb923c,color:#fff7ed,stroke-width:2px;
    classDef ai fill:#3b0764,stroke:#c084fc,color:#faf5ff,stroke-width:2px;
    classDef data fill:#052e16,stroke:#4ade80,color:#f0fdf4,stroke-width:2px;
    classDef ui fill:#3f0713,stroke:#fb7185,color:#fff1f2,stroke-width:2px;

    class A sources;
    class B,C backend;
    class D,E detection;
    class F ai;
    class G data;
    class H ui;
```

## MVP scope

### Log ingestion
- REST endpoint: `POST /api/v1/events`
- File upload for `.log`, `.txt`, `.csv`, `.json`
- Linux SSH/Auth
- Apache/Nginx
- Generic firewall logs
- Custom CSV/JSON

### Normalized event contract

```json
{
  "timestamp": "2026-09-21T20:32:14Z",
  "source_ip": "45.83.10.22",
  "destination_ip": "10.0.0.5",
  "source_port": 54321,
  "destination_port": 22,
  "protocol": "TCP",
  "event_type": "authentication_failure",
  "username": "admin",
  "source": "linux_ssh"
}
```

### Detection engine
- Brute-force / credential guessing
- Port scanning
- Known flagged source
- Request bursts / possible DoS
- Successful login after repeated failures

### Risk scoring

| Score | Severity |
|---:|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

AI must never be the sole source of severity.

## Detection pipeline

```mermaid
flowchart TD
    A["Raw Event"] --> B{"Supported format?"}
    B -- "No" --> X["Reject / quarantine"]
    B -- "Yes" --> C["Parse"]
    C --> D["Normalize"]
    D --> E["Persist event"]
    E --> F["Run detection rules"]
    F --> G{"Suspicious?"}
    G -- "No" --> H["Store as normal event"]
    G -- "Yes" --> I["Calculate risk score"]
    I --> J["Create threat record"]
    J --> K["Generate AI explanation"]
    K --> L["Display in dashboard"]

    classDef input fill:#0f172a,stroke:#38bdf8,color:#f8fafc,stroke-width:2px;
    classDef processing fill:#172554,stroke:#60a5fa,color:#eff6ff,stroke-width:2px;
    classDef decision fill:#422006,stroke:#facc15,color:#fefce8,stroke-width:2px;
    classDef threat fill:#450a0a,stroke:#f87171,color:#fef2f2,stroke-width:2px;
    classDef safe fill:#052e16,stroke:#4ade80,color:#f0fdf4,stroke-width:2px;

    class A input;
    class C,D,E,F processing;
    class B,G decision;
    class I,J,K,L,X threat;
    class H safe;
```

## Technical stack

- Python 3.12+
- FastAPI
- Pydantic
- SQLAlchemy
- Alembic
- PostgreSQL
- React
- TypeScript
- Vite
- Tailwind CSS
- Docker / Docker Compose
- Pytest
- GitHub Actions

## Delivery roadmap

### v0.1 — Foundation
FastAPI, PostgreSQL, Alembic, Docker, health endpoint, event ingestion, event model, tests, CI.

### v0.2 — Detection
Parsers, normalization, deterministic detection framework, risk scoring, threat records.

### v0.3 — AI Analyst
Provider abstraction, evidence-aware summaries, prompt-injection defenses, validation and fallback.

### v0.4 — Threat Intelligence
MITRE ATT&CK mappings, IP reputation abstraction, timelines, search/filtering, human-approved banned-IP integration design.

### v0.5 — Advanced Analytics
Historical aggregation, baselines, anomaly scoring, correlation, tuning and load testing.

### v0.9 — Hardening
Threat model, auth, upload/rate controls, security scanning, audit logging, release candidate QA.

### v1.0 — Portfolio Release
Polished documentation, demo data, UI, release automation, coverage gate and portfolio narrative.

## Engineering principles

- Explainable detections before opaque ML.
- Human review before automated blocking.
- No secrets or production credentials.
- Sanitized/synthetic sample logs only.
- Security rules must be unit-testable.
- Raw logs and normalized events remain distinguishable.
- AI output never silently overwrites deterministic evidence.
- Architecture diagrams must use **Mermaid code with explicit styling/colors**.
