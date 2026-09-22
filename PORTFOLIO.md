# AI Security Analyst — Portfolio Narrative

## Short summary

An explainable security operations platform that converts heterogeneous telemetry
into normalized events, deterministic detections, evidence-backed risk scores, and
analyst-ready investigations.

## Project narrative

AI Security Analyst demonstrates an end-to-end security engineering workflow, not
an opaque AI demo. FastAPI ingests and normalizes logs, testable rules create threat
evidence and risk scores, PostgreSQL preserves the investigation trail, and a
React/TypeScript dashboard makes findings reviewable. AI enrichment is optional,
schema-validated, and isolated from authoritative severity. Production-minded
delivery includes migrations, containers, access controls, failure-safe provider
abstractions, an accessible synthetic demo, and automated quality/security gates.

## Key decisions

- Deterministic rules and explicit score factors remain authoritative.
- AI explains supplied evidence; validation and fallback preserve facts.
- Threat fingerprints make repeat analysis idempotent.
- Raw context stays distinguishable from normalized fields.
- Production requires authentication and request/host/rate controls.
- Blocking remains human-approved and outside the automated boundary.
- Demo inputs use synthetic RFC 5737 ranges.

## Technology

Python 3.12, FastAPI, Pydantic, SQLAlchemy, Alembic, PostgreSQL 17, React 18,
TypeScript, Vite, Docker Compose, Nginx, Pytest, Ruff, mypy, Bandit, pip-audit,
Trivy, and GitHub Actions.

## Resume-ready bullets

- Built a platform that normalizes JSON, CSV, authentication, web, and firewall telemetry into a unified event model.
- Implemented explainable detections, risk scoring, evidence persistence, MITRE ATT&CK enrichment, analytics, and correlation.
- Designed optional AI summaries with schema validation, prompt-injection defenses, deterministic fallback, and no authority over severity.
- Hardened a FastAPI/PostgreSQL/React stack with API roles, request controls, migrations, containers, and request IDs.
- Established CI gates for tests, coverage, typing, linting, dependency auditing, static analysis, scanning, and production builds.

## Review links

- [README](README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Guided demo](docs/DEMO.md)
- [v1.0.0 release](https://github.com/alianisreyesr/ai-security-analyst/releases/tag/v1.0.0)
