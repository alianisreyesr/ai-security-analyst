# Changelog

Notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

### Security

- Backend and frontend containers now run as non-root users (frontend uses `nginx-unprivileged` on port 8080).
- docker-compose publishes the API on 127.0.0.1 only.
- `.env.example` documents that `AUTH_ENABLED=false` is for local development only; `APP_ENV=prod` is treated like `production`.

## [1.0.0] - 2026-09-22

### Added

- Multi-format ingestion, normalized events, deterministic detections, and explainable risk.
- Persistent evidence, reviews, analytics, anomaly detection, and threat correlation.
- Validated optional AI summaries, MITRE ATT&CK mappings, and reputation enrichment.
- React investigation dashboard and reproducible 21-event synthetic demo.
- Authentication, request controls, audit context, and production hardening.
- CI gates for tests, 85% coverage, typing, linting, auditing, and vulnerability scans.
- Semantic-version validation and automated release packaging.

[1.0.0]: https://github.com/alianisreyesr/ai-security-analyst/releases/tag/v1.0.0
