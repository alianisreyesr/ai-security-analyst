# Changelog

Notable changes are documented here. The project follows Semantic Versioning.

## [Unreleased]

### Security

- Backend and frontend containers now run as non-root users (frontend uses `nginx-unprivileged` on port 8080).
- docker-compose publishes the API on 127.0.0.1 only.
- `.env.example` documents that `AUTH_ENABLED=false` is for local development only; `APP_ENV=prod` is treated like `production`.

### Changed

- Rate limiting can resolve the real client IP behind a trusted reverse proxy (`TRUSTED_PROXIES`) and purges idle clients from memory.
- The request size limit now also applies to chunked bodies; invalid `X-Request-ID` values are replaced.
- Evidence rendered into LLM prompts can no longer close the `<untrusted_security_evidence>` block; the reason for an AI fallback is logged.
- A non-object reputation provider response is reported as a provider error instead of a 500.
- The dashboard stores the API key in `sessionStorage` instead of `localStorage`.
- nginx serves security headers and a 2 MB body limit.
- Backend dependencies are pinned in `backend/requirements*.txt`, the frontend has a `package-lock.json` installed with `npm ci`, and Dependabot is enabled.
- Ruff now also covers `backend/alembic`; deprecated HTTP status constants were removed.

### Tests

- Added mock-based tests for the AI chat and reputation providers (both now 100% covered) and for the new middleware behavior.

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
