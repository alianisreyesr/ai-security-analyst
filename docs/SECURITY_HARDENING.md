# Security Hardening Guide

## Production baseline

Set at minimum:

```env
APP_ENV=production
AUTH_ENABLED=true
ANALYST_API_KEY=<secret-manager-value>
ADMIN_API_KEY=<different-secret-manager-value>
RATE_LIMIT_ENABLED=true
CORS_ALLOWED_ORIGINS=https://your-dashboard.example
ALLOWED_HOSTS=api.example
ENABLE_API_DOCS=false
```

Do not commit the resulting environment file. Inject credentials using the deployment platform's secret mechanism.

## Authentication and authorization

The API accepts `X-API-Key` when authentication is enabled.

- **analyst**: normal protected API access.
- **admin**: analyst access plus privileged maintenance/rebuild operations.

Use distinct high-entropy keys. Rotate them after suspected exposure and avoid putting them in URLs, screenshots, logs or issue reports.

## Input controls

- `MAX_REQUEST_BYTES` bounds request bodies before application parsing.
- `MAX_BATCH_CONTENT_CHARS` bounds batch content.
- `MAX_BATCH_ROWS` bounds parsed batch rows.
- `RATE_LIMIT_REQUESTS_PER_MINUTE` provides a process-local abuse guard.

A reverse proxy/API gateway should provide an additional distributed rate limit in production.

## Network and browser exposure

Keep CORS disabled unless a browser frontend needs it. If enabled, list explicit origins rather than wildcards. Configure `ALLOWED_HOSTS` for the production hostname. Terminate TLS before traffic reaches the application.

## AI and enrichment secrets

`AI_API_KEY` and `REPUTATION_API_KEY` must come from runtime secrets. Never place them in sample files or GitHub issues. External-provider responses remain enrichment, not authoritative evidence.

## Release checks

1. Run unit/integration tests.
2. Apply Alembic migrations against PostgreSQL.
3. Build the backend container.
4. Run dependency, static-analysis and container vulnerability scans.
5. Confirm production refuses unsafe authentication configuration.
6. Confirm API docs and CORS/host settings match the deployment.
7. Review the threat model and known limitations.
