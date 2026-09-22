# Security Hardening

## Production baseline

Recommended production environment:

```text
APP_ENV=production
AUTH_ENABLED=true
ANALYST_API_KEY=<secret>
ADMIN_API_KEY=<different-secret>
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=120
MAX_REQUEST_BYTES=2000000
ENABLE_API_DOCS=false
CORS_ALLOWED_ORIGINS=https://your-dashboard.example
ALLOWED_HOSTS=api.example.com
```

Do not commit the real values.

## Request protection

The API enforces:

- Pydantic schema validation;
- global `Content-Length` request-size checking;
- ingestion-specific content limits;
- optional per-process rate limiting;
- API-key authentication and role checks;
- trusted-host restrictions when configured;
- explicit CORS allow-list when configured.

## Response protection

Responses include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- restrictive `Permissions-Policy`
- `Cache-Control: no-store` for API responses
- `Strict-Transport-Security` in production

## Audit and observability

Every request receives an `X-Request-ID`.

The audit logger records:

- request ID;
- method;
- path;
- status code;
- duration;
- authenticated role/name when available.

It deliberately does **not** log request bodies, API keys or provider credentials.

## API documentation exposure

Interactive OpenAPI documentation remains available in non-production environments.

In production it is disabled unless `ENABLE_API_DOCS=true` is explicitly set.

## Rate limiting

The built-in limiter is a lightweight per-process defense for this application.

For multiple production replicas, use a shared gateway-level limiter in addition to the application limiter.

## Secret handling

Secrets belong in environment variables or a deployment secret store.

Examples of secret values:
- `DATABASE_URL`
- `POSTGRES_PASSWORD`
- `ANALYST_API_KEY`
- `ADMIN_API_KEY`
- `AI_API_KEY`
- `REPUTATION_API_KEY`

The repository should contain only placeholders or empty example values.

## CI security checks

The release-candidate CI includes:

- unit/integration tests;
- static type checking;
- dependency vulnerability audit;
- static security analysis;
- PostgreSQL migration verification;
- container build;
- filesystem and container vulnerability scanning.

### Scanner false-positive policy

Scanner findings are not ignored merely to make CI pass. An ignore is allowed only when the repository contains reproducible evidence that the vulnerable component is not present at runtime in the reported version.

The current Trivy image scan sees stale package metadata from lower Python base-image layers for:

- `GHSA-6v7p-g79w-8964` — reports `msgpack 1.1.2`;
- `CVE-2025-47273` — reports `setuptools 70.3.0`.

The final runtime image explicitly installs fixed versions and CI verifies them before scanning:

- `msgpack >= 1.2.1`;
- `setuptools >= 78.1.1`.

Only those two IDs are listed in `.trivyignore`. If runtime-version verification fails, CI fails before Trivy runs. Any new HIGH/CRITICAL finding remains blocking and must be investigated.

## Mermaid-only architecture rule

Architecture and security-flow diagrams remain Mermaid source in Markdown. Generated diagram image files should not be committed.
