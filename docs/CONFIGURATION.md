# Configuration reference

Copy `.env.example` to `.env`. Never commit the resulting file or real keys.
Pydantic reads the variables below; Docker Compose additionally consumes the three
`POSTGRES_*` values.

## Application and database

| Variable | Default/example | Purpose |
|---|---|---|
| `APP_NAME` | `AI Security Analyst` | OpenAPI/application title |
| `APP_ENV` | `development` | Runtime mode; `production` enables startup security requirements |
| `LOG_LEVEL` | `INFO` | Python application log level |
| `DATABASE_URL` | PostgreSQL URL | SQLAlchemy connection URL |
| `POSTGRES_DB` | `security_analyst` | Compose database name |
| `POSTGRES_USER` | `security_analyst` | Compose database user |
| `POSTGRES_PASSWORD` | `change_me` | Compose database password; replace before use |

## Input and HTTP security

| Variable | Default | Purpose |
|---|---:|---|
| `MAX_BATCH_ROWS` | `5000` | Maximum parsed rows per batch |
| `MAX_BATCH_CONTENT_CHARS` | `1000000` | Maximum batch content length |
| `MAX_REQUEST_BYTES` | `2000000` | Maximum request-body size |
| `AUTH_ENABLED` | `false` | Require `X-API-Key` authentication |
| `ANALYST_API_KEY` | empty | Read/ingest/analyze key |
| `ADMIN_API_KEY` | empty | Key for all routes, including administrative operations |
| `RATE_LIMIT_ENABLED` | `false` | Enable in-memory per-client throttling |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `120` | Per-process request allowance |
| `CORS_ALLOWED_ORIGINS` | empty | Comma-separated exact browser origins |
| `ALLOWED_HOSTS` | empty | Comma-separated trusted Host values |
| `ENABLE_API_DOCS` | `false` | Expose OpenAPI routes in production |

Production requires `AUTH_ENABLED=true` plus both non-empty API keys. Use distinct,
random secrets and inject them through the deployment platform rather than storing
them in an image.

## Detection

| Variable | Default | Purpose |
|---|---:|---|
| `BRUTE_FORCE_FAILURE_THRESHOLD` | `5` | Failed-login threshold |
| `BRUTE_FORCE_WINDOW_SECONDS` | `300` | Brute-force evaluation window |
| `AUTH_FOLLOWUP_WINDOW_SECONDS` | `300` | Success-after-failures correlation window |
| `PORT_SCAN_UNIQUE_PORTS_THRESHOLD` | `10` | Unique-port threshold |
| `PORT_SCAN_WINDOW_SECONDS` | `300` | Port-scan evaluation window |
| `REQUEST_BURST_THRESHOLD` | `50` | Web-request threshold |
| `REQUEST_BURST_WINDOW_SECONDS` | `60` | Web-request evaluation window |

Changing thresholds changes detection behavior and should include tests and a
documented tuning rationale.

## AI analyst and reputation

| Variable | Default | Purpose |
|---|---:|---|
| `AI_PROVIDER` | `disabled` | AI provider selector |
| `AI_BASE_URL` | empty | Provider endpoint |
| `AI_API_KEY` | empty | Provider credential |
| `AI_MODEL` | empty | Provider model identifier |
| `AI_TIMEOUT_SECONDS` | `15` | Provider timeout |
| `AI_PROMPT_TEMPLATE_VERSION` | `v1` | Stored prompt contract version |
| `REPUTATION_PROVIDER` | `disabled` | Reputation provider selector |
| `REPUTATION_BASE_URL` | empty | Reputation endpoint |
| `REPUTATION_API_KEY` | empty | Reputation credential |
| `REPUTATION_TIMEOUT_SECONDS` | `10` | Provider timeout |
| `REPUTATION_CACHE_TTL_SECONDS` | `3600` | Cache lifetime |

Both integrations are optional. The public demo works with them disabled.

## Analytics and correlation

| Variable | Default | Purpose |
|---|---:|---|
| `ANALYTICS_MAX_DAYS` | `90` | Maximum analytics rebuild range |
| `BASELINE_MIN_SAMPLES` | `5` | Samples required for a ready baseline |
| `ANOMALY_SCORE_THRESHOLD` | `60` | Anomaly flag threshold |
| `CORRELATION_WINDOW_SECONDS` | `1800` | Threat grouping window |
| `CORRELATION_GROUP_KEY` | `source_ip` | Supported grouping key |
| `CORRELATION_MIN_THREATS` | `2` | Threats required to create a case |
