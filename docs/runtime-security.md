# Runtime Security

## Production requirements

Production must set:

- `APP_ENV=production`
- `AUTH_ENABLED=true`
- Strong, distinct `ANALYST_API_KEY` and `ADMIN_API_KEY`
- A production `DATABASE_URL`
- Explicit `ALLOWED_HOSTS`
- Explicit `CORS_ALLOWED_ORIGINS` only when browser access is required
- `RATE_LIMIT_ENABLED=true` with a deployment-appropriate threshold
- External provider credentials only when those providers are enabled

API documentation is disabled in production unless `ENABLE_API_DOCS=true` is deliberately set.

## Secret handling

Do not commit API keys, database passwords, provider tokens, or production `.env` files. Inject them through the deployment platform or secret manager. Rotate credentials if they are exposed.

## API keys

The current foundation provides two roles:

- **analyst** — normal investigation/API access
- **admin** — analyst access plus sensitive maintenance/rebuild/correlation operations

Use separate keys. Do not reuse provider or database credentials as application API keys.

## HTTP boundary

Configure trusted hosts and terminate TLS at the deployment boundary. Production responses include HSTS. API responses include defensive security headers and no-store caching where applicable.

## Limits

Request body, batch row, analytics range, correlation window, and rate limits are configurable. Keep limits finite in production and tune them from measured workloads rather than disabling them.

## External providers

AI and reputation integrations are optional. Provider failures must degrade gracefully. Never include secrets or unnecessary sensitive context in prompts or enrichment requests.
