# v0.9 Release Candidate Checklist

This checklist records the release-candidate evidence before the project advances to v1.0.

## Security architecture

- [x] Threat model documents assets, trust boundaries, attacker-controlled inputs, abuse cases, mitigations, and residual risks.
- [x] Trust-boundary diagrams are stored as styled Mermaid source.
- [x] AI/log/provider content is explicitly treated as untrusted.
- [x] Deterministic evidence remains authoritative over AI output.

## Authentication and authorization

- [x] Optional API-key authentication is implemented for local/development flexibility.
- [x] Production refuses to start with authentication disabled.
- [x] Analyst and admin roles are explicit.
- [x] Protected API routes require identity when authentication is enabled.
- [x] Administrative analytics rebuild and correlation operations require admin role.
- [x] Missing/invalid credentials and insufficient role cases are tested.

## Input and abuse controls

- [x] Request-size limits exist.
- [x] Batch content/row limits exist.
- [x] Rate limiting exists and is tested.
- [x] Analytics lookbacks/ranges and correlation query size are bounded.
- [x] Parsers fail safely on malformed input.

## Runtime and secrets

- [x] Secrets are supplied by environment/configuration rather than committed values.
- [x] `.env.example` contains placeholders/blank secret fields.
- [x] Request audit logs exclude API keys and request bodies.
- [x] Production API documentation exposure is disabled by default.
- [x] CORS and trusted hosts are explicit allow-lists when configured.

## Automated release gates

GitHub Actions run **#193** passed all release-candidate jobs:

- [x] Ruff lint
- [x] Unit/integration tests
- [x] mypy type checking
- [x] pip-audit dependency vulnerability scan
- [x] Bandit static security analysis
- [x] PostgreSQL 17 migrations and table verification
- [x] Backend Docker build
- [x] Fixed runtime package-version verification
- [x] Trivy repository filesystem scan
- [x] Trivy backend container scan

## Scanner exception review

The two IDs in `.trivyignore` are narrow exceptions for stale base-layer metadata only. CI first verifies that the final runtime contains fixed versions. See [security-hardening.md](security-hardening.md).

No general severity suppression is enabled.

## Clean-environment evidence

The CI runner begins from a clean hosted environment and successfully:

1. installs the backend;
2. runs tests/static checks;
3. starts PostgreSQL 17;
4. applies every Alembic migration;
5. verifies expected database tables;
6. builds the backend image from the checked-in Dockerfile;
7. scans the repository and final image.

## Known limitations

- Built-in rate limiting is per-process; multi-replica deployments should add a gateway/shared limiter.
- API keys are suitable for this portfolio release, but enterprise deployment should prefer OIDC/SSO with managed key/session lifecycle.
- External AI/reputation providers introduce privacy, availability, and policy dependencies.
- Detection rules can produce false positives; reviews are stored separately and do not mutate original evidence.
- The frontend remains scheduled for the portfolio-release phase.
- Deployment infrastructure is documented but not yet a hosted production service.

## v0.9 exit decision

All blocking v0.9 security/quality gates are satisfied. Remaining work belongs to the v1.0 portfolio-release milestone.
