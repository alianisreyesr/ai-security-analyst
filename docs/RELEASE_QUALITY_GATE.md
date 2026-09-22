# Release quality gate

The `Backend CI / Release readiness` check is the authoritative automated gate for a stable release.

## Required checks

A release candidate is ready only when all of these jobs succeed:

- Backend tests, Ruff, and mypy
- PostgreSQL migration validation
- Dependency audit with `pip-audit`
- Static security analysis with Bandit
- Repository and backend-container scanning with Trivy
- Backend container hardening checks

The release-readiness job runs even when an upstream job fails and reports a failure unless every critical job completed successfully.

## Coverage policy

Backend tests must maintain at least **85% line coverage**.

The initial enforced baseline was selected after the suite recorded **90% coverage with 69 passing tests**. The five-point margin allows small refactors while still preventing material untested regressions. Raising the threshold is preferred as the suite grows; lowering it requires a documented rationale.

CI publishes `backend-coverage/coverage.xml` as a workflow artifact for 14 days. The XML report supports detailed inspection and future coverage-service integration.

## Release decision

Automation is necessary but not sufficient. Before tagging a stable release:

1. Confirm Backend CI, Frontend CI, and Dev Container CI are green for the target commit.
2. Review any documented Trivy exception and its expiry/rationale.
3. Verify the synthetic demo path from ingestion through threat investigation.
4. Confirm release artifacts contain no credentials, private telemetry, or environment files.
5. Record the target commit and results in the release notes.
