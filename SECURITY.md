# Security Policy

## Scope

AI Security Analyst processes untrusted security telemetry, uploaded files, network identifiers, and AI-generated analysis.

## Reporting

Do not publish real credentials, API keys, tokens, private infrastructure details, sensitive production logs, or exploitable private-system information in public issues.

## Data handling rules

- Use synthetic or sanitized sample logs.
- Never commit secrets.
- Treat uploaded log content as untrusted input.
- Treat LLM output as untrusted and non-authoritative.
- Deterministic evidence and detection logic remain the source of truth.
- Human approval is required before any future blocking/enforcement action.
- Avoid storing unnecessary sensitive data.

## AI-specific security

The project should defend against:
- Prompt injection embedded in log content
- Unsupported or hallucinated threat claims
- AI output being mistaken for deterministic evidence
- Leakage of secrets into model prompts
- Unbounded input sizes or resource usage

## Dependency security

Dependencies should be constrained appropriately and checked with automated dependency/security scanning before v1.0.
