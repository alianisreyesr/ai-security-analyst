# Contributing

## Workflow

By current project decision, implementation is written directly to `main`.

1. Start from an issue with acceptance criteria.
2. Keep each change focused and traceable.
3. Add/update tests for behavior changes.
4. Run required checks before considering an issue complete.
5. Update documentation when behavior changes.

## Engineering standards

- Prefer explainable deterministic detections over opaque behavior.
- Keep parsers and rules independently testable.
- Validate untrusted input.
- Never commit secrets or sensitive real-world logs.
- Use synthetic fixtures.
- Keep raw and normalized events distinguishable.
- AI explanations must not overwrite or fabricate evidence.
- Architecture diagrams must be Mermaid source with styles/colors.

## Commit style

Prefer Conventional Commit-style messages:
- `feat: add SSH auth parser`
- `fix: prevent duplicate threat creation`
- `test: add brute-force rule fixtures`
- `docs: document risk scoring`
- `security: validate uploaded log size`
