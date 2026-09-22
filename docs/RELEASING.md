# Release process

The repository follows Semantic Versioning. VERSION is the source of truth and
must match the Python package, FastAPI application, and frontend package.

## Process

1. Update VERSION and all version-bearing metadata.
2. Update CHANGELOG.md and add versioned notes under docs/releases.
3. Run python scripts/check_version.py.
4. Push the release commit to main.
5. Confirm all CI and Release workflows pass.
6. Verify the GitHub Release, source archive, and checksum.

A VERSION change on main triggers the release workflow. It validates metadata,
runs the coverage gate and frontend build, checks tracked filenames for common
secret files, packages tracked source with git archive, and creates v<VERSION>.
Manual dispatch and safe idempotent re-runs are supported.

## Checklist

- [ ] SemVer metadata is consistent.
- [ ] Changelog and notes describe shipped behavior.
- [ ] Backend coverage is at least 85%.
- [ ] Frontend type checking and build pass.
- [ ] Security and container checks pass.
- [ ] Samples are synthetic; no credentials or .env files are tracked.
- [ ] Archive checksum is attached.
- [ ] Release tag targets the intended main commit.

Archives use git archive, excluding ignored and untracked files. The protected
GitHub Actions token is not embedded in artifacts.
