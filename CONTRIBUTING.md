# Contributing

## Scope and principles

- Project files, documentation, user-facing help, and comments should be written in **English**.
- Target Debian/Ubuntu Linux. Explicitly document dependencies and tested versions.
- Default to read-only behavior; use explicit opt-in for any mutation.
- Separate detection, evidence collection, remediation, and client-report rendering.
- Do not add hostnames, credentials, production paths, private client information, or malware samples to Git.
- Work on focused review branches only when necessary; do not rewrite history or force-push without coordination.

## Versioning

Use Semantic Versioning for future releases. Changes with recovery impact require tests and clear upgrade notes. Update `README.md` and `CHANGELOG.md` with each relevant change.

## Review and validation

Before proposing changes:

```bash
bash -n bin/wp-integrity-audit.sh
# If installed:
shellcheck bin/wp-integrity-audit.sh
```

Use a disposable WordPress fixture and synthetic database. Validate both positive and negative IOC tests, permission handling, cleanup on failure, redaction, interrupted recovery, symlinks, hostile archives, and database restore. Never run integration tests against a production database.

## Pull request checklist

- Explain behavior and security implications.
- Add regression tests for modified behavior.
- Update documentation and changelog.
- Verify no secrets were added to the current tree or Git history.
- Show the exact test commands and outcomes, with failures clearly identified.
