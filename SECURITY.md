# Security Policy

## Supported versions

There is currently **no declared production-supported release**. The existing script contains documented high-impact risks; see [Security Review](docs/SECURITY_REVIEW.md).

## Reporting vulnerabilities

Please **do not disclose credentials, tokens, database exports, forensic archives, site addresses, or exploit details in public issues**. Report suspected vulnerabilities privately to the repository owner using GitHub's private vulnerability reporting feature if enabled. Otherwise contact the maintainer through an established private channel. No unverified security email address is provided.

Include a concise description, affected revision, reproduction steps using dummy data, impact, and a proposed mitigation. Do not upload real client data.

## Handling suspected exposed secrets

If a real secret is found in Git history, treat it as compromised: revoke/rotate it immediately, investigate access, and then arrange history cleanup if appropriate. Deleting a file in a new commit does **not** remove it from prior commits.

## Operational guidance

- Prefer a disposable forensic copy over running on production.
- Protect all case directories with restrictive permissions, access controls, encryption at rest, and defined retention.
- Avoid publishing full SQL dumps or reports with internal paths; review every export before sharing.
- Require explicit operator approval and independent tested backups for recovery.
- Never infer that a scan without findings proves the site is clean.
