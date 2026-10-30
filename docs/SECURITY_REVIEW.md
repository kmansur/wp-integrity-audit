# Security Review — 2026-10-30

## Scope and evidence

Static inspection of GitHub default-branch commit `88858aef8b279a574f2d785ab3d18d7e485933ba`, containing only `bin/wp-integrity-audit.sh` (743 lines). The available repository history showed one initial commit. **No runtime execution, site scan, actual database restore, ShellCheck run, or independent history-wide secret scanner was performed.** Findings should be confirmed through isolated tests. No plaintext production password or private key was identified in the reviewed tracked script; this does not certify the repository as secret-free.

## Findings

| ID | Severity | Location (initial baseline) | Issue | Recommended action |
|---|---|---|---|---|
| SEC-001 | Critical | L694–704 | A matching IOC can trigger deletion of the **entire** `active_plugins` or `cron` option. This is not surgical cleanup and can break plugin activation or scheduled jobs. | Parse serialized content safely, remove only confirmed malicious entries, validate serialization and maintain exact restore coverage. |
| SEC-002 | High | L70–75, L237–250, L492–494 | Complete site archive and SQL dump contain credentials/PII and are written to a fixed case root. Full dumps also run for database *audit* modes. | Configurable private output path, least privilege, retention/encryption controls, explicit backup opt-in for read-only modes. |
| SEC-003 | High | L546–618, L83–133 | Client evidence may include unsanitized SQL snippets, DB names, relative paths or serialized values; redaction is heuristic and may leave secrets or user data. | Produce metadata-only external reports by default; allowlist fields, test against synthetic secrets, manually approve exports. |
| SEC-004 | High | L343–355 | ZIP extraction checks traversal strings but does not explicitly validate symlink entries, destination containment, archive quotas, or trusted release hashes. | Safe archive extraction with type/size limits, canonical-path validation and integrity checks; test hostile ZIP fixtures. |
| SEC-005 | High | L188–194, L678–690, L694–725 | Rollback is incomplete across the filesystem and DB. `SWAPPED` is set only after both moves; a failure between moves may leave `wp-content` absent. | Transaction-like recovery plan, explicit states, traps for EXIT/signals, preflight checks and rehearsed restore. |
| SEC-006 | High | L24–30, L463–492 | Root is always required and DB passwords are placed in environment variables (`MYSQL_PWD` and exported Python environment), increasing exposure to privileged observers. | Least-privilege audit paths; use secured option files without password-bearing process environments. |
| SEC-007 | Medium | L27–28, L60, L70, L74, L442 | WH01-specific lock, incident root, core fallback and media filename expose internal operational details and reduce portability. | Replace with documented configurable paths and remove client/incident-specific defaults. |
| SEC-008 | Medium | L6–19, L2, elsewhere | Help has a misspelled filename (`wp-integraty-audit.sh.sh`); many comments/messages are not English. | Consistent CLI naming, English localization and detailed explanatory comments. |
| SEC-009 | Medium | L48–65, L661–680 | Path/source validation does not fully establish that a supplied clean source is trusted, immutable or free of symlink surprises. | Canonical-path containment, ownership/permission requirements, symlink policy, verified package provenance. |
| SEC-010 | Medium | L217, L528–657 | Hardcoded IOC rules create blind spots and can conflate historical references with compromise. | Versioned, tested signatures, confidence categories and manual review workflow. |
| SEC-011 | Medium | L492–494 | A successful dump does not itself demonstrate a valid restore; hash covers an artifact but not restored DB usability. | Test restore to an isolated disposable DB and verify structure/consistency. |
| SEC-012 | Medium | Repository root | No initial README, changelog, tests, security policy, or license. | Add maintained documentation, test suite, security disclosures, and choose a license explicitly. |

## Secret exposure review

- **Observed:** hardcoded operational paths and an incident-specific media filename in source; these are contextual information disclosures, not proven credentials.
- **Not observed in reviewed tracked source:** an obvious literal DB password, access token, SSH private key, or cloud key.
- **Not inspected:** private server artifacts, runtime log/backup contents, external services, deleted historical objects, and actual credentials in deployed `wp-config.php`.
- **Repository status at review:** public. Do not place production forensic outputs in the repository.

## Priority order

1. Fix destructive option deletion (SEC-001) and recovery rollback (SEC-005) before any production restore.
2. Protect backup/database secrets and redesign client exports (SEC-002, SEC-003, SEC-006).
3. Harden download/extraction trust and source handling (SEC-004, SEC-009).
4. Remove environment-specific constants; add tests, documentation and CI checks (SEC-007–012).

## Verification criteria for follow-up work

Use a disposable WordPress test site. Confirm that legitimate serialized `active_plugins` and `cron` entries survive remediation; simulate interruptions between filesystem moves; test malformed/symlink/oversized ZIPs; test redaction with synthetic credentials; inspect process environment; and verify that audit modes do not unexpectedly require or create privileged database backups.
