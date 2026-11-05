# Python Architecture

## Intent

Standalone Python 3.10+ command-line tool for offline/authorized WordPress incident assessment. One explicit CLI entry point is currently kept in `bin/wp-integrity-audit.py` to simplify review and deployment. The implementation uses only Python's standard library, plus existing Linux/MySQL command-line tools.

## Runtime path

1. Parse args and validate site structure; select secure case root and exclusive advisory lock.
2. Collect file IOC matches and process indicators, plus Elementor cache metrics.
3. Write metadata-oriented findings and a human-readable report for `--audit`.
4. For database audit modes, parse only literal configuration values from `wp-config.php`, prepare a temporary protected MySQL option file, execute read-only SQL, generate redacted metadata.
5. For mutating modes, require an interactive confirmation, collect full site and DB backups, validate clean sources, prepare staging copies and optional official WordPress downloads.
6. Preflight serialized WordPress options; abort instead of deleting a complete active plugin/cron option.
7. Require a second interactive confirmation before modifying site or DB, then perform specified changes and collect post-operation findings.
8. Cleanup temporary MySQL authentication material on exit.

## Command coverage

| Flag | Implementation | Important constraint |
|---|---|---|
| `--audit` | File/process IOC checks, Elementor inventory, JSON/Markdown reports | Filesystem reports are written |
| `--audit-db` | Database suspicious users/options/tokens | No full DB dump |
| `--audit-db-post` | Database check after changes | Read-only |
| `--apply-files` | Validate source, stage, compare, quarantine and swap content | Manual validation/restore |
| `--apply-db` | Backup, token/family-option cleanup and post-scan | Serialized malicious options fail closed |
| `--recover` | Combination with optional core copy and salt rotation | Non-atomic across file/DB changes |

## Data boundaries

- The target WordPress tree is read, except in mutating modes.
- Case directory contains file paths, hashes, evidence and possibly backups with secret content.
- MySQL login metadata is temporarily written to a private option file, unlinked on context exit.
- WordPress.org network access only occurs with `--official-sync`; download URLs must be HTTPS and from an approved host.
- Python never executes site PHP.

## Limitations

The current report redaction is only best-effort; do not share reports without manual review. The IOC signatures cover a known incident family and cannot assert site cleanliness. Recovery lacks atomic transaction coverage across filesystem/DB, and serialized suspicious options require careful manual remediation. End-to-end WordPress/MariaDB fixture tests and disaster recovery rehearsals remain a release blocker.
