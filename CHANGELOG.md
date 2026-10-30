# Changelog

All project documentation and source commentary are in English. Versions follow Semantic Versioning.

## [0.1.0] - 2026-10-30 (Python branch; pre-release)

### Added
- Python 3.10+ implementation of CLI modes: `--audit`, `--audit-db`, `--audit-db-post`, `--apply-files`, `--apply-db`, and `--recover`.
- Incident IOC search, process inventory, metadata-only client reporting, SQL checks, snapshot/quarantine, core copy, official WordPress.org component downloads, salt rotation, Elementor inventory and component comparisons.
- Restrictive case-file permissions, protected temporary MySQL credentials, independent `--case-root`, unit tests, synthetic MySQL integration tests and CI checks.

### Changed
- Database audit no longer performs full backups; these are restricted to mutating operations.
- Potentially destructive removal of entire serialized `active_plugins`/`cron` options is replaced by fail-closed manual remediation.
- Unsafe inferred recursive uploads ownership changes are replaced by metadata-only auditing.
- Clean source symlinks and special files are rejected before copying.
- Quarantine and failed stage directories are moved outside the document root.
- Post-recovery file/process/database IOC scanning blocks a clean completion status when indicators remain.
- Password and salt rewriting refuses symlinked WordPress configuration and restricts file permissions.
- Tests cover synthetic database backups, full-file scanning, symlink handling and salt rotation.
- Forensic case roots inside a WordPress document root are rejected.
- WordPress.org package downloads now enforce the trusted HTTPS host after redirects.
- File scans read full PHP-like file content in bounded chunks, rather than checking only the first portion.

### Known limitations
- No production WordPress/MySQL integration validation or restore rehearsal completed.
- File and DB operations cannot form one atomic transaction; an operator-controlled restore remains necessary.
- The signature corpus is incident-specific; clean results do not certify a clean WordPress installation.
- Legacy Bash is retained in Git history on `main`; this branch has only the Python runtime.

## [Legacy baseline] - 2026-10-30

- Initial Bash implementation, original version `2026.10.28.18`.
