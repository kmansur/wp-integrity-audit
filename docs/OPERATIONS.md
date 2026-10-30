# Python Operator Handbook

## Read-only audit

```bash
python3 bin/wp-integrity-audit.py --audit /path/to/wordpress --case-root /secure/cases
python3 bin/wp-integrity-audit.py --audit-db /path/to/wordpress --case-root /secure/cases
```

Use authorized sites or offline forensic copies. Case files are created with restrictive permissions. A DB audit reads `wp-config.php` to obtain literal database configuration values; dynamic PHP configuration is rejected.

## File and database recovery

Recovery is a development feature and must only be exercised on disposable WordPress fixtures until end-to-end tests exist. Provide an independent, tested backup before running. The tool creates its own archive and SQL dump, but **these have not been proven restorable**. Quarantine paths are recorded in the private case folder. Reopening an incident site requires operator review of process persistence, users, permissions, plugin provenance, core integrity, and external credentials.

## Flags

- `--source`: independent clean `wp-content` directory.
- `--replace-plugins-themes`: explicit permission for staged plugin/theme directories.
- `--official-sync`: download official WordPress.org packages; reject unavailable/custom components.
- `--core-source`: independently verified clean WordPress core directory, used with `--recover`.
- `--db-host`: override database hostname.
- `--domain-label`: sanitized label for case filenames.
- `--case-root`: secure directory for reports and recovery evidence.

## Sensitive outputs

Site archives include complete WordPress files, including `wp-config.php`. SQL dumps include all tables and may contain credentials, personal information and application tokens. Keep outside web roots, encrypt at rest according to local policies, restrict access and use retention controls. Do not commit evidence or reports.

## Validation

```bash
python3 -m compileall -q bin tests
python3 -m unittest discover -s tests -v
```

These checks cover syntax and selected isolated behavior. Before declaring production readiness, build disposable WordPress/MySQL/MariaDB fixtures and validate both normal and interruption/error paths, restoring all backups independently.
