# WordPress Integrity Audit — Python branch

Python 3 implementation of the WordPress filesystem/database incident audit and recovery utility for Debian and Ubuntu.

> **Security status: pre-release; recovery has not been validated against real WordPress/MySQL test fixtures.** Do not deploy recovery modes on production until integration tests and restore drills pass.

## Requirements

- Python 3.10 or later, standard library only.
- Debian/Ubuntu with `ps` for process inventory.
- For database modes: `mysql` client.
- For recovery: `mysqldump`, sufficient storage, root privileges, independently verified backups, and a site in maintenance/isolation.
- Network access to WordPress.org only with `--official-sync`.

## Usage

```bash
python3 bin/wp-integrity-audit.py --help
python3 bin/wp-integrity-audit.py --audit /var/www/example/public_html
python3 bin/wp-integrity-audit.py --audit-db /var/www/example/public_html
python3 bin/wp-integrity-audit.py --audit-db-post /var/www/example/public_html
```

The legacy option set is preserved: `--audit`, `--audit-db`, `--audit-db-post`, `--apply-files`, `--apply-db`, `--recover`, `--source`, `--core-source`, `--domain-label`, `--db-host`, `--replace-plugins-themes`, `--official-sync` and `--version`. New option: `--case-root`.

Examples for **isolated disaster-recovery rehearsal only**:

```bash
sudo python3 bin/wp-integrity-audit.py --apply-files /srv/fixture/wordpress --source /srv/fixtures/clean-wp-content
sudo python3 bin/wp-integrity-audit.py --apply-db /srv/fixture/wordpress
sudo python3 bin/wp-integrity-audit.py --recover /srv/fixture/wordpress --source /srv/fixtures/clean-wp-content --core-source /srv/fixtures/clean-wordpress
```

Mutating modes require interactive confirmations; no `--yes` bypass exists. Reports default to `/var/lib/wp-integrity-audit/cases`, and are created with restrictive permissions. Case roots inside the WordPress document root are rejected.

## Critical differences from the legacy Bash script

- No PHP execution or WP-CLI.
- Read-only database audits no longer create complete SQL/site backups; recovery does.
- MySQL secrets are stored in a temporary `0600` client configuration rather than placed on the command line or in environment variables.
- `active_plugins` and `cron` are **not deleted wholesale** if malicious markers are found. Recovery stops and requires specific manual remediation.
- ZIP packages are validated for path traversal, special entries and size limits. Package download redirects must remain on trusted HTTPS WordPress.org hosts.
- Automatic guessed ownership/permission mutations of uploads are replaced with metadata reporting.
- The original script-specific media path is not retained.
- Quarantined WordPress content is moved outside the site's document root, while confidential backups remain under the private case directory. Recovery validates literal WordPress authentication salts and optional clean-core sources before changes, then re-scans files/processes/database and refuses to declare success if recognized indicators remain. Operators still must independently verify backups and site operation.
- Recovery is **not atomic across the filesystem and database** and core replacement does not remove extraneous files. Use isolated fixtures and a controlled recovery plan.
- The staged replacement tree is rescanned in full before installation. If SQL modifications have started, an error never triggers automatic restoration of pre-change files because the database commit state may be uncertain; follow the documented manual restore procedure instead.

## Tests

```bash
python3 -m compileall -q bin tests
python3 -m unittest discover -s tests -v
```

GitHub Actions runs unit tests on Python 3.10–3.13 and a separate synthetic MySQL 8 integration job. These tests now include a disposable MySQL dump-and-restore verification, but remain insufficient to certify full live WordPress recovery, plugin compatibility and site availability.

## Security and privacy

Do not commit case directories, site backups, SQL dumps, credentials, client paths or private reports. Reports contain file paths and hashes; review them before sharing. [Security notes](SECURITY.md).

## Versioning

This rewrite starts at `0.1.0` (development/pre-release). It does not supersede or modify the historical Bash version `2026.10.28.18`. The Bash entry point was removed from this branch; the original remains available in Git history on `main`.

## Audit coverage (important)

`--audit` now performs **filesystem, process and database** checks by default and requires access to MySQL/MariaDB. If a database query fails, the audit fails rather than reporting zero findings. Use `--audit --files-only` to explicitly skip SQL; the report will say `Database audit: NOT EXECUTED` and `NOT EVALUATED`.

The database matrix checks family-specific options (`sc_*`), historical `SimplePluginLogger_plugin_info_before_update` references, serialized `cron` and `active_plugins` markers, WordPress sessions, application passwords and suspicious login patterns. Report conclusions are computed from the collected records, not from assumptions about the site. Known plugin guard files receive specific contextual classes; those classifications are **pattern recognition, not cryptographic proof of legitimacy**. Wordfence `wflogs` configuration contents are never excerpted.

Relative paths are preserved to support incident triage. Reports may still contain client-specific filenames and need review before disclosure.

The report's `Database findings` count includes only positive records, while every SQL check remains explicitly represented in `database-evidence.json`. Sensitive substrings in relative paths are masked without removing long, legitimate directory names.
