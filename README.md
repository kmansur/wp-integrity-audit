# WordPress Integrity Audit

Security-focused WordPress filesystem and database incident audit and recovery utility for **Debian/Ubuntu Linux**.

> **Status: security review required before production recovery.** The current implementation is a host-specific incident-response script, not a general-purpose, verified WordPress malware cleaner. Read [SECURITY.md](SECURITY.md) and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) before running it. A clean report is **not** evidence of an uncompromised website.

## What it does

- Inspects WordPress files for a specific family of indicators of compromise (IOCs), including `SC_ADV_BEGIN`, `--sc-cli`, `trace-inspector-pad`, and `cipher-feeder`.
- Inventories PHP files under uploads and gathers relevant process information.
- Provides targeted database queries for suspicious WordPress options, users, sessions, and cron records.
- Generates private forensic artifacts and management/client-oriented reports.
- Includes **optional invasive recovery operations** that stage/replace `wp-content`, update database records, rotate salts, and adjust permissions.

## Requirements

- Debian or Ubuntu Linux; Bash, GNU coreutils, GNU find, grep, tar, flock, Python 3, MySQL/MariaDB client and `mysqldump`.
- Root privileges (currently enforced even for read-only scans).
- Local access to a WordPress installation with `wp-admin`, `wp-includes`, `wp-content`, `wp-load.php`, and `wp-config.php`.
- For recovery: adequate free storage, a trusted clean source, maintenance isolation, and verified independent backups.
- Network access to WordPress.org only when using `--official-sync`.

## Installation

Review the code before installation. Clone and inspect the script:

```bash
git clone https://github.com/kmansur/wp-integrity-audit.git
cd wp-integrity-audit
bash -n bin/wp-integrity-audit.sh
chmod 750 bin/wp-integrity-audit.sh
```

**Do not pipe remote content directly into a root shell.**

## Commands

The actual file name is `bin/wp-integrity-audit.sh`. The script's own help currently contains a misspelled legacy filename; use the paths below.

| Option | Intended operation | Writes or sensitive artifacts |
|---|---|---|
| `--audit TARGET` | File and process IOC inventory | Writes case files and reports; does not intentionally change the WordPress tree |
| `--audit-db TARGET` | Targeted database IOC inspection | Creates a **full site archive and complete database dump** before querying |
| `--audit-db-post TARGET` | Post-recovery database inspection | Creates a **full site archive and complete database dump** |
| `--apply-files TARGET --source DIR` | Replace `wp-content` from a staged source | **Changes site files** |
| `--apply-db TARGET` | Delete matching DB rows and invalidate sessions | **Changes database and permissions** |
| `--recover TARGET --source DIR` | Combined recovery workflow | **Changes files, DB, salts, and permissions** |

Optional switches: `--core-source DIR`, `--domain-label LABEL`, `--db-host HOST`, `--replace-plugins-themes`, `--official-sync`, `--help`, `--version`.

### Read-only file inventory (still creates local reports)

```bash
sudo bash bin/wp-integrity-audit.sh --audit /var/www/example.com/public_html
```

Run on an isolated host or forensic copy where feasible. Reports may contain server paths, names, or snippets that should not be shared without manual review.

**Do not execute recovery flags in production** until the high-severity issues in the security review have been addressed and tested with representative WordPress fixtures.

## Output and data handling

The script currently writes case data under the **hardcoded host-specific path** `/root/incident-wh01-20261028/`, including archives, SQL dumps, report files, inventory, hashes, and temporary connection files. The directory must be protected, must never be served by a web server, and must not be committed to Git. Some generated artifacts may include credentials or personal data. Client-facing redaction is incomplete and must be manually verified.

## Documentation

- [Architecture and operation](docs/ARCHITECTURE.md)
- [Operator guidance](docs/OPERATIONS.md)
- [Security review and remediation priorities](docs/SECURITY_REVIEW.md)
- [Development and testing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)
- [Release history](CHANGELOG.md)

## Versioning and compatibility

Adopt [Semantic Versioning](https://semver.org/) for future releases. The legacy shell variable `SCRIPT_VERSION='2026.10.28.18'` is an existing date-based identifier and has **not** been changed in this documentation-only review. No new release is asserted.

## License

**No license file was present at the initial review.** All rights are reserved by default unless the repository owner selects and publishes a license. Do not assume MIT or any other license.
