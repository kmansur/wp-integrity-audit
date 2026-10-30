# Architecture and Data Flow

## Current implementation

The project currently consists of one Bash script: `bin/wp-integrity-audit.sh` (743 lines in the initial revision). It embeds Python programs for parsing WordPress configuration, generating evidence, downloading WordPress.org components, and rotating salts.

### Execution sequence

1. Enforce root, prerequisites, and an exclusive lock.
2. Parse CLI mode/options; resolve and validate WordPress target and optional clean sources.
3. Create a case directory and log/report streams.
4. Collect static file/process IOCs.
5. For `--audit`, write reports and exit **before database connection or full backups**.
6. For other modes, create a full site archive, parse DB settings from `wp-config.php`, create a client configuration, and dump the full database.
7. Run targeted SQL review or perform selected replacement/remediation operations.
8. Write final reports and clean up the temporary MySQL configuration when the EXIT trap executes.

### Current modes and trust boundaries

- `--audit`: no intentional modification of WordPress site files; writes output elsewhere on the host.
- `--audit-db` / `--audit-db-post`: SQL SELECT queries, but **not side-effect free** due to full backups and output files.
- `--apply-files`: sources a clean `wp-content` tree and moves existing content to quarantine.
- `--apply-db`: runs SQL DELETE operations, resets sessions/application-password records, and changes filesystem metadata.
- `--recover`: combines actions and optionally synchronizes WordPress.org components.

### Forensic outputs

The case directory may contain `site-before.tar.gz`, `database-before.sql`, SHA-256 checksums, raw evidence, administrator login names, filesystem paths, logs, and human-readable reports. The CSV management report aggregates targets and case locations.

### Architectural limitations

The current logic is tailored to a specific malware family and incident host. It is not a complete WordPress security baseline. It cannot authenticate every plugin or detect all persistence mechanisms. Static signatures may produce false positives/negatives. Recovery steps are not atomic across the filesystem and database, and the current rollback coverage is incomplete.

## Recommended future structure

- `bin/`: minimal safe CLI and policy checks.
- `lib/`: filesystem, DB, IOC, evidence, redaction, and recovery modules.
- `tests/`: fixtures and isolated regression/integration tests.
- `docs/`: operator manual, architecture, threat model, and security review.
- `CHANGELOG.md`, `SECURITY.md`, release metadata and license (when selected).

This is a **proposal**, not a claim that these modules already exist.
