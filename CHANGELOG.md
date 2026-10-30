# Changelog

All project documentation and source commentary are in English. Versions follow Semantic Versioning.

## [Unreleased]

### Audit report improvements
- Correct historical-cache excerpt handling after failed MySQL CI regression.
- Show interpreted values for two strictly allowlisted numeric transient options.
- Replace the aggregated database finding count with category-specific counts.
- Record the tool's SHA-256 in the report, explain dynamic WordPress cron behavior and add a classification legend.
- Extend MySQL integration tests for the report formatting and classification.
- Record a separate informational cron fingerprint with SHA-256, size, UTC capture time and known marker count, even when no IOC matches.
- Add an explicit `LIBERAÇÃO NÃO RECOMENDADA` release-gate warning to audit reports and a regression assertion.


## [0.2.0] - 2026-10-30 (pre-release)

### Changed
- Combined default audit now includes database checks. Use `--files-only` to omit them explicitly.
- Report coverage and technical conclusions distinguish historical references, active markers and unaudited areas.
- Context-aware classification for recognized plugin guards, retaining relative paths.
- Add regression coverage proving default audit fails closed without database configuration, rather than emitting misleading zero findings.



### Added
- Synthetic MySQL integration test that restores a generated SQL backup into a second isolated database and verifies WordPress fixture records.

### Fixed
- Remove temporary staged WordPress files if SQL preflight or operator confirmation fails, before any site modification.
- Add regression coverage for swap failure rollback and evidence-file permissions.
- Read archived file bodies to detect truncated or corrupted tar backups instead of checking headers alone.
- Scan complete staged content with the same full-file and filename IOC checks used for clean sources, including files downloaded during official component synchronization.
- Prevent automatic filesystem rollback after a database write has started, because a client error does not prove the transaction was rolled back.
- Add a regression test for malware markers after the first 256 KiB of staged PHP content.

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
- Recovery preflight validates literal WordPress salts and core-source paths before starting mutations.
- File scans read full PHP-like file content in bounded chunks, rather than checking only the first portion.

### Known limitations
- No production WordPress/MySQL integration validation or restore rehearsal completed.
- File and DB operations cannot form one atomic transaction; an operator-controlled restore remains necessary.
- The signature corpus is incident-specific; clean results do not certify a clean WordPress installation.
- Legacy Bash is retained in Git history on `main`; this branch has only the Python runtime.

## [Legacy baseline] - 2026-10-30

- Initial Bash implementation, original version `2026.10.28.18`.

### Audit coverage and classification
- Run targeted database inspection by default with `--audit`; add explicit `--files-only` for filesystem-only inspection.
- Distinguish skipped database analysis from zero findings and fail if mandatory database checks cannot execute.
- Inspect family-specific options, historical plugin-update cache, cron, active plugins, stored sessions, application passwords and suspicious administrator names.
- Recognize specific Sucuri, WPForms and Simple History guard patterns and quarantine Wordfence configuration snippets from the report.
- Preserve relative file paths, including long names, and generate an evidence-based technical opinion.
- Add fixture regressions for two family residues, historical references, cron, plugins and session counts.

- Count only positive database records in the report summary, retaining explicit `NOT_FOUND` and `ABSENT` checks in JSON; protect sensitive path fragments without destroying long filename context.

### Database evidence enrichment
- Preserve exact WordPress option names (including the SimplePluginLogger historic update cache) without entropy redaction.
- Include database name and physical options/usermeta table names in the client report.
- Distinguish `RESIDUO_FAMILIA_REQUER_LIMPEZA` from historical and informational evidence.
- Gather full-value SHA-256, byte length and bounded encoding metadata for candidate option records.
- Limit exported snippets to known IOC tokens; deliberately withhold arbitrary encoded/decoded content to avoid leaking credentials.
- Report separate counts for family residues, historical references and stored session records.
- Add database integration regression tests for naming, classification, checksums and report contents.

### Report clarity and safe scalar evidence
- Classify two allowlisted numeric `sc_*` transient keys as `ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO` and show their safe scalar value only after strict length and digit validation.
- Keep arbitrary family options and credential-like values masked; include a regression fixture with a fake private token.
- Render SQL evidence details as individual Markdown sections after the completed summary table instead of breaking table layout.

- Remove duplicated database audit status from the client report and explicitly state whether SQL dump and file snapshot evidence were generated.

### Standardized operational results
- Add final result statuses, return codes, an executive Markdown summary, and a privacy-conscious `report.json`.
- Separate family, historical, informational, file-classification and process counters.
- Reserve `COMPROMETIMENTO_CONFIRMADO` / exit 20 for independently confirmed evidence; heuristic markers alone are incomplete investigations.
- Return 10 for family residues and 40 when the user intentionally omits database checks.
- Introduce regression coverage for the status contract, JSON summary and read-only CLI return codes.

### Case evidence indexing
- Repair previous CI failures caused by a missing explicit `NOT EVALUATED` label and incomplete synthetic evidence records.
- Generate deterministic per-case FILE/DB evidence identifiers and a separate JSON index with SQL table and column provenance.
- Generate a single-row CSV audit summary for fleet consolidation; add unit regression checks.

### Case comparison
- Add read-only `--compare OLD_CASE NEW_CASE` with optional `--compare-output`.
- Write private Markdown and JSON comparison reports identifying new, removed and changed file/database evidence.
- Reject comparisons with incomplete database audits or mismatched database names; add synthetic regression tests.

- Prevent comparison output directories from being created inside either source case; add regression test.
