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

This rewrite starts at `0.2.0` (development/pre-release). It does not supersede or modify the historical Bash version `2026.10.28.18`. The Bash entry point was removed from this branch; the original remains available in Git history on `main`.

## Audit coverage (important)

`--audit` now performs **filesystem, process and database** checks by default and requires access to MySQL/MariaDB. If a database query fails, the audit fails rather than reporting zero findings. Use `--audit --files-only` to explicitly skip SQL; the report will say `Database audit: NOT EXECUTED` and `NOT EVALUATED`.

The database matrix checks family-specific options (`sc_*`), historical `SimplePluginLogger_plugin_info_before_update` references, serialized `cron` and `active_plugins` markers, WordPress sessions, application passwords and suspicious login patterns. Report conclusions are computed from the collected records, not from assumptions about the site. Known plugin guard files receive specific contextual classes; those classifications are **pattern recognition, not cryptographic proof of legitimacy**. Wordfence `wflogs` configuration contents are never excerpted.

Relative paths are preserved to support incident triage. Reports may still contain client-specific filenames and need review before disclosure.

The report's `Database findings` count includes only positive records, while every SQL check remains explicitly represented in `database-evidence.json`. Sensitive substrings in relative paths are masked without removing long, legitimate directory names.

## Detailed database evidence

The database report now records the literal database name and physical `<prefix>options`/`<prefix>usermeta` tables so an operator can locate records in phpMyAdmin. WordPress option identifiers such as `SimplePluginLogger_plugin_info_before_update` are preserved without length-based redaction. Family-specific options receive `RESIDUO_FAMILIA_REQUER_LIMPEZA`, while historical references retain `HISTORICAL_REFERENCE`.

For candidate option values, the tool collects full-value SHA-256, exact byte length and a limited encoding classification. Excerpts are restricted to recognized IOC tokens; arbitrary original or decoded database data is deliberately omitted because it can contain credentials and tokens. This is a safe-evidence compatibility choice rather than exact parity with the legacy Shell's unrestricted technical excerpts. Summaries distinguish confirmed family residues, historical references and informational WordPress sessions. Do not distribute detailed case JSON without review.

### Scalar IOC evidence and Markdown layout

Two exact, known family transient keys (`_transient_sc_spread_interval` and `_transient_timeout_sc_spread_interval`) can expose their complete value only when it consists exclusively of 1–20 decimal digits and the SQL byte length matches the extracted value. They receive `ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO`. Other values, including arbitrary `sc_*` content, remain masked. Database findings are displayed as one intact summary table followed by separate per-record Markdown sections; no list entries are inserted inside a table.

## Audit-report release constraints

A completed targeted scan is **not** a production-release authorization. A dynamic WordPress cron entry is recorded as informational evidence (SHA-256, byte count, UTC collection time and recognized marker count) without treating ordinary hash changes as malware. The report displays the tool's own SHA-256 to tie output to a specific installed version. Values from non-allowlisted options remain masked.

Planned but not yet implemented: optional independently validated forensic dump, broader posts/postmeta and host-persistence collection, structured process/network inventory, CSV export, stable dedicated exit codes, module split and automated release decision. Until these features are validated, retain isolation and use human sign-off for site release.

Audit reports now explicitly state whether a database dump and full-file snapshot were performed. Pure audit modes leave both as `NOT PERFORMED`; snapshot generation remains limited to explicitly confirmed mutating recovery workflows. No forensic snapshot is implied by an ordinary read-only audit.

## Standardized audit results (pre-release)

The default audit creates `report.md` and `report.json`. Both include a final status and an executive summary, with separate family-residue, historical, informational, active-marker, file-pattern and process counters.

Audit exit codes: `0` means no known explicit markers under the completed targeted audit; `10` means family residues require remediation; `20` is reserved for independently confirmed compromise (the current heuristic detector does **not** assert this automatically); `30` means an audit/connection error; `40` means incomplete evidence, including an intentional `--files-only` run or indicators requiring investigation. These are process return codes, not shell error strings. Automation should not equate code 0 with permission to reopen a site.

The `report.json` contains high-level summary and result status only; detailed evidence remains in separately protected case files. This stage does not yet provide CSV consolidation, optional forensic dumps or a full host-persistence audit.

## Evidence indexing and CSV

Each case now includes `evidence-index.json` with deterministic `FILE-001` / `DB-001` references, SQL table/column provenance, and relative file paths. A one-row `report.csv` provides a privacy-conscious fleet-summary alongside `report.json` and `report.md`. Evidence IDs are unique within a case, not across different collections; use the case directory identifier as the namespace.

## Compare two complete audit cases

`python3 bin/wp-integrity-audit.py --compare OLD_CASE NEW_CASE --compare-output /var/lib/wp-integrity-audit/comparisons/review-001`

Comparison never scans or changes the live WordPress site. Both source cases must have complete database coverage and the same database name. Generates private `comparison.json` and `comparison.md` with added, removed and changed file/database evidence (using paths or option identifiers, not ephemeral evidence IDs). A changed cron hash is informational, not proof of compromise. The comparison does not authorize reopening a site.

## WordPress configuration inventory

Read-only audit modes now write `configuration-evidence.json` for configuration files inside the WordPress tree (`.htaccess`, `.user.ini`, `php.ini`, `web.config` and related names). Only relative paths, metadata, modes and SHA-256 values are collected; file contents are never exported. This inventory does not inspect host-wide Apache/PHP-FPM configuration, and a configuration file's presence does not demonstrate compromise.

Hidden-directory PHP files now receive `PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO` unless stronger indicators apply. This is a contextual review flag, not a compromise finding; `.well-known` is excluded from the hidden-directory heuristic.

## Optional core integrity and host persistence metadata

`--audit --check-core TARGET` reads the installed `wp-includes/version.php` as plain text, requests official MD5 checksums over HTTPS from `api.wordpress.org`, and writes `core-integrity.json`. It does **not** execute PHP, invoke WP-CLI, download code archives or change core files. Missing or mismatched files are marked for manual review; official checksum comparisons assume `en_US`, so localized WordPress installations may legitimately differ. Checksum unavailability is explicitly recorded in JSON and must not be interpreted as integrity success.

`--audit --host-persistence TARGET` additionally inventories metadata (paths, SHA-256, sizes and modes) from selected Linux cron, systemd, PHP and Apache configuration locations. It writes `host-persistence.json`, never exports configuration bodies, and does not change or restart services. This is **not** a complete host-persistence investigation: per-user crontabs, running processes, deleted files, and external services require separate review. These probes are opt-in and available only in audit mode.

## Optional probe status integration

When `--check-core` is requested, unavailability or mismatches in official checksums are exposed in the executive summary and `report.json` (`optional_probe_review`). If there are no higher-priority family residues, these findings return status `AUDITORIA_INCOMPLETA` and exit code `40`. Existing confirmed family residues retain status `RESIDUOS_REQUEREM_LIMPEZA` (exit `10`), with optional issues listed alongside them. A clean checksum result is not proof of site integrity.

## Version 0.3.0: full passive audit by default

A normal invocation (`python3 bin/wp-integrity-audit.py /path/to/wordpress`) now runs all implemented passive scans: WordPress files, configuration metadata, Core checksum verification, Linux host-persistence metadata, Elementor asset checks, matching processes and SQL indicators. No remediation is performed. **The Core check contacts the official WordPress checksum API over HTTPS; use `--skip-core` in offline environments.** Disable unwanted checks with `--skip-core`, `--skip-host-persistence`, `--skip-db` (alias `--files-only`), `--skip-files`, `--skip-config`, `--skip-processes` or `--skip-elementor`. Skipped checks are documented in the case report and an otherwise clean report becomes `AUDITORIA_INCOMPLETA` (exit 40). Confirmed family residues continue to return exit 10.

**Important:** Host-persistence scans read selected /etc paths and may require filesystem permissions. File contents remain excluded from the host inventory. Destructive `--apply-files`, `--apply-db`, and `--recover` require explicit selection and interactive approval; they are never part of a default audit. The `--compare` workflow remains separately invoked.

## Report evidence reconciliation

The management summary now reports Core discrepancy counts, WordPress configuration review counts and external host IOC counts from the corresponding JSON evidence files. Core findings and WordPress-local configuration paths and SHA-256 hashes are listed in report.md. Host inventory file paths are excluded from its host-persistence summary and retained in the protected host-persistence.json for internal technical review.

report.json includes domain, case_id, core_discrepancies, configuration_review_count and host_persistence_indicators. The CSV keeps domain and case_id in separate columns. Ordinary host configuration files are classified INVENTARIADO_SEM_INDICADOR; only an explicit known family IOC match receives HOST_INDICATOR_REQUIRES_INVESTIGATION. A lack of matching known IOCs is not a guarantee of host integrity.

## Client-facing and internal reports

The case now generates `report.md` as a management-oriented summary without host paths, detailed infrastructure inventories, or vendor/product names. `technical-report.md` contains detailed WordPress Core discrepancies, local configuration paths and hashes, database evidence and classification notes. `host-persistence.json` remains internal-only; the reports show aggregate host counts. `report.json` contains separate `domain` and `case_id` fields and evidence-derived Core, configuration and host counters; `report.csv` also separates `domain` and `case_id`.

The host inventory classifies ordinary entries as `INVENTARIADO_SEM_INDICADOR` and only labels bounded recognized-family matches `HOST_INDICATOR_REQUIRES_INVESTIGATION`. Ordinary entries are not certified benign. The management risk overview is qualitative; it must not be used as a release authorization.

## Supplementary evidence consistency and triage

The JSON summary's `security_configuration_review` now includes WordPress configuration files actually flagged for review, matching `configuration_review_count`. Configuration files without recognized directive patterns are retained as `CONFIGURACAO_INVENTARIADA_SEM_INDICADOR`; relevant rules are recorded only as indicator *names*, never their potentially sensitive arguments. Inventory totals and review totals are different and must not be confused. The management risk assessment uses `LOW — no known indicators found` for a completed host inventory with no recognized IOC and `NOT DETERMINED` if the host inventory is unavailable. Neither implies that all persistence has been excluded.

Known BitNinja-associated host paths are labeled `COMPONENTE_DE_SEGURANCA_CONHECIDO` for inventory purposes only, not cryptographically authenticated. Their paths remain in private internal evidence, not in the management report. The `evidence-index.json` now includes Core, configuration, host and process evidence identifiers.

## Strict MetForm upload-cache triage

A PHP `index.php` under uploads is classified as `LEGITIMO_VALIDADO` only if its full contents match the exact `Silence is golden.` guard bytes (LF/CRLF); arbitrary PHP at this location remains reviewable. A `font-awesome-<16 lowercase hex>.php` file under `wp-content/uploads/metform/cache/icons/` with a PHP return-array header is classified as `CACHE_PLUGIN_REQUER_VALIDACAO`, **not** as verified plugin content. The full file and its generation mechanism remain unverified; this classification **still forces exit code 40** in an otherwise marker-free audit. File-name matches alone never certify integrity.

## Akismet access control and report consistency

The Akismet `wp-content/plugins/akismet/.htaccess` receives `LEGITIMO_VALIDADO` only when a narrow parser finds a deny-by-default policy with asset-scoped FilesMatch grants and no unrecognized directives or PHP-executable extensions. Other Akismet rules remain subject to manual review. The `security_configuration_review` count in JSON now matches the configuration review total; any plugin security-file review is recorded separately. The management database risk is `LOW — no selected database IOC` only if targeted SQL checks were executed without family residues or selected active markers. WordPress sessions are informational and are not by themselves an indicator of compromise.

A MetForm PHP return-array header and absence of a small set of known IOCs do not prove all 1.6 MB of cache data safe. Until verified against a trusted plugin implementation or a strict full-file parser, these caches remain `CACHE_PLUGIN_REQUER_VALIDACAO`.

## Guarded cache and Apache compatibility checks

The MetForm icon-cache recognizer accepts an expected generator comment followed by an `ABSPATH` exit guard and PHP `return array` header. This is still only `CACHE_PLUGIN_REQUER_VALIDACAO` and requires whole-file source verification; it never authorizes a clean status by itself. The Akismet `.htaccess` recognizer now supports nested `IfModule` blocks for Apache authorization compatibility while rejecting unknown directives, executable-extension grants and unscoped access grants. Unrecognized safe variations remain reviewable, rather than silently trusted.

MetForm cache recognition inspects only a bounded header for contextual classification; the separate full-file IOC scan still takes precedence. An apparent MetForm cache with a family indicator elsewhere in its contents must remain under investigation. Full source verification against the installed plugin generator is an outstanding prerequisite for trusted-cache classification.

## Recovery safeguards (0.4.0)

Post-recovery verification now evaluates actual active database marker states, known file IOCs and process indicators. Absent placeholders and ordinary WordPress session/application-password records do not by themselves fail the post-check. **Recovery remains experimental**: replacement ownership, upload preservation and exact-version sync must be proven in disposable tests before it is used on production sites. Do not infer that CI unit tests authorize recovery.

## 0.5.0 safety gate and generic scanning

The default read-only audit now recognizes a limited set of generic PHP webshell/obfuscation expressions and additional legacy script extensions. These are heuristic indicators requiring manual review. **All mutating modes are temporarily disabled** until end-to-end safety tests establish preservation of user uploads, Unix ownership, exact version synchronization and reliable rollback. No live recovery should be attempted with this build.

## Version 0.6.0: WordPress persistence and timeline

Full passive audits now write `wordpress-persistence.json`, an inventory of MU-plugins and selected drop-ins, including relative paths, hashes and byte sizes. They also write `timeline.json`, a 30-day metadata timeline based on filesystem mtime/ctime. The latter is **not a creation-time history**, and no script code is executed. Both sources are investigative context and do not imply compromise by presence alone. These inventories currently run with the default full audit and retain private-case permissions. Mutating modes are still disabled.

## Component version and provenance audit (0.7.0, experimental)

The default read-only audit inventories local WordPress Core, plugin and theme versions. `--offline` skips all external component-version requests but preserves local inventories. `--skip-version-check` skips this entire new component step and reports reduced coverage. `--official-compare` explicitly enables the default HTTPS comparison. New private case outputs are `component-version-evidence.json`, `component-version-report.md` and `component-version-report.csv`, using `CORE-001`, `PLUGIN-###` and `THEME-###` IDs. API failures are not interpreted as missing/unofficial components. The current implementation **does not yet correlate active plugins/themes with database options or verify plugin/theme package checksums**; treat provenance as preliminary, not cryptographic authenticity.

The version inventory also reads selected WordPress database option values (`active_plugins`, `template`, `stylesheet`) through the existing credential-protected read-only MySQL client. For official plugins, it optionally fetches small HTTPS checksum manifests for the *installed* version; executable packages are never fetched. A checksum mismatch is a review finding, not proof of malware. Plugin/Theme availability on WordPress.org cannot authenticate premium or custom code. The 0.7.0 feature remains pre-release until CI and disposable WordPress fixture testing passes.

WordPress Core version comparison also consults the official HTTPS version-check service; an outdated release is reported separately from checksum mismatches, which retain priority. Any API failure is reported as unavailable rather than as proof of a nonofficial component.

Officially listed plugins without a downloadable checksum manifest receive `PLUGIN_OFICIAL_SEM_CHECKSUM` when their installed version matches the official version. Missing manifests are not considered evidence of modification. The management report counts components flagged as premium/customized separately from unavailable API results.

All component-version evidence and generated report labels are in English. Read-only component results are supplementary and require validation on a disposable full WordPress test installation prior to production acceptance.

## 0.8.0 checksum hardening

Component-version scanning now streams file hashes in bounded 1 MiB blocks. It does not execute WordPress code or download executable packages, and refuses symlinks while hashing. Version inventory remains pre-release until full disposable WordPress scenario testing and explicit provenance/coverage acceptance are complete.

## 0.9.0 official plugin extra-file detection

When an official plugin checksum manifest is available, the component audit now reports executable files present in the plugin directory but absent from the manifest as `EXTRA_EXECUTABLE` evidence. These remain review findings, not malware confirmation. Plugins without an official manifest are not treated as infected merely because their origin cannot be verified.

## 0.10.0 manifest validation

Checksum verification requires usable file entries. A retrieved but empty or invalid checksum manifest is classified as unavailable, not a verified match. Audit remains passive and destructive recovery modes remain disabled.

## 0.11.0 official metadata API error classification

WordPress.org plugin/theme lookup HTTP 404 is recorded as `NOT_FOUND_OFFICIAL_REPOSITORY`; service errors and Core checksum errors remain `API_UNAVAILABLE`. These states never prove maliciousness or authenticate a premium/custom component.

## 0.12.0 coverage and provenance corrections

The technical Core coverage field now reflects `component-version-evidence.json`, and Core outdated counts are separate from plugin/theme counts. An officially unlisted plugin is recorded as `PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO`, not malware. Where the main plugin header has no readable version, the inventory preserves the version-unidentified condition rather than inventing a local release. `LEGITIMO_VALIDADO` for large PHP caches requires full trusted-source or structural verification; a plausible header alone is not enough.

## 0.13.0 verified artifact exceptions

A previously inspected MetForm cache artifact is allowlisted by its **full SHA-256 hash plus exact relative path**, not merely by a generator comment. The exception covers only that reviewed byte-identical file; any cache update produces a new digest and must be reviewed independently. This is local evidence-based classification, **not** certification by the MetForm publisher. Akismet configuration recognition allows deny-by-default legacy/modern Apache rules and static-asset-only `FilesMatch` exceptions. Broad grants are rejected.

The component management summary now separately counts plugins requiring source/version review (for example an unlisted Envato plugin or an unreadable Popup Maker version). These reviews do not, by themselves, assert malicious activity or change the audit exit code. A single previously inspected MetForm cache hash is the sole narrow exception; all changed bytes trigger renewed review.

## 0.14.0 terminal report display and review-aware status

After normal audit completion, `report.md` is printed on an interactive standard-output TTY and its case path is always shown. If stdout is redirected or piped, only the report path is printed, even with `--show-report`. `--no-show-report` takes priority over `--show-report`. The internal `technical-report.md` is never auto-displayed. Automation exit codes are unchanged: 0 no selected markers or unresolved reviews; 10 known residues; 20 independently confirmed compromise (reserved); 30 execution error; 40 incomplete audit or unresolved review. Non-malware Core update, configuration and provenance/version review findings now yield `REVISAO_NECESSARIA` with exit 40; this does not indicate confirmed compromise.

Akismet static-asset allowlists are checked for executable file extensions, without rejecting harmless filename substrings such as `refresh`.

The component detail report includes manual review guidance for plugins absent from WordPress.org and for unreadable local plugin versions. It explicitly states that a repository miss is not evidence of malware and recommends verifying vendor origin, license, package and hash with the site owner.

## 0.15.0 customer-facing evidence narrative

The management `report.md` now contains an individual finding for each relevant database indicator, file/configuration review and Core/plugin/theme component requiring action. Each finding explains its meaning, recorded state and available SHA-256 evidence without publishing database values, credentials or technical commands. The separate technical report remains restricted. The management report does **not** automatically certify an outage justification or identify an attacker: the service interruption decision must be supported by its own contemporaneous authorization and incident-response record.

## 0.16.0 forensic evidence and containment record

Completed audits write `evidence-manifest.json`, containing SHA-256 hashes and byte sizes of ordinary private case evidence files, and `incident-containment-record.md`, an explicit operator-completion template. The tool never invents the outage timeline, containment authorization or an attacker's identity. A local hash manifest alone is not a tamper-proof or independently attested chain of custody; secure external retention and signed provenance remain necessary for legal/forensic-grade evidence.

## 0.17.0 optional customer PDF

Use `--pdf-report` to generate `management-report.pdf` from the customer-facing `report.md`. Optional dependency: `python3 -m pip install reportlab` in an isolated environment. PDF generation uses no network requests, does not ingest `technical-report.md`, escapes report content before paragraph rendering and restricts generated PDF permissions to owner-only. Without `reportlab`, the CLI fails with an explicit error instead of silently substituting another document. Do not publish the technical case directory.

## 0.18.0 administrator metadata inventory

A normal read-only audit additionally creates `administrator-inventory.json`, listing administrator role candidates as account IDs, SHA-256 pseudonyms and registration dates. Real login names are not exported. `UNAVAILABLE` is recorded if the SQL query cannot run; this is not mistaken for zero administrators. This is an inventory heuristic, not evidence that any user is malicious. Multisite roles and super administrators require further validation.

## 0.19.0 evidence verification and restricted packaging

Use `python3 bin/wp-integrity-audit.py --verify-case /path/to/case` to recompute file SHA-256 and detect missing/modified or unlisted post-capture files (0 for match; 40 for differences). Use `--bundle-evidence` during an audit to create an owner-only `evidence-bundle.tar.gz` plus `evidence-bundle.sha256`; the restricted archive includes internal technical details and **must not be given directly to a customer**. The management report and optional management PDF remain the appropriate customer deliverables. A hash manifest is not independent timestamping, authentication or a cryptographic signature.

The existing `--compare OLD_CASE NEW_CASE` flow also compares Core/plugin/theme component state when both cases have component evidence. Management findings display a calibrated review-priority description; these labels indicate triage urgency, not independent proof of active malware or attribution.
