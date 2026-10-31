# Histórico de alterações

O projeto utiliza versionamento semântico. As mensagens e a documentação destinadas ao operador e ao cliente devem ser produzidas em português do Brasil.

## [Não publicado]

## [0.21.2] - 2026-10-31

### Internacionalização (pt-BR)
- Tradução do assunto e do corpo dos e-mails enviados ao cliente.
- Tradução do título, da paginação e das mensagens de falha da exportação PDF.
- Tradução das mensagens de validação e falha de entrega SMTP.
- Tradução das opções de ajuda mais utilizadas e das principais mensagens de conclusão da auditoria.
- Tradução da política de segurança e dos comentários do arquivo de exemplo SMTP.
- Inclusão de instruções operacionais em português no início do README.
- Preservação de parâmetros de linha de comando, chaves SMTP e identificadores internos para evitar incompatibilidades.

### Pendente
- Revisão integral das demais mensagens do programa, conteúdo de relatórios e documentação histórica ainda em inglês, com testes de regressão e validação visual do PDF.


## [0.21.1] - 2026-10-31

### Changed
- Document the existing default evidence directory `/var/lib/wp-integrity-audit/cases` and retain optional `--case-root` overrides.
- Resolve SMTP configuration from `/etc/wp-integrity-audit/config.cfg` when `--email-to` is supplied, without requiring an additional configuration argument.
- Add `--config` as the preferred override and retain `--smtp-config` as a backward-compatible alias.
- Keep SMTP delivery strictly opt-in and preserve existing private-file permissions and verified TLS requirements.


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

### Configuration evidence inventory
- Audit WordPress-tree `.htaccess`, `.user.ini`, `php.ini`, `web.config` and related files without executing or revealing their contents.
- Write `configuration-evidence.json` with relative paths, byte sizes, permissions and hashes.
- Add regression test to prevent config-content credential exposure.

- Add heuristic review classification for PHP scripts in hidden WordPress directories, excluding `.well-known`; include a synthetic unit test.

### Optional integrity and persistence probes
- Add `--check-core` to compare selected installed WordPress Core files to the official checksum API; results written to `core-integrity.json`.
- Add opt-in `--host-persistence` metadata inventory of selected Linux cron, systemd, PHP and Apache configuration directories.
- Treat unavailable checksum data, missing core files, and non-English locale differences as review items, never as evidence of confirmed compromise.
- Restrict optional probes to read-only audit mode; add synthetic manifest and host-root validation tests.

### Optional probe status integrity
- Include incomplete/mismatching WordPress Core checksum results in `report.json` and the executive summary.
- Assign exit `40` for otherwise clean cases with unresolved Core discrepancies, without overriding confirmed family residues (exit `10`).
- Add regression tests for both status precedences.

## [0.3.0] - 2026-10-30

### Changed
- Run all implemented passive audit probes by default: WordPress files, configuration metadata, official Core checksum verification, host persistence metadata, Elementor, process indicators and database checks.
- Replace opt-in `--check-core` / `--host-persistence` CLI with opt-out `--skip-core` / `--skip-host-persistence`; add `--skip-files`, `--skip-config`, `--skip-processes`, `--skip-elementor`, and `--skip-db` (alias `--files-only`).
- Preserve explicitly selected recovery workflows and interactive approval; no mutation in the normal audit path.
- Track omitted scopes in reports and return exit 40 for otherwise clean but incomplete audits.
- Add CLI-default and omitted-coverage regression tests.

### Evidence-driven report reconciliation
- Add detailed Core discrepancy and WordPress configuration inventory sections to Markdown, including priority review for wp-includes/version.php.
- Expose Core, configuration and host-persistence counts in JSON and executive summary.
- Separate domain and case_id in CSV and JSON.
- Classify ordinary host configuration files as INVENTARIADO_SEM_INDICADOR rather than indiscriminately labeling them suspicious; flag only recognized IOC patterns for investigation.
- Keep detailed host paths in internal JSON and omit infrastructure names from the Markdown host summary; add regression coverage.

### Management reporting and host IOC triage
- Split management `report.md` from detailed internal `technical-report.md`.
- Summarize Core differences and configuration review counts in both outputs; preserve detailed evidence only in the technical report.
- Keep product-specific host inventory paths in internal `host-persistence.json`; avoid generic suspicion labels for ordinary host files.
- Highlight explicit host indicators in optional probe review without overriding confirmed database residue status.
- Extend report and CSV tests for per-domain case identifiers and sanitized management summaries.

- Align the pre-existing technical-report security-configuration counter with the actual configuration inventory total.

- Add regression assertions that management reporting excludes internal host and WordPress Core file paths.

### Evidence consistency and triage
- Reconcile the management and JSON security-configuration counters, avoiding a zero result when configuration findings exist.
- Record explicit persistence risk level with a caution that no known IOC does not prove absence of host persistence.
- Distinguish recognized BitNinja security-product inventory, unclassified host configuration and explicit indicators.
- Detect security-relevant configuration directive categories without disclosing values, URLs or credentials.
- Extend the evidence index with CORE-, CONFIG-, HOST- and PROC- identifiers, and expand regression tests.

- Fix literal backslash escaping in directive patterns to ensure real Apache/PHP configuration directives are detected.

- Add an additive `status_detail` field for simultaneous family residues and Core discrepancies, preserving stable primary status and exit code.

### MetForm false-positive triage
- Recognize exact WordPress `Silence is golden.` directory guards in uploads.
- Add restricted `CACHE_PLUGIN_REQUER_VALIDACAO` classification for a MetForm Font Awesome cache candidate when its path and PHP return-array header match.
- Keep potential cache findings in required-review counts and return-code precedence; no blanket uploads exemption.
- Add synthetic guard, cache and unrelated PHP regression cases.

### Akismet and SQL risk improvements
- Fix newline escapes in the exact-upload-guard fixture that caused the prior multi-Python unit-test failure.
- Recognize narrowly constrained Akismet deny-by-default .htaccess asset access rules, with rejection tests for broad PHP grants.
- Eliminate duplicate security-configuration counts between JSON and Markdown.
- Show scoped low database risk when completed targeted checks find no selected database IOC; WordPress session rows remain informational.
- Keep MetForm icon caches under review until their full contents and trusted generator are verified.

- Match the observed guarded MetForm cache header with a generator comment and `ABSPATH` guard, preserving manual-review status.
- Support nested `IfModule` blocks in strict Akismet `.htaccess` access-rule recognition.
- Add synthetic regression tests for guarded headers, nested blocks and unsafe grants.

- Strengthen MetForm regression coverage: a plausible generated-cache header containing a known IOC later in the file must retain IOC classification, never legitimate-cache status.

- Align the previous MetForm synthetic cache fixture with the supported guarded-header grammar.

## [0.4.0] - 2026-10-30

### Fixed
- Prevent absent database placeholders and informational session/application-password rows from falsely blocking post-recovery verification.
- Block post-recovery success when files contain `IOC_REQUER_VALIDACAO`, fixing an inconsistent string constant.
- Parse Akismet Apache module names containing dots, including `mod_authz_core.c`.
- Add clean and contaminated post-recovery blocker regression tests.

### Safety
- Recovery remains experimental and requires disposable-environment acceptance tests for file ownership, upload carry-over and exact-version official synchronization before production use.

## [0.5.0] - 2026-10-30

### Security
- Disable `--apply-files`, `--apply-db` and `--recover` until ownership, uploads preservation, exact package versions and rollback are verified end-to-end in disposable fixtures.
- Extend read-only file inspection to `.php5`, `.php7`, `.php8`, `.pht` and `.phps` and add generic obfuscated/dynamic webshell heuristics. These remain review heuristics, not proof of compromise.
- Add synthetic test of generic PHP5 detection and unchanged incomplete-audit exit-code semantics.

## [0.6.0] - 2026-10-30

### Added
- Inventory WordPress mu-plugins and selected top-level drop-ins without executing code (`wordpress-persistence.json`).
- Record a 30-day filesystem metadata timeline (`timeline.json`), showing mtime and ctime without treating ctime as creation time.
- Add isolated regression tests for these inventories.

### Fixed
- Update the existing generic webshell test to expect the correct review classification for `eval($_GET[...])`.

### Limitations
- Timeline and persistence inventory are contextual evidence; their mere presence does not prove malicious activity. Recovery modes remain disabled pending safety homologation.

## [0.7.0] - 2026-10-30

### Added
- Passive Core, plugin and theme header/version inventory by default, with explicit `--skip-version-check`, `--offline` and `--official-compare` flags.
- WordPress.org HTTPS API queries with timeouts, bounded responses and separate API unavailable/not-found statuses.
- Core checksum comparison, missing/modified official paths and extra PHP in core directories and root; no PHP execution or package download.
- Plugin and theme main-file hashes, child theme template information and local metadata.
- Component JSON, Markdown and CSV evidence with stable CORE/PLUGIN/THEME identifiers and separate coverage reporting.
- Synthetic tests for offline isolation, child themes, API unavailability and changed Core hashes.

### Known limitations
- Plugin active state and active theme are not yet linked to read-only database options.
- Official plugin/theme full-tree checksums and provenance validation of premium components are not yet implemented.
- Component version results are additional evidence; complete release semantics and report integration require CI and real WordPress fixture validation.

### Continued in 0.7.0
- Correlate plugin activation and active parent/child theme with read-only `active_plugins`, `template` and `stylesheet` options (without PHP evaluation or unserialization).
- Verify WordPress.org plugin manifest MD5 checksums at the installed plugin version, without downloading plugin code; classify changed files as requiring review.
- Propagate critical Core/plugin integrity differences into incomplete-review exit semantics.
- Expand component report columns to include parent themes, query outcomes and provenance.

- Compare the locally validated Core version with the advertised latest WordPress.org version, preserving checksum mismatch as the higher-priority state.
- Add regression coverage for outdated Core and checksum-review precedence.

- Distinguish an officially listed plugin whose checksum manifest is missing from a genuinely modified plugin (`PLUGIN_OFICIAL_SEM_CHECKSUM`).
- Display premium/custom plugin and theme totals in the management report.
- Add regression tests for current and outdated WordPress.org plugin versions and unavailable plugin checksum manifests.

- Standardize generated component-management report headings and labels in English.

## [0.8.0] - 2026-10-30

### Security and reliability
- Stream SHA-256 and MD5 checksum validation in fixed-size chunks instead of reading whole WordPress component files into memory.
- Explicitly reject symlink targets in file digest helpers.
- Add large synthetic file and symlink regression tests.
- Maintain read-only audit behavior and disabled destructive modes pending recovery safety validation.

## [0.9.0] - 2026-10-30

### Added
- Detect additional executable PHP files absent from a successfully retrieved official WordPress.org plugin checksum manifest.
- Preserve conservative `PLUGIN_COM_ARQUIVOS_MODIFICADOS` review classification rather than asserting malware.
- Regression-test an official manifest with an unexpected executable file.

### Limitations
- The new extra-file detection applies only where a trustworthy official plugin manifest is available. Theme file provenance and complete disposable-site acceptance remain outstanding.

## [0.10.0] - 2026-10-30

### Security and correctness
- Reject unusable WordPress Core checksum manifests with no valid file entries rather than incorrectly declaring a checksum match.
- Require at least one usable plugin checksum entry before declaring plugin checksum validation successful.
- Record the number of checksum entries actually evaluated.
- Add a regression test for a traversal-only Core manifest.

## [0.11.0] - 2026-10-30

### Fixed
- Differentiate HTTP 404 for official plugin/theme metadata (component not found) from HTTP 5xx/transport errors (API unavailable).
- A Core checksum HTTP 404 remains unavailable, not a plugin/theme absence result.
- Add mocked HTTP failure regression cases without external requests.

## [0.12.0] - 2026-10-30

### Fixed
- Use the actual component checksum coverage in the technical report instead of reporting the retired separate Core probe as `NOT EXECUTED`.
- Expose independent `core_outdated` count, preserving plugin/theme outdated counts.
- Flag officially unlisted plugins as origin-unconfirmed review, and plugins without a parseable local version as version-unidentified.
- Add synthetic regression coverage for an installed Core release with verified checksums and a newer upstream release.

### Security
- The generated MetForm icon-cache header and the Akismet plugin path are not by themselves cryptographic proof of safe content. Continue requiring strict review before marking large PHP caches legitimate.

### Reviewed false-positive evidence (0.13.0)
- Recognize one previously inspected MetForm Font Awesome cache only when its exact file path and full SHA-256 digest match the case-specific reviewed artifact; no blanket trust of generated caches.
- Support Akismet legacy `Order Deny,Allow` alongside modern authorization modules and tightly scoped static assets.
- Continue treating changed MetForm caches as requiring review, and reject unscoped Akismet grants.

- Add a management counter for plugins requiring provenance/version review, separate from confirmed malware and outdated-version counts.
- Extend regression coverage for an exact reviewed cache SHA-256 matching versus a modified digest.

## [0.14.0] - 2026-10-30

### Added
- Show `report.md` automatically on an interactive standard-output terminal after audit completion.
- Add `--show-report` and `--no-show-report`; explicit suppression has priority and redirected output never prints the report body.
- Print the management report path without exposing the internal technical report.

### Fixed
- Set `REVISAO_NECESSARIA` with exit code 40 when Core updates, component provenance/version reviews, or configuration reviews remain outstanding, without claiming malware.
- Use component Core verification coverage in the technical report, avoiding the retired legacy probe's `NOT EXECUTED` label.
- Align management release recommendation with actual exit status.

### Tests
- Cover TTY/non-TTY behavior, explicit suppression and unresolved-component exit semantics.

- Fix overly broad Akismet static-asset extension screening: `refresh` filenames were incorrectly rejected because they contain the suffix `sh`. Only executable file extensions are disallowed.

- Include explicit non-malware provenance-review guidance for plugins missing from WordPress.org and missing-version guidance for locally unreadable plugin headers in component Markdown and CSV evidence.

## [0.15.0] - 2026-10-30

### Added
- Itemized, customer-facing management-report evidence with individual case IDs, findings, classifications, human-readable meaning and SHA-256 references.
- Separate documented technical observations from an independently authorized containment decision and avoid claiming incident attribution or exact outage cause.
- Redact raw database payloads, credentials and internal command details from the client-facing section.
- Regression test for evidence IDs and prevention of raw SQL value disclosure.

### Limitations
- Reports show what current read-only probes observed; they cannot independently prove who initiated an outage or that malware executed.

## [0.16.0] - 2026-10-30

### Added
- SHA-256 forensic case manifest for each regular evidence file captured in the private case directory, with individual sizes and explicit provenance limitations.
- Separate, deliberately unfilled incident-containment record template documenting the information the incident owner must supply to justify taking a website offline.
- Symlink-safe manifest traversal and tests proving the template cannot invent an outage or its decision maker.

### Security
- Read-only WordPress inspection remains the default; mutating modes stay disabled.
- The manifest records hashes of evidence files at the time it is generated and does not, on its own, establish an authenticated chain of custody.

## [0.17.0] - 2026-10-30

### Added
- Optional `--pdf-report` export of the customer-facing `report.md` to `management-report.pdf` in the private case directory.
- Page-numbered local PDF rendering with escaped report content and private file permissions.
- PDF export depends on optional `reportlab`; no network calls or automatic installation are performed.
- Regression test that missing optional dependencies produce a controlled failure without touching technical-report content.

### Limitations
- PDF rendering requires separate document-visual QA for long, real incident reports; the Markdown remains the authoritative editable management report.

## [0.18.0] - 2026-10-30

### Added
- Read-only administrator role-candidate inventory using role metadata from WordPress users/usermeta, pseudonymized SHA-256 login names and registration metadata.
- Explicit `UNAVAILABLE` account-coverage state rather than false zero counts when the database query fails.
- Regression tests for account pseudonymization and unavailable coverage.

### Limitations
- The role test is a serialized-value substring heuristic and does not validate authorization, prove compromise or cover multisite super administrators. The results are kept in restricted JSON evidence, not the customer-facing report.

## [0.19.0] - 2026-10-30

### Added
- `--verify-case CASE`: read-only SHA-256 verification of evidence listed in `evidence-manifest.json`, identifying missing, modified and post-capture unlisted files.
- `--bundle-evidence`: explicitly package private case evidence into `evidence-bundle.tar.gz` with an accompanying SHA-256 sidecar. The bundle contains sensitive technical material and must not be sent directly to a customer.
- Regression tests for manifest tampering, bundle permissions, credential-file exclusion and status precedence.

### Fixed
- Preserve confirmed-residue status (exit 10) when Core or component integrity reviews coexist; record concurrent integrity concerns without suppressing the primary incident finding.

### Limitations
- The bundle and manifest are unsigned; independent immutable storage and approved custody logs are necessary for legal-grade chain of custody.

- Extend existing case-to-case comparisons with Core/plugin/theme version, source-state and main-file hash changes when both cases contain component evidence.
- Include a calibrated review-priority label for each customer-facing finding; such labels do not assert active compromise.
- Add regression tests for historical plugin-version changes and review-priority wording.

- Create restricted evidence bundles via a temporary private file and atomic rename, rejecting credentials before creating any archive.

- Expand passive Debian/Ubuntu persistence inventory to include `/etc/profile.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/sudoers.d` and `/var/spool/cron`.
- Eliminate automatic trusted-security-component classification based only on a `bitninja` substring in a filesystem path.

- Add a conditional real PDF smoke test that verifies PDF magic bytes and owner-only permissions when the optional ReportLab dependency is present.

## [0.20.0] - 2026-10-31

### Reliability
- Generate customer management PDFs in a private temporary file and atomically publish only after successful rendering and PDF header validation.
- Return the documented execution error code 30 for controlled PDF export errors rather than an uncaught traceback.
- Use a bounded five-byte signature read and remove partial temporary files on rendering failures.
- Add a regression test for missing management source and absence of partial PDFs.

### Operational limits
- PDF export remains optional and must be visually checked with real long incident reports before customer delivery.

## [0.21.0] - 2026-10-31

### Added
- Explicit `--email-to` and `--smtp-config` CLI switches to send only the customer management PDF after a read-only audit.
- External INI SMTP configuration with validated TLS (`starttls` or `ssl`) and a separate owner-only password file; credential values never belong in the repository.
- Non-secret sample `config/smtp.example.cfg`.
- Sender and recipient validation, safe email attachments, fail-closed TLS and controlled mail-delivery error handling.
- Regression tests for permissive SMTP file permissions and email header injection.

### Security
- Sending is always opt-in. SMTP errors return 30 and do not convert unresolved audit findings into success. An accepted SMTP submission does not guarantee mailbox delivery.

- Reject mail delivery options when running historical case comparison; email can only be triggered during an explicit audit.
