# Python Operator Handbook

## Integração de cron/persistência (0.41.1)

`--sc-host-root` integra o inventário seguro ao caso principal. Informe somente caminhos autorizados; a cobertura e os indicadores aparecem no relatório, e qualquer achado exige revisão. A ferramenta não altera crontab, systemd, Apache ou PHP-FPM.

## Auto-verificação e cron (0.41.0)

`--self-check` valida apenas a instalação do auditor e retorna 40 se houver dependência ausente. `bin/sc403_host.py` recebe raízes explicitamente autorizadas para inventário de cron e persistência. O código lê arquivos como dados não confiáveis, registra hash e marcadores e decodifica Base64 sem executar o resultado. Não use essa função como autorização para remover tarefas; qualquer alteração deve seguir o plano aprovado e preservar rollback.

## Monitoramento ampliado (0.40.1)

O comparador também verifica mudanças nos arquivos opcionais de reconstrução, linha do tempo, exposição lateral, SHM, persistência e processos. Ele registra somente metadados e hashes; valores de banco, payloads, tokens e conteúdo bruto permanecem fora da saída. Qualquer alteração exige revisão humana e não autoriza reativação.

## Monitoramento comparativo (0.40.0)

Use `bin/sc403_monitor.py` com dois casos íntegros e privados. O monitoramento reutiliza a validação de manifesto e ABSPATH, não executa PHP e não modifica os casos. Código de saída 40 indica novos indicadores, mudanças de hash ou cobertura incompleta; código 0 significa somente que não houve mudança nos indicadores comparados, nunca que o site está liberado.

Não agende o comando automaticamente sem autorização operacional. Para integração com Zabbix, consuma o JSON estável e mantenha o diretório de casos com permissões restritas. Compare os eventos com logs e aprovações de mudança, pois hashes podem mudar legitimamente.

## Homologação sintética (0.39.0)

`python3 bin/sc403_homologacao.py` executa somente uma fixture temporária criada pelo próprio teste. O código não acessa WordPress real, não conecta a banco, não executa PHP, não reinicia serviço e verifica que o hash do artefato permanece igual. O resultado `APROVADA_COM_BLOQUEIOS` significa que as barreiras sintéticas funcionaram; não significa que a recuperação foi homologada para produção nem que um site está limpo.

## Coordenador de recuperação (0.38.0)

O arquivo privado `sc403-recovery-plan.json` é um plano técnico não executável. Ele não encerra processos, não remove segmentos SHM, não altera cron, Apache, PHP-FPM, arquivos ou banco. O plano organiza as etapas em ordem, informa pré-condições e registra condições que exigem interrupção e revisão humana.

Não trate `execucao_automatica_autorizada: false` ou `liberacao_do_site_autorizada: false` como formalidade: ambas são barreiras deliberadas. Antes de qualquer remediação, valide backup restaurável em ambiente descartável, isolamento do domínio, escopo do usuário Unix, processos associados, diretivas de persistência, dump SQL e rollback. Exposição lateral e dumps SHM pendentes mantêm bloqueios específicos no plano.

## Auditoria de exposição lateral (0.37.0)

A opção `--sc-authorized-root` habilita uma coleta restrita de risco estrutural entre instalações WordPress. Informe apenas raízes previamente autorizadas e repita a opção para incluir mais de uma raiz. A coleta não percorre o servidor de forma irrestrita, não segue links simbólicos, não executa PHP, não testa escrita e não modifica Apache, PHP-FPM, cron, banco ou permissões.

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/site/html \
  --domain-label exemplo.com.br \
  --sc-authorized-root /usr/local/www/data/conta
```

O resultado privado `sc403-lateral-exposure.json` distingue instalações localizadas por marcadores WordPress, proprietário UID/GID, permissões dos diretórios sensíveis, `uploads` sem bloqueio de execução PHP confirmado, compartilhamento de UID entre instalações, processos associados por referência explícita ao caminho e pools PHP-FPM associados somente quando o caminho aparece no arquivo de configuração.

Compartilhar UID, possuir diretório gravável ou não localizar um pool associado não prova comprometimento. Riscos estruturais ou cobertura incompleta mantêm a auditoria em revisão e não autorizam liberação. A opção não substitui auditoria de banco, cron, Apache, PHP-FPM, processos, memória compartilhada ou logs.

## Read-only audit

### Estado de reconstrução SC (0.36.0)

As auditorias com banco executam uma consulta limitada para `sc_reins_*`, `sc_ini_fail`, `sc_ini_dead`, `sc_fetch_fails` e timestamps de recuperação. A análise é somente de metadados: valores não são alterados, desserializados nem executados. O resultado privado `sc403-reinfection-state.json` informa o dia UTC observado, a interpretação reconhecida, fatos, hipóteses e limitações.

Um contador do dia atual pode indicar backoff ou circuito de falha, mas não demonstra que uma reconstrução ocorreu. Um contador ausente também não prova ausência de persistência. Não remova opções `sc_*` com base apenas nesta evidência.

### Timestamps, padding e linha do tempo

`mtime % 100000 == 93819` e PHP com tamanho/padding incomum são sinais contextuais. O auditor registra esses sinais como revisão e preserva tamanho, hash e metadados, sem declarar malware por um único indício. `sc403-timeline.json` diferencia coleta, metadado de arquivo, estado SQL, processo e endpoint em log; quando não existe horário observável, o evento permanece sem data confiável.

```bash
python3 bin/wp-integrity-audit.py --audit /path/to/wordpress --case-root /secure/cases
python3 bin/wp-integrity-audit.py --audit-db /path/to/wordpress --case-root /secure/cases
```

Use authorized sites or offline forensic copies. Case files are created with restrictive permissions. A DB audit reads `wp-config.php` to obtain literal database configuration values; dynamic PHP configuration is rejected.

The 0.26.0 database audit also scans common WordPress text columns for complete Base64 candidates. Base64 and Base64/GZIP values are decoded only in memory and are never executed, unserialized or written in clear text to reports. Evidence contains only encoding type, sizes, SHA-256 values and known marker names. `--remove-confirmed-encoded-db-payload` is an explicit recovery selector and removes only encoded options whose decoded content contains confirmed incident markers; candidates without markers require a separately reviewed `--remove-db-option` selection.

## File and database recovery

Recovery is a development feature and must only be exercised on disposable WordPress fixtures until end-to-end tests exist. Provide an independent, tested backup before running. The tool creates its own archive and SQL dump, but **these have not been proven restorable**. Quarantine paths are outside the document root and recorded in the private case folder. Successful recovery requires a post-operation file/process/DB scan, though this is not proof of a clean site. Reopening an incident site requires operator review of process persistence, users, permissions, plugin provenance, core integrity, and external credentials.

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

## Default database coverage

`--audit` now combines filesystem, process and MySQL checks. The operator must have a valid readable WordPress `wp-config.php` with literal DB constants and a reachable MySQL/MariaDB server. Database connection errors fail the audit. Use `--audit --files-only TARGET` to intentionally omit the database; the report explicitly identifies this omission. No full database export is performed during these audits.

The result should be interpreted from the live case evidence, never copied from a previous incident. Historical references in plugin caches are reported separately from active indicators. Files identified as plugin guard patterns are not cryptographically verified, and may still require independent package integrity checks.

## Detailed SQL evidence handling

The summary includes the literal DB name and physical `options` and `usermeta` table identifiers. Option names are not considered passwords and are preserved. Candidate options include full-value SHA-256 digests and byte lengths; these are generated by MySQL without copying complete raw values into the report. Encoding classification is bounded and never unserializes PHP or evaluates code. The only textual excerpts eligible for inclusion in report files are recognized IOC marker names. Full unmasked and decoded excerpts are excluded by policy, because the legacy Shell approach could disclose credentials. If deeper manual interpretation is required, inspect the source database in a restricted incident-response session instead of exporting it to a client report.

## Numeric transient evidence

Full scalar values are included only for `_transient_sc_spread_interval` and `_transient_timeout_sc_spread_interval` when they are short decimal-digit strings and the complete original value length is verified. Every other option's raw value remains protected. SQL records appear under individual Markdown evidence subsections after the summary table.

## Exit codes and evidence coverage

`0` targeted checks complete with no explicit known markers; `10` family residue requiring remediation; `20` independently confirmed compromise, including a process matching the incident family's execution markers; `30` error; `40` incomplete evidence. Use the `status` and `exit_code` fields in `report.json`, and preserve the same case directory for all detailed evidence. A non-zero detection result does not mean the audit failed. A result of 0 does not authorize reopening a WordPress installation.

## Evidence references and CSV

`evidence-index.json` maps case-local `FILE-###` and `DB-###` identifiers to relative file paths or physical SQL tables and columns. `report.csv` is a single-row aggregate suitable for an external collector; group by case directory because IDs restart on each run. The detailed SQL evidence remains in `database-evidence.json`.

## Read-only case comparison

Use `--compare OLD_CASE NEW_CASE --compare-output PATH` on two prior complete audit directories. Both must identify the same database; differences are based on relative file paths and option-name/kind pairs rather than run-local evidence IDs. The tool produces `comparison.md` and `comparison.json`, without contacting the production site. Changes in dynamic cron hashes require manual interpretation.

## Read-only WordPress configuration inventory

Every audit collects configuration file metadata within the target WordPress tree in `configuration-evidence.json`. This inventory omits raw contents, so a hash change requires contextual inspection. It does not extend to system-level Apache, PHP-FPM or cron persistence and is not a release approval.

## Optional Core and Linux probes

Run `--audit --check-core TARGET` for official checksum comparison. The tool obtains the version without executing PHP and currently uses the English-US checksum set. Localized distributions may have legitimate checksum differences; check `core-integrity.json` for `COMPLETE`, `INCOMPLETE`, or `UNAVAILABLE`. This does not verify themes, plugins, or every unexpected file outside the manifest.

Run `--audit --host-persistence TARGET` to record selected Linux configuration metadata in `host-persistence.json`. Contents are not exported. These options do not change files, reload configuration, execute WP-CLI, or restart services. Host-level collection is not exhaustive and should be reviewed separately during incident response.

## Optional probe exit-status precedence

Official Core mismatch or checksum retrieval failure is reported in `optional_probe_review`. If the primary targeted audit has no markers, the status becomes `AUDITORIA_INCOMPLETA` (40). Confirmed family residues continue to return `RESIDUOS_REQUEREM_LIMPEZA` (10), while also listing Core review issues. Check `report.json`, not only the shell exit status, before taking action.

## Full passive scan is the default (0.3.0)

`python3 bin/wp-integrity-audit.py /srv/www/wordpress` runs all passive checks implemented by the tool. Disable specific checks using `--skip-core`, `--skip-host-persistence`, `--skip-db`, `--skip-files`, `--skip-config`, `--skip-processes` and `--skip-elementor`. The legacy `--files-only` spelling remains an alias of `--skip-db`. Optional Core checks require outgoing HTTPS connectivity to api.wordpress.org. No PHP or WP-CLI invocation is performed. Recovery commands are explicit and separately confirmed; they never run as a side effect of an audit. An audit with skipped coverage is treated as incomplete unless confirmed residue already requires remediation.

## Interpreting supplementary audit evidence

The WordPress Core section in report.md shows each reference discrepancy, and the WordPress configuration section contains relative paths and hashes without configuration content. The external persistence section displays counts only; system paths and security product names remain in the private host-persistence.json. A recognized IOC is not necessarily proof of execution. The CSV includes separate domain and case_id fields; store case IDs alongside domain names to correlate executions.

## Report distribution boundaries

`report.md` is intended for managerial review; `technical-report.md`, `database-evidence.json`, `configuration-evidence.json`, and `host-persistence.json` are internal technical evidence and require restricted access. `report.json` and `report.csv` are machine-readable summaries. Check every file before distributing it to a client: field names and WordPress site names may still reveal contextual details. Host IOC matching is heuristic and classification `INVENTARIADO_SEM_INDICADOR` is not proof that a system component is trustworthy.

## Configuration and host triage semantics

`CONFIGURACAO_REQUER_VALIDACAO` is used for recognized handler, PHP setting, auto prepend/append, external rewrite or access-control directives; the evidence contains indicator category names, not directive values. Ordinary config files are `CONFIGURACAO_INVENTARIADA_SEM_INDICADOR`. Host inventory distinguishes `COMPONENTE_DE_SEGURANCA_CONHECIDO`, `INVENTARIADO_SEM_INDICADOR`, and `HOST_INDICATOR_REQUIRES_INVESTIGATION`. Known security-product naming is a contextual classification, not authenticity validation. Private host paths should never be distributed with the management report.

## MetForm cache review

`CACHE_PLUGIN_REQUER_VALIDACAO` is a preliminary classification: validate the local MetForm plugin source and entire cache file before claiming it is legitimate. This heuristic neither executes PHP nor evaluates the returned array. `index.php` uploads guard recognition requires exact source contents and excludes files containing extra code. Preserve any known malicious artifacts outside the served document root as internal evidence, and verify web-server aliases separately.

## Conservative Akismet and MetForm validation

Akismet .htaccess is accepted as a known guard only when the entire non-comment directive set is consistent with a deny-by-default rule and FilesMatch exceptions for static assets. Review any unusual directives manually. MetForm cache candidates remain a review finding even when their prefix resembles `return array`; do not treat missing common dangerous-function names as a full integrity check. A risk label `LOW — no selected database IOC` refers only to the selected implemented queries, not a complete database compromise exclusion.

## Guarded MetForm and Akismet variants

MetForm cache headers may contain a generator comment and `defined('ABSPATH') || exit;` before the return-array statement. This is a contextual cache candidate only; the full file and trusted generator must be verified before `LEGITIMO_VALIDADO` is appropriate. Akismet access rules may nest Apache legacy and modern authorization modules under `FilesMatch`. The validator rejects unknown grammar and broad executable-extension grants rather than treating them as automatically safe.

For MetForm candidates, first verify the installed plugin generator and the full-file content; a matching header alone is never release evidence. Known family indicators anywhere in scanned content override cache classification.

## Recovery release gate (0.4.0)

Do not operate `--apply-files`, `--apply-db`, or `--recover` on production until staging and rollback are homologated. Post-recovery blocker checks evaluate active database states and known file/process IOCs, not merely the presence of result objects. Explicitly verify the original `wp-content/uploads` media and WordPress ownership in a disposable fixture. Keep the existing site backups immutable before any recovery experiment.

## Mandatory recovery gate (0.5.0)

`--apply-files`, `--apply-db`, and `--recover` fail closed and perform no modification. Re-enable these only after disposable acceptance tests prove ownership and media preservation, source-version correctness, and rollback under injected failures. Default audit remains read-only for the target site and emits private case artifacts. Generic webshell signatures require operator confirmation and must not be treated as forensic proof.

## Recent changes and WordPress persistence

Use `timeline.json` to correlate recent filesystem changes with incident timestamps, remembering that Unix ctime reflects metadata changes and that adversaries may alter mtime. Check `wordpress-persistence.json` for MU-plugins and drop-ins requiring independent provenance validation. The default timeline window is 30 days. Preserve the private case directory and do not distribute internal paths without review.

## Component-version evidence

Run a normal `--audit` for local and official checks, use `--offline` to prevent network calls during component checks or `--skip-version-check` for explicitly reduced component coverage. Inspect `component-version-evidence.json` for individual query states, local headers, theme parent relationships and Core checksum discrepancies. API-unavailable means connectivity/response uncertainty, **not** an unofficial package. Avoid interpreting absent metadata or premium/customized code as malware. No components are downloaded or executed in audit mode.

Version inspection consults WordPress.org component metadata and official plugin checksum manifests over HTTPS with bounded reads. It does not download or execute plugin/theme packages. Child themes and components declaring vendor-managed Update URI are not silently treated as missing or malware. An official plugin MD5 checksum mismatch is flagged for manual investigation. Ensure the review is not treated as cryptographic proof of authenticity, and cross-check the active theme with read-only database metadata.

For Core reporting, the checksum manifest is requested for the installed version and locale, while the official version-check endpoint provides the latest advertised version. These are independent results; an outdated but checksum-matching Core and a modified Core are different states. A failure to reach either endpoint must not silently imply that WordPress is current.

A WordPress.org plugin listing and a checksum manifest are separate sources. A listed plugin can lack a checksum manifest for its installed version; report `PLUGIN_OFICIAL_SEM_CHECKSUM` rather than asserting modifications. Modified files require actual checksum differences. Premium/custom component totals are contextual inventory, not a malware count.

## Streamed hashes (0.8.0)

Official Core and plugin manifest comparisons and local main-file evidence use bounded streaming digests. Checksum mismatches still indicate review requirements, not confirmed malware. Neither file hashing nor the inventory traverses symlinked components by design.

## Unexpected plugin executables (0.9.0)

Review `checksum_findings` for `EXTRA_EXECUTABLE` results: they identify PHP-family files absent from an official plugin manifest for the installed version. Investigate plugin-specific generated code or custom extensions before deciding whether a finding is malicious. The auditor never removes the file.

Checksum results are considered verified only when at least one valid checksum entry was actually evaluated. An empty or malformed manifest cannot produce a successful component integrity claim. Check `verified_files` / `checksum_verified_files` counters alongside comparison states.

## Distinguishing repository absence from service outages

For official component metadata lookups, HTTP 404 represents a component not found in the queried endpoint. API 5xx and network failures are `API_UNAVAILABLE`. Core checksum 404 does not establish WordPress Core absence; it means the requested checksum data could not be obtained. Review evidence before attributing component origin.

## Coverage reconciliation (0.12.0)

Use the component evidence Core `verified_files` count and `coverage.core` field for actual checksum execution. A Core update being available does not itself indicate tampering or invalidate a checksum match. Plugin origin-unconfirmed and local-version-unidentified states require provenance review, not automatic malware determination. For Akismet and MetForm artifacts, verify complete content or trusted provenance before granting legitimacy exemptions.

## Reviewed-cache provenance

The `LEGITIMO_VALIDADO` exception for the identified MetForm font-awesome cache requires an exact match to a review-recorded SHA-256 and exact path. Never add cache hashes from a filename alone; validate candidate source and contents before curating a new digest. Hash mismatch returns the artifact to manual review. Akismet `.htaccess` validation recognizes legacy `Order Deny,Allow` and scoped static-asset grants without authorizing PHP access.

## Console management report (0.14.0)

The CLI prints the management-report path after audits. A TTY displays `report.md` between clear delimiters; redirected stdout never displays the document body. `--no-show-report` always suppresses the body, including when `--show-report` is also present. The technical report is private and is never printed automatically. Scripts should continue to consume case `report.json` and the process exit code. Pending non-malware Core, configuration, or component-origin reviews produce review status and exit 40 rather than success.

## Customer-facing incident evidence (0.15.0)

Review the management report before giving it to the customer. Each case item has an evidence identifier and a plain-English interpretation. Cross-reference the private evidence files for underlying material, and do not copy raw SQL values, credentials, or infrastructure details into the customer copy. Clearly distinguish forensic observations, historical residues and unverified component provenance from confirmed compromise. If website isolation was performed, attach the separately maintained containment decision, timestamp, decision owner, scope and justification; the audit alone cannot prove these facts.

## Case evidence manifest and containment documentation

Keep the generated case outside the WordPress document root, retain restricted permissions and copy the manifest and evidence to independent immutable storage under documented custody. The manifest excludes symlinked files and itself and provides per-file SHA-256 checksums. Record the operator, timestamp, legal authorization, scope and business impact in a separately approved containment record. Never substitute an automatically generated report for an actual outage decision or claim that hashes prove who made changes.

## Customer PDF delivery

Enable `--pdf-report` only when the local optional `reportlab` dependency is installed. Review the generated `management-report.pdf` visually before distribution, especially long evidence IDs and paths. The report is based on `report.md`, which is separate from the restricted technical report. Preserve the case SHA-256 manifest and never email the full evidence directory to an unauthenticated recipient.

## Administrator inventory

Review `administrator-inventory.json` in the restricted case folder. Correlate account IDs and registration metadata with approved account-management records. Login names are hashed; note that unsalted hashes of human-readable names can be guessable and must remain private. The inventory does not imply that a privileged user is malicious and does not cover all WordPress multisite privilege mechanisms.

## Verify and preserve a case

After capture, verify integrity with `--verify-case CASE_DIRECTORY`. It does not modify the source case, and it returns 40 if the evidence differs from the recorded manifest. Optionally produce a restricted bundle during the audit using `--bundle-evidence`, then transfer it to independently secured storage with a documented custody process. Compare its sidecar SHA-256 after transfer. Do not publish the bundle: it contains technical evidence that may disclose infrastructure context. The main findings' exit codes preserve known-residue precedence even when other reviews coexist.

## Cross-case component history and review priorities

Compare two complete audit cases using `--compare OLD_CASE NEW_CASE` and inspect `comparison.json`/`comparison.md` for added, removed and changed component-version states, where both cases include component metadata. Customer-facing review priorities communicate triage urgency, not an independently validated severity score or confirmation of malicious execution.

## Expanded passive host persistence checks

The auditor now inventories `/etc/profile.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/sudoers.d` and `/var/spool/cron` alongside existing cron, systemd, PHP and Apache configuration directories. Results remain metadata/IOC-based; absence of indicators does not prove an uncompromised host. Do not infer security trust from filenames alone.

## Handling PDF export failures

When `--pdf-report` fails (missing ReportLab or a renderer error), the CLI uses execution error code 30 and does not intentionally leave a partially published PDF. Inspect the restricted case `report.md` and its evidence before retrying. Do not treat a successful CLI run as visual validation of multipage layout; inspect output with an appropriate PDF viewer prior to external distribution.

## Explicit SMTP delivery (0.21.0)

Copy `config/smtp.example.cfg` to `/etc/wp-integrity-audit/smtp.cfg` and configure hostname, verified TLS mode, sender, username and an absolute password_file. Restrict both files to 0600 and secure the directory. Use `--email-to recipient@example.com --smtp-config /etc/wp-integrity-audit/smtp.cfg` during a normal read-only audit. This sends only `management-report.pdf`; it never attaches `technical-report.md` or the private case bundle. The receiver must be authorized before executing. A failed SMTP operation produces exit 30; always inspect `report.json` separately to determine the actual audit findings. Avoid configuring plaintext SMTP or putting authentication secrets into the .cfg itself.
## Auditoria de exposição lateral (0.37.0)

A opção `--sc-authorized-root` habilita uma coleta restrita de risco estrutural entre instalações WordPress. Informe apenas raízes previamente autorizadas e repita a opção para incluir mais de uma raiz. A coleta não percorre o servidor de forma irrestrita, não segue links simbólicos, não executa PHP, não testa escrita e não modifica Apache, PHP-FPM, cron, banco ou permissões.

```bash
python3 bin/wp-integrity-audit.py \
  /usr/local/www/data/site/html \
  --domain-label exemplo.com.br \
  --sc-authorized-root /usr/local/www/data/conta
```

O resultado privado `sc403-lateral-exposure.json` distingue:

- instalações localizadas por marcadores WordPress;
- proprietário UID/GID e permissões dos diretórios sensíveis;
- `uploads` sem bloqueio de execução PHP confirmado;
- compartilhamento de UID entre instalações;
- processos associados por referência explícita ao caminho;
- pools PHP-FPM associados somente quando o caminho aparece no arquivo de configuração.

Compartilhar UID, possuir diretório gravável ou não localizar um pool associado não prova comprometimento. Riscos estruturais ou cobertura incompleta mantêm a auditoria em revisão e não autorizam liberação. O relatório técnico preserva a distinção entre fatos observados e inferências; a opção não substitui auditoria de banco, cron, Apache, PHP-FPM, processos, memória compartilhada ou logs.
