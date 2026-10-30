# Bash-to-Python Migration Matrix

The `Python` branch is a fresh Python implementation of the original Bash CLI, not an automated syntactic translation.

| Legacy behavior | Python implementation | Notes |
|---|---|---|
| Argument parsing and `--version` | argparse, SemVer `0.1.0` | CLI help in English |
| Exclusive host lock | fcntl flock | Case-root scoped |
| IOC filenames and content | Python pathlib/os.walk/regex | Limited to known signatures |
| PHP files in uploads | Recursive file inspection | No PHP execution |
| Process indicators | `ps` subprocess | Fixed argument vector |
| File evidence and report | JSON + Markdown | External report metadata only |
| DB connection from wp-config.php | Literal define parser | Dynamic PHP values rejected |
| DB IOC inspection | MySQL batch SELECT | Audits do not dump entire databases |
| Full site backup | tarfile | Mutating modes only |
| Full DB backup | mysqldump | Mutating modes only |
| Component comparison | Python set inventory | Categorized by plugins and themes |
| Official WordPress sync | urllib + hardened ZIP extraction | HTTPS trusted domains; size/type limits |
| File staging/quarantine | shutil and same-filesystem rename | Interrupted failures may require restore |
| Suspicious user investigation | SQL user-login regex | No automatic user removal |
| Session/application password cleanup | Transactional SQL DELETE | Mutating modes only |
| Malicious serialized cron/plugin options | Fail-closed manual review | Destructive whole-option deletion intentionally not reproduced |
| WP core replacement | shutil.copytree/copy2 | Extraneous files not deleted |
| WP auth salts | Python secrets, atomic replace | Literal values only |
| Upload owner/perms | Metadata-only reporting | Legacy guessed recursive chown/chmod intentionally not reproduced |
| Elementor asset audit | File inventory | No client-specific video path |
| Management report | Markdown/JSON per case | Legacy global CSV not replicated to avoid exposure |

**Compatibility:** The six major CLI modes and their main intent are present. Some unsafe side effects were explicitly removed, and output formats/paths differ. This is a security-oriented functional migration, **not byte-for-byte equivalence**.

**Release gate:** Isolated unit tests alone cannot confirm a production-ready recovery workflow. Dedicated WordPress and MySQL/MariaDB fixture integration testing remains required.
