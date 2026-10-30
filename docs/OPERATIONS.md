# Operator Guide

## Safety classification

**Audit mode is not completely without side effects:** every invocation writes private reports, case directories, and lock files. Database audit modes also create full backups. Recovery options can cause site downtime or data loss.

## Preflight for an authorized assessment

1. Confirm authorization, target scope, and maintenance constraints.
2. Prefer offline or snapshotted copies and isolate any suspected compromised site.
3. Check free space, disk permissions, site paths, and installed commands.
4. Review the script and assess the limitations in `SECURITY_REVIEW.md`.
5. Ensure case artifacts reside outside document roots with access restricted to the incident-response team.
6. Verify restore procedures independently; a generated archive alone is not evidence of a usable recovery point.

## Usage example

```bash
sudo bash bin/wp-integrity-audit.sh --audit /var/www/example.com/public_html
```

Review the terminal output and private case reports. File matches require independent triage; a match inside a security plugin or historical data may not indicate an active infection.

## Database audits

`--audit-db` and `--audit-db-post` create a full database dump and filesystem archive before running SELECT checks. This can consume large storage capacity and produces highly sensitive artifacts. Do not transmit them in tickets or commit them to Git.

## Recovery modes — not approved for unattended production use

`--apply-files`, `--apply-db`, and `--recover` can change a live website. The current code has high-risk deletion and recovery-safety limitations. Stop and remediate those issues before using recovery modes in production.

### Post-assessment review

- Independently inspect suspicious files and SQL findings.
- Check WordPress core, plugin/theme provenance, scheduled tasks, external persistence, IAM/users, webserver/PHP services, and permissions.
- Rotate potentially compromised credentials through the approved change process.
- Handle case data as confidential forensic evidence; set retention and securely dispose of copies when authorized.

## Troubleshooting

- Missing `wp-config.php`: script exits even for file-only audit.
- Missing MySQL tools: current prerequisite gate exits before starting any mode.
- Insufficient space: script may fail prior to database operations.
- Existing lock: another instance may be active; inspect before taking action.
- Custom WordPress layouts or DB configuration expressions: existing parser may not support them.

## Known configuration debt

The present implementation hardcodes an incident directory under `/root`, a recovery lock with `wh01` naming, an optional local clean-core fallback, and a specific media path. These must be generalized before multi-customer deployment.
