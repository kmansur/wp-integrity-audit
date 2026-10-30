# Development Guidelines

- Write code, documentation, user-facing messages and comments in English; discuss design with users in Portuguese.
- Target Linux Debian/Ubuntu and Python 3.10 or later.
- Keep the default behavior read-only for the WordPress installation.
- Avoid shell command construction, PHP execution, and secrets on command lines.
- Apply restrictive evidence permissions and metadata-only external reporting.
- Treat findings as evidence requiring validation, never definitive proof of compromise or cleanliness.
- Use isolated fixtures for changes to recovery, database and filesystem operations.
- Maintain `README.md` and `CHANGELOG.md` for every functional change.
- Use SemVer for releases. Do not release recovery functionality without end-to-end disaster recovery tests.

## Checks

```bash
python3 -m compileall -q bin tests
python3 -m unittest discover -s tests -v
```

Document command output and limitations in pull requests. Do not expose client data in issue descriptions or test fixtures.
