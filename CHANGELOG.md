# Changelog

All notable changes should be recorded here. Future releases should follow [Semantic Versioning](https://semver.org/) and [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Project README, architecture, operational guidance, security review, responsible disclosure guidance, and contributor guide.
- Expanded explanatory comments in the existing shell script, without intentionally changing behavior.

### Security
- Documented risks and limitations in the existing database cleanup, site/database backups, report sanitization, archive extraction, rollback, and environment-specific paths.
- No fixes to recovery behavior are claimed. Production recovery requires further hardening and testing.

## [Legacy baseline] - 2026-10-30

- Initial GitHub commit `88858aef8b279a574f2d785ab3d18d7e485933ba`.
- Existing script reports version `2026.10.28.18`. This is not a Semantic Versioning release.
