"""Isolated regression tests for the Python CLI; no production data required."""
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "wp-integrity-audit.py"
spec = importlib.util.spec_from_file_location("wp_integrity_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PythonAuditTests(unittest.TestCase):
    def test_version_and_modules(self):
        self.assertRegex(audit.VERSION, r"^\d+\.\d+\.\d+$")
        self.assertTrue(callable(audit.file_audit))
        self.assertTrue(callable(audit.sql_cleanup))
        self.assertTrue(callable(audit.official_sync))

    def test_literal_config_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wp-config.php"
            path.write_text("""<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'test-fake-secret');
define('DB_HOST', 'localhost');
$table_prefix = 'wp_';
""")
            config, prefix = audit.parse_wordpress(path)
            self.assertEqual(config["DB_PASSWORD"], "test-fake-secret")
            self.assertEqual(prefix, "wp_")

    def test_reject_dynamic_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wp-config.php"
            path.write_text("<?php define('DB_PASSWORD', getenv('SECRET'));")
            with self.assertRaises(audit.AuditError):
                audit.parse_wordpress(path)

    def test_audit_finds_ioc_and_writes_private_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            root.mkdir()
            case.mkdir()
            (root / "sample.php").write_text("<?php /* SC_ADV_BEGIN */")
            findings = audit.file_audit(root, case)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["indicator"], "SC_ADV_BEGIN")
            self.assertEqual(stat.S_IMODE((case / "file-evidence.json").stat().st_mode), 0o600)

    def test_safe_zip_rejects_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as writer:
                writer.writestr("../escape.php", "<?php")
            with zipfile.ZipFile(archive) as reader:
                with self.assertRaises(audit.AuditError):
                    audit.safe_zip_extract(reader, Path(directory) / "output")

    def test_safe_zip_extracts_normal_file(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "ok.zip"
            with zipfile.ZipFile(archive, "w") as writer:
                writer.writestr("plugin/hello.php", "<?php")
            with zipfile.ZipFile(archive) as reader:
                audit.safe_zip_extract(reader, Path(directory) / "output")
            self.assertEqual((Path(directory) / "output/plugin/hello.php").read_text(), "<?php")

    def test_cli_audit_end_to_end(self):
        """Smoke-test the real CLI without DB or root privileges."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "example" / "public_html"
            case_root = Path(directory) / "cases"
            root.mkdir(parents=True)
            for folder in ("wp-admin", "wp-includes", "wp-content"):
                (root / folder).mkdir()
            (root / "wp-load.php").write_text("<?php")
            (root / "wp-config.php").write_text("<?php")
            (root / "wp-content" / "sample.php").write_text("<?php // cipher-feeder")
            import subprocess
            result = subprocess.run(
                ["python3", str(SCRIPT), "--audit", "--files-only", str(root), "--case-root", str(case_root)],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [p for p in case_root.iterdir() if p.is_dir()]
            self.assertEqual(len(cases), 1)
            self.assertTrue((cases[0] / "report.md").is_file())
            self.assertTrue((cases[0] / "file-evidence.json").is_file())
            self.assertFalse((cases[0] / "database-before.sql").exists())

    def test_full_file_scan_detects_tail_indicator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            case = Path(directory) / "case"
            root.mkdir()
            case.mkdir()
            (root / "long.php").write_text("X" * 350_000 + " sc_cron_guard")
            findings = audit.file_audit(root, case)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["indicator"], "sc_cron_guard")

    def test_reject_symlinks_in_clean_source(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "clean"
            site = base / "site"
            source.mkdir()
            site.mkdir()
            (source / "link").symlink_to("/etc/passwd")
            with self.assertRaises(audit.AuditError):
                audit.validate_source(source, site)

    def test_quarantine_is_outside_document_root(self):
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory) / "site"
            case = Path(directory) / "case"
            stage = Path(directory) / "stage"
            site.mkdir()
            case.mkdir()
            (site / "wp-content").mkdir()
            (site / "wp-content" / "old.txt").write_text("old")
            stage.mkdir()
            (stage / "new.txt").write_text("new")
            quarantine = audit.swap_files(site, stage, case)
            self.assertNotIn(site, quarantine.parents)
            self.assertTrue((quarantine / "old.txt").exists())
            self.assertTrue((site / "wp-content" / "new.txt").exists())

    def test_recovery_preflight_rejects_missing_salts(self):
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            (site / "wp-config.php").write_text("<?php")
            with self.assertRaises(audit.AuditError):
                audit.preflight_recovery_sources(site, None)

    def test_recovery_preflight_accepts_literal_salts(self):
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            keys = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                    "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
            (site / "wp-config.php").write_text(
                "<?php\n" + "".join("define('" + key + "', 'synthetic');\n" for key in keys)
            )
            audit.preflight_recovery_sources(site, None)

    def test_salt_rotation_preserves_other_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "wp-config.php"
            keys = ("AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                    "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT")
            config.write_text("<?php\n" + "".join(
                "define('" + key + "', 'old-secret');\n" for key in keys
            ) + "define('DB_NAME', 'example');\n")
            config.chmod(0o644)
            audit.rotate_salts(config)
            output = config.read_text()
            self.assertNotIn("old-secret", output)
            self.assertIn("define('DB_NAME', 'example');", output)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
            for key in keys:
                self.assertIn("define('" + key + "', '", output)

    def test_salt_rotation_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            real = Path(directory) / "actual.php"
            link = Path(directory) / "wp-config.php"
            real.write_text("<?php")
            link.symlink_to(real)
            with self.assertRaises(audit.AuditError):
                audit.rotate_salts(link)

    def test_stage_rejects_indicator_after_first_256kb(self):
        """Stage validation must not truncate scanning to the beginning."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            source = root / "source"
            case = root / "case"
            (target / "wp-content").mkdir(parents=True)
            source.mkdir()
            case.mkdir()
            (source / "late.php").write_text("x" * 350000 + " SC_ADV_BEGIN")
            with self.assertRaises(audit.AuditError):
                audit.stage_files(target, source, case, False, False)
            self.assertEqual(list(root.glob(".wp-content-stage-*")), [])

    def test_swap_failure_restores_original_content(self):
        """A missing stage must not leave wp-content absent."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site = base / "site"
            case = base / "case"
            site.mkdir()
            case.mkdir()
            (site / "wp-content").mkdir()
            (site / "wp-content" / "original.txt").write_text("unchanged")
            with self.assertRaises(OSError):
                audit.swap_files(site, base / "missing-stage", case)
            self.assertEqual((site / "wp-content" / "original.txt").read_text(), "unchanged")
            self.assertFalse(list(base.glob(".site.wp-content-quarantine-*")))

    def test_case_files_not_written_with_public_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            case = audit.ensure_private_dir(base / "cases")
            audit.write_private(case / "evidence.txt", "synthetic private report")
            self.assertEqual(stat.S_IMODE(case.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((case / "evidence.txt").stat().st_mode), 0o600)

    def test_guard_classification_and_relative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "site"
            case = Path(directory) / "case"
            case.mkdir()
            paths = {
                "wp-content/uploads/sucuri/index.php": "<?php exit(0); // datastore=",
                "wp-content/uploads/simple-history-logs-example/index.php": "<?php // Silence is golden",
                "wp-content/uploads/wpforms/cache/index.php": "<?php // 404 Not Found",
                "wp-content/wflogs/config-synced.php": "<?php // trace-inspector-pad historical reference",
            }
            for name, content in paths.items():
                p = target / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            results = {item["path"]: item for item in audit.file_audit(target, case)}
            for name in list(paths)[:3]:
                self.assertEqual(results[name]["classification"], "LEGITIMO_VALIDADO")
            wordfence = results["wp-content/wflogs/config-synced.php"]
            self.assertEqual(wordfence["classification"], "CONFIGURACAO_PLUGIN_SEGURANCA_REQUER_VALIDACAO")
            self.assertEqual(wordfence["snippet"], "")

    def test_report_distinguishes_skipped_database_and_keeps_long_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            path = "wp-content/uploads/" + "x" * 60 + "/index.php"
            finding = {"path": path, "classification": "PHP_UPLOAD_REQUER_VALIDACAO", "sha256": "a" * 64}
            audit.make_report(case, "audit", [finding], [], None)
            report = (case / "report.md").read_text()
            self.assertIn(path, report)
            self.assertIn("NOT EXECUTED", report)
            self.assertIn("NOT EVALUATED", report)
            self.assertNotIn("[LONG_VALUE_REDACTED]", report)

    def test_sensitive_path_substrings_only(self):
        path = "wp-content/uploads/" + "a" * 60 + "/192.168.1.10-password=test-secret.php"
        sanitized = audit.sanitize_relative_path(path)
        self.assertIn("a" * 60, sanitized)
        self.assertNotIn("192.168.1.10", sanitized)
        self.assertNotIn("test-secret", sanitized)

    def test_secret_redaction(self):
        self.assertNotIn("example-secret", audit.redact("password=example-secret"))
        self.assertNotIn("192.168.1.20", audit.redact("192.168.1.20"))

    def test_rollback_when_second_rename_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            root.mkdir()
            (root / "wp-content").mkdir()
            case = Path(directory) / "case"
            case.mkdir()
            with self.assertRaises(OSError):
                audit.swap_files(root, Path(directory) / "nonexistent-stage", case)
            self.assertTrue((root / "wp-content").is_dir())


if __name__ == "__main__":
    unittest.main()
