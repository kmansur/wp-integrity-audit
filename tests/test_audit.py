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
                ["python3", str(SCRIPT), "--audit", str(root), "--case-root", str(case_root)],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            cases = [p for p in case_root.iterdir() if p.is_dir()]
            self.assertEqual(len(cases), 1)
            self.assertTrue((cases[0] / "report.md").is_file())
            self.assertTrue((cases[0] / "file-evidence.json").is_file())
            self.assertFalse((cases[0] / "database-before.sql").exists())

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
