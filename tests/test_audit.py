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
            self.assertEqual(result.returncode, 40, result.stderr)
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

    def test_default_audit_fails_closed_without_database_configuration(self):
        """Missing SQL coverage must not be silently reported as zero."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            cases = Path(directory) / "cases"
            root.mkdir()
            for name in ("wp-admin", "wp-includes", "wp-content"):
                (root / name).mkdir()
            (root / "wp-load.php").write_text("<?php")
            (root / "wp-config.php").write_text("<?php")
            import subprocess
            result = subprocess.run(
                ["python3", str(SCRIPT), "--audit", str(root), "--case-root", str(cases)],
                capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported/nonliteral", result.stderr.lower())
            self.assertFalse(any(cases.rglob("database-evidence.json")))

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
            report = (case / "technical-report.md").read_text()
            self.assertIn(path, report)
            self.assertIn("NOT EXECUTED", report)
            self.assertIn("NOT EVALUATED", report)
            self.assertIn("Database dump: NOT PERFORMED", report)
            self.assertIn("File snapshot: NOT PERFORMED", report)
            self.assertNotIn("Database audit coverage:", report)
            self.assertIn("LIBERAÇÃO NÃO RECOMENDADA", report)
            self.assertNotIn("[LONG_VALUE_REDACTED]", report)

    def test_sensitive_path_substrings_only(self):
        path = "wp-content/uploads/" + "a" * 60 + "/192.168.1.10-password=test-secret.php"
        sanitized = audit.sanitize_relative_path(path)
        self.assertIn("a" * 60, sanitized)
        self.assertNotIn("192.168.1.10", sanitized)
        self.assertNotIn("test-secret", sanitized)

    def test_final_status_contract_and_json(self):
        """Residual family entries produce 10; unverified scope produces 40."""
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            db = [
                {"kind": "family_option", "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA",
                 "length": "1", "name": "_transient_sc_spread_interval"},
                {"kind": "historical_cache", "state": "HISTORICAL_REFERENCE",
                 "length": "60", "name": "SimplePluginLogger_plugin_info_before_update"},
                {"kind": "session_rows", "state": "PRESENT", "length": "1"},
            ]
            status, code, counts = audit.audit_status([], [], db)
            self.assertEqual((status, code), ("RESIDUOS_REQUEREM_LIMPEZA", 10))
            self.assertEqual(counts["confirmed_family_residues"], 1)
            self.assertEqual(counts["historical_references"], 1)
            self.assertEqual(counts["informational_records"], 1)
            self.assertEqual(audit.audit_status([], [], None)[:2], ("AUDITORIA_INCOMPLETA", 40))
            audit.make_report(case, "audit", [], [], db, "fixture_db", "wp_")
            import json
            document = json.loads((case / "report.json").read_text())
            self.assertEqual(document["status"], status)
            self.assertEqual(document["exit_code"], 10)
            self.assertTrue((case / "report.csv").exists())
            index = json.loads((case / "evidence-index.json").read_text())
            self.assertEqual(index["database"][0]["id"], "DB-001")
            self.assertEqual(index["database"][0]["table"], "wp_options")
            self.assertIn("Management Summary", (case / "report.md").read_text())

    def test_compare_cases_reports_added_removed_and_changed(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before, after, output = (root / name for name in ("before", "after", "out"))
            before.mkdir()
            after.mkdir()
            for directory, files, options in (
                (before, [{"path": "old.php", "sha256": "a" * 64},
                          {"path": "changed.php", "sha256": "a" * 64}],
                         [{"kind": "family_option", "name": "sc_old", "sha256": "1" * 64}]),
                (after, [{"path": "new.php", "sha256": "b" * 64},
                         {"path": "changed.php", "sha256": "b" * 64}],
                        [{"kind": "family_option", "name": "sc_new", "sha256": "2" * 64}]),
            ):
                (directory / "report.json").write_text(json.dumps({
                    "database": "fixture_db", "database_audited": True,
                    "status": "RESIDUOS_REQUEREM_LIMPEZA"}))
                (directory / "file-evidence.json").write_text(json.dumps(files))
                (directory / "database-evidence.json").write_text(json.dumps(options))
            with self.assertRaises(audit.AuditError):
                audit.compare_cases(before, after, before / "nested-output")
            result = audit.compare_cases(before, after, output)
            self.assertEqual(result["diff"]["files"]["added"], ["new.php"])
            self.assertEqual(result["diff"]["files"]["removed"], ["old.php"])
            self.assertEqual(result["diff"]["files"]["changed"], ["changed.php"])
            self.assertIn("family_option:sc_new", result["diff"]["database"]["added"])
            self.assertTrue((output / "comparison.md").is_file())
            self.assertTrue((output / "comparison.json").is_file())

    def test_compare_refuses_incomplete_database_cases(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            a, b = base / "a", base / "b"
            a.mkdir()
            b.mkdir()
            for p in (a, b):
                (p / "report.json").write_text(json.dumps({
                    "database": "fixture_db", "database_audited": False}))
            with self.assertRaises(audit.AuditError):
                audit.compare_cases(a, b, base / "out")

    def test_configuration_inventory_does_not_export_contents(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site = base / "site"
            case = base / "case"
            site.mkdir()
            case.mkdir()
            private = site / ".user.ini"
            private.write_text("auto_prepend_file=/private/secret-value.php")
            (site / "wp-content").mkdir()
            (site / "wp-content" / ".htaccess").write_text("Deny from all")
            evidence = audit.configuration_audit(site, case)
            self.assertEqual(len(evidence), 2)
            serialized = (case / "configuration-evidence.json").read_text()
            self.assertNotIn("secret-value", serialized)
            self.assertNotIn("auto_prepend_file=", serialized)
            self.assertEqual(len(evidence[0]["sha256"]), 64)
            self.assertIn("CONFIGURACAO_REQUER_VALIDACAO",
                          {x["classification"] for x in evidence})

    def test_hidden_directory_php_is_review_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            (root / "wp-content" / ".hidden-cache").mkdir(parents=True)
            case.mkdir()
            (root / "wp-content" / ".hidden-cache" / "test.php").write_text("<?php echo 'test';")
            results = audit.file_audit(root, case)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["classification"], "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO")

    def test_core_integrity_with_synthetic_manifest(self):
        import hashlib
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            (root / "wp-includes").mkdir(parents=True)
            case.mkdir()
            version = root / "wp-includes" / "version.php"
            version.write_text("<?php $wp_version = '6.8.2';")
            core = root / "wp-load.php"
            core.write_text("<?php /* synthetic */")
            digest = hashlib.md5(core.read_bytes()).hexdigest()
            manifest = {"checksums": {"wp-load.php": digest,
                                      "wp-admin/missing.php": "a" * 32,
                                      "wp-includes/version.php": "0" * 32,
                                      "wp-content/plugin.php": "0" * 32}}
            result = audit.core_integrity_audit(root, case, manifest)
            kinds = {x["classification"] for x in result["findings"]}
            self.assertIn("CORE_MODIFICADO_REQUER_REVISAO", kinds)
            self.assertIn("CORE_AUSENTE_REQUER_REVISAO", kinds)
            self.assertEqual(result["checked_files"], 2)
            self.assertEqual(result["version"], "6.8.2")
            self.assertTrue((case / "core-integrity.json").exists())

    def test_core_integrity_without_version_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            root.mkdir()
            case.mkdir()
            result = audit.core_integrity_audit(root, case)
            self.assertEqual(result["status"], "UNAVAILABLE")

    def test_host_inventory_rejects_arbitrary_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(audit.AuditError):
                audit.host_persistence_inventory(Path(directory), [Path(directory)])

    def test_core_discrepancy_marks_clean_case_incomplete(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            audit.write_private(case / "core-integrity.json", json.dumps({
                "status": "COMPLETE",
                "findings": [{"path": "wp-load.php",
                              "classification": "CORE_MODIFICADO_REQUER_REVISAO"}],
            }))
            audit.make_report(case, "audit", [], [], [], "fixture", "wp_")
            result = json.loads((case / "report.json").read_text())
            self.assertEqual(result["status"], "AUDITORIA_INCOMPLETA")
            self.assertEqual(result["exit_code"], 40)
            self.assertEqual(len(result["optional_probe_review"]), 1)

    def test_family_residues_keep_priority_over_core_discrepancy(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            audit.write_private(case / "core-integrity.json",
                                json.dumps({"status": "UNAVAILABLE", "findings": []}))
            audit.make_report(case, "audit", [], [],
                              [{"kind": "family_option", "name": "sc_test",
                                "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA", "length": "1"}],
                              "fixture", "wp_")
            result = json.loads((case / "report.json").read_text())
            self.assertEqual(result["exit_code"], 10)
            self.assertTrue(result["optional_probe_review"])

    def test_all_passive_checks_enabled_by_default(self):
        from unittest.mock import patch
        with patch("sys.argv", ["wp-integrity-audit.py", "/tmp/example-site"]):
            options = audit.parse_args()
        self.assertEqual(options.mode, "audit")
        for flag in ("skip_db", "skip_files", "skip_config", "skip_core",
                     "skip_host_persistence", "skip_processes", "skip_elementor"):
            self.assertFalse(getattr(options, flag))

    def test_skip_switches_are_explicit(self):
        from unittest.mock import patch
        with patch("sys.argv", ["wp-integrity-audit.py", "--skip-core",
                                 "--skip-host-persistence", "--skip-db",
                                 "/tmp/example-site"]):
            options = audit.parse_args()
        self.assertTrue(options.skip_core)
        self.assertTrue(options.skip_host_persistence)
        self.assertTrue(options.skip_db)

    def test_skipped_checks_keep_clean_case_incomplete(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            audit.make_report(case, "audit", [], [], [], "fixture", "wp_")
            audit.mark_incomplete_case(case, ["core", "database"])
            doc = json.loads((case / "report.json").read_text())
            self.assertEqual(doc["status"], "AUDITORIA_INCOMPLETA")
            self.assertEqual(doc["exit_code"], 40)
            self.assertEqual(doc["omitted_checks"], ["core", "database"])
            self.assertIn("## Omitted checks", (case / "report.md").read_text())

    def test_core_config_host_summary_and_domain_case_id(self):
        import json
        import csv
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory) / "mbengenharia.com-20261030T220303Z-538f44"
            case.mkdir()
            audit.write_private(case / "core-integrity.json", json.dumps({
                "status": "COMPLETE", "findings": [
                    {"path": "readme.html", "classification": "CORE_AUSENTE_REQUER_REVISAO"},
                    {"path": "wp-includes/version.php", "classification": "CORE_MODIFICADO_REQUER_REVISAO"}]}))
            audit.write_private(case / "configuration-evidence.json", json.dumps([
                {"path": ".htaccess", "classification": "CONFIGURACAO_REQUER_VALIDACAO", "sha256": "a" * 64}]))
            audit.write_private(case / "host-persistence.json", json.dumps([
                {"path": "/etc/apache2/conf.d/ordinary.conf", "classification": "INVENTARIADO_SEM_INDICADOR"},
                {"path": "/etc/cron.d/suspect", "classification": "HOST_INDICATOR_REQUIRES_INVESTIGATION"}]))
            audit.make_report(case, "audit", [], [], [], "fixture", "wp_")
            doc = json.loads((case / "report.json").read_text())
            self.assertEqual(doc["domain"], "mbengenharia.com")
            self.assertEqual(doc["case_id"], "20261030T220303Z-538f44")
            self.assertEqual(doc["configuration_review_count"], 1)
            self.assertEqual(doc["summary"]["security_configuration_review"], 1)
            self.assertEqual(doc["persistence_risk"], "REVIEW REQUIRED")
            self.assertEqual(doc["core_discrepancies"], 2)
            self.assertEqual(doc["status_detail"], "AUDITORIA_INCOMPLETA")
            self.assertEqual(doc["host_persistence_indicators"], 1)
            md = (case / "technical-report.md").read_text()
            self.assertIn("wp-includes/version.php", md)
            self.assertIn("CORE_MODIFICADO_REQUER_REVISAO", md)
            self.assertIn("| `.htaccess` |", md)
            self.assertNotIn("ordinary.conf", md)
            client_report = (case / "report.md").read_text()
            self.assertIn("Management Summary", client_report)
            self.assertNotIn("/etc/apache2", client_report)
            self.assertNotIn("wp-includes/version.php", client_report)
            self.assertIn("Core discrepancies", client_report)
            csv_rows = list(csv.reader((case / "report.csv").open()))
            self.assertEqual(csv_rows[0][:2], ["domain", "case_id"])
            self.assertEqual(csv_rows[1][:2], ["mbengenharia.com", "20261030T220303Z-538f44"])

    def test_configuration_directives_only_export_labels(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "site"
            case = Path(folder) / "case"
            root.mkdir()
            case.mkdir()
            (root / ".htaccess").write_text("AddHandler application/x-httpd-php .jpg\\n")
            (root / ".user.ini").write_text("memory_limit=256M\\n")
            result = audit.configuration_audit(root, case)
            by_name = {item["path"]: item for item in result}
            self.assertEqual(by_name[".htaccess"]["classification"], "CONFIGURACAO_REQUER_VALIDACAO")
            self.assertEqual(by_name[".user.ini"]["classification"], "CONFIGURACAO_INVENTARIADA_SEM_INDICADOR")
            evidence = (case / "configuration-evidence.json").read_text()
            self.assertIn("HANDLER_OVERRIDE", evidence)
            self.assertNotIn("application/x-httpd-php", evidence)

    def test_upload_guard_and_metform_cache_are_distinct(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "site"
            case = Path(folder) / "case"
            icons = site / "wp-content/uploads/metform/cache/icons"
            icons.mkdir(parents=True)
            case.mkdir()
            (icons / "index.php").write_bytes(b"<?php\n// Silence is golden.\n")
            (icons / "font-awesome-38edd54e30815111.php").write_bytes(
                b"<?php return array('fa-home' => 'icon');")
            (icons / "other.php").write_bytes(b"<?php eval($_GET['x']);")
            records = {item["path"].rsplit("/", 1)[-1]: item
                       for item in audit.file_audit(site, case)}
            self.assertEqual(records["index.php"]["classification"], "LEGITIMO_VALIDADO")
            self.assertEqual(records["font-awesome-38edd54e30815111.php"]["classification"],
                             "CACHE_PLUGIN_REQUER_VALIDACAO")
            self.assertEqual(records["other.php"]["classification"],
                             "PHP_UPLOAD_REQUER_VALIDACAO")
            status, code, summary = audit.audit_status(list(records.values()), [], [])
            self.assertEqual(code, 40)
            self.assertEqual(summary["file_indicators_requiring_review"], 2)

    def test_akismet_guard_rejects_unscoped_grants(self):
        valid = '<FilesMatch "\.(css|js|png)$">\nRequire all granted\n</FilesMatch>\nRequire all denied\n'
        self.assertTrue(audit.akismet_access_guard(valid))
        self.assertFalse(audit.akismet_access_guard("Require all granted\nRequire all denied\n"))
        self.assertFalse(audit.akismet_access_guard(
            '<FilesMatch "\.(php|css)$">\nRequire all granted\n</FilesMatch>\nRequire all denied\n'))
        self.assertFalse(audit.akismet_access_guard(valid + "AddHandler application/x-httpd-php .png\n"))

    def test_akismet_config_count_not_double_counted(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            audit.write_private(case / "configuration-evidence.json", json.dumps([
                {"path": "wp-content/plugins/akismet/.htaccess", "classification": "LEGITIMO_VALIDADO",
                 "sha256": "a" * 64},
                {"path": ".htaccess", "classification": "CONFIGURACAO_REQUER_VALIDACAO",
                 "sha256": "b" * 64}]))
            audit.make_report(case, "audit", [], [], [], "fixture", "wp_")
            result = json.loads((case / "report.json").read_text())
            self.assertEqual(result["configuration_review_count"], 1)
            self.assertEqual(result["summary"]["security_configuration_review"], 1)
            self.assertIn("LOW — no selected database IOC", (case / "report.md").read_text())

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
