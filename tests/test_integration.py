"""Synthetic MySQL and WordPress integration tests (opt in via WP_AUDIT_INTEGRATION).

These tests run only against an isolated CI database. Never point at production.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "wp_integrity_audit", Path(__file__).resolve().parents[1] / "bin" / "wp-integrity-audit.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


@unittest.skipUnless(os.getenv("WP_AUDIT_INTEGRATION") == "1", "Requires disposable MySQL fixture")
class MySQLFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.case = Path(cls.directory.name) / "evidence"
        cls.case.mkdir(mode=0o700)
        cls.config = {
            "host": os.getenv("WP_AUDIT_DB_HOST", "127.0.0.1"),
            "user": os.getenv("WP_AUDIT_DB_USER", "root"),
            "password": os.getenv("WP_AUDIT_DB_PASSWORD", "synthetic-test-password"),
        }
        cls.dbname = "wp_audit_fixture"
        cls.client_ctx = audit.database_client(cls.config, cls.case)
        cls.cnf = cls.client_ctx.__enter__()
        command = ["mysql", f"--defaults-extra-file={cls.cnf}", "-e"]
        subprocess.run(command + [f"CREATE DATABASE IF NOT EXISTS {cls.dbname}"], check=True)
        cls.query("""
            CREATE TABLE IF NOT EXISTS wp_options (
                option_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                option_name VARCHAR(191) NOT NULL UNIQUE,
                option_value LONGTEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wp_users (
                ID BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_login VARCHAR(191) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wp_usermeta (
                umeta_id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NOT NULL,
                meta_key VARCHAR(191), meta_value LONGTEXT
            );
            DELETE FROM wp_options;
            DELETE FROM wp_users;
            DELETE FROM wp_usermeta;
            INSERT INTO wp_options(option_name,option_value) VALUES
                ('active_plugins','a:1:{i:0;s:19:"legitimate/plugin.php";}'),
                ('cron','a:0:{}'),
                ('sc_fake','indicator'),
                ('malware_reference','cipher-feeder');
            INSERT INTO wp_users(user_login) VALUES ('admin_abcdef');
            INSERT INTO wp_usermeta(user_id,meta_key,meta_value) VALUES
                (1,'session_tokens','session'),(1,'wp_application_passwords','api');
        """)

    @classmethod
    def tearDownClass(cls):
        try:
            subprocess.run(["mysql", f"--defaults-extra-file={cls.cnf}", "-e",
                            f"DROP DATABASE IF EXISTS {cls.dbname}"], check=True)
        finally:
            cls.client_ctx.__exit__(None, None, None)
            cls.directory.cleanup()

    @classmethod
    def query(cls, sql):
        return audit.query_db(cls.cnf, cls.dbname, sql)

    def setUp(self):
        """Reset synthetic data before every test to make tests order-independent."""
        self.query("""
            DELETE FROM wp_options;
            DELETE FROM wp_users;
            DELETE FROM wp_usermeta;
            INSERT INTO wp_options(option_name, option_value) VALUES
              ('active_plugins','a:1:{i:0;s:21:"legitimate/plugin.php";}'),
              ('cron','a:0:{}'),
              ('sc_fake','indicator'),
              ('malware_reference','cipher-feeder');
            INSERT INTO wp_users(user_login) VALUES ('admin_abcdef');
            INSERT INTO wp_usermeta(user_id,meta_key,meta_value) VALUES
              (1,'session_tokens','session'), (1,'wp_application_passwords','api');
        """)

    def test_readonly_audit_detects_fixture(self):
        findings = audit.database_audit(self.cnf, self.dbname, "wp_", self.case)
        kinds = {item["kind"] for item in findings}
        self.assertIn("suspicious_users", kinds)
        self.assertIn("family_option", kinds)
        self.assertIn("marker_option", kinds)
        self.assertIn("session_rows", kinds)
        self.assertFalse((self.case / "database-before.sql").exists())

    def test_full_audit_distinguishes_residues_and_historical_cache(self):
        """Reproduce the reported two residues and non-executing history."""
        self.query("""
            INSERT INTO wp_options(option_name,option_value) VALUES
              ('sc_second','family marker'),
              ('SimplePluginLogger_plugin_info_before_update','trace-inspector-pad');
        """)
        result = audit.database_audit(self.cnf, self.dbname, "wp_", self.case)
        by_kind = {}
        for item in result:
            by_kind.setdefault(item["kind"], []).append(item)
        self.assertEqual(sum(x["state"] != "NOT_FOUND" for x in by_kind["family_option"]), 2)
        self.assertEqual(by_kind["historical_cache"][0]["state"], "HISTORICAL_REFERENCE")
        self.assertEqual(by_kind["cron_marker"][0]["state"], "NOT_FOUND")
        self.assertEqual(by_kind["active_plugins_marker"][0]["state"], "NOT_FOUND")
        self.assertEqual(by_kind["session_rows"][0]["length"], "1")
        audit.make_report(self.case, "audit", [], [], result)
        report = (self.case / "technical-report.md").read_text()
        self.assertIn("Auditoria do banco de dados: **EXECUTADA**", report)
        self.assertIn("Resíduos em opções e transientes: **2**", report)
        self.assertIn("isso não comprova execução ativa", report)

    def test_detailed_evidence_preserves_history_and_value_hashes(self):
        self.query("""
            INSERT INTO wp_options(option_name,option_value) VALUES
                ('SimplePluginLogger_plugin_info_before_update','trace-inspector-pad');
        """)
        rows = audit.database_audit(self.cnf, self.dbname, "wp_", self.case)
        history = next(x for x in rows if x["kind"] == "historical_cache")
        residue = next(x for x in rows if x["kind"] == "family_option")
        self.assertEqual(history["name"], "SimplePluginLogger_plugin_info_before_update")
        self.assertEqual(history["state"], "HISTORICAL_REFERENCE")
        self.assertEqual(history["safe_excerpt"], "[OMITTED_BY_POLICY]")
        self.assertEqual(residue["state"], "RESIDUO_FAMILIA_REQUER_LIMPEZA")
        self.assertEqual(len(residue["sha256"]), 64)
        self.assertEqual(residue["value_length_bytes"], len("indicator"))
        audit.make_report(self.case, "audit", [], [], rows, self.dbname, "wp_")
        report = (self.case / "technical-report.md").read_text()
        self.assertIn("wp_options", report)
        self.assertIn("wp_usermeta", report)
        self.assertIn("Resíduos da família investigada:", report)
        self.assertIn("Referências históricas:", report)
        self.assertIn("Legenda das classificações", report)
        self.assertIn("SHA-256 da ferramenta:", report)
        self.assertIn("Indicadores ativos no banco de dados:", report)

    def test_numeric_transient_excerpts_and_markdown_layout(self):
        """Only allowlisted scalar transient values are shown in reports."""
        self.query("""
            INSERT INTO wp_options(option_name,option_value) VALUES
              ('_transient_sc_spread_interval','1'),
              ('_transient_timeout_sc_spread_interval','1793545906'),
              ('sc_private_token','super-secret-value');
        """)
        evidence = audit.database_audit(self.cnf, self.dbname, "wp_", self.case)
        indexed = {item["name"]: item for item in evidence if item["kind"] == "family_option"}
        self.assertEqual(indexed["_transient_sc_spread_interval"]["safe_excerpt"], "1")
        self.assertEqual(indexed["_transient_timeout_sc_spread_interval"]["safe_excerpt"], "1793545906")
        self.assertEqual(indexed["_transient_sc_spread_interval"]["value_classification"],
                         "ESCALAR_TEXTO_NUMERO_NAO_CODIFICADO")
        self.assertEqual(indexed["sc_private_token"]["safe_excerpt"], "[OMITTED_BY_POLICY]")
        audit.make_report(self.case, "audit", [], [], evidence, self.dbname, "wp_")
        report = (self.case / "technical-report.md").read_text()
        self.assertIn("#### `_transient_sc_spread_interval`", report)
        self.assertIn("- Evidência sem dados sigilosos: `1`", report)
        self.assertIn("- Valor interpretado: `1`", report)
        self.assertIn("- Valor interpretado: `1793545906`", report)
        self.assertIn("O WordPress modifica o agendamento cron automaticamente", report)
        self.assertIn("Indicadores conhecidos no cron: 0", report)
        cron = next(x for x in evidence if x["kind"] == "cron_metadata")
        self.assertEqual(len(cron["sha256"]), 64)
        self.assertIn("collected_at_utc", cron)
        self.assertIn("### Detalhes das evidências", report)
        self.assertNotIn("super-secret-value", report)
        self.assertIn("|---|---|---|---|\n", report)

    def test_safe_cleanup_preserves_legitimate_options(self):
        audit.sql_cleanup(self.cnf, self.dbname, "wp_", self.case)
        values = dict(self.query(
            "SELECT option_name, option_value FROM wp_options WHERE option_name IN ('active_plugins','cron')"
        ))
        self.assertIn("active_plugins", values)
        self.assertIn("cron", values)
        self.assertEqual(self.query("SELECT COUNT(*) FROM wp_options WHERE option_name='sc_fake'"), [["0"]])
        self.assertEqual(self.query("SELECT COUNT(*) FROM wp_usermeta WHERE meta_key='session_tokens'"), [["0"]])

    def test_recovery_snapshot_contains_site_and_database(self):
        """Check archive/dump integrity using only the disposable CI database."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "wordpress"
            case = Path(directory) / "case"
            root.mkdir()
            case.mkdir(mode=0o700)
            (root / "wp-content").mkdir()
            (root / "wp-content" / "fixture.txt").write_text("synthetic file")
            audit.snapshot(root, case, self.cnf, self.dbname)
            self.assertTrue((case / "site-before.tar.gz").is_file())
            self.assertTrue((case / "database-before.sql").is_file())
            self.assertGreater((case / "database-before.sql").stat().st_size, 100)
            import tarfile
            with tarfile.open(case / "site-before.tar.gz") as archive:
                self.assertIn("site/wp-content/fixture.txt", archive.getnames())
            self.assertIn("wp_options", (case / "database-before.sql").read_text(errors="replace"))

    def test_database_dump_restores_into_disposable_database(self):
        """Verify a generated dump by restoring it into an isolated second DB.

        Never restore into the live fixture or a production database.
        """
        restore_db = "wp_audit_restore_fixture"
        command = ["mysql", f"--defaults-extra-file={self.cnf}"]
        try:
            subprocess.run(command + ["-e", f"CREATE DATABASE {restore_db}"], check=True)
            with tempfile.TemporaryDirectory() as directory:
                site = Path(directory) / "site"
                case = Path(directory) / "case"
                site.mkdir()
                case.mkdir()
                (site / "wp-content").mkdir()
                (site / "wp-content" / "proof.txt").write_text("synthetic restore test")
                audit.snapshot(site, case, self.cnf, self.dbname)
                with (case / "database-before.sql").open("rb") as dump:
                    subprocess.run(command + [restore_db], stdin=dump, check=True)
                with (case / "site-before.tar.gz").open("rb") as archive:
                    self.assertGreater(len(archive.read()), 100)
                rows = audit.query_db(self.cnf, restore_db,
                    "SELECT option_value FROM wp_options WHERE option_name='active_plugins';")
                self.assertEqual(rows, [['a:1:{i:0;s:21:"legitimate/plugin.php";}']])
                rows = audit.query_db(self.cnf, restore_db,
                    "SELECT COUNT(*) FROM wp_users WHERE user_login='admin_abcdef';")
                self.assertEqual(rows, [["1"]])
        finally:
            subprocess.run(command + ["-e", f"DROP DATABASE IF EXISTS {restore_db}"], check=True)

    def test_refuses_to_delete_malicious_serialized_option(self):
        self.query("UPDATE wp_options SET option_value='cipher-feeder' WHERE option_name='cron'")
        with self.assertRaises(audit.AuditError):
            audit.sql_cleanup(self.cnf, self.dbname, "wp_", self.case)
        self.assertEqual(self.query("SELECT option_value FROM wp_options WHERE option_name='cron'"),
                         [["cipher-feeder"]])


if __name__ == "__main__":
    unittest.main()
