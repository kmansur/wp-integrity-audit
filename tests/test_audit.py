"""Isolated regression tests for the Python CLI; no production data required."""
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
import unittest.mock
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

    def test_plano_sql_rejeita_opcoes_criticas_e_nomes_inseguros(self):
        for nome in ("cron", "active_plugins", "siteurl", "home", "wp_user_roles",
                     "wp_capabilities", "opcao';DROP", "nome com espaço", "a" * 192):
            with self.subTest(nome=nome):
                with self.assertRaises(audit.AuditError):
                    audit.database_cleanup_plan("unused.cnf", "fixture", "wp_", [nome])
        with self.assertRaises(audit.AuditError):
            audit.database_cleanup_plan("unused.cnf", "fixture", "wp_", ["sc_fake", "sc_fake"])
        self.assertEqual(audit.database_cleanup_plan("unused.cnf", "fixture", "wp_", []), [])

    def test_fonte_de_recuperacao_nao_pode_abranger_site(self):
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            site = raiz / "site"
            site.mkdir()
            (site / "wp-content").mkdir()
            with self.assertRaises(audit.AuditError):
                audit.validate_source(raiz, site)
            with self.assertRaises(audit.AuditError):
                audit.validate_source(site / "wp-content", site)

    def test_fonte_de_recuperacao_rejeita_webshell_generica(self):
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            site = raiz / "site"
            limpa = raiz / "limpa"
            site.mkdir()
            limpa.mkdir()
            (limpa / "payload.php").write_bytes(b"<?php eval(base64_decode('aGVsbG8='));")
            with self.assertRaises(audit.AuditError):
                audit.validate_source(limpa, site)

    def test_fonte_de_recuperacao_rejeita_diretorio_de_indicador(self):
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            site = raiz / "site"
            fonte = raiz / "fonte"
            site.mkdir()
            (fonte / ".sc_exemplo").mkdir(parents=True)
            (fonte / ".sc_exemplo" / "arquivo.txt").write_text("texto", encoding="utf-8")
            with self.assertRaises(audit.AuditError):
                audit.validate_source(fonte, site)

    def test_stage_de_recuperacao_preserva_propriedade_e_bloqueia_escrita_publica(self):
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            site, fonte, caso = (raiz / s for s in ("site", "fonte", "caso"))
            (site / "wp-content/plugins").mkdir(parents=True)
            (site / "wp-content/themes").mkdir()
            (site / "wp-content/uploads").mkdir()
            (site / "wp-content/uploads/data.txt").write_text("original")
            for pasta_rel in ("plugins", "themes", "uploads"):
                (fonte / pasta_rel).mkdir(parents=True, exist_ok=True)
            (fonte / "uploads/data.txt").write_text("arquivo limpo")
            (fonte / "uploads/data.txt").chmod(0o600)
            (fonte / "uploads/novo.txt").write_text("arquivo novo")
            (fonte / "uploads/novo.txt").chmod(0o600)
            (site / "wp-content/uploads/data.txt").chmod(0o644)
            caso.mkdir()
            estagio = audit.stage_files(site, fonte, caso, True, False)
            try:
                arquivo = estagio / "uploads/data.txt"
                self.assertEqual(arquivo.read_text(), "arquivo limpo")
                self.assertEqual(arquivo.stat().st_uid, (site / "wp-content/uploads/data.txt").stat().st_uid)
                self.assertEqual(arquivo.stat().st_gid, (site / "wp-content/uploads/data.txt").stat().st_gid)
                self.assertFalse(arquivo.stat().st_mode & stat.S_IWOTH)
                self.assertEqual(stat.S_IMODE(arquivo.stat().st_mode), 0o644)
                novo = estagio / "uploads/novo.txt"
                self.assertEqual(stat.S_IMODE(novo.stat().st_mode), 0o644)
            finally:
                import shutil
                shutil.rmtree(estagio)

    def test_remediacao_cron_serializado_preserva_outros_hooks(self):
        import remediacao_serializada as rs
        evento = ("array", [(b"hash", ("array", [(b"schedule", False), (b"args", ("array", []))]))])
        anterior = ("array", [(1700000000, ("array", [(b"sc_cron_fetch", evento),
                                                       (b"woocommerce_hook", evento)])),
                               (b"version", 2)])
        origem = rs.serializar(anterior)
        novo, quantidade = rs.remover_hook_cron(origem, "sc_cron_fetch")
        self.assertEqual(quantidade, 1)
        verificado = rs.LeitorPHP(novo).completo()
        self.assertEqual([k for k, _ in verificado[1][0][1][1]], [b"woocommerce_hook"])
        self.assertIn(b"version", novo)
        self.assertEqual(rs.remover_hook_cron(novo, "sc_cron_fetch")[1], 0)

    def test_remediacao_plugin_reindexa_e_preserva_outros(self):
        import remediacao_serializada as rs
        origem = rs.serializar(("array", [(0, b"akismet/akismet.php"),
                                          (1, b"trace-inspector-pad/trace-inspector-pad.php"),
                                          (2, b"elementor/elementor.php")]))
        novo, quantidade = rs.desativar_plugin(origem, "trace-inspector-pad/trace-inspector-pad.php")
        self.assertEqual(quantidade, 1)
        self.assertEqual(rs.LeitorPHP(novo).completo(), ("array", [
            (0, b"akismet/akismet.php"), (1, b"elementor/elementor.php")]))

    def test_remediacao_serializada_rejeita_objetos_e_dados_invalidos(self):
        import remediacao_serializada as rs
        entradas = [b'O:4:"Test":0:{}', b'a:1:{i:0;s:2:"x";}', b's:3:"abc";trash']
        for entrada in entradas:
            with self.subTest(entrada=entrada):
                with self.assertRaises(rs.SerializacaoInsegura):
                    rs.LeitorPHP(entrada).completo()
        with self.assertRaises(rs.SerializacaoInsegura):
            rs.desativar_plugin(b"a:0:{}", "../teste.php")
        with self.assertRaises(rs.SerializacaoInsegura):
            rs.remover_hook_cron(b"a:0:{}", "hook;DELETE")

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
            self.assertIn("NÃO AVALIADO", report)
            self.assertIn("Cópia SQL do banco de dados: NÃO REALIZADA", report)
            self.assertIn("Cópia dos arquivos do site: NÃO REALIZADA", report)
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
            self.assertIn("Relatório Gerencial", (case / "report.md").read_text())

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
            self.assertIn("Relatório Gerencial", client_report)
            self.assertNotIn("/etc/apache2", client_report)
            self.assertNotIn("wp-includes/version.php", client_report)
            self.assertIn("Divergências do núcleo do WordPress que exigem revisão", client_report)
            with (case / "report.csv").open(newline="", encoding="utf-8") as arquivo_csv:
                csv_rows = list(csv.reader(arquivo_csv))
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
                b"<?php /* Generated by MetForm */ defined('ABSPATH') || exit; return array('fa-home' => 'icon');")
            (icons / "other.php").write_bytes(b"<?php eval($_GET['x']);")
            records = {item["path"].rsplit("/", 1)[-1]: item
                       for item in audit.file_audit(site, case)}
            self.assertEqual(records["index.php"]["classification"], "LEGITIMO_VALIDADO")
            self.assertEqual(records["font-awesome-38edd54e30815111.php"]["classification"],
                             "CACHE_PLUGIN_REQUER_VALIDACAO")
            self.assertEqual(records["other.php"]["classification"],
                             "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW")
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
            self.assertIn("BAIXO — nenhum indicador pesquisado encontrado no banco de dados", (case / "report.md").read_text())

    def test_metform_guarded_header_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "site"
            case = Path(folder) / "case"
            icons = site / "wp-content/uploads/metform/cache/icons"
            icons.mkdir(parents=True)
            case.mkdir()
            valid = icons / "font-awesome-38edd54e30815111.php"
            valid.write_text("<?php\n/* Generated by MetForm */\ndefined('ABSPATH') || exit;\nreturn array ('fa-home' => 'icon');\n")
            records = audit.file_audit(site, case)
            self.assertEqual(records[0]["classification"], "CACHE_PLUGIN_REQUER_VALIDACAO")
            self.assertEqual(audit.audit_status(records, [], [])[1], 40)
            valid.write_text("<?php\n/* Generated by MetForm */\nreturn array ('fa-home' => 'icon');\n")
            self.assertFalse(audit.metform_icon_cache_candidate(
                "wp-content/uploads/metform/cache/icons/font-awesome-38edd54e30815111.php", valid))

    def test_akismet_nested_apache_blocks(self):
        valid = (
            "<IfModule mod_access_compat.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n"
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
            '<FilesMatch "\.(css|js)$">\n'
            "<IfModule mod_access_compat.c>\nAllow from all\n</IfModule>\n"
            "<IfModule mod_authz_core.c>\nRequire all granted\n</IfModule>\n"
            "</FilesMatch>\n")
        self.assertTrue(audit.akismet_access_guard(valid))
        self.assertFalse(audit.akismet_access_guard(valid + "Require all granted\n"))

    def test_metform_cache_header_never_certifies_malicious_tail(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "site"
            case = Path(folder) / "case"
            icons = site / "wp-content/uploads/metform/cache/icons"
            icons.mkdir(parents=True)
            case.mkdir()
            relative = "wp-content/uploads/metform/cache/icons/font-awesome-38edd54e30815111.php"
            cache = site / relative
            cache.write_bytes(
                b"<?php\n/* Generated by MetForm */\n"
                b"defined('ABSPATH') || exit;\nreturn array ('fa-home' => 'icon');\n"
                b"/* --sc-cli */\n")
            self.assertTrue(audit.metform_icon_cache_candidate(relative, cache))
            matches = audit.file_audit(site, case)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["classification"], "IOC_REQUER_VALIDACAO")
            self.assertEqual(audit.audit_status(matches, [], [])[1], 40)

    def test_post_recovery_blockers_clean_placeholders(self):
        clean = [
            {"kind": "family_option", "state": "NOT_FOUND"},
            {"kind": "marker_option", "state": "ABSENT"},
            {"kind": "session_rows", "state": "PRESENT", "length": "1"},
            {"kind": "application_password_rows", "state": "PRESENT", "length": "1"},
        ]
        self.assertEqual(audit.post_recovery_blockers(clean, [], []), [])
        dirty = clean + [{"kind": "family_option", "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA"}]
        self.assertIn("database:family_option", audit.post_recovery_blockers(dirty, [], []))
        self.assertIn("file_ioc", audit.post_recovery_blockers(
            clean, [{"classification": "IOC_REQUER_VALIDACAO"}], []))
        self.assertIn("process_ioc", audit.post_recovery_blockers(clean, [], ["test-process"]))

    def test_generic_webshell_patterns_and_legacy_php_extensions(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder) / "site"
            case = Path(folder) / "case"
            site.mkdir()
            case.mkdir()
            (site / "loader.php5").write_text("<?php eval(base64_decode('cGF5bG9hZA=='));")
            evidence = audit.file_audit(site, case)
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["classification"], "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW")
            self.assertEqual(audit.audit_status(evidence, [], [])[1], 40)

    def test_wordpress_persistence_inventory_and_recent_timeline(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            (root / "wp-content/mu-plugins").mkdir(parents=True)
            case.mkdir()
            (root / "wp-content/mu-plugins/audit.php").write_text("<?php")
            (root / "wp-content/object-cache.php").write_text("<?php")
            (root / "wp-content/regular.txt").write_text("example")
            records = audit.wordpress_persistence_inventory(root, case)
            self.assertEqual(len(records), 2)
            self.assertTrue(all(r["sha256"] for r in records))
            timeline = audit.recent_file_timeline(root, case)
            self.assertEqual(len(timeline), 3)
            content = json.loads((case / "timeline.json").read_text())
            self.assertIn("not creation time", content["timestamp_note"])

    def test_component_versions_offline_and_child_theme(self):
        import json
        import component_versions as cv
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "site"
            case = Path(directory) / "case"
            (root / "wp-includes").mkdir(parents=True)
            (root / "wp-content/plugins/akismet").mkdir(parents=True)
            (root / "wp-content/themes/parent").mkdir(parents=True)
            (root / "wp-content/themes/child").mkdir(parents=True)
            case.mkdir()
            (root / "wp-includes/version.php").write_text("<?php $wp_version = '6.8.3'; $wp_local_package = 'pt_BR';")
            (root / "wp-content/plugins/akismet/akismet.php").write_text("<?php\n/* Plugin Name: Akismet\nVersion: 5.7.2 */")
            (root / "wp-content/themes/parent/style.css").write_text("/* Theme Name: Parent\nVersion: 1.0 */")
            (root / "wp-content/themes/child/style.css").write_text("/* Theme Name: Child\nVersion: 2.0\nTemplate: parent */")
            with unittest.mock.patch.object(cv, "api_json", side_effect=AssertionError("Network access in offline mode")):
                result = cv.audit(root, case, offline=True)
            self.assertEqual(result["coverage"]["status"], "AUDITORIA_LOCAL_SEM_CONSULTA_OFICIAL")
            self.assertEqual(result["components"][0]["locale"], "pt_BR")
            self.assertEqual(next(x for x in result["components"] if x["slug"] == "child")["state"], "TEMA_FILHO_CUSTOMIZADO")
            self.assertEqual(result["summary"]["plugins_checked"], 1)
            self.assertEqual(len((case / "component-version-report.csv").read_text().splitlines()), 5)

    def test_cabecalho_popup_maker_nao_confunde_anotacao_php(self):
        import component_versions as cv
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            plugin = raiz / "wp-content/plugins/popup-maker"
            plugin.mkdir(parents=True)
            (plugin / "bootstrap.php").write_text("<?php // arquivo auxiliar", encoding="utf-8")
            (plugin / "popup-maker.php").write_text(
                "<?php\n/**\n * Plugin Name:       Popup Maker\n * Version:           1.25.0\n */\n"
                "/**\n * @param array{\n *     version: string,\n * } $dados\n */\n",
                encoding="utf-8")
            registro = cv.local_components(raiz, "plugin")[0]
            self.assertEqual(registro["local_version"], "1.25.0")
            self.assertEqual(registro["header_status"], "VALIDADO")
            self.assertEqual(registro["main_file"], "wp-content/plugins/popup-maker/popup-maker.php")
            with unittest.mock.patch.object(cv, "api_json", return_value=(
                    "SUCCESS", {"version": "1.25.0"}, "https://api.wordpress.org/plugins/info/1.2/")):
                cv.compare_official(registro)
            self.assertEqual(registro["state"], "PLUGIN_OFICIAL_ATUAL")
            self.assertEqual(registro["query_status"], "OFFICIAL_MATCH")

    def test_cabecalho_em_comentario_nao_aceita_versao_de_outro_bloco(self):
        import component_versions as cv
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            plugin = raiz / "wp-content/plugins/exemplo"
            plugin.mkdir(parents=True)
            (plugin / "exemplo.php").write_text(
                "<?php\n/* Plugin Name: Exemplo */\n/** Version: 9.9.9 */\n"
                "function exemplo() { return 'version: string,'; }\n", encoding="utf-8")
            registro = cv.local_components(raiz, "plugin")[0]
            self.assertIsNone(registro["local_version"])
            self.assertEqual(registro["header_status"], "VERSAO_AUSENTE")
            with unittest.mock.patch.object(cv, "api_json", return_value=(
                    "SUCCESS", {"version": "9.9.9"}, "https://api.wordpress.org/plugins/info/1.2/")):
                cv.compare_official(registro)
            self.assertEqual(registro["state"], "PLUGIN_VERSAO_NAO_IDENTIFICADA")
            self.assertEqual(registro["query_status"], "OFFICIAL_COMPONENT_FOUND_VERSION_UNVERIFIED")

    def test_secao_de_componentes_em_portugues(self):
        import json
        import component_versions as cv
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            (caso / "component-version-evidence.json").write_text(json.dumps({
                "coverage": {"status": "EXECUTED", "local": "EXECUTED",
                             "official": "EXECUTED", "core": "EXECUTED"},
                "summary": {"core_version": "7.1.3", "plugins_checked": 1,
                            "plugins_outdated": 0, "plugins_requiring_provenance_review": 0}
            }))
            (caso / "report.md").write_text("# Relatório gerencial\n")
            cv.append_management_section(caso)
            texto = (caso / "report.md").read_text()
            self.assertIn("## Versões e componentes", texto)
            self.assertIn("WordPress instalado: 7.1.3", texto)
            self.assertNotIn("Versions and components", texto)
            self.assertNotIn("Coverage status:", texto)

    def test_cron_informativo_nao_aparece_como_alerta_do_cliente(self):
        texto = "\n".join(audit.customer_findings(
            [], [{"evidence_id": "DB-009", "kind": "cron_metadata",
                  "name": "cron", "state": "INFORMATIONAL", "sha256": "a" * 64}],
            [], None))
        self.assertNotIn("DB-009 - Banco de dados", texto)
        self.assertIn("Nenhuma ocorrência individual", texto)

    def test_component_official_api_failure_is_not_absence(self):
        import component_versions as cv
        item = {"type": "plugin", "slug": "akismet", "local_version": "5.7.2",
                "official_version": None, "source": "unknown", "state": "PLUGIN_REQUER_REVISAO",
                "query_status": "SKIPPED"}
        with unittest.mock.patch.object(cv, "api_json", return_value=("API_UNAVAILABLE", None, "https://api.wordpress.org/")):
            cv.compare_official(item)
        self.assertEqual(item["query_status"], "API_UNAVAILABLE")
        self.assertEqual(item["state"], "PLUGIN_REQUER_REVISAO")

    def test_modified_core_checksum_is_review_only(self):
        import component_versions as cv
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wp-includes").mkdir()
            (root / "wp-admin").mkdir()
            (root / "wp-includes/version.php").write_text("<?php $wp_version = '6.8.3';")
            record = cv.local_core(root)
            with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"checksums": {"wp-includes/version.php": "0" * 32}}, "https://api.wordpress.org/")):
                cv.check_core(root, record, False)
            self.assertEqual(record["state"], "CORE_MODIFICADO_REQUER_REVISAO")

    def test_component_plugin_premium_and_custom_source_no_network(self):
        import component_versions as cv
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "wp-content/plugins/custom").mkdir(parents=True)
            (root / "wp-content/plugins/custom/custom.php").write_text(
                "<?php\n/* Plugin Name: Local Custom\nVersion: 1.2.3\nUpdate URI: https://vendor.example/plugin */")
            records = cv.local_components(root, "plugin", set())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["state"], "PLUGIN_PREMIUM_REQUER_FONTE_CONFIAVEL")
            self.assertFalse(records[0]["active"])

    def test_component_database_metadata_no_php_evaluation(self):
        with unittest.mock.patch.object(audit, "query_db", return_value=[
            ["active_plugins", '613a313a7b693a303b733a31373a22616b69736d65742f616b69736d65742e706870223b7d'],
            ["template", "706172656e74"],
            ["stylesheet", "6368696c64"]]):
            active, template, stylesheet = audit.component_db_metadata("config", "wordpress", "wp_")
        self.assertEqual(template, "parent")
        self.assertEqual(stylesheet, "child")
        self.assertIsInstance(active, set)

    def test_core_outdated_version_preserves_checksum_review(self):
        import component_versions as cv
        core = {"local_version": "6.7.1", "locale": "en_US",
                "state": "CORE_VALIDADO", "official_version": "6.7.1"}
        with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"offers": [{"current": "6.8.1"}]}, "https://api.wordpress.org/core/version-check/1.7/")):
            cv.check_core_latest(core)
        self.assertEqual(core["state"], "CORE_DESATUALIZADO")
        self.assertEqual(core["official_version"], "6.8.1")
        core["state"] = "CORE_MODIFICADO_REQUER_REVISAO"
        with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"offers": [{"current": "6.8.1"}]}, "https://api.wordpress.org/core/version-check/1.7/")):
            cv.check_core_latest(core)
        self.assertEqual(core["state"], "CORE_MODIFICADO_REQUER_REVISAO")

    def test_official_plugin_current_and_outdated_classifications(self):
        import component_versions as cv
        item = {"type": "plugin", "slug": "akismet", "local_version": "5.7.2",
                "official_version": None, "source": "unknown",
                "state": "PLUGIN_REQUER_REVISAO", "query_status": "SKIPPED"}
        with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"version": "5.7.2"}, "https://api.wordpress.org/plugins/info/1.2/")):
            cv.compare_official(item)
        self.assertEqual(item["state"], "PLUGIN_OFICIAL_ATUAL")
        self.assertEqual(item["query_status"], "OFFICIAL_MATCH")
        item["local_version"] = "5.7.1"
        with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"version": "5.7.2"}, "https://api.wordpress.org/plugins/info/1.2/")):
            cv.compare_official(item)
        self.assertEqual(item["state"], "PLUGIN_OFICIAL_DESATUALIZADO")

    def test_versao_local_maior_nao_e_correspondencia_oficial(self):
        import component_versions as cv
        item = {"type": "plugin", "slug": "exemplo", "local_version": "9.0.1",
                "official_version": None, "source": "unknown",
                "state": "PLUGIN_REQUER_REVISAO", "query_status": "SKIPPED"}
        with unittest.mock.patch.object(cv, "api_json", return_value=(
                "SUCCESS", {"version": "8.9.9"}, "https://api.wordpress.org/plugins/info/1.2/")):
            cv.compare_official(item)
        self.assertEqual(item["query_status"], "OFFICIAL_VERSION_DIFFERENT_UNVERIFIED")
        self.assertEqual(item["state"], "PLUGIN_REQUER_REVISAO")
        self.assertIn("procedência", item["review_guidance"])

    def test_official_plugin_without_checksum_not_assumed_modified(self):
        import component_versions as cv
        import urllib.error
        with tempfile.TemporaryDirectory() as folder:
            item = {"type": "plugin", "slug": "akismet", "local_version": "5.7.2",
                    "official_version": "5.7.2", "source": "wordpress.org",
                    "state": "PLUGIN_OFICIAL_ATUAL", "query_status": "OFFICIAL_MATCH"}
            error = urllib.error.HTTPError("https://downloads.wordpress.org/", 404, "Not found", {}, None)
            with unittest.mock.patch.object(cv.urllib.request, "urlopen", side_effect=error):
                cv.official_plugin_checksums(item, Path(folder))
            self.assertEqual(item["state"], "PLUGIN_OFICIAL_SEM_CHECKSUM")
            self.assertEqual(item["checksum_status"], "UNAVAILABLE")

    def test_component_checksum_streaming(self):
        import component_versions as cv
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "large.php"
            payload = b"safe-test-content" * 100000
            file.write_bytes(payload)
            self.assertEqual(cv.file_digest(file), hashlib.sha256(payload).hexdigest())
            self.assertEqual(cv.file_digest(file, "md5"), hashlib.md5(payload).hexdigest())
            link = Path(folder) / "linked.php"
            link.symlink_to(file)
            with self.assertRaises(OSError):
                cv.file_digest(link)

    def test_official_plugin_extra_php_requires_review(self):
        import component_versions as cv
        import hashlib
        import json
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            plugin = root / "wp-content/plugins/example"
            plugin.mkdir(parents=True)
            (plugin / "example.php").write_bytes(b"<?php // official")
            (plugin / "rogue.php").write_bytes(b"<?php // extra")
            expected = hashlib.md5((plugin / "example.php").read_bytes()).hexdigest()
            manifest = json.dumps({"files": {"example.php": expected}}).encode()
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def geturl(self): return "https://downloads.wordpress.org/plugin-checksums/example/1.0.json"
                def read(self, count): return manifest
            item = {"slug": "example", "local_version": "1.0", "state": "PLUGIN_OFICIAL_ATUAL"}
            with unittest.mock.patch.object(cv.urllib.request, "urlopen", return_value=Response()):
                cv.official_plugin_checksums(item, root)
            self.assertEqual(item["state"], "PLUGIN_COM_ARQUIVOS_MODIFICADOS")
            self.assertIn({"path": "rogue.php", "reason": "EXTRA_EXECUTABLE"}, item["checksum_findings"])

    def test_core_unusable_manifest_never_passes(self):
        import component_versions as cv
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"local_version": "6.8.3", "locale": "en_US",
                      "state": "CORE_CHECKSUM_INDISPONIVEL", "query_status": "SKIPPED"}
            with unittest.mock.patch.object(cv, "api_json", return_value=(
                    "SUCCESS", {"checksums": {"../outside": "0" * 32}},
                    "https://api.wordpress.org/core/checksums/1.0/")):
                cv.check_core(root, record, False)
            self.assertEqual(record["query_status"], "API_UNAVAILABLE")
            self.assertNotEqual(record["state"], "CORE_VALIDADO")

    def test_official_api_http_error_classification(self):
        import component_versions as cv
        import urllib.error
        cases = [
            ("/plugins/info/1.2/", 404, "NOT_FOUND_OFFICIAL_REPOSITORY"),
            ("/themes/info/1.2/", 404, "NOT_FOUND_OFFICIAL_REPOSITORY"),
            ("/plugins/info/1.2/", 503, "API_UNAVAILABLE"),
            ("/core/checksums/1.0/", 404, "API_UNAVAILABLE"),
        ]
        for endpoint, code, expected in cases:
            with self.subTest(endpoint=endpoint, code=code):
                error = urllib.error.HTTPError("https://api.wordpress.org", code, "failure", {}, None)
                with unittest.mock.patch.object(cv.urllib.request, "urlopen", side_effect=error):
                    state, data, url = cv.api_json(endpoint, {"action": "test"})
                self.assertEqual(state, expected)
                self.assertIsNone(data)
                self.assertTrue(url.startswith("https://api.wordpress.org/"))

    def test_component_core_coverage_and_outdated_summary(self):
        import component_versions as cv
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "site"
            case = Path(folder) / "case"
            (root / "wp-includes").mkdir(parents=True)
            (root / "wp-admin").mkdir()
            (root / "wp-content/plugins").mkdir(parents=True)
            (root / "wp-content/themes").mkdir()
            case.mkdir()
            version_file = root / "wp-includes/version.php"
            version_file.write_text("<?php $wp_version = '7.1.3';")
            digest = hashlib.md5(version_file.read_bytes()).hexdigest()
            def api(endpoint, params, **kwargs):
                if endpoint == "/core/checksums/1.0/":
                    return "SUCCESS", {"checksums": {"wp-includes/version.php": digest}}, "https://api.wordpress.org"
                if endpoint == "/core/version-check/1.7/":
                    return "SUCCESS", {"offers": [{"current": "7.1.4"}]}, "https://api.wordpress.org"
                raise AssertionError(endpoint)
            with unittest.mock.patch.object(cv, "api_json", side_effect=api):
                result = cv.audit(root, case)
            self.assertEqual(result["coverage"]["core"], "EXECUTED")
            self.assertEqual(result["summary"]["core_outdated"], 1)
            self.assertEqual(result["summary"]["plugins_outdated"], 0)
            self.assertEqual(result["components"][0]["state"], "CORE_DESATUALIZADO")

    def test_akismet_realistic_asset_allowlist(self):
        rules = (
            "<IfModule !mod_authz_core.c>\nOrder Deny,Allow\nDeny from all\n</IfModule>\n"
            "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n"
            '<FilesMatch "^(form\.js|akismet(-frontend|-admin)?\.js|akismet(-admin)?(-rtl)?\.css|inter\.css)$">\n'
            "<IfModule !mod_authz_core.c>\nAllow from all\n</IfModule>\n"
            "<IfModule mod_authz_core.c>\nRequire all granted\n</IfModule>\n"
            "</FilesMatch>\n"
            '<FilesMatch "^(logo-(a|full)-2x\.png|akismet-refresh-logo\.svg)$">\n'
            "<IfModule mod_authz_core.c>\nRequire all granted\n</IfModule>\n"
            "</FilesMatch>\n")
        self.assertTrue(audit.akismet_access_guard(rules))
        self.assertFalse(audit.akismet_access_guard(rules + "Require all granted\n"))

    def test_reviewed_metform_cache_is_hash_bound(self):
        relative = "wp-content/uploads/metform/cache/icons/font-awesome-38edd54e30815111.php"
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder) / "cache.php"
            cache.write_text("<?php return array();")
            self.assertFalse(audit.reviewed_metform_cache(relative, cache))
            with unittest.mock.patch.object(audit, "sha256", return_value=audit.REVIEWED_METFORM_CACHE_SHA256[relative]):
                self.assertTrue(audit.reviewed_metform_cache(relative, cache))
                self.assertFalse(audit.reviewed_metform_cache("wp-content/uploads/other/cache.php", cache))

    def test_reviewed_metform_cache_clears_file_review_on_exact_digest(self):
        relative = "wp-content/uploads/metform/cache/icons/font-awesome-38edd54e30815111.php"
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "site"
            case = Path(folder) / "case"
            file = target / relative
            file.parent.mkdir(parents=True)
            case.mkdir()
            file.write_text("<?php /* Generated by MetForm */ defined('ABSPATH') || exit; return array('fa-home' => 1);")
            expected = audit.REVIEWED_METFORM_CACHE_SHA256[relative]
            with unittest.mock.patch.object(audit, "sha256", return_value=expected):
                findings = audit.file_audit(target, case)
            self.assertEqual(findings[0]["classification"], "LEGITIMO_VALIDADO")
            self.assertEqual(audit.audit_status(findings, [], [])[1], 0)
            with unittest.mock.patch.object(audit, "sha256", return_value="0" * 64):
                findings = audit.file_audit(target, case)
            self.assertNotEqual(findings[0]["classification"], "LEGITIMO_VALIDADO")

    def test_management_report_tty_and_redirect_behavior(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / "report.md").write_text("# Public management report\n")
            output = io.StringIO()
            with unittest.mock.patch.object(audit.sys, "stdout", output):
                audit.present_management_report(case, tty=True)
            self.assertIn("--- start of report ---", output.getvalue())
            self.assertIn("# Public management report", output.getvalue())
            output = io.StringIO()
            with unittest.mock.patch.object(audit.sys, "stdout", output):
                audit.present_management_report(case, show=True, tty=False)
            self.assertIn("Management report:", output.getvalue())
            self.assertNotIn("# Public management report", output.getvalue())
            output = io.StringIO()
            with unittest.mock.patch.object(audit.sys, "stdout", output):
                audit.present_management_report(case, show=True, no_show=True, tty=True)
            self.assertNotIn("# Public management report", output.getvalue())

    def test_pending_component_review_triggers_exit_40(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "example-20261030T000000Z-abcdef"
            case.mkdir()
            (case / "component-version-evidence.json").write_text(json.dumps({
                "coverage": {"local": "EXECUTED", "official": "EXECUTED", "core": "EXECUTED"},
                "summary": {"core_outdated": 1},
                "components": [{"state": "PLUGIN_ORIGEM_NAO_CONFIRMADA_REQUER_REVISAO"}]
            }))
            audit.make_report(case, "audit", [], [], [])
            record = json.loads((case / "report.json").read_text())
            self.assertEqual(record["exit_code"], 40)
            self.assertEqual(record["status"], "REVISAO_NECESSARIA")
            self.assertIn("Verificação do núcleo: EXECUTADA", (case / "report.md").read_text())

    def test_customer_report_individual_evidence_is_redacted(self):
        findings = audit.customer_findings(
            [{"evidence_id": "FILE-001", "path": "wp-content/uploads/example.php",
              "classification": "PHP_UPLOAD_REQUER_VALIDACAO", "sha256": "a" * 64}],
            [{"evidence_id": "DB-001", "kind": "family_option", "name": "sc_test",
              "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA", "sha256": "b" * 64,
              "safe_excerpt": "do-not-show-secret"}],
            [{"evidence_id": "CONFIG-001", "path": ".htaccess",
              "classification": "CONFIGURACAO_REQUER_VALIDACAO"}],
            {"components": [{"component_id": "CORE-001", "slug": "wordpress",
                             "state": "CORE_DESATUALIZADO"}]})
        text = "\\n".join(findings)
        for identifier in ("FILE-001", "DB-001", "CONFIG-001", "CORE-001"):
            self.assertIn(identifier, text)
        self.assertNotIn("do-not-show-secret", text)
        self.assertIn("indisponibilidade do site", text.lower())

    def test_relatorio_separa_incidente_historico_manutencao_e_procedencia(self):
        entradas = [
            {"evidence_id": "DB-001", "kind": "family_option", "name": "sc_test",
             "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA", "sha256": "a" * 64},
            {"evidence_id": "DB-002", "kind": "historical_cache", "name": "cache_anterior",
             "state": "HISTORICAL_REFERENCE", "sha256": "b" * 64}
        ]
        componentes = {"components": [
            {"component_id": "CORE-001", "slug": "wordpress", "state": "CORE_DESATUALIZADO",
             "local_version": "7.1.3", "official_version": "7.1.4"},
            {"component_id": "PLUGIN-002", "slug": "outro", "state": "PLUGIN_REQUER_REVISAO",
             "local_version": "9.0.1", "official_version": "8.9.9"}
        ]}
        texto = "\n".join(audit.customer_findings([], entradas, [], componentes))
        self.assertIn("Natureza do achado: INDICADOR RESIDUAL DO INCIDENTE", texto)
        self.assertIn("Natureza do achado: REFERÊNCIA HISTÓRICA", texto)
        self.assertIn("Natureza do achado: MANUTENÇÃO / ATUALIZAÇÃO", texto)
        self.assertIn("Natureza do achado: PROCEDÊNCIA / VERSÃO NÃO CONFIRMADA", texto)
        self.assertIn("Versão instalada: 9.0.1; versão de referência: 8.9.9", texto)
        self.assertIn("não comprova comprometimento", texto)
        self.assertNotIn("password=", texto)

    def test_relatorio_cron_informativo_continua_fora_dos_alertas(self):
        entrada = [{"evidence_id": "DB-009", "name": "cron", "kind": "cron_metadata",
                    "state": "INFORMATIONAL", "sha256": "c" * 64}]
        texto = "\n".join(audit.customer_findings([], entrada, [], None))
        self.assertNotIn("DB-009 - Banco de dados", texto)
        self.assertIn("Nenhuma ocorrência individual", texto)

    def test_customer_configuration_priority_in_portuguese(self):
        texto = "\n".join(audit.customer_findings(
            [], [], [{"evidence_id": "CONFIG-001", "path": ".htaccess",
                       "classification": "CONFIGURACAO_REQUER_VALIDACAO"}], None))
        self.assertIn("MÉDIA — item executável ou divergência", texto)
        self.assertIn("Configuração", texto)
        self.assertIn("Sobre a indisponibilidade do site", texto)
        self.assertNotIn("Review priority:", texto)
        self.assertNotIn("service interruption", texto)

    def test_structured_persistence_risk_is_not_localized(self):
        self.assertEqual(audit.traduzir_estado("REVIEW REQUIRED"), "REVISÃO NECESSÁRIA")
        self.assertEqual(audit.traduzir_estado("NOT DETERMINED"), "NÃO DETERMINADO")
        self.assertEqual(audit.traduzir_estado("LOW — no known indicators found"),
                         "BAIXO — nenhum indicador conhecido encontrado")

    def test_evidence_manifest_rejects_symlinks_and_has_valid_hashes(self):
        import json
        import hashlib
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "case"
            case.mkdir()
            (case / "report.md").write_text("Customer report")
            (case / "technical-report.md").write_text("Private details")
            (case / "link").symlink_to(case / "report.md")
            manifest = audit.create_evidence_manifest(case)
            names = [record["file"] for record in manifest["files"]]
            self.assertEqual(names, ["report.md", "technical-report.md"])
            self.assertEqual(manifest["files"][0]["sha256"],
                             hashlib.sha256(b"Customer report").hexdigest())
            saved = json.loads((case / "evidence-manifest.json").read_text())
            self.assertEqual(saved["algorithm"], "SHA-256")

    def test_containment_note_does_not_invent_outage(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            audit.incident_containment_note(case, "example.test")
            content = (case / "incident-containment-record.md").read_text()
            self.assertIn("NÃO VERIFICADO NESTA AUDITORIA", content)
            self.assertIn("NÃO DOCUMENTAD", content)
            self.assertIn("example.test", content)

    def test_pdf_export_only_reads_management_report(self):
        import report_export
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / "technical-report.md").write_text("PRIVATE-SERVER-DETAILS")
            (case / "report.md").write_text("# Management report\n\nPublic observation\n")
            with unittest.mock.patch.dict("sys.modules", {"reportlab": None}):
                with self.assertRaises(report_export.PDFExportError):
                    report_export.export_management_pdf(case)
            self.assertFalse((case / "management-report.pdf").exists())

    def test_administrator_inventory_hash_only(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            with unittest.mock.patch.object(audit, "query_db", return_value=[
                ["7", "a" * 64, "2026-10-01 10:00:00"]]):
                result = audit.admin_account_inventory("cnf", "wordpress", "wp_", case)
            self.assertEqual(result["count"], 1)
            saved = json.loads((case / "administrator-inventory.json").read_text())
            self.assertEqual(saved["coverage"], "EXECUTED")
            self.assertEqual(saved["accounts"][0]["login_sha256"], "a" * 64)
            self.assertNotIn("admin@example", (case / "administrator-inventory.json").read_text())

    def test_administrator_inventory_reports_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            with unittest.mock.patch.object(audit, "query_db", side_effect=audit.AuditError("denied")):
                result = audit.admin_account_inventory("cnf", "wordpress", "wp_", Path(folder))
            self.assertEqual(result["coverage"], "UNAVAILABLE")
            self.assertIsNone(result["count"])

    def test_case_manifest_verification_and_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            file = case / "report.md"
            file.write_text("Evidence at capture")
            audit.create_evidence_manifest(case)
            self.assertEqual(audit.verify_evidence_manifest(case)["status"], "MATCH")
            file.write_text("Modified evidence")
            result = audit.verify_evidence_manifest(case)
            self.assertEqual(result["status"], "DIFFERENCES_FOUND")
            self.assertEqual(result["differences"][0]["result"], "MODIFIED")

    def test_private_evidence_bundle_contains_manifest(self):
        import tarfile
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / "report.md").write_text("Public summary")
            (case / "technical-report.md").write_text("Internal notes")
            audit.create_evidence_manifest(case)
            archive = audit.bundle_case_evidence(case)
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            with tarfile.open(archive, "r:gz") as stream:
                self.assertIn("evidence-manifest.json", stream.getnames())
                self.assertIn("technical-report.md", stream.getnames())
                self.assertNotIn("evidence-bundle.tar.gz", stream.getnames())
            self.assertEqual(audit.verify_evidence_manifest(case)["status"], "MATCH")

    def test_bundle_rejects_database_secret_file(self):
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / "mysql-client.cnf").write_text("password=redacted")
            audit.create_evidence_manifest(case)
            with self.assertRaises(audit.AuditError):
                audit.bundle_case_evidence(case)

    def test_status_precedence_residue_remains_primary(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder) / "example-20261030T000000Z-abcdef"
            case.mkdir()
            (case / "component-version-evidence.json").write_text(json.dumps({
                "coverage": {"local": "EXECUTED", "official": "EXECUTED", "core": "EXECUTED"},
                "summary": {"core_outdated": 1},
                "components": [{"state": "CORE_MODIFICADO_REQUER_REVISAO"}]
            }))
            db = [{"kind": "family_option", "name": "sc_test", "length": "1",
                   "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA"}]
            audit.make_report(case, "audit", [], [], db)
            report = json.loads((case / "report.json").read_text())
            self.assertEqual(report["exit_code"], 10)
            self.assertEqual(report["status"], "RESIDUOS_REQUEREM_LIMPEZA")
            self.assertTrue(report["summary"]["critical_component_review"])

    def test_historical_case_component_changes(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before, after = root / "before", root / "after"
            before.mkdir()
            after.mkdir()
            for case, version in ((before, "1.0"), (after, "1.1")):
                (case / "report.json").write_text(json.dumps({
                    "database": "wordpress", "database_audited": True, "status": "REVISAO_NECESSARIA"}))
                (case / "file-evidence.json").write_text("[]")
                (case / "database-evidence.json").write_text("[]")
                (case / "component-version-evidence.json").write_text(json.dumps({
                    "components": [{"type": "plugin", "slug": "akismet", "local_version": version,
                                    "state": "PLUGIN_OFICIAL_ATUAL", "main_file_sha256": "a" * 64}]}))
            comparison = audit.compare_cases(before, after, root / "out")
            self.assertEqual(comparison["diff"]["components"]["changed"], ["plugin:akismet"])

    def test_customer_review_priorities_do_not_claim_compromise(self):
        details = audit.customer_findings([], [
            {"evidence_id": "DB-001", "kind": "family_option",
             "name": "sc_test", "state": "RESIDUO_FAMILIA_REQUER_LIMPEZA"}
        ], [], {})
        document = "\n".join(details)
        self.assertIn("PRIORIDADE ALTA", document)
        self.assertIn("não comprova comprometimento ativo", document)

    def test_pdf_export_when_optional_dependency_is_installed(self):
        import importlib.util
        import report_export
        if importlib.util.find_spec("reportlab") is None:
            self.skipTest("Optional reportlab not installed")
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            (case / "report.md").write_text(
                "# Relatório gerencial — auditoria de integridade\n\n## Evidências\n\n- DB-001: revisão necessária — configuração, código e ações\n")
            (case / "technical-report.md").write_text("PRIVATE-DO-NOT-EXPORT")
            pdf = report_export.export_management_pdf(case)
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
            self.assertEqual(pdf.stat().st_mode & 0o777, 0o600)

    def test_pdf_portuguese_accents_and_pagination(self):
        import importlib.util
        import report_export
        if importlib.util.find_spec("reportlab") is None:
            self.skipTest("Dependência opcional reportlab não instalada")
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            linhas = ["# Relatório técnico-gerencial — revisão de segurança",
                      "## Evidências e conclusão"]
            linhas += ["- Item %03d: alteração, proteção, execução e verificação de integridade." % i
                       for i in range(250)]
            (case / "report.md").write_text("\n".join(linhas) + "\n", encoding="utf-8")
            pdf = report_export.export_management_pdf(case)
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
            self.assertGreater(pdf.stat().st_size, 1000)
            self.assertEqual(pdf.stat().st_mode & 0o777, 0o600)
            # A extração verifica conteúdo, paginação e caracteres Unicode,
            # não apenas a assinatura do arquivo PDF.
            if importlib.util.find_spec("fitz") is not None:
                import fitz
                with fitz.open(pdf) as documento:
                    self.assertGreater(len(documento), 1)
                    conteudo = "\n".join(pagina.get_text() for pagina in documento)
                self.assertIn("proteção", conteudo)
                self.assertIn("execução", conteudo)
                self.assertIn("conclusão", conteudo)

    def test_pdf_export_error_is_operational_error(self):
        import report_export
        self.assertTrue(issubclass(report_export.PDFExportError, RuntimeError))
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            with self.assertRaises(report_export.PDFExportError):
                report_export.export_management_pdf(case)
            self.assertFalse((case / "management-report.pdf").exists())
            self.assertEqual(list(case.glob(".management-report-*")), [])

    def test_pdf_rejeita_relatorio_grande_ou_link_simbolico(self):
        import report_export
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            origem = caso / "report.md"
            externo = caso / "origem-real.md"
            externo.write_text("# Relatório original", encoding="utf-8")
            origem.symlink_to(externo)
            with self.assertRaises(report_export.PDFExportError):
                report_export.export_management_pdf(caso)
            origem.unlink()
            with origem.open("wb") as arquivo:
                arquivo.truncate(8 * 1024 * 1024 + 1)
            with self.assertRaises(report_export.PDFExportError):
                report_export.export_management_pdf(caso)
            self.assertFalse((caso / "management-report.pdf").exists())

    def test_smtp_rejeita_pdf_grande_e_link_simbolico(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            pdf = raiz / "management-report.pdf"
            original = raiz / "original.pdf"
            original.write_bytes(b"%PDF-1.4")
            pdf.symlink_to(original)
            with self.assertRaises(mail_delivery.MailDeliveryError):
                mail_delivery._ler_regular_limitado(pdf, 20 * 1024 * 1024)
            pdf.unlink()
            with pdf.open("wb") as arquivo:
                arquivo.truncate(20 * 1024 * 1024 + 1)
            with self.assertRaises(mail_delivery.MailDeliveryError):
                mail_delivery._ler_regular_limitado(pdf, 20 * 1024 * 1024)
            self.assertEqual(mail_delivery._ler_regular_limitado(original, 4096), b"%PDF-1.4")

    def test_smtp_rejeita_senha_com_caminho_relativo(self):
        import mail_delivery
        import unittest.mock
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            cfg = caso / "smtp.cfg"
            cfg.write_text("[smtp]\nhost = smtp.example.com\nport = 587\nsecurity = starttls\n"
                           "from_address = auditor@example.com\nusername = auditor@example.com\n"
                           "password_file = senha-relativa\n", encoding="utf-8")
            cfg.chmod(0o600)
            with unittest.mock.patch.object(mail_delivery.smtplib, "SMTP") as envio:
                with self.assertRaises(mail_delivery.MailDeliveryError):
                    mail_delivery.send_management_report(caso, "cliente@example.com", cfg)
                envio.assert_not_called()

    def test_smtp_limita_configuracao_e_valida_permissoes_no_descritor(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            arquivo = raiz / "smtp.cfg"
            with arquivo.open("wb") as stream:
                stream.truncate(64 * 1024 + 1)
            arquivo.chmod(0o600)
            with self.assertRaises(mail_delivery.MailDeliveryError):
                mail_delivery._ler_regular_limitado(arquivo, 64 * 1024, privado=True)
            arquivo.write_text("[smtp]\n", encoding="utf-8")
            arquivo.chmod(0o644)
            with self.assertRaises(mail_delivery.MailDeliveryError):
                mail_delivery._ler_regular_limitado(arquivo, 64 * 1024, privado=True)
            arquivo.chmod(0o600)
            self.assertEqual(mail_delivery._ler_regular_limitado(arquivo, 64 * 1024, privado=True),
                             b"[smtp]\n")

    def test_mail_delivery_requires_private_config(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as folder:
            case = Path(folder)
            config = case / "smtp.cfg"
            config.write_text("[smtp]\nhost = smtp.example.com\nport = 587\nsecurity = starttls\n")
            config.chmod(0o644)
            with self.assertRaises(mail_delivery.MailDeliveryError):
                mail_delivery.send_management_report(case, "recipient@example.com", config)

    def test_smtp_envio_aceito_com_starttls_verificado(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            senha = caso / "smtp-secret"
            senha.write_text("senha-de-teste\n", encoding="utf-8")
            senha.chmod(0o600)
            cfg = caso / "smtp.cfg"
            cfg.write_text("[smtp]\nhost = smtp.example.com\nport = 587\nsecurity = starttls\n"
                           "from_address = auditor@example.com\nusername = auditor@example.com\n"
                           f"password_file = {senha}\n", encoding="utf-8")
            cfg.chmod(0o600)
            (caso / "management-report.pdf").write_bytes(b"%PDF-1.4\nconteudo-de-teste")
            with unittest.mock.patch.object(mail_delivery.smtplib, "SMTP") as classe:
                instancia = classe.return_value.__enter__.return_value
                instancia.has_extn.return_value = True
                instancia.send_message.return_value = {}
                mail_delivery.send_management_report(caso, "cliente@example.com", cfg)
                instancia.starttls.assert_called_once()
                instancia.login.assert_called_once_with("auditor@example.com", "senha-de-teste")
                instancia.send_message.assert_called_once()
                mensagem = instancia.send_message.call_args.args[0]
                self.assertEqual(mensagem["To"], "cliente@example.com")
                self.assertEqual(len(list(mensagem.iter_attachments())), 1)

    def test_smtp_nao_envia_sem_starttls(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            senha = caso / "smtp-secret"
            senha.write_text("senha-de-teste", encoding="utf-8")
            senha.chmod(0o600)
            cfg = caso / "smtp.cfg"
            cfg.write_text("[smtp]\nhost = smtp.example.com\nport = 587\nsecurity = starttls\n"
                           "from_address = auditor@example.com\nusername = auditor@example.com\n"
                           f"password_file = {senha}\n", encoding="utf-8")
            cfg.chmod(0o600)
            (caso / "management-report.pdf").write_bytes(b"%PDF-1.4\nconteudo")
            with unittest.mock.patch.object(mail_delivery.smtplib, "SMTP") as classe:
                instancia = classe.return_value.__enter__.return_value
                instancia.has_extn.return_value = False
                with self.assertRaisesRegex(mail_delivery.MailDeliveryError, "STARTTLS"):
                    mail_delivery.send_management_report(caso, "cliente@example.com", cfg)
                instancia.login.assert_not_called()
                instancia.send_message.assert_not_called()

    def test_smtp_erros_seguros_sem_vazamento_de_credenciais(self):
        import mail_delivery
        import smtplib
        import socket
        import ssl
        credencial = b"senha-super-secreta"
        casos = (
            (smtplib.SMTPAuthenticationError(535, credencial), "Autenticação SMTP recusada"),
            (socket.gaierror(8, "hostname-confidencial"), "DNS"),
            (ConnectionRefusedError("servidor-confidencial"), "Conexão SMTP recusada"),
            (ssl.SSLCertVerificationError("certificado interno"), "certificado TLS"),
            (smtplib.SMTPRecipientsRefused({"cliente@example.com": (550, credencial)}),
             "recusou o destinatário"),
        )
        for erro, trecho in casos:
            mensagem = mail_delivery._erro_smtp(erro)
            self.assertIn(trecho, mensagem)
            self.assertNotIn("senha-super-secreta", mensagem)
            self.assertNotIn("hostname-confidencial", mensagem)
            self.assertNotIn("servidor-confidencial", mensagem)

    def test_smtp_recusa_parcial_nao_e_sucesso(self):
        import mail_delivery
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            senha = caso / "smtp-secret"
            senha.write_text("senha-de-teste", encoding="utf-8")
            senha.chmod(0o600)
            cfg = caso / "smtp.cfg"
            cfg.write_text("[smtp]\nhost = smtp.example.com\nport = 465\nsecurity = ssl\n"
                           "from_address = auditor@example.com\nusername = auditor@example.com\n"
                           f"password_file = {senha}\n", encoding="utf-8")
            cfg.chmod(0o600)
            (caso / "management-report.pdf").write_bytes(b"%PDF-1.4\nconteudo")
            with unittest.mock.patch.object(mail_delivery.smtplib, "SMTP_SSL") as classe:
                instancia = classe.return_value.__enter__.return_value
                instancia.send_message.return_value = {"cliente@example.com": (550, b"recusado")}
                with self.assertRaisesRegex(mail_delivery.MailDeliveryError, "recusou"):
                    mail_delivery.send_management_report(caso, "cliente@example.com", cfg)

    def test_mail_delivery_rejects_header_injection(self):
        import mail_delivery
        with self.assertRaises(mail_delivery.MailDeliveryError):
            mail_delivery._address("recipient@example.com\nBcc: attacker@example.com")

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
