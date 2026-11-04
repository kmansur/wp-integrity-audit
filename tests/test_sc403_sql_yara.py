"""Teste isolado do inventário SQL SC e do motor YARA opcional."""
from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

BIN = Path(__file__).resolve().parents[1] / "bin"
sys.path.insert(0, str(BIN))
import sc403_yara

spec = importlib.util.spec_from_file_location("wp_audit_sc_teste", BIN / "wp-integrity-audit.py")
auditoria = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditoria)


class TestSQLObjetosSC(unittest.TestCase):
    def test_inventario_sem_corpos_sql(self):
        with tempfile.TemporaryDirectory() as d:
            case = Path(d)
            def consulta(_, __, sql):
                if "information_schema.TRIGGERS" in sql:
                    return [["tr_auditoria", "wp_options"]]
                return []
            with patch.object(auditoria, "query_db", side_effect=consulta):
                res = auditoria.database_sql_objects_audit("cnf", "wordpress", case)
            self.assertEqual(len(res["objetos"]), 1)
            self.assertEqual(res["objetos"][0]["nome"], "tr_auditoria")
            self.assertNotIn("ACTION_STATEMENT", json.dumps(res))
            self.assertTrue((case / "sc403-sql-objects.json").exists())

    def test_permissao_sql_insuficiente(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(auditoria, "query_db", side_effect=OSError("permissao negada")):
                res = auditoria.database_sql_objects_audit("cnf", "wordpress", Path(d))
            self.assertEqual(res["status"], "INCOMPLETA")
            self.assertEqual(len(res["fontes_nao_consultadas"]), 3)

    def test_yara_nao_instalado(self):
        with patch.object(sc403_yara.shutil, "which", return_value=None):
            res = sc403_yara.scanner_yara(Path("/var/www/site"), Path("/etc/wp-integrity-audit/test.yar"))
        self.assertEqual(res["status"], "INCOMPLETA")
        self.assertEqual(res["motivo"], "YARA_NAO_INSTALADO")


if __name__ == "__main__":
    unittest.main()
