import base64
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_host
import sc403_selfcheck


class TestHostAudit(unittest.TestCase):
    def test_cron_base64_e_marcador_sao_apenas_inventariados(self):
        with tempfile.TemporaryDirectory() as temp:
            raiz = Path(temp) / "cron.d"
            raiz.mkdir()
            codificado = base64.b64encode(b"echo SCV:4.3.24").decode()
            (raiz / "job").write_text(f"* * * * * echo {codificado}|base64 -d|bash\n")
            resultado = sc403_host.auditar([raiz.parent])
            self.assertFalse(resultado["executou_comandos"])
            self.assertEqual(len(resultado["indicadores_requerendo_revisao"]), 1)
            texto = str(resultado)
            self.assertNotIn("echo SCV:4.3.24", texto)

    def test_raiz_inexistente_e_reportada_sem_excecao(self):
        resultado = sc403_host.auditar([Path("/nao-existe-wp-audit")])
        self.assertEqual(resultado["cobertura"], "INCOMPLETA")

    def test_selfcheck_nao_le_credenciais(self):
        resultado = sc403_selfcheck.verificar(Path(__file__).parents[1] / "bin")
        self.assertIn(resultado["status"], {"OK", "REVISAO_NECESSARIA"})
        self.assertTrue(resultado["somente_leitura"])


if __name__ == "__main__":
    unittest.main()
