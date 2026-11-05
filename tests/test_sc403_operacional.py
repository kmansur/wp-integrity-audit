import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_journal as journal
import sc403_executor as executor
import sc403_identidade as identidade
import sc403_rollback as rollback
import sc403_autorizacao as autorizacao


class TestNucleoOperacional(unittest.TestCase):
    def test_diario_tem_cadeia_e_detecta_adulteracao(self):
        with tempfile.TemporaryDirectory() as temp:
            caminho = Path(temp) / "journal.jsonl"
            journal.registrar(caminho, {"estado": "DESCOBERTO", "recurso": "pid:1"})
            self.assertTrue(journal.verificar(caminho)["válido"])
            caminho.write_text(caminho.read_text() + "{}\n")
            self.assertFalse(journal.verificar(caminho)["válido"])

    def test_identidade_divergente_bloqueia(self):
        esperado = {"boot_id": "a", "server_id": "h"}
        resultado = identidade.comparar(esperado, {"boot_id": "b", "server_id": "h"}, ("boot_id", "server_id"))
        self.assertFalse(resultado["compatível"])

    def test_executor_nunca_executa(self):
        resultado = executor.simular({"id": "pid:1"}, True, True, True)
        self.assertFalse(resultado["executado"])
        self.assertEqual(resultado["estado"], "AUTORIZADO")

    def test_rollback_nao_reintroduz_recurso(self):
        resultado = rollback.plano_reversao({"id": "arquivo:x", "reversibilidade": False})
        self.assertFalse(resultado["executado"])
        self.assertEqual(resultado["estado"], "INTERVENCAO_MANUAL_NECESSARIA")

    def test_aprovacao_exige_hash_do_plano_e_assinatura_externa(self):
        from test_sc403_escopo import manifesto
        base = manifesto()
        base["approval"] = {"plan_sha256": autorizacao.hash_plano(base),
                             "signature": "assinatura-externa", "key_id": "chave-1",
                             "verified_by": "sistema-aprovacao"}
        resultado = autorizacao.validar_aprovacao(base)
        self.assertTrue(resultado["assinatura_presente"])
        self.assertFalse(resultado["assinatura_criptograficamente_verificada"])
        base["operations"] = ["remover"]
        with self.assertRaises(ValueError):
            autorizacao.validar_aprovacao(base)


if __name__ == "__main__":
    unittest.main()
