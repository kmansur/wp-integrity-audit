import tempfile
import datetime as dt
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_journal as journal
import sc403_executor as executor
import sc403_identidade as identidade
import sc403_rollback as rollback
import sc403_autorizacao as autorizacao
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


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

    def test_identidade_do_processo_tem_uid_efetivo_e_starttime(self):
        resultado = identidade.processo(__import__("os").getpid())
        self.assertEqual(resultado["estado"], "INVENTARIADO")
        self.assertEqual(resultado["uid_efetivo"], __import__("os").geteuid())
        self.assertIsInstance(resultado["starttime_ticks"], int)
        self.assertIn("pid_namespace", resultado)

    def test_executor_nunca_executa(self):
        from test_sc403_escopo import manifesto
        base = manifesto()
        agora = dt.datetime(2026, 11, 4, 12, tzinfo=dt.timezone.utc)
        chave = Ed25519PrivateKey.generate()
        aprovacao = {
            "approval_id": "aprovacao-1", "plan_sha256": autorizacao.hash_plano(base),
            "key_id": "chave-1", "verified_by": "admin",
            "approved_at": "2026-11-04T11:00:00Z", "valid_until": "2026-11-05T10:00:00Z",
            "server_id": "host-a",
        }
        aprovacao["signature"] = base64.b64encode(chave.sign(autorizacao.mensagem_assinada(base, aprovacao))).decode()
        politica = {"schema_version": 1, "keys": {"chave-1": {
            "public_key": base64.b64encode(chave.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
            "server_ids": ["host-a"]}}}
        estado = {"identity": base["identity"], "evidence_manifest_sha256": base["evidence_manifest_sha256"],
                  "backup_restauravel": True, "dependencias_resolvidas": True}
        resultado = executor.simular(base, estado, aprovacao, politica, agora=agora)
        self.assertFalse(resultado["executavel"])
        self.assertFalse(resultado["bloqueado"])

    def test_rollback_nao_reintroduz_recurso(self):
        resultado = rollback.plano_reversao({"id": "arquivo:x", "reversibilidade": False})
        self.assertFalse(resultado["executado"])
        self.assertEqual(resultado["estado"], "INTERVENCAO_MANUAL_NECESSARIA")

    def test_aprovacao_ed25519_e_rejeicao_de_alteracao(self):
        from test_sc403_escopo import manifesto
        base = manifesto()
        agora = dt.datetime(2026, 11, 4, 12, tzinfo=dt.timezone.utc)
        chave = Ed25519PrivateKey.generate()
        aprovacao = {"approval_id": "aprovacao-1", "plan_sha256": autorizacao.hash_plano(base),
                     "key_id": "chave-1", "verified_by": "sistema-aprovacao",
                     "approved_at": "2026-11-04T10:00:00Z", "valid_until": "2026-11-05T10:00:00Z",
                     "server_id": "host-a"}
        aprovacao["signature"] = base64.b64encode(chave.sign(autorizacao.mensagem_assinada(base, aprovacao))).decode()
        politica = {"schema_version": 1, "keys": {"chave-1": {
            "public_key": base64.b64encode(chave.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}}}
        resultado = autorizacao.validar_aprovacao(base, aprovacao, politica, agora=agora)
        self.assertTrue(resultado["assinatura_presente"])
        self.assertTrue(resultado["assinatura_criptograficamente_verificada"])
        base["operations"] = ["remover"]
        with self.assertRaises(ValueError):
            autorizacao.validar_aprovacao(base, aprovacao, politica, agora=agora)

    def test_diario_rejeita_registro_incompleto_e_ancora_divergente(self):
        with tempfile.TemporaryDirectory() as temp:
            caminho = Path(temp) / "journal.jsonl"
            journal.registrar(caminho, {"estado": "DESCOBERTO"})
            caminho.write_bytes(caminho.read_bytes() + b'{"linha":')
            self.assertFalse(journal.verificar(caminho)["válido"])


if __name__ == "__main__":
    unittest.main()
