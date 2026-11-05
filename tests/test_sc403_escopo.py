import datetime as dt
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_escopo as escopo


def manifesto():
    return {
        "schema_version": 1, "case_id": "caso-1",
        "identity": {"domain": "exemplo", "wordpress_path": "/srv/exemplo/html", "abspath": "/srv/exemplo/html/",
                      "owner_uid": 2001, "owner_gid": 2001, "server_id": "host-a", "boot_id": "boot-a",
                      "pid_namespace": "pid-a", "ipc_namespace": "ipc-a", "database": "db_a",
                      "table_prefix": "wp_", "related_sites": ["outro"]},
        "evidence_manifest_sha256": "a" * 64,
        "authorization": {"technical_responsible": "admin", "approval_id": "aprov-1",
                           "approved_at": "2026-11-04T10:00:00Z", "valid_until": "2026-11-05T10:00:00Z"},
        "resources": {tipo: [] for tipo in escopo.RECURSOS},
        "operations": ["sinalizar"], "preconditions": ["backup"],
        "forbidden_operations": ["curinga"]
    }


class TestEscopo(unittest.TestCase):
    def test_manifesto_valido_nao_habilita_execucao(self):
        resultado = escopo.validar(manifesto(), dt.datetime(2026, 11, 4, 12, tzinfo=dt.timezone.utc))
        self.assertTrue(resultado["valido"])
        self.assertFalse(resultado["execucao_habilitada"])

    def test_expirado_e_curiga_sao_recusados(self):
        base = manifesto()
        with self.assertRaises(escopo.EscopoRecusado):
            escopo.validar(base, dt.datetime(2026, 11, 6, tzinfo=dt.timezone.utc))
        base = manifesto()
        base["resources"]["processos"] = [{"id": "*", "operation": "sinalizar"}]
        with self.assertRaises(escopo.EscopoRecusado):
            escopo.validar(base, dt.datetime(2026, 11, 4, 12, tzinfo=dt.timezone.utc))

    def test_simulacao_bloqueia_boot_diferente(self):
        base = manifesto()
        estado = {"identity": {**base["identity"], "boot_id": "boot-diferente"},
                  "evidence_manifest_sha256": base["evidence_manifest_sha256"]}
        resultado = escopo.simular(base, estado)
        self.assertTrue(resultado["simulacao"])
        self.assertTrue(resultado["bloqueado"])
        self.assertFalse(resultado["alteracoes_realizadas"])

    def test_proposta_nao_inventa_autorizacao(self):
        with tempfile.TemporaryDirectory() as temp:
            caso = Path(temp)
            (caso / "sc403-identifiers.json").write_text('{"abspath":"/srv/site/html/"}')
            proposta = escopo.gerar_proposta(caso)
            self.assertEqual(proposta["operations"], [])
            self.assertEqual(proposta["authorization"], {})


if __name__ == "__main__":
    unittest.main()
