"""Valida que o plano de recuperação SC não executa ações nem aprova liberação."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_plano
import sc403_homologacao


class TestPlanoSC(unittest.TestCase):
    def test_homologacao_sintetica_preserva_fixture_e_bloqueia_liberacao(self):
        resultado = sc403_homologacao.executar()
        self.assertEqual(resultado["status"], "APROVADA_COM_BLOQUEIOS")
        self.assertTrue(resultado["fixture_descartavel"])
        self.assertTrue(resultado["evidencia_preservada"])
        self.assertTrue(resultado["plano_nao_executavel"])
        self.assertTrue(resultado["liberacao_nao_autorizada"])
        self.assertFalse(resultado["php_executado"])

    def test_gera_plano_bloqueado_e_nao_executavel(self):
        with tempfile.TemporaryDirectory() as tmp:
            caso = Path(tmp)
            (caso / "file-evidence.json").write_text(json.dumps([
                {"path": "wp-content/arquivo.php", "classification": "IOC_REQUER_VALIDACAO"}
            ]))
            (caso / "database-evidence.json").write_text(json.dumps([
                {"kind": "sc403_derived_option", "name": "aabbccddeeff", "state": "REVISAO_NECESSARIA"}
            ]))
            (caso / "sc403-forense.json").write_text(json.dumps({
                "proc": {"status": "COMPLETA", "resultados": []},
                "zip": {"status": "COMPLETA", "resultados": []},
            }))
            plano = sc403_plano.gerar_plano(caso)
            self.assertFalse(plano["execucao_automatica_autorizada"])
            self.assertFalse(plano["liberacao_do_site_autorizada"])
            self.assertIn("INDICADORES_REQUEREM_VALIDACAO", plano["bloqueios"])
            self.assertIn("wp-content/arquivo.php", plano["indicadores"]["arquivos"])
            self.assertIn("aabbccddeeff", plano["indicadores"]["opcoes_sql"])
            self.assertEqual(plano["schema_version"], 2)
            self.assertFalse(any(etapa["executavel"] for etapa in plano["etapas_coordenadas"]))
            self.assertIn("INDICADORES_REQUEREM_VALIDACAO", plano["condicoes_de_interrupcao"])

    def test_plano_considera_lateral_e_memoria(self):
        with tempfile.TemporaryDirectory() as tmp:
            caso = Path(tmp)
            (caso / "sc403-lateral-exposure.json").write_text(json.dumps({"cobertura": "COMPLETA", "riscos": [{"tipo": "UID_COMPARTILHADO"}]}))
            (caso / "sc403-systemv-shm.json").write_text(json.dumps({"kernel": {"status": "COMPLETA"}, "dumps": {"status": "INCOMPLETA"}}))
            plano = sc403_plano.gerar_plano(caso)
            self.assertIn("EXPOSICAO_LATERAL_REQUER_REVISAO", plano["bloqueios"])
            self.assertIn("MEMORIA_SYSTEMV_REQUER_VALIDACAO", plano["bloqueios"])

    def test_evidencia_incompleta_bloqueia(self):
        with tempfile.TemporaryDirectory() as tmp:
            plano = sc403_plano.gerar_plano(Path(tmp))
            self.assertIn("BANCO_NAO_AUDITADO", plano["bloqueios"])
            self.assertIn("RUNTIME_NAO_AUDITADO", plano["bloqueios"])


if __name__ == "__main__":
    unittest.main()
