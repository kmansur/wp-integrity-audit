"""Regressão de relatórios e pós-validação do SC 4.x.

Cenários sintéticos: diretórios sem SHA-256 e persistências recriadas.
Não requer root, WordPress, SQL ou rede.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

BIN = Path(__file__).resolve().parents[1] / "bin"
sys.path.insert(0, str(BIN))
spec = importlib.util.spec_from_file_location("auditoria_sc_relatorio", BIN / "wp-integrity-audit.py")
auditoria = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditoria)


class TestRelatorioSC(unittest.TestCase):
    def test_diretorio_sem_hash_nao_interrompe_relatorio(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            arquivos = [{
                "path": "wp-content/.sc_12345678",
                "classification": "SC_CAMINHO_DERIVADO_REQUER_REVISAO",
                "reason": "Caminho derivado; confirmar procedência",
                "sha256": None,
            }]
            auditoria.make_report(caso, "audit-db", arquivos, [])
            relatorio = (caso / "technical-report.md").read_text(encoding="utf-8")
            resumo = json.loads((caso / "report.json").read_text(encoding="utf-8"))
            self.assertIn("NÃO CALCULADO", relatorio)
            self.assertEqual(resumo["exit_code"], 40)
            self.assertEqual(resumo["summary"]["sc403_derived_file_review"], 1)
            self.assertFalse(resumo["database_audited"])

    def test_opcao_sc_derivada_aparece_no_parecer_e_risco(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            registros = [{
                "kind": "sc403_derived_option",
                "name": "aabbccddeeff",
                "length": "14",
                "state": "REVISAO_NECESSARIA",
                "sha256": "a" * 64,
                "value_length_bytes": 14,
                "value_classification": "SC403_OPCAO_DERIVADA",
                "safe_excerpt": "[VALOR_OMITIDO]",
                "decoded_excerpt": "[VALOR_OMITIDO]",
            }]
            auditoria.make_report(caso, "audit-db", [], [], registros, "wordpress", "wp_")
            gerencial = (caso / "report.md").read_text(encoding="utf-8")
            resumo = json.loads((caso / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(resumo["exit_code"], 40)
            self.assertEqual(resumo["summary"]["sc403_derived_options_requiring_review"], 1)
            self.assertIn("opções privadas sc", gerencial.lower())
            self.assertIn("REVISÃO NECESSÁRIA", gerencial)

    def test_persistencia_pos_recuperacao_bloqueia_status_limpo(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso = Path(pasta)
            (caso / "sc403-recovery-postcheck.json").write_text(json.dumps({
                "bloqueios": ["PROCESSOS_SC_ATIVOS"], "liberacao_autorizada": False,
            }), encoding="utf-8")
            auditoria.make_report(caso, "recover", [], [], [], "wordpress", "wp_")
            resumo = json.loads((caso / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(resumo["exit_code"], 40)
            self.assertEqual(resumo["status"], "AUDITORIA_INCOMPLETA")
            self.assertTrue(resumo["optional_probe_review"])

    def test_outros_bloqueios_pos_recuperacao(self):
        banco = [{"kind": "sc403_derived_option", "state": "REVISAO_NECESSARIA"}]
        arquivos = [{"classification": "SC_CAMINHO_DERIVADO_REQUER_REVISAO"}]
        bloqueios = auditoria.post_recovery_blockers(banco, arquivos, [])
        self.assertIn("sc403_derived_options", bloqueios)
        self.assertIn("sc403_derived_files", bloqueios)


if __name__ == "__main__":
    unittest.main()
