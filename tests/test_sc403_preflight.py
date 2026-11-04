"""Ensaios do pré-validador SC com evidências sintéticas.

Nunca executa operações destrutivas nem requer privilégios administrativos.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_indicadores
import sc403_preflight


def gravar_json(path: Path, objeto) -> None:
    path.write_text(json.dumps(objeto), encoding="utf-8")


class TestPreflightSC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.site = base / "site"
        self.caso = base / "caso"
        self.site.mkdir()
        self.caso.mkdir(mode=0o700)
        self.caso.chmod(0o700)
        for nome in ("wp-content", "wp-includes"):
            (self.site / nome).mkdir()
        (self.site / "wp-config.php").write_text("<?php // exemplo")
        (self.site / "wp-content" / "incidente.php").write_bytes(b"<?php /* SC_ADV_BEGIN */")
        self.registro = {
            "path": "wp-content/incidente.php",
            "classification": "IOC_REQUER_VALIDACAO",
            "sha256": hashlib.sha256(
                (self.site / "wp-content" / "incidente.php").read_bytes()
            ).hexdigest(),
        }
        gravar_json(self.caso / "file-evidence.json", [self.registro])
        gravar_json(self.caso / "sc403-identifiers.json",
                    sc403_indicadores.identificadores(self.site))
        gravar_json(self.caso / "sc403-recovery-plan.json", {
            "tipo": "PLANO_TECNICO_NAO_EXECUTAVEL",
            "bloqueios": ["INDICADORES_REQUEREM_VALIDACAO"],
        })
        self.atualizar_manifesto()

    def tearDown(self):
        self.tmp.cleanup()

    def atualizar_manifesto(self):
        arquivos = []
        for arquivo in self.caso.iterdir():
            if arquivo.name == "evidence-manifest.json":
                continue
            raw = arquivo.read_bytes()
            arquivos.append({
                "file": arquivo.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size_bytes": len(raw),
            })
        gravar_json(self.caso / "evidence-manifest.json", {
            "algorithm": "SHA-256",
            "files": arquivos,
        })

    def analisar(self):
        with patch.object(sc403_preflight.sc403_forense, "inspecionar_proc",
                          return_value={"status": "COMPLETA", "resultados": []}):
            return sc403_preflight.analisar(self.caso, self.site)

    def test_caso_integro_ainda_requer_autorizacao_e_backup(self):
        resultado = self.analisar()
        self.assertEqual(resultado["manifesto"]["status"], "VALIDO")
        self.assertEqual(resultado["hashes_arquivos"]["divergencias"], [])
        self.assertFalse(resultado["liberacao_autorizada"])
        self.assertFalse(resultado["alteracoes_executadas"])
        self.assertIn("BACKUP_RESTAURAVEL_NAO_COMPROVADO", resultado["bloqueios"])

    def test_alteracao_do_arquivo_bloqueia(self):
        (self.site / "wp-content" / "incidente.php").write_bytes(b"<?php /* alterado */")
        resultado = self.analisar()
        self.assertIn("ARQUIVOS_ALTERADOS_DESDE_AUDITORIA", resultado["bloqueios"])

    def test_alteracao_da_evidencia_bloqueia(self):
        (self.caso / "file-evidence.json").write_text("[]", encoding="utf-8")
        resultado = self.analisar()
        self.assertEqual(resultado["manifesto"]["status"], "DIVERGENTE")
        self.assertIn("INTEGRIDADE_CASO_NAO_CONFIRMADA", resultado["bloqueios"])

    def test_caso_de_outro_site_e_recusado(self):
        outro = self.site.parent / "outro"
        outro.mkdir()
        for nome in ("wp-content", "wp-includes"):
            (outro / nome).mkdir()
        (outro / "wp-config.php").write_text("<?php")
        with self.assertRaises(sc403_preflight.PreflightError):
            sc403_preflight.analisar(self.caso, outro)

    def test_link_simbolico_de_arquivo_e_bloqueado(self):
        arquivo = self.site / "wp-content" / "incidente.php"
        original = self.site / "fora.php"
        original.write_bytes(arquivo.read_bytes())
        arquivo.unlink()
        arquivo.symlink_to(original)
        resultado = self.analisar()
        self.assertIn("ARQUIVOS_ALTERADOS_DESDE_AUDITORIA", resultado["bloqueios"])

    def test_processos_ativos_bloqueiam(self):
        with patch.object(sc403_preflight.sc403_forense, "inspecionar_proc",
                          return_value={"status": "COMPLETA", "resultados": [
                              {"pid": 123, "state": "PROC_SC_REQUER_INVESTIGACAO"}
                          ]}):
            resultado = sc403_preflight.analisar(self.caso, self.site)
        self.assertIn("PROCESSOS_SUSPEITOS_ATIVOS", resultado["bloqueios"])
        self.assertEqual(resultado["processos"]["pids_suspeitos"], [123])


if __name__ == "__main__":
    unittest.main()
