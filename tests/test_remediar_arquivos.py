"""Testes da quarentena pontual de arquivos WordPress em diretórios descartáveis."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "remediar_arquivos_wp.py"
spec = importlib.util.spec_from_file_location("remediar_arquivos_wp", SCRIPT)
rem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rem)


class RemediacaoArquivosTests(unittest.TestCase):
    def preparar(self, raiz: Path):
        site, caso = raiz / "site", raiz / "caso"
        pasta = site / "wp-content" / "mu-plugins"
        pasta.mkdir(parents=True)
        caso.mkdir(mode=0o700)
        alvo = pasta / "trace-inspector-pad.php"
        alvo.write_text("<?php /* IOC sintético */", encoding="utf-8")
        digest = hashlib.sha256(alvo.read_bytes()).hexdigest()
        (caso / "file-evidence.json").write_text(json.dumps([{
            "path": "wp-content/mu-plugins/trace-inspector-pad.php",
            "classification": "IOC_REQUER_VALIDACAO", "sha256": digest
        }]), encoding="utf-8")
        return site, caso, alvo

    def test_simulacao_nao_modifica_site(self):
        with tempfile.TemporaryDirectory() as pasta:
            site, caso, alvo = self.preparar(Path(pasta))
            r = rem.executar(site, caso, "wp-content/mu-plugins/trace-inspector-pad.php")
            self.assertEqual(r["estado"], "SIMULACAO")
            self.assertTrue(alvo.exists())

    def test_aplicacao_preserva_copia_e_nao_remove_outros(self):
        with tempfile.TemporaryDirectory() as pasta:
            site, caso, alvo = self.preparar(Path(pasta))
            outro = alvo.parent / "legitimo.php"
            outro.write_text("<?php // legitimo", encoding="utf-8")
            with mock.patch.object(rem.os, "geteuid", return_value=0), \
                 mock.patch.object(rem.subprocess, "run") as ps:
                ps.return_value.stdout = "/usr/bin/python3 agente-seguro\n"
                resultado = rem.executar(site, caso, "wp-content/mu-plugins/trace-inspector-pad.php", aplicar=True)
            self.assertFalse(alvo.exists())
            self.assertTrue(outro.exists())
            copia = Path(resultado["copia"])
            self.assertTrue(copia.is_file())
            self.assertEqual(stat.S_IMODE(copia.stat().st_mode), 0o600)

    def test_hash_diferente_rejeitado(self):
        with tempfile.TemporaryDirectory() as pasta:
            site, caso, alvo = self.preparar(Path(pasta))
            alvo.write_text("conteudo diferente")
            with self.assertRaises(rem.RemocaoRecusada):
                rem.executar(site, caso, "wp-content/mu-plugins/trace-inspector-pad.php")
            self.assertTrue(alvo.exists())

    def test_arquivo_sem_ioc_explicito_rejeitado(self):
        with tempfile.TemporaryDirectory() as pasta:
            site, caso, alvo = self.preparar(Path(pasta))
            registros = json.loads((caso / "file-evidence.json").read_text())
            registros[0]["classification"] = "PHP_UPLOAD_REQUER_VALIDACAO"
            (caso / "file-evidence.json").write_text(json.dumps(registros))
            with self.assertRaises(rem.RemocaoRecusada):
                rem.executar(site, caso, "wp-content/mu-plugins/trace-inspector-pad.php")

    def test_recusa_links_e_travessia_de_diretorios(self):
        with tempfile.TemporaryDirectory() as pasta:
            site, caso, alvo = self.preparar(Path(pasta))
            with self.assertRaises(rem.RemocaoRecusada):
                rem.executar(site, caso, "wp-content/../wp-config.php")
            link = alvo.parent / "link.php"
            link.symlink_to(alvo)
            with self.assertRaises(rem.RemocaoRecusada):
                rem.executar(site, caso, "wp-content/mu-plugins/link.php")


if __name__ == "__main__":
    unittest.main()
