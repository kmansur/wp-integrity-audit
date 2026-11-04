"""Regressão dos mecanismos forenses do SC em ambiente sintético.

Não requer WordPress, root, rede, MySQL ou arquivos maliciosos reais.
"""
from pathlib import Path
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_forense as sc


class TestForenseSC(unittest.TestCase):
    def test_zip_inerte_com_marcador(self):
        with tempfile.TemporaryDirectory() as nome:
            raiz = Path(nome)
            with zipfile.ZipFile(raiz / "pacote.zip", "w") as z:
                z.writestr("plugin/componente.php", "<?php /* SC_ADV_BEGIN */")
                z.writestr("plugin/assets/ok.txt", "conteudo normal")
            resultado = sc.inspecionar_zips(raiz)
            self.assertEqual(resultado["status"], "COMPLETA")
            self.assertEqual(len(resultado["resultados"]), 1)
            self.assertEqual(resultado["resultados"][0]["state"], "ZIP_PAYLOAD_REQUER_REVISAO")
            self.assertFalse((raiz / "plugin").exists())

    def test_zip_legitimo_sem_achados(self):
        with tempfile.TemporaryDirectory() as nome:
            raiz = Path(nome)
            with zipfile.ZipFile(raiz / "tema.zip", "w") as z:
                z.writestr("tema/functions.php", "<?php function exemplo() { return 1; }")
            resultado = sc.inspecionar_zips(raiz)
            self.assertEqual(resultado["resultados"], [])

    def test_config_php_sem_expor_valores(self):
        with tempfile.TemporaryDirectory() as nome:
            raiz = Path(nome)
            (raiz / ".user.ini").write_text("auto_prepend_file=/opt/segredo.php\n")
            resultado = sc.inspecionar_php_config(raiz)
            self.assertEqual(len(resultado["resultados"]), 1)
            self.assertIn("auto_prepend_file", resultado["resultados"][0]["directives"])
            self.assertNotIn("/opt/segredo.php", str(resultado))

    def test_proc_sintetico_apenas_metadados(self):
        with tempfile.TemporaryDirectory() as nome:
            raiz = Path(nome)
            proc = raiz / "proc"
            pid = proc / "412"
            (pid / "fd").mkdir(parents=True)
            (pid / "cmdline").write_bytes(b"/usr/bin/php\x00--sc-cli\x00")
            resultado = sc.inspecionar_proc(raiz, proc_root=proc)
            self.assertEqual(len(resultado["resultados"]), 1)
            self.assertTrue(resultado["resultados"][0]["indicador_comando"])
            self.assertNotIn("--sc-cli", str(resultado))

    def test_bloqueio_recuperacao_inventario_livre(self):
        proc = {"status": "COMPLETA", "resultados": []}
        zips = {"status": "COMPLETA", "resultados": []}
        self.assertEqual(sc.bloqueios_recuperacao(proc, zips), [])

    def test_bloqueio_recuperacao_processo_suspeito(self):
        proc = {"status": "COMPLETA", "resultados": [
            {"pid": 123, "state": "PROC_SC_REQUER_INVESTIGACAO"}]}
        zips = {"status": "COMPLETA", "resultados": []}
        self.assertIn("PROCESSOS_SC_ATIVOS", sc.bloqueios_recuperacao(proc, zips))

    def test_bloqueio_recuperacao_zip_suspeito(self):
        proc = {"status": "COMPLETA", "resultados": []}
        zips = {"status": "COMPLETA", "resultados": [
            {"path": "wp-content/malware.zip", "state": "ZIP_PAYLOAD_REQUER_REVISAO"}]}
        self.assertIn("ZIP_SC_REQUER_REVISAO", sc.bloqueios_recuperacao(proc, zips))

    def test_bloqueio_recuperacao_cobertura_parcial(self):
        proc = {"status": "PARCIAL", "resultados": []}
        zips = {"status": "INCOMPLETA", "resultados": []}
        self.assertEqual(sc.bloqueios_recuperacao(proc, zips),
                         ["PROC_COBERTURA_INCOMPLETA", "ZIP_COBERTURA_INCOMPLETA"])

    def test_php_em_blocos_late_payload(self):
        with tempfile.TemporaryDirectory() as nome:
            caminho = Path(nome) / "grande.php"
            with caminho.open("wb") as out:
                out.write(b"A" * (9 * 1024 * 1024))
                out.write(b" SC_DB_BEGIN ")
            ioc, shell, cobertura = sc._amostra_php(caminho)
            self.assertTrue(ioc)
            self.assertFalse(shell)
            self.assertEqual(cobertura, "COMPLETA")


if __name__ == "__main__":
    unittest.main()
