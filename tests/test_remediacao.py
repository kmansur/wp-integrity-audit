"""Ensaios isolados de remediação de persistência Linux; sem modificar /etc."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "remediar_persistencia_linux.py"
spec = importlib.util.spec_from_file_location("remediar_persistencia_linux", SCRIPT)
modulo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modulo)


class PersistenciaLinuxTests(unittest.TestCase):
    def preparar(self, diretorio):
        raiz = Path(diretorio)
        caso = raiz / "caso"
        caso.mkdir(mode=0o700)
        scripts = raiz / "cron.d"
        scripts.mkdir()
        arquivo = scripts / "teste_infectado"
        arquivo.write_text("# padrão sintético sc_cron_guard\n", encoding="utf-8")
        hash_ = hashlib.sha256(arquivo.read_bytes()).hexdigest()
        (caso / "host-persistence.json").write_text(json.dumps([
            {"path": str(arquivo), "sha256": hash_,
             "classification": "HOST_INDICATOR_REQUIRES_INVESTIGATION"}
        ]), encoding="utf-8")
        return caso, scripts, arquivo

    def test_simulacao_preserva_arquivo(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso, scripts, arquivo = self.preparar(pasta)
            resultado = modulo.executar(caso, arquivo, aplicar=False, raizes=(scripts,))
            self.assertEqual(resultado["estado"], "SIMULACAO")
            self.assertTrue(arquivo.exists())
            self.assertFalse((caso / "quarentena-linux").exists())

    def test_quarentena_preserva_copia_e_remove_apenas_arquivo_identificado(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso, scripts, arquivo = self.preparar(pasta)
            outro = scripts / "servico_legitimo"
            outro.write_text("legitimo", encoding="utf-8")
            with mock.patch.object(modulo.os, "geteuid", return_value=0):
                resultado = modulo.executar(caso, arquivo, aplicar=True, raizes=(scripts,))
            self.assertFalse(arquivo.exists())
            self.assertTrue(outro.exists())
            copia = Path(resultado["copia"])
            self.assertEqual(copia.read_text(), "# padrão sintético sc_cron_guard\n")
            self.assertEqual(stat.S_IMODE(copia.stat().st_mode), 0o600)
            self.assertTrue((copia.parent / (resultado["sha256"] + ".json")).exists())

    def test_hash_divergente_bloqueia_sem_alterar(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso, scripts, arquivo = self.preparar(pasta)
            arquivo.write_text("conteudo alterado")
            with self.assertRaises(modulo.QuarentenaRecusada):
                modulo.executar(caso, arquivo, aplicar=False, raizes=(scripts,))
            self.assertTrue(arquivo.exists())

    def test_evidencia_ausente_e_link_simbolico_sao_recusados(self):
        with tempfile.TemporaryDirectory() as pasta:
            caso, scripts, arquivo = self.preparar(pasta)
            link = scripts / "link_malicioso"
            link.symlink_to(arquivo)
            with self.assertRaises(modulo.QuarentenaRecusada):
                modulo.executar(caso, link, aplicar=False, raizes=(scripts,))
            (caso / "host-persistence.json").unlink()
            with self.assertRaises(modulo.QuarentenaRecusada):
                modulo.executar(caso, arquivo, aplicar=False, raizes=(scripts,))


if __name__ == "__main__":
    unittest.main()
