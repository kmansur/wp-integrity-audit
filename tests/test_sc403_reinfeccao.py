"""Testes da comparação forense SC com dois casos inteiramente sintéticos."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_reinfeccao as sc


def escrever(pasta, nome, obj):
    (pasta / nome).write_text(json.dumps(obj), encoding="utf-8")


def caso(pasta, *, raiz="/var/www/site/", arquivo="wp-content/a.php", digest="a" * 64,
         sql=None, processos=None):
    pasta.mkdir(mode=0o700)
    pasta.chmod(0o700)
    escrever(pasta, "sc403-identifiers.json", {"abspath": raiz})
    escrever(pasta, "file-evidence.json", [
        {"path": arquivo, "classification": "IOC_REQUER_VALIDACAO", "sha256": digest}
    ])
    escrever(pasta, "database-evidence.json", sql or [])
    escrever(pasta, "process-evidence.json", processos or [])
    escrever(pasta, "sc403-forense.json", {
        "proc": {"status": "COMPLETA", "resultados": []},
        "zip": {"status": "COMPLETA", "resultados": []},
    })
    arquivos = []
    for p in pasta.iterdir():
        dados = p.read_bytes()
        arquivos.append({"file": p.name, "sha256": hashlib.sha256(dados).hexdigest(),
                         "size_bytes": len(dados)})
    escrever(pasta, "evidence-manifest.json", {"algorithm": "SHA-256", "files": arquivos})


class TestReinfeccao(unittest.TestCase):
    def test_indicador_novo_exige_revisao(self):
        with tempfile.TemporaryDirectory() as temp:
            raiz = Path(temp)
            a, b = raiz / "anterior", raiz / "atual"
            caso(a)
            caso(b, arquivo="wp-content/b.php")
            resultado = sc.comparar(a, b)
            self.assertIn("wp-content/b.php", resultado["comparacao"]["arquivos"]["novos"])
            self.assertEqual(resultado["estado"], "INDICIOS_DE_REINFECCAO_OU_NOVA_ATIVIDADE")
            self.assertFalse(resultado["liberacao_autorizada"])

    def test_igualdade_nao_equivale_a_liberacao(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "a", Path(temp) / "b"
            caso(a)
            caso(b)
            resultado = sc.comparar(a, b)
            self.assertEqual(resultado["estado"], "INDICADORES_PERSISTENTES_REQUEREM_REVISAO")
            self.assertFalse(resultado["liberacao_autorizada"])

    def test_abspath_diferente_recusado(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "a", Path(temp) / "b"
            caso(a)
            caso(b, raiz="/var/www/outro/")
            with self.assertRaises(sc.ComparacaoRecusada):
                sc.comparar(a, b)

    def test_adulteracao_arquivo_manifesto_recusada(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "a", Path(temp) / "b"
            caso(a)
            caso(b)
            escrever(b, "file-evidence.json", [])
            with self.assertRaises(sc.ComparacaoRecusada):
                sc.comparar(a, b)

    def test_novo_objeto_sql(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b = Path(temp) / "a", Path(temp) / "b"
            caso(a)
            caso(b, sql=[{"kind": "sc403_derived_option", "name": "abcdef123456",
                          "state": "REVISAO_NECESSARIA", "sha256": "b" * 64}])
            resultado = sc.comparar(a, b)
            self.assertEqual(resultado["comparacao"]["opcoes_sql"]["novos"],
                             ["options:abcdef123456"])


if __name__ == "__main__":
    unittest.main()
