"""Testes dos indicadores SC 4.x. Somente arquivos temporários e dados inertes."""
import base64
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_indicadores as sc


class TestIndicadoresSC403(unittest.TestCase):
    def test_iocs_csv_alta_confianca_tem_marcadores_e_opcoes_relevantes(self):
        self.assertIn("SC_TH_BEGIN", sc.CSV_MARCADORES_ALTA_CONFIANCA)
        self.assertIn("sc_payload_persistent", sc.CSV_OPCOES_ALTA_CONFIANCA)
        self.assertTrue(sc.MARCADOR_FORTE.search(b"SC_WC sc_c2_cache"))
    def test_derivacao_abspath_e_endpoints(self):
        raiz = "/var/www/site/"
        dados = sc.identificadores(raiz)
        self.assertEqual(dados["abspath"], raiz)
        self.assertEqual(
            dados["arquivos"]["loader_visivel"],
            "wp-content/" + hashlib.md5((raiz + "htl").encode()).hexdigest()[:8] + ".php",
        )
        self.assertEqual(
            dados["opcoes"]["sw_url"],
            hashlib.md5((raiz + "93819sw_url").encode()).hexdigest()[:12],
        )
        self.assertEqual(
            dados["endpoint_sw"],
            91000000 + int(hashlib.md5((raiz + "epsw").encode()).hexdigest()[:7], 16) % 8999999,
        )
        self.assertEqual(sc.identificadores(raiz[:-1]), dados)

    def test_xor_estatico_nao_vaza_conteudo(self):
        bruto = b'a:1:{s:1:"x";s:12:"SC_ADV_BEGIN";}'
        chave = 77
        valor = base64.b64encode(bytes([chave]) + bytes(b ^ chave for b in bruto))
        achado = sc.decodificar_opcao(valor)
        self.assertEqual(achado["estado"], "DECODIFICADO")
        self.assertTrue(achado["formato_serializado_aparente"])
        self.assertIn("SC_ADV_BEGIN", achado["marcadores"])
        self.assertNotIn("conteudo", achado)
        self.assertNotIn(bruto.decode(), str(achado))

    def test_decodificacao_invalida_e_limites(self):
        self.assertNotEqual(sc.decodificar_opcao(b"nao-base64!")["estado"], "DECODIFICADO")
        self.assertNotEqual(sc.decodificar_opcao(b"A" * 200000)["estado"], "DECODIFICADO")

    def test_arquivo_derivado_e_ausencia(self):
        with tempfile.TemporaryDirectory() as pasta:
            raiz = Path(pasta)
            esperado = sc.identificadores(raiz)["arquivos"]["loader_visivel"]
            arquivo = raiz / esperado
            arquivo.parent.mkdir(parents=True)
            self.assertEqual(sc.investigar_arquivos(raiz), [])
            arquivo.write_bytes(b"<?php /* SC_ADV_BEGIN */")
            achados = sc.investigar_arquivos(raiz)
            self.assertEqual(len(achados), 1)
            self.assertEqual(achados[0]["classification"], "IOC_REQUER_VALIDACAO")
            self.assertEqual(achados[0]["path"], esperado)

    def test_opcoes_derivadas_omitidas(self):
        dados = sc.identificadores("/var/www/site")
        chave = dados["opcoes"]["sw_url"]
        valor = b"a:0:{}"
        xor = 12
        texto = base64.b64encode(bytes([xor]) + bytes(x ^ xor for x in valor))
        linha = [chave, str(len(texto)), hashlib.sha256(texto).hexdigest(), texto.hex()]
        achados = sc.linhas_opcoes([linha], dados)
        self.assertEqual(len(achados), 1)
        self.assertEqual(achados[0]["state"], "REVISAO_NECESSARIA")
        self.assertEqual(achados[0]["decodificacao"]["estado"], "DECODIFICADO")
        self.assertNotIn(texto.decode(), str(achados))
        with self.assertRaises(ValueError):
            sc.linhas_opcoes([[chave, "8", "errado", "zz"]], dados)


if __name__ == "__main__":
    unittest.main()
