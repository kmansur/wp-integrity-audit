"""Testes sintéticos de inventário System V e dumps SC.

Não acessa a memória compartilhada real, não exige root e não executa PHP.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_shm as shm


def montar(payload: bytes, *, sha: str | None = None, tail: bytes = b"") -> bytes:
    digest = sha or hashlib.sha256(payload).hexdigest()
    return f"SCSHM1:{len(payload)}:{digest}\n".encode("ascii") + payload + tail


class TestSC403SHM(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.dump = self.root / "dumps"
        self.dump.mkdir(mode=0o700)
        self.dump.chmod(0o700)
        self.proc = self.root / "shm"
        self.proc.write_text(
            "key shmid perms size cpid lpid nattch uid gid\n"
            "0x00000000 27 600 4096 12 12 1 1000 1000\n",
            encoding="ascii",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_dump_e_kernel_sao_inventarios_separados(self):
        payload = b"<?php /* SCV:5.1.2 SC_ADV_BEGIN */" + b"A" * 128
        (self.dump / "shmid-27.bin").write_bytes(montar(payload, tail=b"\x00" * 64))
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(len(r["kernel"]["segmentos"]), 1)
        self.assertEqual(len(r["dumps"]["registros"]), 1)
        self.assertEqual(r["dumps"]["registros"][0]["classification"],
                         "SHM_PAYLOAD_SCV_COMPATIVEL_REQUER_VALIDACAO")
        self.assertTrue(r["dumps"]["registros"][0]["hash_match"])
        self.assertFalse(r["dumps"]["registros"][0]["vinculo_com_kernel_confirmado"])
        self.assertFalse(r["liberacao_autorizada"])

    def test_hash_invalido_e_revisao_do_dump_nao_do_kernel(self):
        payload = b"<?php /* SCV:4.5.7 SC_ADV_BEGIN */"
        (self.dump / "shmid-7.bin").write_bytes(montar(payload, sha="0" * 64))
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(r["dumps"]["registros"][0]["classification"],
                         "SHM_DUMP_REQUER_VALIDACAO")
        self.assertFalse(r["dumps"]["registros"][0]["hash_match"])

    def test_versao_sozinha_nao_comprova_comprometimento(self):
        payload = b"SCV:5.1.2"
        (self.dump / "shmid-7.bin").write_bytes(montar(payload))
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(r["dumps"]["registros"][0]["classification"],
                         "SHM_DUMP_REQUER_VALIDACAO")
        self.assertFalse(r["dumps"]["registros"][0]["ioc_adicional"])

    def test_dump_truncado_e_revisao(self):
        payload = b"SCV:5.1.2 SC_ADV_BEGIN"
        (self.dump / "shmid-7.bin").write_bytes(montar(payload)[:-5])
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertFalse(r["dumps"]["registros"][0]["size_match"])
        self.assertEqual(r["dumps"]["registros"][0]["classification"],
                         "SHM_DUMP_REQUER_VALIDACAO")

    def test_cabecalho_invalido(self):
        (self.dump / "shmid-7.bin").write_bytes(b"arquivo sem cabecalho")
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(r["dumps"]["registros"][0]["classification"],
                         "SHM_DUMP_FORMAT_INVALID")

    def test_arquivo_simbolico_incompleta(self):
        origem = self.root / "origem.bin"
        origem.write_bytes(montar(b"SCV:5.1.2"))
        (self.dump / "shmid-7.bin").symlink_to(origem)
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(r["dumps"]["status"], "INCOMPLETA")
        self.assertEqual(r["dumps"]["registros"], [])

    def test_limite_arquivo_muito_grande(self):
        with (self.dump / "shmid-7.bin").open("wb") as arq:
            arq.truncate(shm.LIMITE_DUMP + 1)
        r = shm.auditar(self.dump, tabela=self.proc)
        self.assertEqual(r["dumps"]["status"], "INCOMPLETA")
        self.assertEqual(r["dumps"]["registros"], [])

    def test_diretorio_publico_rejeitado(self):
        self.dump.chmod(0o755)
        with self.assertRaises(shm.EvidenciaSHMInvalida):
            shm.auditar(self.dump, tabela=self.proc)


if __name__ == "__main__":
    unittest.main()
