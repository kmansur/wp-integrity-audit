"""Testes de correlação HTTP de endpoints derivados (logs artificiais)."""
import gzip
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import sc403_logs as logs


class TestLogsSC(unittest.TestCase):
    def test_contagem_sem_exportar_ips_ou_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_text(
                '192.0.2.13 - - [01/Nov/2026] "GET /?p=91234567 HTTP/1.1" 200 123 token=secret\n'
                '192.0.2.14 - - [01/Nov/2026] "POST /?p=92345678 HTTP/1.1" 404 5\n'
                '192.0.2.14 - - [01/Nov/2026] "GET /?p=912345678 HTTP/1.1" 404 5\n'
            )
            resultado = logs.auditar_logs([path], 91234567, 92345678)
            self.assertEqual(resultado["total_service_worker"], 1)
            self.assertEqual(resultado["total_instalador"], 1)
            self.assertNotIn("192.0.2.", str(resultado))
            self.assertNotIn("token=secret", str(resultado))

    def test_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log.gz"
            with gzip.open(path, "wb") as out:
                out.write(b'GET /wp-admin/?p=91234567 HTTP/1.1\n')
            self.assertEqual(logs.auditar_logs([path], 91234567, 92345678)
                             ["total_service_worker"], 1)

    def test_linha_muito_grande(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log"
            path.write_bytes(b"x" * 70000)
            result = logs.auditar_logs([path], 91234567, 92345678)
            self.assertEqual(result["status"], "INCOMPLETA")


if __name__ == "__main__":
    unittest.main()
