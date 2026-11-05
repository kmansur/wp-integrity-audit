"""Homologação sintética e descartável das barreiras de recuperação SC.

Este módulo nunca executa PHP, acessa banco real, reinicia serviços ou altera
um caminho recebido pelo operador. A fixture é criada em diretório temporário,
validada e destruída pelo sistema ao final da função.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

import sc403_plano


def _sha256(caminho: Path) -> str:
    return hashlib.sha256(caminho.read_bytes()).hexdigest()


def executar() -> dict:
    """Executa a homologação sintética e retorna somente resultados resumidos."""
    with tempfile.TemporaryDirectory(prefix="wp-integrity-homologacao-") as temporario:
        raiz = Path(temporario)
        site = raiz / "site"
        (site / "wp-content" / "uploads").mkdir(parents=True)
        (site / "wp-content" / "mu-plugins").mkdir(parents=True)
        (site / "wp-load.php").write_text("<?php // fixture não executável\n", encoding="utf-8")
        (site / "wp-config.php").write_text("<?php // configuração sintética\n", encoding="utf-8")
        for pasta in ("wp-admin", "wp-includes"):
            (site / pasta).mkdir()
        candidato = site / "wp-content" / "uploads" / "fixture.php"
        candidato.write_text("<?php /* SCV:4.3.24 sintético; não executar */\n", encoding="utf-8")
        digest_antes = _sha256(candidato)
        caso = raiz / "caso"
        caso.mkdir()
        (caso / "file-evidence.json").write_text(json.dumps([{
            "path": "wp-content/uploads/fixture.php",
            "classification": "IOC_REQUER_VALIDACAO",
        }]), encoding="utf-8")
        (caso / "database-evidence.json").write_text("[]", encoding="utf-8")
        (caso / "sc403-forense.json").write_text(json.dumps({
            "proc": {"status": "COMPLETA", "resultados": []},
            "zip": {"status": "COMPLETA", "resultados": []},
        }), encoding="utf-8")
        plano = sc403_plano.gerar_plano(caso)
        digest_depois = _sha256(candidato)
        return {
            "schema_version": 1,
            "status": "APROVADA_COM_BLOQUEIOS",
            "fixture_descartavel": True,
            "php_executado": False,
            "banco_real_acessado": False,
            "servicos_alterados": False,
            "evidencia_preservada": digest_antes == digest_depois,
            "plano_nao_executavel": not plano["execucao_automatica_autorizada"],
            "liberacao_nao_autorizada": not plano["liberacao_do_site_autorizada"],
            "bloqueios": plano["bloqueios"],
            "limitacoes": [
                "A fixture não representa todas as versões do WordPress ou do SC.",
                "Não valida restauração real de MySQL, Apache ou PHP-FPM.",
                "A aprovação demonstra apenas as barreiras sintéticas exercitadas.",
            ],
        }


if __name__ == "__main__":
    print(json.dumps(executar(), ensure_ascii=False, indent=2))
