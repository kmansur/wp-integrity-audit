"""Correlação de endpoints SC em logs HTTP locais, sem exportar PII.

Não faz requisições HTTP e não grava IP, cookie, User-Agent ou linha do log.
"""
from __future__ import annotations
import gzip
from pathlib import Path
import re

LIMITE_ARQUIVO = 128 * 1024 * 1024
LIMITE_LINHAS = 2_000_000


def auditar_logs(caminhos: list[Path], endpoint_sw: int, endpoint_instalador: int) -> dict:
    """Conta referências exatas a ?p=<id> ou &p=<id> em logs Apache/Nginx."""
    if len(caminhos) > 20:
        return {"status": "INCOMPLETA", "motivo": "LIMITE_ARQUIVOS", "arquivos": []}
    patterns = {
        "service_worker": re.compile(rb"[?&]p=" + str(endpoint_sw).encode() + rb"(?![0-9])"),
        "instalador": re.compile(rb"[?&]p=" + str(endpoint_instalador).encode() + rb"(?![0-9])"),
    }
    resultados = []
    cobertura = "COMPLETA"
    for caminho in caminhos:
        item = {"arquivo": str(caminho), "service_worker": 0, "instalador": 0}
        try:
            if caminho.is_symlink() or not caminho.is_file() or caminho.stat().st_size > LIMITE_ARQUIVO:
                item["estado"] = "ARQUIVO_INDISPONIVEL_OU_GRANDE"
                cobertura = "INCOMPLETA"
                resultados.append(item)
                continue
            opener = gzip.open if caminho.suffix == ".gz" else open
            with opener(caminho, "rb") as stream:
                for indice, linha in enumerate(stream, 1):
                    if indice > LIMITE_LINHAS:
                        item["estado"] = "LIMITE_LINHAS"
                        cobertura = "INCOMPLETA"
                        break
                    for chave, expressao in patterns.items():
                        if expressao.search(linha):
                            item[chave] += 1
            item.setdefault("estado", "COMPLETA")
        except (OSError, EOFError, ValueError):
            item["estado"] = "FALHA_LEITURA"
            cobertura = "INCOMPLETA"
        resultados.append(item)
    return {
        "status": cobertura,
        "arquivos": resultados,
        "total_service_worker": sum(x["service_worker"] for x in resultados),
        "total_instalador": sum(x["instalador"] for x in resultados),
        "aviso": "Correspondências de URL não comprovam execução nem identidade de cliente.",
    }
