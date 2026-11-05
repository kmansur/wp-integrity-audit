"""Inventário somente leitura de persistência Linux e cron.

Os arquivos são tratados como dados não confiáveis. Comandos Base64 são
decodificados apenas em memória para identificar marcadores; nunca são executados.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path
import re

MARCADORES = re.compile(r"SCV:[0-9]+|SCSHM1|sc_(?:reins|ini|fetch|cron|persist|last_)|kinetic-relay|cipher-feeder|defunct-kernel|trace-inspector|base64\s+-d", re.I)
BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/])")


def _arquivo(caminho: Path, limite: int = 262144) -> dict:
    registro = {"path": str(caminho)}
    try:
        if caminho.is_symlink() or not caminho.is_file():
            registro["estado"] = "NAO_REGULAR"
            return registro
        dado = caminho.read_bytes()[:limite]
        texto = dado.decode("utf-8", "replace")
        registro.update({"estado": "LIDO", "tamanho_bytes": caminho.stat().st_size,
                         "sha256_amostra": hashlib.sha256(dado).hexdigest(),
                         "marcadores": sorted(set(MARCADORES.findall(texto)))})
        codificados = []
        for candidato in BASE64.findall(texto):
            try:
                decodificado = base64.b64decode(candidato, validate=True)
            except (binascii.Error, ValueError):
                continue
            nomes = sorted(set(MARCADORES.findall(decodificado.decode("utf-8", "replace"))))
            if nomes:
                codificados.append({"tamanho": len(decodificado), "marcadores": nomes,
                                    "sha256": hashlib.sha256(decodificado).hexdigest()})
        registro["base64_com_marcador"] = codificados[:32]
    except OSError as erro:
        registro["estado"] = "LEITURA_INCOMPLETA"
        registro["erro"] = type(erro).__name__
    return registro


def auditar(caminhos: list[Path]) -> dict:
    registros = []
    erros = []
    for raiz in caminhos:
        raiz = Path(raiz)
        if raiz.is_symlink() or not raiz.is_dir():
            erros.append(f"RAIZ_INVALIDA:{raiz}")
            continue
        try:
            for caminho in sorted(raiz.rglob("*")):
                if caminho.is_symlink() or not caminho.is_file():
                    continue
                if caminho.name in {"crontab", "cron.allow", "cron.deny"} or "/cron" in str(caminho):
                    registros.append(_arquivo(caminho))
        except OSError:
            erros.append(f"FALHA_LEITURA:{raiz}")
    achados = [x for x in registros if x.get("marcadores") or x.get("base64_com_marcador")]
    return {"schema_version": 1, "cobertura": "COMPLETA" if not erros else "INCOMPLETA",
            "arquivos_inventariados": registros, "indicadores_requerendo_revisao": achados,
            "erros": erros, "executou_comandos": False,
            "observacao": "Decodificação Base64 foi somente em memória; nenhum comando foi executado."}
