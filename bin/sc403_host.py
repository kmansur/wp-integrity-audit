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
LIMITE_ARQUIVOS = 20000


def _raiz_segura(raiz: Path) -> Path:
    if not raiz.is_absolute() or raiz.is_symlink():
        raise ValueError("raiz de persistência deve ser absoluta e não simbólica")
    real = raiz.resolve(strict=True)
    if real == Path("/") or len(real.parts) < 3:
        raise ValueError("raiz de persistência ampla demais")
    return real


def _elegivel(caminho: Path) -> bool:
    texto = str(caminho)
    partes = set(caminho.parts)
    return ("cron" in texto or "systemd" in partes or "php" in partes or
            "apache" in partes or caminho.name in {"rc.local", "ld.so.preload"} or
            caminho.suffix in {".service", ".timer", ".socket", ".conf"})


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
        try:
            raiz = _raiz_segura(raiz)
        except (OSError, ValueError):
            erros.append(f"RAIZ_INVALIDA:{raiz}")
            continue
        try:
            for caminho in sorted(raiz.rglob("*")):
                if caminho.is_symlink() or not caminho.is_file():
                    continue
                if len(registros) >= LIMITE_ARQUIVOS:
                    erros.append("LIMITE_ARQUIVOS_ATINGIDO")
                    break
                if _elegivel(caminho):
                    registros.append(_arquivo(caminho))
        except OSError:
            erros.append(f"FALHA_LEITURA:{raiz}")
    achados = [x for x in registros if x.get("marcadores") or x.get("base64_com_marcador")]
    return {"schema_version": 1, "cobertura": "COMPLETA" if not erros else "INCOMPLETA",
            "arquivos_inventariados": registros, "indicadores_requerendo_revisao": achados,
            "erros": erros, "executou_comandos": False,
            "observacao": "Decodificação Base64 foi somente em memória; nenhum comando foi executado."}
