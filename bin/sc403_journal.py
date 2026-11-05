"""Diário append-only com cadeia SHA-256; não executa operações."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _linha(evento: dict, anterior: str) -> tuple[str, str]:
    corpo = {"anterior": anterior, "evento": evento}
    linha = json.dumps(corpo, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return linha, hashlib.sha256(linha.encode()).hexdigest()


def verificar(caminho: Path) -> dict:
    anterior = "0" * 64
    quantidade = 0
    if not caminho.exists():
        return {"válido": True, "eventos": 0, "hash_final": anterior}
    if caminho.is_symlink():
        return {"válido": False, "motivo": "link simbólico"}
    try:
        for bruto in caminho.read_text(encoding="utf-8").splitlines():
            registro = json.loads(bruto)
            if registro.get("hash") != hashlib.sha256(registro["linha"].encode()).hexdigest():
                return {"válido": False, "motivo": "hash da linha divergente", "linha": quantidade + 1}
            linha = json.loads(registro["linha"])
            if linha.get("anterior") != anterior:
                return {"válido": False, "motivo": "cadeia divergente", "linha": quantidade + 1}
            anterior = registro["hash"]
            quantidade += 1
    except (OSError, ValueError, KeyError, TypeError):
        return {"válido": False, "motivo": "diário inválido", "linha": quantidade + 1}
    return {"válido": True, "eventos": quantidade, "hash_final": anterior}


def registrar(caminho: Path, evento: dict) -> dict:
    estado = verificar(caminho)
    if not estado["válido"]:
        raise ValueError("diário inválido; não acrescentar evento")
    anterior = estado["hash_final"]
    linha, digest = _linha(evento, anterior)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    with caminho.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"linha": linha, "hash": digest}, ensure_ascii=False, sort_keys=True) + "\n")
    return {"hash": digest, "eventos": estado["eventos"] + 1}
