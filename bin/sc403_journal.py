"""Diário append-only verificável, sem alegar imutabilidade por si só."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path


def _linha(evento: dict, anterior: str, sequencia: int) -> tuple[str, str]:
    corpo = {"anterior": anterior, "evento": evento, "sequencia": sequencia}
    linha = json.dumps(corpo, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False)
    return linha, hashlib.sha256(linha.encode("utf-8")).hexdigest()


def _abrir_lock(caminho: Path) -> int:
    lock = caminho.with_name(caminho.name + ".lock")
    if caminho.parent.is_symlink() or lock.is_symlink():
        raise ValueError("diretório ou lock do diário é link simbólico")
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.chmod(lock, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def verificar(caminho: Path, ancora: str | None = None) -> dict:
    anterior = "0" * 64
    quantidade = 0
    if caminho.is_symlink():
        return {"válido": False, "motivo": "link simbólico"}
    if not caminho.exists():
        return {"válido": True, "eventos": 0, "hash_final": anterior}
    if not caminho.is_file():
        return {"válido": False, "motivo": "diário não é arquivo regular"}
    try:
        bruto = caminho.read_bytes()
        if bruto and not bruto.endswith(b"\n"):
            return {"válido": False, "motivo": "registro final incompleto", "linha": quantidade + 1}
        for texto in bruto.splitlines():
            registro = json.loads(texto.decode("utf-8"))
            linha = registro["linha"]
            digest = registro["hash"]
            if not isinstance(linha, str) or not isinstance(digest, str):
                raise ValueError
            if digest != hashlib.sha256(linha.encode("utf-8")).hexdigest():
                return {"válido": False, "motivo": "hash da linha divergente", "linha": quantidade + 1}
            objeto = json.loads(linha)
            if objeto.get("anterior") != anterior or objeto.get("sequencia") != quantidade + 1:
                return {"válido": False, "motivo": "cadeia ou sequência divergente", "linha": quantidade + 1}
            anterior = digest
            quantidade += 1
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"válido": False, "motivo": "diário inválido", "linha": quantidade + 1}
    if ancora is not None and ancora != anterior:
        return {"válido": False, "motivo": "âncora externa divergente", "linha": quantidade}
    return {"válido": True, "eventos": quantidade, "hash_final": anterior}


def registrar(caminho: Path, evento: dict, ancora: str | None = None) -> dict:
    """Acrescenta um evento com lock, escrita completa, flush e fsync."""
    if not isinstance(evento, dict):
        raise ValueError("evento deve ser objeto")
    fd_lock = _abrir_lock(caminho)
    try:
        estado = verificar(caminho, ancora=ancora)
        if not estado["válido"]:
            raise ValueError("diário inválido; não acrescentar evento")
        anterior = estado["hash_final"]
        linha, digest = _linha(evento, anterior, estado["eventos"] + 1)
        caminho.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if caminho.exists() and caminho.is_symlink():
            raise ValueError("diário tornou-se link simbólico")
        fd = os.open(str(caminho), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            dados = (json.dumps({"linha": linha, "hash": digest}, ensure_ascii=False,
                                sort_keys=True) + "\n").encode("utf-8")
            deslocamento = 0
            while deslocamento < len(dados):
                deslocamento += os.write(fd, dados[deslocamento:])
            os.fsync(fd)
        finally:
            os.close(fd)
        return {"hash": digest, "eventos": estado["eventos"] + 1}
    finally:
        fcntl.flock(fd_lock, fcntl.LOCK_UN)
        os.close(fd_lock)
