#!/usr/bin/env python3
"""Quarentena seletiva de persistência Linux previamente identificada na auditoria.

Não interrompe processos, desabilita systemd nem executa scripts investigados.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

RAIZES = (Path("/etc/cron.d"), Path("/etc/profile.d"), Path("/etc/systemd/system"))

class QuarentenaRecusada(RuntimeError):
    """Validação de segurança impediu operação."""

def hash_arquivo(caminho: Path) -> tuple[str, os.stat_result, bytes]:
    fd = os.open(caminho, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fonte:
        info = os.fstat(fonte.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4_000_000:
            raise QuarentenaRecusada("Arquivo não regular ou acima do limite de 4 MiB")
        dados = fonte.read(4_000_001)
        if len(dados) > 4_000_000:
            raise QuarentenaRecusada("Arquivo excede o limite")
        return hashlib.sha256(dados).hexdigest(), info, dados

def validar_candidato(caso: Path, caminho: Path, *, raizes=RAIZES) -> tuple[str, os.stat_result, bytes]:
    if caminho.is_symlink() or not caminho.is_absolute():
        raise QuarentenaRecusada("Exige caminho absoluto regular, sem links")
    if not any(caminho.parent.resolve(strict=True) == raiz.resolve(strict=True) for raiz in raizes):
        raise QuarentenaRecusada("Diretório não autorizado para quarentena automatizada")
    if caminho.parent == Path("/etc/systemd/system") and caminho.suffix not in (".service", ".timer"):
        raise QuarentenaRecusada("Somente unidades systemd service/timer podem ser selecionadas")
    evidencia = caso / "host-persistence.json"
    if evidencia.is_symlink() or not evidencia.is_file():
        raise QuarentenaRecusada("Inventário do Linux não localizado no caso")
    registros = json.loads(evidencia.read_text(encoding="utf-8"))
    encontrados = [x for x in registros if x.get("path") == str(caminho)
                   and x.get("classification") == "HOST_INDICATOR_REQUIRES_INVESTIGATION"]
    if len(encontrados) != 1:
        raise QuarentenaRecusada("Arquivo não consta como indicador no inventário")
    resumo, info, conteudo = hash_arquivo(caminho)
    if not re.fullmatch("[a-f0-9]{64}", str(encontrados[0].get("sha256", ""))) or resumo != encontrados[0]["sha256"]:
        raise QuarentenaRecusada("Hash do arquivo diverge da evidência; execute nova auditoria")
    return resumo, info, conteudo

def executar(caso: Path, caminho: Path, *, aplicar: bool, raizes=RAIZES) -> dict:
    if caso.is_symlink() or not caso.is_dir() or stat.S_IMODE(caso.stat().st_mode) & 0o077:
        raise QuarentenaRecusada("Diretório do caso deve ser privado e não pode ser link")
    resumo, info, conteudo = validar_candidato(caso, caminho, raizes=raizes)
    plano = {"arquivo": str(caminho), "sha256": resumo, "tamanho": len(conteudo),
             "estado": "SIMULACAO" if not aplicar else "QUARENTENA_APLICADA"}
    if not aplicar:
        return plano
    if os.geteuid() != 0:
        raise QuarentenaRecusada("Aplicação de quarentena no Linux exige root")
    if caminho.parent == Path("/etc/systemd/system"):
        # Arquivos de unidades ativas ou habilitadas exigem contenção manual e
        # análise de dependências, não alteração automática de serviços.
        ativo = subprocess.run(["systemctl", "is-active", caminho.name],
                               capture_output=True, text=True, check=False)
        habilitado = subprocess.run(["systemctl", "is-enabled", caminho.name],
                                    capture_output=True, text=True, check=False)
        if ativo.stdout.strip() != "inactive" or habilitado.stdout.strip() != "disabled":
            raise QuarentenaRecusada("Unidade systemd ativa/habilitada ou estado indefinido; intervenção manual obrigatória")
    vault = caso / "quarentena-linux"
    if vault.is_symlink():
        raise QuarentenaRecusada("Destino de quarentena inseguro")
    vault.mkdir(mode=0o700, exist_ok=True)
    os.chmod(vault, 0o700)
    destino = vault / (resumo + "-" + caminho.name)
    if destino.exists() or destino.is_symlink():
        raise QuarentenaRecusada("Arquivo já possui cópia em quarentena; não sobrescrever")
    fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as saida:
            saida.write(conteudo)
            saida.flush()
            os.fsync(saida.fileno())
        copia_hash, _, _ = hash_arquivo(destino)
        atual_hash, atual_info, _ = hash_arquivo(caminho)
        if (copia_hash != resumo or atual_hash != resumo or
                (info.st_dev, info.st_ino) != (atual_info.st_dev, atual_info.st_ino)):
            raise QuarentenaRecusada("Arquivo alterado antes da remoção; quarentena preservada")
        os.unlink(caminho)
    except BaseException:
        # Preservar a cópia em caso de falha para investigação; não tocar em outros arquivos.
        raise
    plano["copia"] = str(destino)
    if caminho.parent == Path("/etc/systemd/system"):
        plano["pendencia"] = "Avaliar systemctl daemon-reload e dependências; serviço não foi modificado"
    (vault / (resumo + ".json")).write_text(json.dumps(plano, indent=2, ensure_ascii=False) + "\n",
                                            encoding="utf-8")
    os.chmod(vault / (resumo + ".json"), 0o600)
    return plano

def main() -> int:
    p = argparse.ArgumentParser(description="Quarentena assistida de persistência Linux previamente evidenciada")
    p.add_argument("--case", type=Path, required=True, help="Diretório privado do caso de auditoria")
    p.add_argument("--file", type=Path, required=True, help="Caminho exato do arquivo em /etc/cron.d ou /etc/profile.d")
    modos = p.add_mutually_exclusive_group(required=True)
    modos.add_argument("--dry-run", action="store_true", help="Somente verificar elegibilidade")
    modos.add_argument("--apply", action="store_true", help="Aplicar quarentena após confirmação")
    args = p.parse_args()
    if args.apply:
        if not sys.stdin.isatty() or input("Confirme isolamento, backup e autorização digitando QUARENTENA: ").strip() != "QUARENTENA":
            raise QuarentenaRecusada("Confirmação negada")
    plano = executar(args.case, args.file, aplicar=args.apply)
    print(json.dumps(plano, indent=2, ensure_ascii=False))
    return 40 if args.apply else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QuarentenaRecusada, OSError, ValueError, json.JSONDecodeError) as erro:
        print("ERRO: não foi possível executar a quarentena seletiva com segurança", file=sys.stderr)
        sys.exit(30)
