#!/usr/bin/env python3
"""Quarentena reversível de arquivos ou diretórios WordPress previamente auditados.

Nunca executa PHP. Diretórios só podem ser movidos quando o operador informa o
caminho exato e todos os arquivos regulares têm evidência/hash correspondente.
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

class RemocaoRecusada(RuntimeError):
    """Arquivo não atende aos requisitos de quarentena segura."""

def leitura_segura(path: Path) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 30_000_000:
            raise RemocaoRecusada("Arquivo não regular ou maior que 30 MiB")
        conteudo = f.read(30_000_001)
        if len(conteudo) > 30_000_000:
            raise RemocaoRecusada("Arquivo maior que o limite")
        return conteudo, info

def validar(site: Path, caso: Path, relativo: str):
    if not re.fullmatch(r"wp-content/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", relativo) or ".." in relativo.split("/"):
        raise RemocaoRecusada("Caminho relativo fora de wp-content ou inválido")
    if caso.is_symlink() or not caso.is_dir() or stat.S_IMODE(caso.stat().st_mode) & 0o077:
        raise RemocaoRecusada("Caso precisa estar em diretório privado")
    raiz = site.resolve(strict=True)
    path = raiz / relativo
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise RemocaoRecusada("Links simbólicos não são admitidos")
    if (raiz / "wp-content").resolve(strict=True) not in path.parents:
        raise RemocaoRecusada("Arquivo fora do wp-content")
    evidencia = caso / "file-evidence.json"
    if evidencia.is_symlink() or not evidencia.is_file():
        raise RemocaoRecusada("Evidência de arquivos ausente")
    registros = json.loads(evidencia.read_text(encoding="utf-8"))
    candidatos = [v for v in registros if v.get("path") == relativo and
                  v.get("classification") == "IOC_REQUER_VALIDACAO"]
    if len(candidatos) != 1:
        raise RemocaoRecusada("Arquivo não tem indicador explícito na auditoria")
    dados, st = leitura_segura(path)
    digest = hashlib.sha256(dados).hexdigest()
    if candidatos[0].get("sha256") != digest:
        raise RemocaoRecusada("Hash mudou desde a auditoria")
    return path, digest, dados, st


def validar_diretorio(site: Path, caso: Path, relativo: str):
    if not re.fullmatch(r"wp-content/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", relativo):
        raise RemocaoRecusada("Diretório relativo inválido")
    raiz = site.resolve(strict=True)
    path = raiz / relativo
    content = (raiz / "wp-content").resolve(strict=True)
    if path.is_symlink() or not path.is_dir() or content not in path.parents:
        raise RemocaoRecusada("Diretório inexistente, link simbólico ou fora de wp-content")
    evidencia = caso / "file-evidence.json"
    if evidencia.is_symlink() or not evidencia.is_file():
        raise RemocaoRecusada("Evidência de arquivos ausente")
    registros = json.loads(evidencia.read_text(encoding="utf-8"))
    by_path = {v.get("path"): v for v in registros if isinstance(v, dict)}
    component_evidence = caso / "component-directory-evidence.json"
    if component_evidence.is_file() and not component_evidence.is_symlink():
        try:
            components = json.loads(component_evidence.read_text(encoding="utf-8"))
            for entries in components.values():
                for item in entries:
                    by_path.setdefault(item.get("path"), item)
        except (OSError, ValueError, AttributeError):
            raise RemocaoRecusada("Evidência de componente inválida")
    arquivos = []
    total = 0
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise RemocaoRecusada("Diretório contém link simbólico")
        if not item.is_file():
            continue
        rel = item.relative_to(raiz).as_posix()
        dados, info = leitura_segura(item)
        digest = hashlib.sha256(dados).hexdigest()
        registro = by_path.get(rel)
        if not registro or registro.get("sha256") != digest:
            raise RemocaoRecusada(f"Arquivo sem evidência correspondente ou hash alterado: {rel}")
        if registro.get("classification") not in {
            "IOC_REQUER_VALIDACAO", "ARQUIVO_SUSPEITO_REQUER_VALIDACAO",
            "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO", "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW",
            "PHP_OFUSCACAO_REQUER_QUARENTENA",
            "PLUGIN_FAMILIA_INCIDENTE_REQUER_QUARENTENA", "WORDPRESS_PERSISTENCE_REQUIRES_CONTEXT",
        }:
            raise RemocaoRecusada(f"Arquivo não classificado para quarentena: {rel}")
        total += len(dados)
        if total > 200_000_000:
            raise RemocaoRecusada("Diretório excede 200 MiB")
        arquivos.append((item, rel, digest, info))
    if not arquivos:
        raise RemocaoRecusada("Diretório sem arquivos regulares")
    return path, arquivos

def executar(site: Path, caso: Path, relativo: str, *, aplicar=False) -> dict:
    path, digest, dados, info = validar(site, caso, relativo)
    resultado = {"arquivo": relativo, "sha256": digest,
                 "estado": "QUARENTENA_APLICADA" if aplicar else "SIMULACAO"}
    if not aplicar:
        return resultado
    if os.geteuid() != 0:
        raise RemocaoRecusada("Aplicação exige root")
    ps = subprocess.run(["ps", "-eo", "args="], check=True, capture_output=True, text=True).stdout
    if any(s in linha for linha in ps.splitlines() for s in ("--sc-cli", "--sc-succ", "cipher-feeder", ".gr_")):
        raise RemocaoRecusada("Processos suspeitos ativos: isole e preserve antes de modificar arquivos")
    destino_dir = caso / "quarentena-wordpress"
    if destino_dir.is_symlink():
        raise RemocaoRecusada("Destino inválido")
    destino_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(destino_dir, 0o700)
    destino = destino_dir / (digest + "-" + path.name)
    fd = os.open(destino, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as saida:
        saida.write(dados)
        saida.flush()
        os.fsync(saida.fileno())
    novo, _ = leitura_segura(destino)
    atual, atual_stat = leitura_segura(path)
    if (hashlib.sha256(novo).hexdigest() != digest or
            hashlib.sha256(atual).hexdigest() != digest or
            (info.st_dev, info.st_ino) != (atual_stat.st_dev, atual_stat.st_ino)):
        raise RemocaoRecusada("Arquivo alterado antes da remoção; quarentena preservada")
    os.unlink(path)
    resultado["copia"] = str(destino)
    registro = destino_dir / (digest + ".json")
    fd = os.open(registro, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)
    return resultado


def executar_diretorio(site: Path, caso: Path, relativo: str, *, aplicar=False) -> dict:
    path, arquivos = validar_diretorio(site, caso, relativo)
    resultado = {"diretorio": relativo, "arquivos": len(arquivos),
                 "sha256": {rel: digest for _, rel, digest, _ in arquivos},
                 "estado": "QUARENTENA_APLICADA" if aplicar else "SIMULACAO"}
    if not aplicar:
        return resultado
    if os.geteuid() != 0:
        raise RemocaoRecusada("Aplicação exige root")
    ps = subprocess.run(["ps", "-eo", "args="], check=True, capture_output=True, text=True).stdout
    if any(s in linha for linha in ps.splitlines() for s in ("--sc-cli", "--sc-succ", "cipher-feeder", ".gr_")):
        raise RemocaoRecusada("Processos suspeitos ativos: isole e preserve antes de modificar arquivos")
    destino_root = caso / "quarentena-wordpress"
    destino_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(destino_root, 0o700)
    destino = destino_root / (hashlib.sha256(str(path).encode()).hexdigest()[:16] + "-" + path.name)
    if destino.exists() or destino.is_symlink():
        raise RemocaoRecusada("Destino de quarentena já existe")
    # Rename is atomic and reversible within the same filesystem.  Preserve
    # the original directory hierarchy in the case directory.
    path.rename(destino)
    resultado["copia"] = str(destino)
    registro = destino_root / (destino.name + ".json")
    fd = os.open(registro, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)
    return resultado

def main():
    p = argparse.ArgumentParser(description="Quarentena pontual de malware WordPress confirmado")
    p.add_argument("--site", required=True, type=Path)
    p.add_argument("--case", required=True, type=Path)
    grupo = p.add_mutually_exclusive_group(required=True)
    grupo.add_argument("--file", help="Caminho relativo exato dentro de wp-content")
    grupo.add_argument("--directory", help="Diretório relativo exato previamente evidenciado")
    modos = p.add_mutually_exclusive_group(required=True)
    modos.add_argument("--dry-run", action="store_true")
    modos.add_argument("--apply", action="store_true")
    args = p.parse_args()
    if args.apply and (not sys.stdin.isatty() or
                       input("Confirme isolamento, backup e evidência digitando QUARENTENA: ").strip() != "QUARENTENA"):
        raise RemocaoRecusada("Confirmação negada")
    resultado = (executar(args.site, args.case, args.file, aplicar=args.apply)
                 if args.file else executar_diretorio(args.site, args.case, args.directory, aplicar=args.apply))
    print(json.dumps(resultado,
                     indent=2, ensure_ascii=False))
    return 40 if args.apply else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RemocaoRecusada, OSError, ValueError, subprocess.CalledProcessError):
        print("ERRO: quarentena do WordPress recusada por validação de segurança", file=sys.stderr)
        sys.exit(30)
