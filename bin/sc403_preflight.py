#!/usr/bin/env python3
"""Pré-validação segura de recuperação SC; não realiza operações destrutivas.

O objetivo é invalidar planos obsoletos antes de qualquer execução assistida:
vincula caso ao ABSPATH, confere manifesto e hashes, observa /proc e inventaria
pendências do banco, navegador e isolamento. Não altera site, banco ou processos.

Referência técnica: ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later).
Esta implementação é independente, em português, sem incorporar killchains.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sc403_forense
import sc403_indicadores
import sc403_plano

MAX_EVIDENCIA = 16 * 1024 * 1024
MAX_ARQUIVO = 64 * 1024 * 1024
MAX_ITENS = 10000
SHA = re.compile(r"^[0-9a-fA-F]{64}$")


class PreflightError(RuntimeError):
    """Falha em pré-condição que impede a avaliação segura."""


def _arquivo_privado(caminho: Path, limite: int = MAX_EVIDENCIA) -> bytes:
    if caminho.is_symlink():
        raise PreflightError("Evidência com link simbólico")
    fd = os.open(caminho, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limite:
            raise PreflightError("Evidência inválida ou excessiva")
        return f.read(limite + 1)


def _json(caso: Path, nome: str):
    try:
        return json.loads(_arquivo_privado(caso / nome))
    except (ValueError, OSError, UnicodeDecodeError) as erro:
        raise PreflightError("Evidência obrigatória indisponível ou inválida: " + nome) from erro


def _hash_arquivo(caminho: Path, limite: int = MAX_ARQUIVO) -> str | None:
    if caminho.is_symlink():
        return None
    fd = os.open(caminho, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limite:
            return None
        h = hashlib.sha256()
        for bloco in iter(lambda: f.read(262144), b""):
            h.update(bloco)
        if os.fstat(f.fileno()).st_size != info.st_size:
            return None
        return h.hexdigest()


def conferir_manifesto(caso: Path) -> dict:
    """Compara arquivos previstos, sem regravar o caso forense."""
    manifest = _json(caso, "evidence-manifest.json")
    if manifest.get("algorithm") != "SHA-256" or not isinstance(manifest.get("files"), list):
        raise PreflightError("Formato de manifesto inválido")
    itens = manifest["files"]
    if len(itens) > MAX_ITENS:
        raise PreflightError("Manifesto excede limite")
    divergencias, esperados = [], set()
    for item in itens:
        rel = item.get("file")
        digest = item.get("sha256")
        if (not isinstance(rel, str) or not rel or Path(rel).is_absolute() or
                ".." in Path(rel).parts or "\x00" in rel or rel in esperados or
                not isinstance(digest, str) or not SHA.fullmatch(digest)):
            raise PreflightError("Entrada de manifesto inválida")
        esperados.add(rel)
        atual = caso / rel
        try:
            confirmado = _hash_arquivo(atual)
        except OSError:
            confirmado = None
        if confirmado != digest.lower():
            divergencias.append(rel)
    # Um caso pode conter um pacote de evidências feito após o manifesto.
    ignorados = {"evidence-manifest.json", "evidence-bundle.tar.gz",
                 "evidence-bundle.sha256"}
    atuais = set()
    for item in caso.rglob("*"):
        if item.is_symlink():
            divergencias.append("LINK_SIMBOLICO_EM_CASO")
            continue
        if item.is_file():
            rel = item.relative_to(caso).as_posix()
            if rel not in ignorados:
                atuais.add(rel)
    divergencias.extend(sorted(atuais - esperados))
    return {"status": "VALIDO" if not divergencias else "DIVERGENTE",
            "arquivos_conferidos": len(itens),
            "divergencias": sorted(set(divergencias))[:200]}


def analisar(caso: Path, site: Path) -> dict:
    """Constrói parecer conservador sem conceder autorização de correção."""
    if caso.is_symlink() or site.is_symlink():
        raise PreflightError("Caminhos simbólicos proibidos")
    caso = caso.resolve(strict=True)
    site = site.resolve(strict=True)
    if not caso.is_dir() or not site.is_dir() or caso == site or site in caso.parents or caso in site.parents:
        raise PreflightError("Site e caso devem estar em diretórios independentes")
    if stat.S_IMODE(caso.stat().st_mode) & 0o077:
        raise PreflightError("Diretório do caso não é privado (0700 esperado)")
    if not all((site / p).exists() for p in ("wp-config.php", "wp-content", "wp-includes")):
        raise PreflightError("Diretório não parece instalação WordPress")
    identificadores = _json(caso, "sc403-identifiers.json")
    esperado = sc403_indicadores.raiz_normalizada(site)
    if identificadores.get("abspath") != esperado:
        raise PreflightError("ABSPATH do caso diverge do diretório analisado")
    manifesto = conferir_manifesto(caso)
    evidencias = _json(caso, "file-evidence.json")
    if not isinstance(evidencias, list):
        raise PreflightError("Inventário de arquivos inválido")
    plano = _json(caso, "sc403-recovery-plan.json")
    if plano.get("tipo") != "PLANO_TECNICO_NAO_EXECUTAVEL":
        raise PreflightError("Plano SC ausente ou incompatível")
    divergencias = []
    verificados = 0
    bytes_conferidos = 0
    maximo_bytes = 512 * 1024 * 1024
    for registro in evidencias:
        if not isinstance(registro, dict):
            raise PreflightError("Registro de arquivo inválido")
        rel, digest = registro.get("path"), registro.get("sha256")
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise PreflightError("Caminho suspeito no inventário")
        if not isinstance(digest, str) or not SHA.fullmatch(digest):
            divergencias.append({"arquivo": rel, "motivo": "HASH_ORIGINAL_AUSENTE"})
            continue
        caminho = site / rel
        try:
            tamanho_arquivo = caminho.lstat().st_size
        except OSError:
            tamanho_arquivo = 0
        if bytes_conferidos + tamanho_arquivo > maximo_bytes:
            divergencias.append({"arquivo": rel, "motivo": "ORCAMENTO_BYTES_EXCEDIDO"})
            break
        bytes_conferidos += tamanho_arquivo
        # Inspecionar componentes intermediários evita seguir symlinks.
        cursor = site
        simbolico = False
        for parte in Path(rel).parts:
            cursor = cursor / parte
            if cursor.is_symlink():
                simbolico = True
                break
        if simbolico:
            divergencias.append({"arquivo": rel, "motivo": "LINK_SIMBOLICO"})
            continue
        try:
            novo = _hash_arquivo(caminho)
        except OSError:
            novo = None
        verificados += 1
        if novo != digest.lower():
            divergencias.append({"arquivo": rel, "motivo": "ALTERADO_AUSENTE_OU_NAO_VERIFICAVEL"})
        if verificados >= MAX_ITENS:
            divergencias.append({"arquivo": "[LIMITE]", "motivo": "LIMITE_INVENTARIO"})
            break
    runtime = sc403_forense.inspecionar_proc(site)
    proc_criticos = [i["pid"] for i in runtime.get("resultados", [])
                     if i.get("state") == "PROC_SC_REQUER_INVESTIGACAO"]
    bloqueios = list(plano.get("bloqueios", []))
    if manifesto["status"] != "VALIDO":
        bloqueios.append("INTEGRIDADE_CASO_NAO_CONFIRMADA")
    if divergencias:
        bloqueios.append("ARQUIVOS_ALTERADOS_DESDE_AUDITORIA")
    if runtime.get("status") != "COMPLETA":
        bloqueios.append("PROCESSOS_COBERTURA_INCOMPLETA")
    if proc_criticos:
        bloqueios.append("PROCESSOS_SUSPEITOS_ATIVOS")
    # O sistema não consegue provar a revogação dos service workers de
    # todos os navegadores, nem o isolamento do site ou a restauração de backup.
    bloqueios.extend(("BACKUP_RESTAURAVEL_NAO_COMPROVADO",
                     "ISOLAMENTO_DO_SITE_NAO_COMPROVADO",
                     "SERVICES_WORKERS_E_SESSOES_NAO_COMPROVADOS",
                     "BANCO_SQL_ATUAL_NAO_REVALIDADO"))
    return {
        "schema_version": 1,
        "site": str(site), "caso": str(caso),
        "estado": "NAO_APTO_PARA_RECUPERACAO_AUTOMATICA",
        "alteracoes_executadas": False,
        "liberacao_autorizada": False,
        "manifesto": manifesto,
        "hashes_arquivos": {"verificados": verificados,
                            "divergencias": divergencias[:200]},
        "processos": {"cobertura": runtime.get("status"),
                      "pids_suspeitos": sorted(proc_criticos)},
        "bloqueios": sorted(set(bloqueios)),
        "procedimento": [
            "Preservar o caso original e verificar backups por restauração.",
            "Confirmar autorização formal, contenção e isolamento por domínio.",
            "Conferir processos, /proc, System V, php-fpm, Apache, cron e banco.",
            "Revisar e executar quarentena pontual somente de IOCs confirmados.",
            "Corrigir banco com seleção exata e comparação otimista de hash.",
            "Neutralizar service workers e invalidar sessões dos administradores.",
            "Executar auditoria independente posterior, comparar casos e aprovar liberação manualmente.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pré-validação de recuperação SC (somente leitura)")
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Arquivo JSON fora do site e do caso (não sobrescreve)")
    args = parser.parse_args()
    resultado = analisar(args.case, args.site)
    if args.output is not None:
        destino = args.output.absolute()
        # Diretório de saída também não pode passar por links simbólicos.
        if destino.parent.is_symlink() or destino.parent.resolve(strict=True) != destino.parent:
            raise PreflightError("Diretório de saída deve ser um caminho físico sem links")
        site = args.site.resolve(strict=True)
        caso = args.case.resolve(strict=True)
        if (destino == site or site in destino.parents or destino == caso or
                caso in destino.parents or destino.is_symlink()):
            raise PreflightError("Saída deve ficar fora do site e do caso")
        fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as arquivo:
            json.dump(resultado, arquivo, ensure_ascii=False, indent=2)
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    return 40


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PreflightError, OSError, ValueError, json.JSONDecodeError):
        print("ERRO: pré-validação recusada; verifique caminhos, evidências e permissões", file=sys.stderr)
        raise SystemExit(30)
