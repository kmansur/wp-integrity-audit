#!/usr/bin/env python3
"""Comparação forense de dois casos para investigar reinfecção SC.

Não executa código WordPress, não modifica casos e nunca declara site liberado.
Exige evidências completas e hashes de manifesto íntegros em ambos os casos.
Crédito técnico: ux2dev/wordpress-sc403-cleaner (GPL-2.0-or-later).
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

MAX_JSON = 24 * 1024 * 1024
MAX_ARQUIVOS = 20000
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ComparacaoRecusada(RuntimeError):
    """Evidência inválida, insegura ou de instalação diferente."""


def _ler(caso: Path, nome: str):
    arquivo = caso / nome
    if arquivo.is_symlink() or not arquivo.is_file() or arquivo.stat().st_size > MAX_JSON:
        raise ComparacaoRecusada("Arquivo de evidência obrigatório ausente/inseguro: " + nome)
    fd = os.open(arquivo, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        dados = stream.read(MAX_JSON + 1)
    if len(dados) > MAX_JSON:
        raise ComparacaoRecusada("Evidência acima do limite")
    try:
        return json.loads(dados)
    except (ValueError, UnicodeDecodeError) as erro:
        raise ComparacaoRecusada("JSON inválido: " + nome) from erro


def _digest(caminho: Path, tamanho_esperado: int) -> str:
    fd = os.open(caminho, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != tamanho_esperado or info.st_size > MAX_JSON:
            raise ComparacaoRecusada("Arquivo alterado ou excede limite")
        resumo = hashlib.sha256()
        for bloco in iter(lambda: stream.read(262144), b""):
            resumo.update(bloco)
        return resumo.hexdigest()


def validar_manifesto(caso: Path) -> None:
    itens = _ler(caso, "evidence-manifest.json")
    if itens.get("algorithm") != "SHA-256" or not isinstance(itens.get("files"), list):
        raise ComparacaoRecusada("Manifesto não suportado")
    if len(itens["files"]) > MAX_ARQUIVOS:
        raise ComparacaoRecusada("Manifesto excede limite")
    conferidos = set()
    for item in itens["files"]:
        if not isinstance(item, dict):
            raise ComparacaoRecusada("Registro inválido no manifesto")
        nome, sha, tamanho = item.get("file"), item.get("sha256"), item.get("size_bytes")
        if (not isinstance(nome, str) or not nome or nome.startswith("/") or "\x00" in nome
                or ".." in Path(nome).parts or nome in conferidos
                or not isinstance(sha, str) or not SHA256.fullmatch(sha)
                or not isinstance(tamanho, int) or not 0 <= tamanho <= MAX_JSON):
            raise ComparacaoRecusada("Entrada de manifesto insegura")
        conferidos.add(nome)
        cursor = caso
        for parte in Path(nome).parts:
            cursor = cursor / parte
            if cursor.is_symlink():
                raise ComparacaoRecusada("Link simbólico em evidência")
        try:
            encontrado = _digest(caso / nome, tamanho)
        except OSError as erro:
            raise ComparacaoRecusada("Arquivo de evidência não pode ser lido") from erro
        if encontrado != sha:
            raise ComparacaoRecusada("Manifesto divergente: " + nome)
    ignorar = {"evidence-manifest.json", "evidence-bundle.tar.gz", "evidence-bundle.sha256"}
    atuais = set()
    for arquivo in caso.rglob("*"):
        if arquivo.is_symlink():
            raise ComparacaoRecusada("Link simbólico inesperado no caso")
        if arquivo.is_file() and arquivo.relative_to(caso).as_posix() not in ignorar:
            atuais.add(arquivo.relative_to(caso).as_posix())
    if atuais != conferidos:
        raise ComparacaoRecusada("Arquivos não inventariados no caso forense")


def _arquivos(entradas) -> dict[str, str]:
    if not isinstance(entradas, list):
        raise ComparacaoRecusada("Inventário de arquivos inválido")
    achados = {}
    for item in entradas:
        if not isinstance(item, dict):
            raise ComparacaoRecusada("Registro de arquivo inválido")
        nome, classificacao = item.get("path"), item.get("classification")
        if isinstance(nome, str) and isinstance(classificacao, str) and classificacao in {
            "IOC_REQUER_VALIDACAO", "SC_CAMINHO_DERIVADO_REQUER_REVISAO",
            "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO", "PHP_OFUSCACAO_REQUER_QUARENTENA",
            "WEB_SHELL_HEURISTIC_REQUIRES_REVIEW", "PHP_ANOMALIA_COMPORTAMENTAL_REQUER_REVISAO",
        }:
            achados[nome] = item.get("sha256") or "[HASH_INDISPONIVEL]"
    return achados


def _opcoes(entradas) -> dict[str, str]:
    if not isinstance(entradas, list):
        raise ComparacaoRecusada("Evidência SQL inválida")
    achados = {}
    for item in entradas:
        if not isinstance(item, dict):
            raise ComparacaoRecusada("Registro SQL inválido")
        if (item.get("kind") in {"sc403_derived_option", "family_option", "encoded_payload",
                                  "marker_option", "cron_marker", "cron_hook_anomaly"} and
                item.get("state") not in ("NOT_FOUND", "ABSENT") and
                isinstance(item.get("name"), str)):
            key = str(item.get("source_table_suffix", "options")) + ":" + item["name"]
            achados[key] = item.get("sha256") or "[HASH_INDISPONIVEL]"
    return achados


def comparar(anterior: Path, atual: Path) -> dict:
    if anterior.resolve(strict=True) == atual.resolve(strict=True):
        raise ComparacaoRecusada("É necessário informar dois casos distintos")
    for caminho in (anterior, atual):
        if caminho.is_symlink() or not caminho.is_dir():
            raise ComparacaoRecusada("Diretório do caso inválido")
        if stat.S_IMODE(caminho.stat().st_mode) & 0o077:
            raise ComparacaoRecusada("Caso precisa ter permissões privadas")
        validar_manifesto(caminho)
    antes = _ler(anterior, "sc403-identifiers.json")
    depois = _ler(atual, "sc403-identifiers.json")
    if (not isinstance(antes, dict) or not isinstance(depois, dict)
            or not isinstance(antes.get("abspath"), str)
            or antes.get("abspath") != depois.get("abspath")):
        raise ComparacaoRecusada("Não é possível comparar instalações com ABSPATH diferentes")
    pares = {}
    for categoria, seletor, origem in (
        ("arquivos", _arquivos, "file-evidence.json"),
        ("opcoes_sql", _opcoes, "database-evidence.json"),
    ):
        base = seletor(_ler(anterior, origem))
        novo = seletor(_ler(atual, origem))
        adicionados = sorted(novo.keys() - base.keys())
        removidos = sorted(base.keys() - novo.keys())
        alterados = sorted(k for k in base.keys() & novo.keys() if base[k] != novo[k])
        pares[categoria] = {
            "novos": adicionados, "ausentes_no_novo_caso": removidos,
            "hash_alterado": alterados, "persistentes": sorted(
                k for k in base.keys() & novo.keys() if base[k] == novo[k]),
        }
    procs_antes = _ler(anterior, "process-evidence.json")
    procs_agora = _ler(atual, "process-evidence.json")
    if not isinstance(procs_antes, list) or not isinstance(procs_agora, list):
        raise ComparacaoRecusada("Evidências de processos inválidas")
    dados_forense = _ler(atual, "sc403-forense.json")
    if not isinstance(dados_forense, dict) or not isinstance(dados_forense.get("proc"), dict) or not isinstance(dados_forense.get("zip"), dict) or not isinstance(dados_forense["proc"].get("resultados"), list):
        raise ComparacaoRecusada("Evidência de runtime inválida")
    incompleta = (dados_forense.get("proc", {}).get("status") != "COMPLETA"
                  or dados_forense.get("zip", {}).get("status") != "COMPLETA")
    suspeitos = [p for p in dados_forense.get("proc", {}).get("resultados", [])
                 if isinstance(p, dict) and p.get("state") == "PROC_SC_REQUER_INVESTIGACAO"]
    zip_atuais = dados_forense["zip"].get("resultados", [])
    if not isinstance(zip_atuais, list):
        raise ComparacaoRecusada("Inventário ZIP inválido")
    zip_suspeitos = [z.get("path") for z in zip_atuais
                    if isinstance(z, dict) and z.get("state") == "ZIP_PAYLOAD_REQUER_REVISAO"]
    novos = any(pares[k]["novos"] or pares[k]["hash_alterado"] for k in pares)
    persistentes = any(pares[k]["persistentes"] for k in pares)
    retorno = {
        "schema_version": 1, "tipo": "COMPARACAO_FORENSE_SC",
        "abspath": antes["abspath"], "caso_anterior": str(anterior),
        "caso_atual": str(atual),
        "integridade_casos": "VALIDADA_LOCALMENTE",
        "comparacao": pares,
        "indicadores_processo_anterior": len(procs_antes),
        "indicadores_processo_atual": len(procs_agora),
        "processos_suspeitos_runtime_atual": len(suspeitos),
        "arquivos_zip_com_indicadores_sc": sorted(p for p in zip_suspeitos if isinstance(p, str)),
        "cobertura_incompleta": incompleta,
        "estado": ("INDICIOS_DE_REINFECCAO_OU_NOVA_ATIVIDADE" if novos or
                   suspeitos or procs_agora or zip_suspeitos else
                   "INDICADORES_PERSISTENTES_REQUEREM_REVISAO" if persistentes else
                   "REVISAO_NECESSARIA_COBERTURA_INCOMPLETA" if incompleta else
                   "SEM_INDICADOR_NOS_DADOS_COMPARADOS"),
        "liberacao_autorizada": False,
        "nota": ("Ausência de novos indicadores não demonstra erradicação. "
                 "Mudanças de hash podem ocorrer legitimamente e exigem revisão humana."),
    }
    return retorno


def main() -> int:
    p = argparse.ArgumentParser(description="Comparar casos de WordPress para investigar reinfecção SC")
    p.add_argument("--anterior", type=Path, required=True)
    p.add_argument("--atual", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    resultado = comparar(args.anterior, args.atual)
    if args.output:
        destino = args.output.absolute()
        for raiz in (args.anterior.resolve(), args.atual.resolve()):
            if destino == raiz or raiz in destino.parents:
                raise ComparacaoRecusada("Saída não pode ficar dentro dos casos")
        if destino.parent.is_symlink() or destino.is_symlink():
            raise ComparacaoRecusada("Saída simbólica não permitida")
        fd = os.open(destino, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(resultado, stream, indent=2, ensure_ascii=False)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
    return 40


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ComparacaoRecusada, ValueError, OSError):
        print("ERRO: comparação forense recusada; valide os casos", file=sys.stderr)
        raise SystemExit(30)
