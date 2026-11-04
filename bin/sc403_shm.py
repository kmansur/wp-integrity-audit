"""Inventário forense System V e validação estática de dumps relacionados ao SC.

Não anexa, lê ou remove segmentos SHM ativos. Nunca executa PHP.
Um SHA-256 contido no próprio dump verifica consistência interna, NÃO
autenticidade, origem ou vínculo com um segmento real do kernel.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

CABECALHO = re.compile(rb"\ASCSHM1:(?P<tamanho>\d{1,10}):(?P<sha256>[0-9a-f]{64})\r?\n")
VERSAO = re.compile(rb"SCV:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
NOME = re.compile(r"\Ashmid-([0-9]{1,10})\.bin\Z")
LIMITE_DUMP = 16 * 1024 * 1024
LIMITE_TOTAL = 64 * 1024 * 1024
LIMITE_ITENS = 32
LIMITE_PROC = 1024 * 1024
IOC = re.compile(rb"SC_ADV_BEGIN|SC_DB_BEGIN|SC_TH_BEGIN|sc_payload_persistent|"
                 rb"sc_persist_manifest|--sc-cli|--sc-succ|trace-inspector-pad|"
                 rb"kinetic-relay-live", re.I)


class EvidenciaSHMInvalida(ValueError):
    """O arquivo não pode ser processado nas condições de segurança previstas."""


def _ler_limitado(path: Path, limite: int) -> bytes:
    if path.is_symlink():
        raise EvidenciaSHMInvalida("Link simbólico não permitido")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limite:
            raise EvidenciaSHMInvalida("Arquivo não regular ou acima do limite")
        dados = stream.read(limite + 1)
        if len(dados) > limite:
            raise EvidenciaSHMInvalida("Limite de leitura atingido")
        depois = os.fstat(stream.fileno())
        if (info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns) != (
                depois.st_ino, depois.st_dev, depois.st_size, depois.st_mtime_ns):
            raise EvidenciaSHMInvalida("Arquivo foi alterado durante a coleta")
        return dados


def inventariar_kernel(tabela: Path = Path("/proc/sysvipc/shm")) -> dict:
    """Lê somente metadados do kernel; nenhum segmento é anexado."""
    if tabela.is_symlink():
        return {"status": "INCOMPLETA", "segmentos": [], "motivo": "TABELA_SIMBOLICA"}
    try:
        linhas = _ler_limitado(tabela, LIMITE_PROC).decode("ascii", "replace").splitlines()
    except (OSError, EvidenciaSHMInvalida):
        return {"status": "INCOMPLETA", "segmentos": [], "motivo": "TABELA_INACESSIVEL"}
    if not linhas:
        return {"status": "INCOMPLETA", "segmentos": [], "motivo": "CABECALHO_AUSENTE"}
    colunas = linhas[0].split()
    requeridas = {"shmid", "key", "size", "uid", "gid", "cpid", "lpid", "nattch"}
    if not requeridas.issubset(set(colunas)):
        return {"status": "INCOMPLETA", "segmentos": [], "motivo": "COLUNAS_AUSENTES"}
    registros = []
    erro = False
    for linha in linhas[1:]:
        campos = linha.split()
        if len(campos) != len(colunas):
            erro = True
            continue
        valores = dict(zip(colunas, campos))
        if not valores["shmid"].isdigit():
            erro = True
            continue
        registros.append({
            "source": "live_kernel_inventory",
            "shmid": int(valores["shmid"]),
            "key": valores["key"][:32], "bytes": valores["size"][:24],
            "uid": valores["uid"][:24], "gid": valores["gid"][:24],
            "cpid": valores["cpid"][:24], "lpid": valores["lpid"][:24],
            "nattch": valores["nattch"][:24],
            "classification": "SHM_SEGMENT_REQUER_CAPTURA",
            "content_read": False,
        })
        if len(registros) >= 10000:
            erro = True
            break
    return {"status": "INCOMPLETA" if erro else "COMPLETA",
            "segmentos": registros,
            "observacao": "Inventário do host, não atribuído a um site específico."}


def _inspecionar_dump(nome: str, blob: bytes, shmid: int) -> dict:
    reg = {"source": "forensic_dump", "path": nome,
           "shmid_declarado_no_nome": shmid,
           "file_size": len(blob),
           "file_sha256": hashlib.sha256(blob).hexdigest(),
           "content_read": True, "executado": False,
           "vinculo_com_kernel_confirmado": False}
    match = CABECALHO.match(blob)
    if match is None:
        reg.update({"classification": "SHM_DUMP_FORMAT_INVALID",
                    "header_valid": False})
        return reg
    tamanho = int(match.group("tamanho"))
    inicial = match.end()
    corpo = blob[inicial:inicial + tamanho]
    cauda = blob[inicial + tamanho:]
    valido_tamanho = len(corpo) == tamanho
    digest = hashlib.sha256(corpo).hexdigest()
    igual = digest == match.group("sha256").decode("ascii")
    versao = VERSAO.search(corpo) if valido_tamanho else None
    marcador = bool(IOC.search(corpo)) if valido_tamanho else False
    reg.update({
        "header_valid": True, "declared_payload_bytes": tamanho,
        "payload_available_bytes": min(len(blob) - inicial, tamanho),
        "payload_sha256": digest,
        "declared_sha256": match.group("sha256").decode("ascii"),
        "hash_match": bool(valido_tamanho and igual),
        "size_match": valido_tamanho,
        "version": versao.group(0).decode("ascii") if versao else None,
        "ioc_adicional": marcador,
        "tail_bytes": len(cauda),
        "tail_all_zero": not any(cauda),
    })
    if not valido_tamanho or not igual or any(cauda):
        reg["classification"] = "SHM_DUMP_REQUER_VALIDACAO"
    elif versao and marcador:
        reg["classification"] = "SHM_PAYLOAD_SCV_COMPATIVEL_REQUER_VALIDACAO"
    else:
        reg["classification"] = "SHM_DUMP_REQUER_VALIDACAO"
    return reg


def auditar(dump_dir: Path | None = None, *,
            tabela: Path = Path("/proc/sysvipc/shm")) -> dict:
    """Separa inventário live dos dumps; nenhum resultado conta duas vezes."""
    kernel = inventariar_kernel(tabela)
    resultado = {"schema_version": 1, "kernel": kernel,
                 "dumps": {"status": "NAO_SOLICITADO", "registros": [], "erros": []},
                 "liberacao_autorizada": False,
                 "observacao": "Metadados do host e arquivos de dump são evidências independentes; "
                               "nomes shmid não comprovam origem. Nenhuma memória ativa foi lida."}
    if dump_dir is None:
        return resultado
    if dump_dir.is_symlink():
        raise EvidenciaSHMInvalida("Diretório de dumps simbólico")
    raiz = dump_dir.resolve(strict=True)
    if not raiz.is_dir():
        raise EvidenciaSHMInvalida("Diretório de dumps inexistente")
    if stat.S_IMODE(raiz.stat().st_mode) & 0o077:
        raise EvidenciaSHMInvalida("Diretório dos dumps deve ter permissão privada (0700)")
    registros, erros = [], []
    arquivos = sorted(raiz.glob("shmid-*.bin"))
    if len(arquivos) > LIMITE_ITENS:
        raise EvidenciaSHMInvalida("Quantidade de dumps excede limite de 32")
    total = 0
    ids = set()
    for item in arquivos:
        match = NOME.fullmatch(item.name)
        if not match:
            erros.append({"arquivo": item.name[:128], "motivo": "NOME_INVALIDO"})
            continue
        shmid = int(match.group(1))
        if shmid in ids:
            erros.append({"arquivo": item.name[:128], "motivo": "SHMID_DUPLICADO"})
            continue
        ids.add(shmid)
        try:
            if item.lstat().st_size + total > LIMITE_TOTAL:
                raise EvidenciaSHMInvalida("ORCAMENTO_TOTAL_EXCEDIDO")
            blob = _ler_limitado(item, LIMITE_DUMP)
            total += len(blob)
            registros.append(_inspecionar_dump(item.name, blob, shmid))
        except (OSError, EvidenciaSHMInvalida) as exc:
            erros.append({"arquivo": item.name[:128], "motivo": type(exc).__name__})
    resultado["dumps"] = {
        "status": "INCOMPLETA" if erros else "COMPLETA",
        "registros": registros, "erros": erros,
        "total_lido_bytes": total,
    }
    return resultado
