"""Verificações complementares do SC WordPress Malware (somente leitura).

Referências técnicas:
- ux2dev/wordpress-sc403-cleaner, GPL-2.0-or-later
- rfxn/linux-malware-detect, GPL-2.0: monitoramento e defesa em camadas
- nbs-system/php-malware-finder, LGPL-3.0: detecção estática

Esta implementação não copia rotinas destrutivas nem executa PHP.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

IOC = re.compile(rb"SC_ADV_BEGIN|SC_DB_BEGIN|SC_TH_BEGIN|SCV:[0-9]+|"
                 rb"sc_payload_persistent|sc_persist_manifest|--sc-cli|--sc-succ|"
                 rb"trace-inspector-pad|kinetic-relay-live|sc_own_manifest", re.I)
LIMITE_ZIP = 64 * 1024 * 1024
LIMITE_ITEM = 8 * 1024 * 1024
LIMITE_ITENS = 2500
LIMITE_SCAN = 32 * 1024 * 1024
RE_SHELL = re.compile(rb"eval\s*\(\s*base64_decode\s*\(|gzinflate\s*\(\s*base64_decode", re.I)


def _sha256_arquivo(caminho: Path, limite: int = LIMITE_SCAN) -> tuple[str | None, bool]:
    """Hash completo apenas para arquivo limitado; falso quando cobertura incompleta."""
    tamanho = caminho.stat().st_size
    if tamanho > limite:
        return None, False
    h = hashlib.sha256()
    with caminho.open("rb") as stream:
        for bloco in iter(lambda: stream.read(262144), b""):
            h.update(bloco)
    return h.hexdigest(), True


def _amostra_php(arquivo: Path, maximo: int = LIMITE_SCAN) -> tuple[bool, bool, str]:
    """Scanner contínuo em blocos para não perder marcadores após os primeiros 8 MiB."""
    tamanho = arquivo.stat().st_size
    if tamanho > maximo:
        return False, False, "LIMITE_EXCEDIDO"
    marcador, shell = False, False
    overlap = b""
    with arquivo.open("rb") as stream:
        for bloco in iter(lambda: stream.read(262144), b""):
            janela = overlap + bloco
            marcador |= bool(IOC.search(janela))
            shell |= bool(RE_SHELL.search(janela))
            overlap = janela[-256:]
    return marcador, shell, "COMPLETA"


def inspecionar_zips(raiz: Path, maximo_arquivos: int = 15000) -> dict:
    """Analisa metadados de ZIP e amostras limitadas de PHP sem extrair em disco.

    Não aceita links simbólicos, arquivos muito grandes ou índices excessivos.
    """
    resultados = []
    verificados = 0
    erros = []
    for diretorio, pastas, arquivos in os.walk(raiz, followlinks=False):
        pastas[:] = [p for p in pastas if not (Path(diretorio) / p).is_symlink()]
        for nome in arquivos:
            verificados += 1
            if verificados > maximo_arquivos:
                return {"status": "INCOMPLETA", "motivo": "LIMITE_INVENTARIO",
                        "resultados": resultados, "erros": erros}
            if not nome.lower().endswith(".zip"):
                continue
            caminho = Path(diretorio) / nome
            if caminho.is_symlink():
                continue
            relativo = caminho.relative_to(raiz).as_posix()
            try:
                tamanho = caminho.stat().st_size
                if tamanho > LIMITE_ZIP:
                    resultados.append({"path": relativo, "state": "ZIP_NAO_INSPECIONADO_LIMITE",
                                        "size": tamanho, "confidence": "BAIXA"})
                    continue
                if not zipfile.is_zipfile(caminho):
                    continue
                encontrados = []
                total = 0
                with zipfile.ZipFile(caminho) as pacote:
                    itens = pacote.infolist()
                    if len(itens) > LIMITE_ITENS:
                        resultados.append({"path": relativo, "state": "ZIP_NAO_INSPECIONADO_LIMITE",
                                            "size": tamanho, "confidence": "BAIXA"})
                        continue
                    for item in itens:
                        total += item.file_size
                        if total > LIMITE_ZIP:
                            raise ValueError("ZIP excede orçamento de descompressão")
                        nome_interno = item.filename.replace("\\", "/")
                        if (item.is_dir() or not nome_interno.lower().endswith((".php", ".phtml", ".phar"))
                                or item.file_size > LIMITE_ITEM):
                            continue
                        with pacote.open(item) as stream:
                            trecho = stream.read(min(item.file_size, LIMITE_ITEM) + 1)
                        marcadores = bool(IOC.search(trecho))
                        shell = bool(RE_SHELL.search(trecho))
                        if marcadores or shell:
                            encontrados.append({"member": nome_interno[:512],
                                                "ioc": marcadores, "webshell": shell})
                if encontrados:
                    resultados.append({"path": relativo, "state": "ZIP_PAYLOAD_REQUER_REVISAO",
                                        "size": tamanho, "confidence": "ALTA" if any(x["ioc"] for x in encontrados) else "MEDIA",
                                        "members": encontrados[:30]})
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as erro:
                erros.append({"path": relativo, "reason": type(erro).__name__})
    return {"status": "INCOMPLETA" if erros else "COMPLETA",
            "resultados": resultados, "erros": erros}


def inspecionar_php_config(raiz: Path) -> dict:
    """Lê apenas configurações pontuais sem divulgar seus valores completos."""
    candidatos = [raiz / ".user.ini", raiz / "php.ini", raiz / ".htaccess",
                  raiz / "wp-content" / ".user.ini", raiz / "wp-content" / ".htaccess"]
    resultados = []
    for arquivo in candidatos:
        try:
            if arquivo.is_symlink() or not arquivo.is_file():
                continue
            if arquivo.stat().st_size > 1024 * 1024:
                resultados.append({"path": arquivo.relative_to(raiz).as_posix(),
                                    "state": "CONFIG_GRANDE_REQUER_REVISAO"})
                continue
            dados = arquivo.read_bytes()
            chaves = sorted(set(x.decode("ascii") for x in
                re.findall(rb"(?i)\b(?:auto_prepend_file|auto_append_file|"
                           rb"allow_url_include|php_value|AddHandler|SetHandler|"
                           rb"RewriteRule)\b", dados)))
            if chaves:
                resultados.append({"path": arquivo.relative_to(raiz).as_posix(),
                                    "state": "CONFIG_PHP_REQUER_CONTEXTO",
                                    "directives": chaves,
                                    "ioc": bool(IOC.search(dados))})
        except (OSError, UnicodeError):
            resultados.append({"path": arquivo.relative_to(raiz).as_posix(),
                                "state": "CONFIG_LEITURA_INCOMPLETA"})
    return {"resultados": resultados}


def inspecionar_proc(raiz: Path, proc_root: Path = Path("/proc"),
                    maximo: int = 30000) -> dict:
    """Relaciona processos com o site, mapeamentos anômalos e arquivos apagados.

    Não lê memória, segredos nem conteúdo de fd. Não encerra processos.
    """
    resultado = []
    erros = []
    vistos = 0
    falhas_acesso = 0
    base = str(raiz.resolve())
    try:
        pids = [p for p in proc_root.iterdir() if p.name.isdecimal()]
    except OSError:
        return {"status": "INCOMPLETA", "reason": "PROC_INDISPONIVEL", "resultados": []}
    for pid_dir in pids:
        vistos += 1
        if vistos > maximo:
            return {"status": "INCOMPLETA", "reason": "LIMITE_PROCESSOS", "resultados": resultado}
        try:
            raw = (pid_dir / "cmdline").read_bytes()[:8192]
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", "backslashreplace")
            # Não persistir argv (pode conter senhas); apenas booleanos e PID.
            pertence = base in cmd
            indicador = bool(IOC.search(raw))
            arquivo_removido = False
            fd = pid_dir / "fd"
            if pertence or indicador:
                try:
                    for entrada in list(fd.iterdir())[:512]:
                        try:
                            destino = os.readlink(entrada)
                        except OSError:
                            continue
                        if "(deleted)" in destino and (base in destino or ".sc_" in destino):
                            arquivo_removido = True
                            break
                except OSError:
                    pass
                resultado.append({"pid": int(pid_dir.name), "site_associado": pertence,
                                  "indicador_comando": indicador,
                                  "arquivo_removido_aberto": arquivo_removido,
                                  "state": "PROC_SC_REQUER_INVESTIGACAO" if indicador or arquivo_removido
                                  else "PROCESSO_ASSOCIADO_INVENTARIADO"})
        except OSError as erro:
            if erro.errno not in (errno.ENOENT, errno.ESRCH):
                falhas_acesso += 1
            continue
    return {"status": "PARCIAL" if falhas_acesso else "COMPLETA",
            "resultados": resultado, "erros": erros,
            "processos_sem_acesso": falhas_acesso}


def inventario_sysv() -> dict:
    """Inventaria System V IPC por ipcs; segmentos não são lidos ou removidos."""
    try:
        processo = subprocess.run(["ipcs", "-m"], capture_output=True, check=False,
                                 timeout=10, text=True, errors="backslashreplace")
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NAO_DISPONIVEL", "segmentos": []}
    if processo.returncode:
        return {"status": "INCOMPLETA", "segmentos": []}
    linhas = []
    for linha in processo.stdout.splitlines():
        campos = linha.split()
        if len(campos) >= 6 and campos[1].isdigit() and campos[0].startswith("0x"):
            linhas.append({"id": int(campos[1]), "owner": campos[2][:64],
                           "bytes": int(campos[4]) if campos[4].isdigit() else None,
                           "nattch": int(campos[5]) if campos[5].isdigit() else None,
                           "state": "SYSV_INVENTARIADO_SEM_ATRIBUICAO"})
    return {"status": "COMPLETA", "segmentos": linhas}


def bloqueios_recuperacao(proc: dict, zip_result: dict) -> list[str]:
    """Retorna bloqueios com base em evidências atuais, sem alterar processos.

    Segue política de falha fechada. Um inventário incompleto impede
    intervenção em produção até identificar sua causa.
    """
    bloqueios = []
    if not isinstance(proc, dict) or proc.get("status") != "COMPLETA":
        bloqueios.append("PROC_COBERTURA_INCOMPLETA")
    elif any(isinstance(item, dict) and
             item.get("state") == "PROC_SC_REQUER_INVESTIGACAO"
             for item in proc.get("resultados", [])):
        bloqueios.append("PROCESSOS_SC_ATIVOS")
    if not isinstance(zip_result, dict) or zip_result.get("status") != "COMPLETA":
        bloqueios.append("ZIP_COBERTURA_INCOMPLETA")
    elif zip_result.get("resultados"):
        bloqueios.append("ZIP_SC_REQUER_REVISAO")
    return bloqueios
