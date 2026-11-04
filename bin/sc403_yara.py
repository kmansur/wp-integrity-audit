"""Execução opt-in do YARA em artefatos WordPress.

O processo externo não recebe senhas ou comandos de shell.
As correspondências são registradas com paths relativos e nome da regra.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

RE_NOME_REGRA = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
MAX_OUTPUT = 1024 * 1024


def scanner_yara(site: Path, regras: Path, timeout: int = 120) -> dict:
    """Varre apenas o site solicitado, com regras locais autorizadas."""
    exe = shutil.which("yara")
    if exe is None:
        return {"status": "INCOMPLETA", "motivo": "YARA_NAO_INSTALADO", "achados": []}
    try:
        if regras.is_symlink() or not regras.is_file():
            return {"status": "INCOMPLETA", "motivo": "REGRAS_INVALIDAS", "achados": []}
        if regras.stat().st_size > 1024 * 1024:
            return {"status": "INCOMPLETA", "motivo": "REGRAS_EXCEDEM_LIMITE", "achados": []}
        if not regras.resolve().is_relative_to(Path("/etc/wp-integrity-audit").resolve()):
            return {"status": "INCOMPLETA", "motivo": "REGRAS_FORA_DE_DIRETORIO_CONFIAVEL", "achados": []}
        processo = subprocess.run(
            [exe, "-r", "-w", str(regras.resolve()), str(site.resolve())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "INCOMPLETA", "motivo": "FALHA_EXECUCAO_OU_TIMEOUT", "achados": []}
    if len(processo.stdout) > MAX_OUTPUT or len(processo.stderr) > MAX_OUTPUT:
        return {"status": "INCOMPLETA", "motivo": "SAIDA_EXCEDE_LIMITE", "achados": []}
    if processo.returncode != 0:
        return {"status": "INCOMPLETA", "motivo": "ERRO_YARA", "achados": []}
    achados = []
    prefixo = str(site.resolve()) + os.sep
    for linha in processo.stdout.decode("utf-8", "backslashreplace").splitlines():
        # Formato padrão: nome_da_regra /path/absoluto
        nome, separador, caminho = linha.partition(" ")
        if not separador or not RE_NOME_REGRA.fullmatch(nome):
            return {"status": "INCOMPLETA", "motivo": "FORMATO_RESULTADO_INVALIDO", "achados": []}
        if not caminho.startswith(prefixo):
            return {"status": "INCOMPLETA", "motivo": "CAMINHO_RESULTADO_FORA_SITE", "achados": []}
        achados.append({"regra": nome, "path": caminho[len(prefixo):],
                        "state": "YARA_REQUER_VALIDACAO"})
        if len(achados) > 2000:
            return {"status": "INCOMPLETA", "motivo": "LIMITE_CORRESPONDENCIAS", "achados": achados}
    return {"status": "COMPLETA", "achados": achados,
            "aviso": "Regra YARA é evidência para revisão, não prova isolada de malware."}
