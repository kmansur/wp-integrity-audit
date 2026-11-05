"""Linha do tempo conservadora das evidências SC.

Eventos sem data confiável permanecem no arquivo, com ``horario_confiavel``
falso. O módulo nunca inventa horário de execução a partir de um indicador.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path


def _evento(tipo: str, fonte: str, *, horario: str | None = None,
            confiavel: bool = False, detalhe: str = "") -> dict:
    return {"tipo": tipo, "fonte": fonte, "horario": horario,
            "horario_confiavel": confiavel, "detalhe": detalhe}


def gerar(case: Path, files: list[dict], processes: list[str],
          reconstrucao: dict | None = None) -> dict:
    agora = dt.datetime.now(dt.timezone.utc).isoformat()
    eventos = [_evento("COLETA_AUDITORIA", "wp-integrity-audit",
                       horario=agora, confiavel=True,
                       detalhe="momento de coleta; não é horário de execução do malware")]
    for item in files:
        if item.get("mtime_utc"):
            eventos.append(_evento(
                "ARQUIVO_INDICADOR_OU_REVISÃO", "filesystem",
                horario=item["mtime_utc"], confiavel=False,
                detalhe=f"{item.get('path', '[CAMINHO_OMITIDO]')} — mtime é metadado manipulável"))
    for processo in processes:
        eventos.append(_evento("PROCESSO_INDICADOR", "processos",
                               detalhe="processo compatível observado; o inventário não fornece horário de início"))
    if reconstrucao:
        for item in reconstrucao.get("indicadores", []):
            horario = item.get("timestamp_utc")
            if not horario and item.get("data_utc"):
                horario = item["data_utc"] + "T00:00:00+00:00"
            eventos.append(_evento("ESTADO_RECONSTRUCAO", "banco de dados",
                                   horario=horario, confiavel=False,
                                   detalhe=f"{item.get('nome', '[NOME_OMITIDO]')}; data/horário pode ter sido gravado ou manipulado"))
    logs_path = case / "sc403-http-logs.json"
    if logs_path.is_file() and not logs_path.is_symlink():
        dados = json.loads(logs_path.read_text(encoding="utf-8"))
        for chave in ("total_service_worker", "total_instalador"):
            if int(dados.get(chave, 0) or 0):
                eventos.append(_evento("ENDPOINT_DERIVADO_EM_LOG", "logs HTTP",
                                       detalhe=f"{chave}={dados[chave]}; linha original e horário não foram exportados"))
    resultado = {
        "schema_version": 1,
        "cobertura": "COMPLETA",
        "coletado_utc": agora,
        "eventos": eventos,
        "observacoes": [
            "Horários de mtime/ctime não estabelecem cronologia confiável.",
            "Indicadores sem timestamp permanecem registrados sem data inventada.",
            "Eventos correlacionados não são contados como ocorrências independentes de comprometimento.",
        ],
    }
    caminho = case / "sc403-timeline.json"
    descriptor_fd = os.open(str(caminho), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    descriptor = os.fdopen(descriptor_fd, "w", encoding="utf-8")
    try:
        caminho.chmod(0o600)
        json.dump(resultado, descriptor, indent=2, ensure_ascii=False)
        descriptor.write("\n")
    finally:
        descriptor.close()
    return resultado
