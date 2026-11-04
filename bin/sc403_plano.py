"""Plano técnico orientado por evidências para remediação coordenada de SC.

Somente leitura: não mata processos, altera banco, move arquivos ou libera site.
O plano não constitui uma ordem executável de limpeza.
"""
from __future__ import annotations

import json
from pathlib import Path


def _ler(caso: Path, nome: str, padrao):
    arquivo = caso / nome
    if not arquivo.is_file() or arquivo.is_symlink():
        return padrao
    try:
        return json.loads(arquivo.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return padrao


def gerar_plano(caso: Path) -> dict:
    """Consolida indicadores, preservando atribuição ao tipo de evidência."""
    arquivos = _ler(caso, "file-evidence.json", [])
    banco = _ler(caso, "database-evidence.json", [])
    forense = _ler(caso, "sc403-forense.json", {})
    sql = _ler(caso, "sc403-sql-objects.json", {})
    endpoints = _ler(caso, "sc403-identifiers.json", {})
    yara = _ler(caso, "sc403-yara.json", {})
    logs = _ler(caso, "sc403-http-logs.json", {})
    processos = _ler(caso, "process-evidence.json", [])
    arquivos_revisao = [
        x.get("path") for x in arquivos if x.get("classification") in (
            "IOC_REQUER_VALIDACAO", "SC_CAMINHO_DERIVADO_REQUER_REVISAO",
            "PHP_DIRETORIO_OCULTO_REQUER_VALIDACAO", "PHP_OFUSCACAO_REQUER_QUARENTENA")
    ]
    opcoes_revisao = [
        x.get("name") for x in banco if x.get("kind") in (
            "sc403_derived_option", "cron_hook_anomaly", "family_option", "marker_option")
            and x.get("state") not in ("ABSENT", "NOT_FOUND")
    ]
    zip_revisao = [
        x.get("path") for x in forense.get("zip", {}).get("resultados", [])
    ]
    processo_revisao = [
        x.get("pid") for x in forense.get("proc", {}).get("resultados", [])
        if x.get("state") == "PROC_SC_REQUER_INVESTIGACAO"
    ]
    registros_yara = len(yara.get("achados", []))
    objetos_sql = len(sql.get("objetos", []))
    endpoints_http = {
        "sw": endpoints.get("endpoint_sw"),
        "instalador": endpoints.get("endpoint_instalador"),
    }
    cobertura = {
        "arquivo": (caso / "file-evidence.json").is_file(),
        "banco": (caso / "database-evidence.json").is_file(),
        "runtime": (caso / "sc403-forense.json").is_file(),
        "sql_programavel": sql.get("status", "NAO_EXECUTADA"),
        "yara": yara.get("status", "NAO_SOLICITADO"),
        "logs": logs.get("status", "NAO_SOLICITADO"),
    }
    pendencias = [
        "Preservar evidências e hashes antes de qualquer alteração.",
        "Confirmar backup externo restaurável e janela de manutenção autorizada.",
        "Isolar execução PHP do site sem interromper serviços de outros domínios.",
        "Revisar manualmente todos os arquivos e objetos SQL listados como candidatos.",
        "Investigar mecanismos de reinfecção em processos, banco, arquivos, memória e navegador.",
        "Rotacionar credenciais e sessões em procedimento aprovado.",
        "Executar nova auditoria independente após remediação e monitorar reinfecção.",
    ]
    bloqueios = []
    if not cobertura["banco"]:
        bloqueios.append("BANCO_NAO_AUDITADO")
    if not cobertura["runtime"]:
        bloqueios.append("RUNTIME_NAO_AUDITADO")
    if forense.get("proc", {}).get("status") not in ("COMPLETA",):
        bloqueios.append("PROCESSOS_COBERTURA_INCOMPLETA")
    if forense.get("zip", {}).get("status") != "COMPLETA":
        bloqueios.append("ZIP_COBERTURA_INCOMPLETA")
    if processos or processo_revisao:
        bloqueios.append("PROCESSO_SUSPEITO_ATIVO_OU_ASSOCIADO")
    if arquivos_revisao or opcoes_revisao or zip_revisao or registros_yara:
        bloqueios.append("INDICADORES_REQUEREM_VALIDACAO")
    plano = {
        "schema_version": 1,
        "tipo": "PLANO_TECNICO_NAO_EXECUTAVEL",
        "execucao_automatica_autorizada": False,
        "liberacao_do_site_autorizada": False,
        "fontes": cobertura,
        "indicadores": {
            "arquivos": sorted(set(p for p in arquivos_revisao if isinstance(p, str))),
            "opcoes_sql": sorted(set(p for p in opcoes_revisao if isinstance(p, str))),
            "arquivos_zip": sorted(set(p for p in zip_revisao if isinstance(p, str))),
            "processos_por_pid": sorted(set(p for p in processo_revisao if isinstance(p, int))),
            "processos_ioc_preexistentes": len(processos),
            "objetos_sql_a_revisar": objetos_sql,
            "correspondencias_yara": registros_yara,
            "acessos_endpoint_sw": logs.get("total_service_worker", 0),
            "acessos_endpoint_instalador": logs.get("total_instalador", 0),
        },
        "endpoints_derivados": endpoints_http,
        "bloqueios": sorted(set(bloqueios)),
        "etapas_preparatorias": pendencias,
        "observacao": "Este plano não contém comandos destrutivos e não substitui análise humana.",
    }
    return plano
