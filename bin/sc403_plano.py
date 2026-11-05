"""Plano técnico orientado por evidências para remediação coordenada de SC.

Somente leitura: não mata processos, altera banco, move arquivos ou libera site.
O plano não constitui uma ordem executável de limpeza.
"""
from __future__ import annotations

import json
from pathlib import Path
import sc403_escopo


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
    lateral = _ler(caso, "sc403-lateral-exposure.json", {})
    if lateral:
        cobertura["exposicao_lateral"] = lateral.get("cobertura", "INCOMPLETA")
        if lateral.get("riscos") or lateral.get("cobertura") != "COMPLETA":
            bloqueios.append("EXPOSICAO_LATERAL_REQUER_REVISAO")
    shm = _ler(caso, "sc403-systemv-shm.json", {})
    if shm:
        cobertura["memoria_systemv"] = {
            "kernel": shm.get("kernel", {}).get("status", "NAO_EXECUTADA"),
            "dumps": shm.get("dumps", {}).get("status", "NAO_EXECUTADA"),
        }
        if shm.get("dumps", {}).get("status") not in (None, "COMPLETA"):
            bloqueios.append("MEMORIA_SYSTEMV_REQUER_VALIDACAO")
    escopo_path = caso / "sc403-remediation-scope.json"
    escopo_resultado = {"presente": False, "valido": False, "execucao_habilitada": False}
    if escopo_path.is_file() and not escopo_path.is_symlink():
        escopo_resultado["presente"] = True
        try:
            escopo_resultado.update(sc403_escopo.validar(json.loads(escopo_path.read_text(encoding="utf-8"))))
        except (OSError, ValueError, json.JSONDecodeError) as erro:
            escopo_resultado["erro"] = type(erro).__name__
            bloqueios.append("ESCOPO_REMEDIACAO_INVALIDO")
    etapas = [
        {"ordem": 1, "nome": "preservar_evidencias", "responsavel": "equipe_forense",
         "precondicoes": ["manifesto e hashes preservados", "cadeia de custódia registrada"],
         "acoes_planejadas": ["validar o caso e o backup sem alterar o site"], "executavel": False},
        {"ordem": 2, "nome": "validar_backup_restauravel", "responsavel": "administrador_do_ambiente",
         "precondicoes": ["backup independente disponível", "teste em ambiente descartável"],
         "acoes_planejadas": ["restaurar uma cópia fora da produção e conferir hashes"], "executavel": False},
        {"ordem": 3, "nome": "conter_escopo_autorizado", "responsavel": "responsavel_pela_mudanca",
         "precondicoes": ["domínio isolado", "janela aprovada", "processos associados identificados"],
         "acoes_planejadas": ["registrar contenção por domínio; não aplicar bloqueio global"], "executavel": False},
        {"ordem": 4, "nome": "neutralizar_persistencia", "responsavel": "equipe_tecnica",
         "precondicoes": ["diretivas PHP e cron revisados", "evidência preservada"],
         "acoes_planejadas": ["produzir plano específico de alteração e rollback"], "executavel": False},
        {"ordem": 5, "nome": "quarentenar_artefatos", "responsavel": "equipe_forense",
         "precondicoes": ["hashes e proprietário registrados", "quarentena fora do document root"],
         "acoes_planejadas": ["mover somente itens aprovados e registrar rollback"], "executavel": False},
        {"ordem": 6, "nome": "revisar_banco_e_credenciais", "responsavel": "administrador_do_site",
         "precondicoes": ["dump consistente", "seletores exatos e aprovados"],
         "acoes_planejadas": ["revisar opções, cron, sessões, administradores e salts"], "executavel": False},
        {"ordem": 7, "nome": "verificar_pos_recuperacao", "responsavel": "equipe_forense",
         "precondicoes": ["alterações documentadas", "auditoria independente agendada"],
         "acoes_planejadas": ["executar nova auditoria e monitorar reaparecimento"], "executavel": False},
    ]
    plano = {
        "schema_version": 2,
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
        "etapas_coordenadas": etapas,
        "condicoes_de_interrupcao": sorted(set(bloqueios)) or ["COBERTURA_COMPLETA_AINDA_EXIGE_APROVACAO"],
        "escopo_remediacao": escopo_resultado,
        "observacao": "Este plano não contém comandos destrutivos e não substitui análise humana.",
    }
    return plano
